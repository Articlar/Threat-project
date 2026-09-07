import hash_utils
import database
import url_utils
import output
import virustotal
import file_utils
import risk_calculation


def main():
    # Opening the locally saved known hashes
    known_hashes = database.load_database()

    while True:
        print("================= Threat and Hash Checks ================\n")
        print("1. HASH ANALYSIS")
        print("2. DOMAIN ANALYSIS")
        print("3. IP ANALYSIS")
        print("4. FILE ANALYSIS")
        print("999. EXIT")
        choice = input("Type a number: ")

        # Hash Analysis Option
        if choice == "1":
            print("======== Hash Analysis ========")
            user_input = input("Input hash here: ")
            hash_result = hash_utils.hash_type(user_input)
            # Input validation
            if hash_result == "Not a hash":
                print("Try again, not a valid hash")
                continue
            data = database.lookup_hash(known_hashes, user_input)

            virustotal_result = virustotal.get_hash_report(user_input)
            risk_result = risk_calculation.calculate_risk_hash(data is not None, virustotal_result)

            result = {
                "hash": user_input,
                "hash_type": hash_result,
                "found_in_local_database": data is not None,
                "name": None,
                "status": None,
                "description": None,
                "virustotal": virustotal_result,
                "risk_score": risk_result
            }

            if data is not None:
                result["name"] = data["name"]
                result["status"] = data["type"]
                result["description"] = data["description"]

            output.print_hash_result(result)

        # Domain Analysis Option
        elif choice == "2":
            print("======== Domain Analysis ========")
            user_input = input("Input URL here: ")

            # Gets hostname from user input
            domain = url_utils.extract_domain(user_input)

            if domain is None:
                print("Could not extract a domain")
                continue

            if url_utils.is_ip_address(domain):
                print("IP address. Use IP Analysis instead")
                continue

            is_domain = url_utils.check_domain(domain)
            if not is_domain:
                print("Invalid domain")
                continue

            # DNS resolution
            ip_address = url_utils.resolve_domain(domain)
            if ip_address is None:
                print("Domain does not resolve")
                continue

            # Fetch from url_utils module
            https_status, http_status = url_utils.get_http_info(domain)
            certificate_info = url_utils.get_certificate_info(domain)
            heuristics = url_utils.analyze_domain(domain)
            url_analysis = url_utils.analyze_url(user_input)
            virustotal_domain_result = virustotal.get_domain_report(domain)
            virustotal_url_result = virustotal.get_url_report(user_input)
            dns_records = url_utils.get_dns_records(domain)

            risk_result = risk_calculation.calculate_risk_domain(virustotal_domain_result, heuristics, url_analysis, certificate_info)
            result = {
                "domain": domain,
                "valid_domain": True,
                "ip_address": ip_address,
                "dns_records": dns_records,
                "https_status": https_status,
                "http_status": http_status,
                "certificate": certificate_info,
                "heuristics": heuristics,
                "url_analysis": url_analysis,
                "virustotal_domain": virustotal_domain_result,
                "virustotal_url": virustotal_url_result,
                "risk": risk_result
            }

            output.print_domain_result(result)

        # IP Analysis Choice
        elif choice == "3":
            print("======== IP Analysis ========")

            user_input = input("Input IP address here: ")

            if not url_utils.is_ip_address(user_input):
                print("Invalid IP Address")
                continue

            ip_version = url_utils.get_ip_version(user_input)
            ip_analysis = url_utils.analyze_ip(user_input)

            virustotal_ip_result = virustotal.get_ip_report(user_input)
            risk_result = risk_calculation.calculate_risk_ip(virustotal_ip_result, ip_analysis)

            result = {
                "ip_address": user_input,
                "valid_ip": True,
                "version": ip_version,
                "analysis": ip_analysis,
                "virustotal": virustotal_ip_result,
                "risk_result": risk_result
            }

            output.print_ip_result(result)

        # File Analysis Option
        elif choice == "4":
            print("======== File Analysis ========")

            file_path = input("Input file path here: ")

            hashes = file_utils.calculate_hashes(file_path)

            if hashes is None:
                print("File does not exist")
                continue

            data = database.load_database()

            md5_result = database.lookup_hash(data, hashes["md5"])
            sha1_result = database.lookup_hash(data, hashes["sha1"])
            sha256_result = database.lookup_hash(data, hashes["sha256"])
            virustotal_result = virustotal.get_hash_report(hashes["sha256"])

            file_metadata = file_utils.get_file_metadata(file_path)
            file_type_analysis = file_utils.analyze_file_type(file_path)
            detected_type = file_utils.detect_file_type(file_path)
            type_mismatch = file_utils.check_file_type_mismatch(file_path)

            local_database_match = sha256_result is not None
            
            risk = risk_calculation.calculate_risk_file(local_database_match, virustotal_result, type_mismatch)
            
            result = {
                "file": file_path,
                "metadata": file_metadata,
                "file_type": file_type_analysis,
                "detected_type": detected_type,
                "type_mismatch": type_mismatch,
                "hashes": hashes,
                "local_database": {
                    "md5": md5_result,
                    "sha1": sha1_result,
                    "sha256": sha256_result
                },
                "virustotal": virustotal_result,
                "risk": risk
            }

            output.print_file_result(result)

        # EXIT
        elif choice == "999":
            break

        else:
            print("Invalid choice, please try again")
    return 

if __name__ == "__main__":
    main()