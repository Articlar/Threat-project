def print_header():
    print()
    print("=" * 30)
    print("     THREAT INTELLIGENCE SCANNER")
    print("=" * 30)


def print_section(title):
    print()
    print("-" * 30)
    print(title)
    print("-" * 30)


def print_hash_result(result):
    print_header()
    print_section("HASH ANALYSIS")

    print(f"Hash:              {result.get('hash', 'N/A')}")
    print(f"Hash Type:         {result.get('hash_type', 'N/A')}")

    print_section("LOCAL DATABASE")

    print(f"Match Found:       {result.get('found_in_local_database', False)}")

    if result.get("found_in_local_database"):
        print(f"Name:              {result.get('name', 'N/A')}")
        print(f"Status:            {result.get('status', 'N/A')}")
        print(f"Description:       {result.get('description', 'N/A')}")

    virustotal = result.get("virustotal")

    if virustotal:
        print_section("VIRUSTOTAL")

        if virustotal.get("found") is False:
            print("Report Found:      NO")
        else:
            stats = virustotal.get("last_analysis_stats", {})

            print("Report Found:      YES")
            print(f"Malicious:         {stats.get('malicious', 0)}")
            print(f"Suspicious:        {stats.get('suspicious', 0)}")
            print(f"Harmless:          {stats.get('harmless', 0)}")
            print(f"Undetected:        {stats.get('undetected', 0)}")

    print_section("RISK ASSESSMENT")

    risk = result.get("risk_score", {})

    print(f"Risk Score:         {risk.get('score', 'N/A')} / 100")
    print(f"Verdict:            {risk.get('verdict', 'UNKNOWN')}")


def print_domain_result(result):
    print_header()
    print_section("DOMAIN ANALYSIS")

    print(f"Domain:             {result.get('domain', 'N/A')}")
    print(f"IP Address:         {result.get('ip_address', 'N/A')}")

    print_section("HTTP / HTTPS")

    print(f"HTTPS Status:       {result.get('https_status', 'N/A')}")
    print(f"HTTP Status:        {result.get('http_status', 'N/A')}")

    certificate = result.get("certificate")

    if certificate:
        print_section("TLS / CERTIFICATE")

        print(f"TLS Version:        {certificate.get('tls_version', 'N/A')}")
        print(f"Cipher:             {certificate.get('cipher', 'N/A')}")
        print(f"Issuer:             {certificate.get('issuer', 'N/A')}")
        print(f"Valid Until:        {certificate.get('not_after', 'N/A')}")

        if certificate.get("certificate_expired") is True:
            print("Certificate:        EXPIRED")
        elif certificate.get("certificate_expired") is False:
            print("Certificate:        VALID")

        print(
            f"Days Remaining:     "
            f"{certificate.get('certificate_days_remaining', 'N/A')}"
        )

    heuristics = result.get("heuristics")

    if heuristics:
        print_section("DOMAIN HEURISTICS")

        print(f"Subdomains:         {heuristics.get('subdomain_count', 0)}")
        print(f"Domain Length:      {heuristics.get('domain_length', 0)}")
        print(f"Hyphens:            {heuristics.get('hyphen_count', 0)}")
        print(f"Digits:             {heuristics.get('digit_count', 0)}")

    url_analysis = result.get("url_analysis")

    if url_analysis:
        print_section("URL ANALYSIS")

        print(f"URL Length:         {url_analysis.get('url_length', 0)}")
        print(f"Path Length:        {url_analysis.get('path_length', 0)}")
        print(f"Query Length:       {url_analysis.get('query_length', 0)}")
        print(f"Has Query:          {url_analysis.get('has_query', False)}")
        print(f"Has Fragment:       {url_analysis.get('has_fragment', False)}")
        print(f"Percent Encoded:    {url_analysis.get('percent_encoded', False)}")
        print(f"@ Symbol:           {url_analysis.get('has_at_symbol', False)}")
        print(f"Punycode:           {url_analysis.get('is_punycode', False)}")

    dns_records = result.get("dns_records")

    if dns_records:
        print_section("DNS RECORDS")

        for record_type, records in dns_records.items():
            print(f"{record_type}:")

            if records:
                for record in records:
                    print(f"  {record}")
            else:
                print("  None")

    print_section("VIRUSTOTAL")

    for label, virustotal_result in [
        ("Domain", result.get("virustotal_domain")),
        ("URL", result.get("virustotal_url"))
    ]:
        if virustotal_result is None:
            continue

        print(f"{label} Report:")

        if virustotal_result.get("found") is False:
            print("  Report Found:    NO")
        else:
            stats = virustotal_result.get(
                "last_analysis_stats",
                {}
            )

            print("  Report Found:    YES")
            print(f"  Malicious:       {stats.get('malicious', 0)}")
            print(f"  Suspicious:      {stats.get('suspicious', 0)}")
            print(f"  Harmless:        {stats.get('harmless', 0)}")
            print(f"  Undetected:      {stats.get('undetected', 0)}")

    print_section("RISK ASSESSMENT")

    risk = result.get("risk", {})

    print(f"Risk Score:         {risk.get('score', 'N/A')} / 100")
    print(f"Verdict:            {risk.get('verdict', 'UNKNOWN')}")


def print_ip_result(result):
    print_header()
    print_section("IP ANALYSIS")

    print(f"IP Address:         {result.get('ip_address', 'N/A')}")
    print(f"Valid IP:           {result.get('valid_ip', False)}")
    print(f"Version:            {result.get('version', 'N/A')}")

    analysis = result.get("analysis")

    if analysis:
        print_section("IP INFORMATION")

        print(f"Private:            {analysis.get('is_private', False)}")
        print(f"Global:             {analysis.get('is_global', False)}")
        print(f"Loopback:           {analysis.get('is_loopback', False)}")
        print(f"Reserved:           {analysis.get('is_reserved', False)}")

    virustotal = result.get("virustotal")

    if virustotal:
        print_section("VIRUSTOTAL")

        if virustotal.get("found") is False:
            print("Report Found:       NO")
        else:
            stats = virustotal.get("last_analysis_stats", {})

            print("Report Found:       YES")
            print(f"Malicious:          {stats.get('malicious', 0)}")
            print(f"Suspicious:         {stats.get('suspicious', 0)}")
            print(f"Harmless:           {stats.get('harmless', 0)}")
            print(f"Undetected:         {stats.get('undetected', 0)}")

    print_section("RISK ASSESSMENT")

    risk = result.get("risk_result", {})

    print(f"Risk Score:         {risk.get('score', 'N/A')} / 100")
    print(f"Verdict:            {risk.get('verdict', 'UNKNOWN')}")


def print_file_result(result):
    print_header()
    print_section("FILE ANALYSIS")

    print(f"File:               {result.get('file', 'N/A')}")

    metadata = result.get("metadata")

    if metadata:
        print(f"File Name:          {metadata.get('file_name', 'N/A')}")
        print(f"Extension:          {metadata.get('file_extension', 'N/A')}")
        print(f"File Size:          {metadata.get('file_size', 'N/A')} bytes")

    file_type = result.get("file_type")

    if file_type:
        print_section("FILE TYPE")

        print(f"Extension:          {file_type.get('extension', 'N/A')}")
        print(f"Executable:         {file_type.get('is_executable', False)}")
        print(f"Script:             {file_type.get('is_script', False)}")

    print(f"Detected Type:      {result.get('detected_type', 'N/A')}")
    print(f"Type Mismatch:      {result.get('type_mismatch', False)}")

    hashes = result.get("hashes")

    if hashes:
        print_section("FILE HASHES")

        print(f"MD5:                {hashes.get('md5', 'N/A')}")
        print(f"SHA1:               {hashes.get('sha1', 'N/A')}")
        print(f"SHA256:             {hashes.get('sha256', 'N/A')}")

    database_results = result.get("local_database", {})

    print_section("LOCAL DATABASE")

    for hash_name, database_result in database_results.items():
        if database_result:
            print(f"{hash_name.upper()}:       MATCH")
            print(f"  Name:             {database_result.get('name', 'N/A')}")
            print(f"  Status:           {database_result.get('type', 'N/A')}")
        else:
            print(f"{hash_name.upper()}:       No match")

    virustotal = result.get("virustotal")

    if virustotal:
        print_section("VIRUSTOTAL")

        if virustotal.get("found") is False:
            print("Report Found:       NO")
        else:
            stats = virustotal.get("last_analysis_stats", {})

            print("Report Found:       YES")
            print(f"Malicious:          {stats.get('malicious', 0)}")
            print(f"Suspicious:         {stats.get('suspicious', 0)}")
            print(f"Harmless:           {stats.get('harmless', 0)}")
            print(f"Undetected:         {stats.get('undetected', 0)}")

    print_section("RISK ASSESSMENT")

    risk = result.get("risk", {})

    print(f"Risk Score:         {risk.get('score', 'N/A')} / 100")
    print(f"Verdict:            {risk.get('verdict', 'UNKNOWN')}")