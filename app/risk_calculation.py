def calculate_virustotal_score(virustotal_result, malicious_points, suspicious_points):
    if not virustotal_result:
        return 0

    stats = virustotal_result.get("last_analysis_stats")

    if not stats:
        return 0

    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)

    total = sum(stats.values())

    if total == 0:
        return 0

    malicious_ratio = malicious / total
    suspicious_ratio = suspicious / total

    score = 0

    score += malicious_ratio * malicious_points
    score += suspicious_ratio * suspicious_points

    return score


def create_verdict(score):
    score = min(round(score, 2), 100)

    if score >= 70:
        verdict = "MALICIOUS"
    elif score >= 30:
        verdict = "SUSPICIOUS"
    else:
        verdict = "LOW_RISK"

    return {
        "score": score,
        "verdict": verdict
    }


def calculate_risk_file(local_database_match, virustotal_result, type_mismatch=False):
    if virustotal_result and virustotal_result.get("found") is False:
        if not local_database_match:
            return {
                "score": 0,
                "verdict": "UNKNOWN"
            }

    score = 0

    if local_database_match:
        score += 50

    score += calculate_virustotal_score(
        virustotal_result,
        malicious_points=40,
        suspicious_points=10
    )

    if type_mismatch:
        score += 15

    return create_verdict(score)


def calculate_risk_hash(local_database_match, virustotal_result):
    if virustotal_result and virustotal_result.get("found") is False:
        if not local_database_match:
            return {
                "score": 0,
                "verdict": "UNKNOWN"
            }

    score = 0

    if local_database_match:
        score += 50

    score += calculate_virustotal_score(
        virustotal_result,
        malicious_points=40,
        suspicious_points=10
    )

    return create_verdict(score)


def calculate_risk_domain(virustotal_result, heuristics=None, url_analysis=None, certificate_info=None):
    if virustotal_result and virustotal_result.get("found") is False:
        return {
            "score": 0,
            "verdict": "UNKNOWN"
        }

    score = 0

    score += calculate_virustotal_score(
        virustotal_result,
        malicious_points=40,
        suspicious_points=10
    )

    if heuristics:
        if heuristics.get("subdomain_count", 0) >= 3:
            score += 10

        if heuristics.get("hyphen_count", 0) >= 2:
            score += 5

        if heuristics.get("digit_count", 0) >= 3:
            score += 5

    if url_analysis:
        if url_analysis.get("has_at_symbol") is True:
            score += 15

        if url_analysis.get("is_punycode") is True:
            score += 10

        if url_analysis.get("url_length", 0) >= 150:
            score += 5

        if url_analysis.get("percent_encoded") is True:
            score += 5

    if certificate_info:
        if certificate_info.get("certificate_expired") is True:
            score += 10

    return create_verdict(score)


def calculate_risk_ip(virustotal_result, ip_analysis=None):
    if virustotal_result and virustotal_result.get("found") is False:
        return {
            "score": 0,
            "verdict": "UNKNOWN"
        }

    score = 0

    score += calculate_virustotal_score(
        virustotal_result,
        malicious_points=60,
        suspicious_points=20
    )

    if ip_analysis:
        if ip_analysis.get("is_reserved") is True:
            score += 5

    return create_verdict(score)