
def calculate_risk(local_database_match, virustotal_result):
    score = 0

    if virustotal_result["found"] is False:
        return {
            "score": score,
            "verdict": "UNKNOWN"
        }
    
    if local_database_match:
        score+= 50

    if virustotal_result:
        stats = virustotal_result.get("last_analysis_stats")

        if stats:
            malicious = stats.get("malicious", 0 )
            suspicious = stats.get("suspicious", 0)
            total = sum(stats.values())

            if total > 0:
                malicious_ratio = malicious / total
                suspicious_ratio = suspicious / total

                score += malicious_ratio * 40
                score += suspicious_ratio * 10

    if score >= 70:
        verdict = "MALICIOUS"
    elif score >= 30:
        verdict = "SUSPICIOUS"
    else:
        verdict = "LOW_RISK"

    return {
        "score": round(score, 2),
        "verdict": verdict
    }