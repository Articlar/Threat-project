from app.risk_calculation import calculate_risk

def test_unknown_file():
    virustotal_result = {
        "found":False
    }

    result = calculate_risk(False, virustotal_result)

    assert result["score"] == 0
    assert result["verdict"] == "UNKNOWN"

def test_local_database_match():
    virustotal_result = {
        "found": True,
        "last_analysis_stats": {
            "malicious": 0,
            "suspicious": 0,
            "harmless": 70,
            "undetected": 10
        }
    }

    result = calculate_risk(True, virustotal_result)

    assert result["score"] == 50
    assert result["verdict"] == "SUSPICIOUS"


def test_virustotal_malicious():
    virustotal_result = {
        "found": True,
        "last_analysis_stats": {
            "malicious": 10,
            "suspicious": 0,
            "harmless": 60,
            "undetected": 10
        }
    }

    result = calculate_risk(False, virustotal_result)

    assert result["score"] == 5
    assert result["verdict"] == "LOW_RISK"