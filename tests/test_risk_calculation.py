from app.risk_calculation import (
    calculate_risk_file,
    calculate_risk_hash,
    calculate_risk_domain,
    calculate_risk_ip
)


def test_calculate_risk_file_unknown():
    virustotal_result = {
        "found": False
    }

    result = calculate_risk_file(
        False,
        virustotal_result
    )

    assert result["score"] == 0
    assert result["verdict"] == "UNKNOWN"


def test_calculate_risk_file_local_database():
    virustotal_result = {
        "found": True,
        "last_analysis_stats": {
            "malicious": 0,
            "suspicious": 0,
            "harmless": 80,
            "undetected": 0
        }
    }

    result = calculate_risk_file(
        True,
        virustotal_result
    )

    assert result["score"] == 50
    assert result["verdict"] == "SUSPICIOUS"


def test_calculate_risk_file_virustotal():
    virustotal_result = {
        "found": True,
        "last_analysis_stats": {
            "malicious": 10,
            "suspicious": 0,
            "harmless": 60,
            "undetected": 10
        }
    }

    result = calculate_risk_file(
        False,
        virustotal_result
    )

    assert result["score"] == 5
    assert result["verdict"] == "LOW_RISK"


def test_calculate_risk_file_type_mismatch():
    virustotal_result = {
        "found": True,
        "last_analysis_stats": {
            "malicious": 0,
            "suspicious": 0,
            "harmless": 80,
            "undetected": 0
        }
    }

    result = calculate_risk_file(
        False,
        virustotal_result,
        type_mismatch=True
    )

    assert result["score"] == 15
    assert result["verdict"] == "LOW_RISK"


def test_calculate_risk_hash():
    virustotal_result = {
        "found": True,
        "last_analysis_stats": {
            "malicious": 20,
            "suspicious": 0,
            "harmless": 60,
            "undetected": 0
        }
    }

    result = calculate_risk_hash(
        False,
        virustotal_result
    )

    assert result["score"] == 10
    assert result["verdict"] == "LOW_RISK"


def test_calculate_risk_domain():
    virustotal_result = {
        "found": True,
        "last_analysis_stats": {
            "malicious": 0,
            "suspicious": 0,
            "harmless": 80,
            "undetected": 0
        }
    }

    heuristics = {
        "subdomain_count": 3,
        "hyphen_count": 2,
        "digit_count": 3
    }

    url_analysis = {
        "has_at_symbol": True,
        "is_punycode": True,
        "url_length": 200,
        "percent_encoded": True
    }

    certificate_info = {
        "certificate_expired": True
    }

    result = calculate_risk_domain(
        virustotal_result,
        heuristics,
        url_analysis,
        certificate_info
    )

    assert result["score"] == 65
    assert result["verdict"] == "SUSPICIOUS"


def test_calculate_risk_ip():
    virustotal_result = {
        "found": True,
        "last_analysis_stats": {
            "malicious": 10,
            "suspicious": 0,
            "harmless": 80,
            "undetected": 10
        }
    }

    ip_analysis = {
        "is_reserved": True
    }

    result = calculate_risk_ip(
        virustotal_result,
        ip_analysis
    )

    assert result["score"] == 11
    assert result["verdict"] == "LOW_RISK"