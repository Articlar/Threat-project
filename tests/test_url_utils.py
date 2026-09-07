from app.url_utils import *

def test_extract_domain():
    assert extract_domain("https://www.example.com") == "www.example.com"
    assert extract_domain("http://www.example.com") == "www.example.com"
    assert extract_domain("https://www.example.com/las") == "www.example.com"
    assert extract_domain("example.com/last") == "example.com"
    assert extract_domain("https://") is None

def test_check_domain():
    assert check_domain("example.com") == True

    assert check_domain("sub.example.com") == True

    assert check_domain("example") == False

    assert check_domain("example..com") == False

    assert check_domain("example-.com") == False

    assert check_domain("exam2@ple.com") == False

    assert check_domain("-example.com") == False

    assert check_domain("ex_ample.com") == False
    assert check_domain("www.example.com") == True

def test_resolve_domain():
    result = resolve_domain("example.com")
    assert result is not None


def test_get_http_info():
    https_status, http_status = get_http_info("example.com")

    assert isinstance(https_status, int) or https_status is None
    assert isinstance(http_status, int) or http_status is None

def test_get_certificate_info():
    result = get_certificate_info("google.com")

    assert result is not None
    assert isinstance(result, dict)
    assert "issuer" in result
    assert "subject" in result
    assert "not_after" in result
    assert result is not None
    assert "certificate_expired" in result
    assert "certificate_days_remaining" in result
    assert "tls_version" in result
    assert "cipher in result"

    assert isinstance(result["certificate_expired"], bool)
    assert isinstance(result["certificate_days_remaining"], int)

    assert result["tls_version"] is not None
    assert result["cipher"] is not None

def test_is_ip_address():
    assert is_ip_address("192.168.1.1") is True
    assert is_ip_address("8.8.8.8") is True
    assert is_ip_address("example.com") is False
    assert is_ip_address("2001:4860:4860::8888") is True
    assert is_ip_address("example.com") is False


def test_count_subdomains():
    assert count_subdomains("example.com") == 0
    assert count_subdomains("www.example.com") == 1
    assert count_subdomains("a.b.example.com") == 2


def test_get_domain_length():
    assert get_domain_length("example.com") == 11


def test_analyze_domain():
    result = analyze_domain("www.example.com")

    assert result["is_ip_address"] is False
    assert result["subdomain_count"] == 1
    assert result["domain_length"] == 15
    assert result["hyphen_count"] == 0
    assert result["digit_count"] == 0

    result = analyze_domain("login-123.example.com")

    assert result["hyphen_count"] == 1
    assert result["digit_count"] == 3

def test_get_ip_version():
    assert get_ip_version("8.8.8.8") == "IPv4"
    assert get_ip_version("2001:4860:4860::8888") == "IPv6"
    assert get_ip_version("example.com") is None

def test_analyze_url():
    result = analyze_url("https://example.com/login?id=123")

    assert result["url_length"] > 0
    assert result["path_length"] == 6
    assert result["query_length"] == 6
    assert result["has_query"] is True
    assert result["has_fragment"] is False
    assert result["percent_encoded"] is False
    assert result["has_at_symbol"] is False
    assert result["is_punycode"] is False

    result = analyze_url("https://example.com@evil.com")

    assert result["has_at_symbol"] is True

    result = analyze_url("https://xn--example.com")

    assert result["is_punycode"] is True

def test_analyze_url_encoded():
    result = analyze_url("https://example.com/%2Fadmin")

    assert result["percent_encoded"] is True

def test_get_dns_records():
    result = get_dns_records("google.com")

    assert isinstance(result, dict)

    for record_type in ["A", "AAAA", "MX", "NS", "CNAME", "TXT"]:
        assert record_type in result
        assert isinstance(result[record_type], list)

def test_analyze_ip():
    result = analyze_ip("8.8.8.8")

    assert result is not None
    assert result["version"] == 4
    assert result["is_global"] is True
    assert result["is_private"] is False

    result = analyze_ip("192.168.1.1")

    assert result["is_private"] is True
    assert result["is_global"] is False

    assert analyze_ip("not-an-ip") is None