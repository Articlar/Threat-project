from app.url_utils import (
    extract_domain, 
    check_domain, 
    resolve_domain, 
    get_http_info
)

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