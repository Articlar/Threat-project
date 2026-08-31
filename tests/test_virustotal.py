from unittest.mock import patch
import urllib.error
from app.virustotal import (
    get_hash_report,
    get_domain_report,
    get_url_report,
    get_ip_report
)

def test_get_hash_report_no_api_key():
    with patch("app.virustotal.os.getenv", return_value=None):
        result = get_hash_report("44d88612fea8a8f36de82e1278abb02f")

    assert result is None

def test_get_hash_report_success():
    fake_data = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 5,
                    "suspicious": 1,
                    "harmless": 60,
                    "undetected": 10
                },
                "reputation": 25,
                "meaningful_name": "example.exe",
                "first_submission_date": 1234567890,
                "last_analysis_date": 1234567890
            }
        }
    }

    with patch("app.virustotal.os.getenv", return_value="fake-api-key"), \
         patch("app.virustotal.json.load", return_value=fake_data), \
         patch("app.virustotal.urllib.request.urlopen") as mock_urlopen:

        mock_urlopen.return_value.__enter__.return_value = object()

        result = get_hash_report("44d88612fea8a8f36de82e1278abb02f")

    assert result["found"] is True
    assert result["reputation"] == 25
    assert result["meaningful_name"] == "example.exe"

def test_get_hash_report_not_found():
    with patch("app.virustotal.os.getenv", return_value="fake-api-key"), \
         patch(
             "app.virustotal.urllib.request.urlopen",
             side_effect=urllib.error.HTTPError(
                 url="https://www.virustotal.com",
                 code=404,
                 msg="Not Found",
                 hdrs=None,
                 fp=None
             )
         ):

        result = get_hash_report("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")

    assert result["found"] is False

def test_get_domain_report_no_api_key():
    with patch("app.virustotal.os.getenv", return_value=None):
        result = get_domain_report("example.com")

    assert result is None


def test_get_domain_report_success():
    fake_data = {
        "data": {
            "attributes": {
                "reputation": 10,
                "categories": {
                    "Google": "Technology"
                },
                "last_analysis_stats": {
                    "malicious": 1,
                    "suspicious": 0,
                    "harmless": 80,
                    "undetected": 5
                },
                "creation_date": 1234567890,
                "registrar": "Example Registrar",
                "last_analysis_date": 1234567890
            }
        }
    }

    with patch("app.virustotal.os.getenv", return_value="fake-api-key"), \
         patch("app.virustotal.json.load", return_value=fake_data), \
         patch("app.virustotal.urllib.request.urlopen") as mock_urlopen:

        mock_urlopen.return_value.__enter__.return_value = object()

        result = get_domain_report("example.com")

    assert result["found"] is True
    assert result["reputation"] == 10
    assert result["registrar"] == "Example Registrar"
    assert result["last_analysis_stats"]["malicious"] == 1


def test_get_domain_report_not_found():
    with patch("app.virustotal.os.getenv", return_value="fake-api-key"), \
         patch(
             "app.virustotal.urllib.request.urlopen",
             side_effect=urllib.error.HTTPError(
                 url="https://www.virustotal.com",
                 code=404,
                 msg="Not Found",
                 hdrs=None,
                 fp=None
             )
         ):

        result = get_domain_report("this-domain-does-not-exist.example")

    assert result["found"] is False

def test_get_url_report_no_api_key():
    with patch("app.virustotal.os.getenv", return_value=None):
        result = get_url_report("https://example.com")

    assert result is None


def test_get_url_report_success():
    fake_data = {
        "data": {
            "attributes": {
                "url": "https://example.com",
                "reputation": 15,
                "categories": {
                    "Google": "Technology"
                },
                "last_analysis_stats": {
                    "malicious": 0,
                    "suspicious": 0,
                    "harmless": 80,
                    "undetected": 10
                },
                "times_submitted": 4,
                "title": "Example Domain",
                "first_submission_date": 1234567890,
                "last_analysis_date": 1234567890
            }
        }
    }

    with patch("app.virustotal.os.getenv", return_value="fake-api-key"), \
         patch("app.virustotal.json.load", return_value=fake_data), \
         patch("app.virustotal.urllib.request.urlopen") as mock_urlopen:

        mock_urlopen.return_value.__enter__.return_value = object()

        result = get_url_report("https://example.com")

    assert result["found"] is True
    assert result["url"] == "https://example.com"
    assert result["reputation"] == 15
    assert result["title"] == "Example Domain"


def test_get_url_report_not_found():
    with patch("app.virustotal.os.getenv", return_value="fake-api-key"), \
         patch(
             "app.virustotal.urllib.request.urlopen",
             side_effect=urllib.error.HTTPError(
                 url="https://www.virustotal.com",
                 code=404,
                 msg="Not Found",
                 hdrs=None,
                 fp=None
             )
         ):

        result = get_url_report("https://this-does-not-exist.example")

    assert result["found"] is False

def test_get_ip_report_no_api_key():
    with patch("app.virustotal.os.getenv", return_value=None):
        result = get_ip_report("8.8.8.8")

    assert result is None


def test_get_ip_report_success():
    fake_data = {
        "data": {
            "attributes": {
                "as_owner": "Google LLC",
                "asn": 15169,
                "country": "US",
                "continent": "NA",
                "reputation": 100,
                "last_analysis_stats": {
                    "malicious": 0,
                    "suspicious": 0,
                    "harmless": 80,
                    "undetected": 10
                },
                "whois_date": 1234567890,
                "tags": ["cloud", "dns"]
            }
        }
    }

    with patch("app.virustotal.os.getenv", return_value="fake-api-key"), \
         patch("app.virustotal.json.load", return_value=fake_data), \
         patch("app.virustotal.urllib.request.urlopen") as mock_urlopen:

        mock_urlopen.return_value.__enter__.return_value = object()

        result = get_ip_report("8.8.8.8")

    assert result["found"] is True
    assert result["as_owner"] == "Google LLC"
    assert result["asn"] == 15169
    assert result["country"] == "US"
    assert result["reputation"] == 100


def test_get_ip_report_not_found():
    with patch("app.virustotal.os.getenv", return_value="fake-api-key"), \
         patch(
             "app.virustotal.urllib.request.urlopen",
             side_effect=urllib.error.HTTPError(
                 url="https://www.virustotal.com",
                 code=404,
                 msg="Not Found",
                 hdrs=None,
                 fp=None
             )
         ):

        result = get_ip_report("192.0.2.1")

    assert result["found"] is False