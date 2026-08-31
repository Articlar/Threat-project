from unittest.mock import patch
from app.virustotal import get_hash_report
import urllib.error

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