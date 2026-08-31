import json
import os
from dotenv import load_dotenv
import urllib.request
import urllib.error

BASE_URL = "https://www.virustotal.com/api/v3"

load_dotenv()

def get_hash_report(hash_string):
    api_key = os.getenv("VT_API_KEY")

    if not api_key:
        return None

    url = f"{BASE_URL}/files/{hash_string}"

    request = urllib.request.Request(
        url,
        headers={
            "x-apikey":api_key
        }
    )

    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            data = json.load(response)

        attributes = data["data"]["attributes"]

        return {
            "found": True,
            "last_analysis_stats": attributes.get("last_analysis_stats"),
            "reputation": attributes.get("reputation"),
            "meaningful_name": attributes.get("meaningful_name"),
            "first_submission_date": attributes.get("first_submission_date"),
            "last_analysis_date": attributes.get("last_analysis_date")
        }

    except urllib.error.HTTPError as error:
        if error.code == 404:
            return {
                "found": False
            }

        return {
            "found": False,
            "error": f"HTTP {error.code}"
        }

    except urllib.error.URLError as error:
        return {
            "found": False,
            "error": str(error)
        }