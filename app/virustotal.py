import json
import os
from dotenv import load_dotenv
import urllib.request
import urllib.error
import base64

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

def get_domain_report(domain):
    api_key = os.getenv("VT_API_KEY")

    if not api_key:
        return None

    url = f"{BASE_URL}/domains/{domain}"
    
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
            "reputation": attributes.get("reputation"),
            "categories": attributes.get("categories"),
            "last_analysis_stats": attributes.get("last_analysis_stats"),
            "creation_date": attributes.get("creation_date"),
            "registrar": attributes.get("registrar"),
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

def get_url_report(url_string):
    api_key = os.getenv("VT_API_KEY")

    if not api_key:
        return None

    url_id = base64.urlsafe_b64encode(url_string.encode()).decode().strip("=")

    url = f"{BASE_URL}/urls/{url_id}"

    request = urllib.request.Request(
        url,
        headers={
            "x-apikey": api_key
        }
    )

    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            data = json.load(response)

        attributes = data["data"]["attributes"]

        return {
            "found": True,
            "url": attributes.get("url"),
            "reputation": attributes.get("reputation"),
            "categories": attributes.get("categories"),
            "last_analysis_stats": attributes.get("last_analysis_stats"),
            "times_submitted": attributes.get("times_submitted"),
            "title": attributes.get("title"),
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

def get_ip_report(ip_address):
    api_key = os.getenv("VT_API_KEY")

    if not api_key:
        return None

    url = f"{BASE_URL}/ip_addresses/{ip_address}"

    request = urllib.request.Request(
        url,
        headers={
            "x-apikey": api_key
        }
    )

    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            data = json.load(response)

        attributes = data["data"]["attributes"]

        return {
            "found": True,
            "as_owner": attributes.get("as_owner"),
            "asn": attributes.get("asn"),
            "country": attributes.get("country"),
            "continent": attributes.get("continent"),
            "reputation": attributes.get("reputation"),
            "last_analysis_stats": attributes.get("last_analysis_stats"),
            "whois_date": attributes.get("whois_date"),
            "tags": attributes.get("tags")
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