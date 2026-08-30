import ssl
import socket
import urllib.request
import urllib.error
from urllib.parse import urlparse

def extract_domain(user_input):
    if "://" not in user_input:
        user_input = "https://" + user_input

    parsed_url = urlparse(user_input)
    return parsed_url.hostname

def check_domain(domain):
    '''
    checkDomain takes a string value 'domain' and checks its domain format. 
    '''
    split_domains = domain.split(".")
    if "" in split_domains:
        return False # Invalid domain
    elif len(split_domains) < 2:
        return False

    allowed_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-"
    for part in split_domains:

        # Check for invalid characters
        for char in part:
            if char not in allowed_chars:
                return False
        # Check for leading/trailing hyphens
        if part[0] == '-' or part[-1] == '-':
            return False

    return True

def resolve_domain(domain):
    try:
        ip_address = socket.gethostbyname(domain)
        return ip_address
    except socket.gaierror:
        return None

def get_http_info(domain):
    https_url = "https://" + domain
    http_url = "http://" + domain
    try:
        with urllib.request.urlopen(https_url) as response:
            https_status = response.status
    except urllib.error.HTTPError as error:
        https_status = error.code
    except urllib.error.URLError:
        https_status = None

    try:
        with urllib.request.urlopen(http_url) as response:
            http_status = response.status
    except urllib.error.HTTPError as error:
        http_status = error.code
    except urllib.error.URLError:
        http_status = None
    return https_status, http_status

def get_certificate_info(domain):
    try:
        context = ssl.create_default_context()

        # Create HTTPS connection to get certificate information through TLS validation
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as secure_sock:
                certificate = secure_sock.getpeercert()

        return {
            "issuer": certificate.get("issuer"),
            "subject": certificate.get("subject"),
            "version": certificate.get("version"),
            "serial_number": certificate.get("serialNumber"),
            "not_before": certificate.get("notBefore"),
            "not_after": certificate.get("notAfter")
        }

    except (socket.error, ssl.SSLError):
        return None