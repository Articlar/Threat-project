# Threat Intelligence Scanner
A Python-based cybersecurity tool that analyzes hashes, domains/URLS, IP addresses, and files using a local threat intelligence, VirusTotal, DNS, TLS, and file analysis.

# Objective/Purpose
The objective of this project was to gain hands-on experience with several areas of cybersecurity and software development:

- Hash analysis and identification
- Domain and URL analysis
- IP and network analysis
- File analysis and detection
- API integration
- Automated testing with Pytest
- Modular Python application design

# Features
- Hash Analysis
    - MD5, SHA-1, and SHA-256 detection
    - Local malicious-hash database lookup
    - VirusTotal reputation lookup

- Domain and URL Analysis
    - Domain validation and DNS resolution
    - A, AAAA, MX, CNAME, and TXT records
    - HTTP/HTTPS status checks
    - TLS certificate and connection information
    - URL and domain heuristics
    - VirusTotal domain and URL reputation

- IP Analysis
    - IPv4 and IPv6 validation
    - Private, global, loopback, and reserved address detection
    - VirusTotal reputation lookup

- File Analysis
    - MD5, SHA-1, and SHA-256 hashing
    - Local database lookup
    - VirusTotal reputation lookup
    - File metadata and extension analysis
    - Magic-byte file-type detection
    - Extension/signature mismatch detection

- Risk Scoring
Risk scores vary by analysis type.
Scores are capped at 100. 
0-29 : Low Risk
30-69: Suspicious
70-100: Malicious
N/A : Unknown

# Installation

Cloning the repository
```bash
git clone 
cd Threat-Project
```

Creating the virtual environemnt
```bash
python -m venv.venv
.venv\Scripts\activate
pip install -r requirements.txt
```

Create a .env file for virustotal:
VT_API_KEY

# Running the application
```bash
python app/main.py
```

# Testing
Run the test suite with:
```bash
python -m pytest
```
