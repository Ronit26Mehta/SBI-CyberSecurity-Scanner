import requests
from urllib.parse import urlparse

def is_valid_url(url):
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])  
    except ValueError:
        return False
    
def check_broken_access_control(url):
    if '/admin/' in url:
        return [{'type': 'Broken Access Control', 'line': 'N/A', 'description': 'Potential access to admin area'}]
    return []

def check_cryptographic_failures(url):
    issues = []
    if "http://" in url:
        issues.append({"type": "Cryptographic Failures", "description": "Transmission over unencrypted HTTP detected."})
    return issues

def check_sql_injection(url):
    issues = []
    payloads = ["' OR '1'='1", "' DROP TABLE users; --"]
    for payload in payloads:
        test_url = f"{url}?username={payload}"
        response = requests.get(test_url)
        if "SQL" in response.text:
            issues.append({"type": "SQL Injection", "description": "Possible SQL Injection vulnerability."})
    return issues

def check_insecure_design(url):
    issues = []
    if "admin" in url:  
        issues.append({"type": "Insecure Design", "description": "Sensitive functionality accessible without proper security design."})
    return issues

def check_security_misconfiguration(url):
    issues = []
    if not is_valid_url(url): 
        return [{"type": "Error", "description": "Invalid URL"}]
    
    response = requests.get(url)
    if "Server" in response.headers:
        issues.append({"type": "Security Misconfiguration", "description": "Server information revealed in headers."})
    return issues

def check_outdated_components(url):
    issues = []
    if not is_valid_url(url):
        return [{"type": "Error", "description": "Invalid URL"}]

    response = requests.get(url)
    if "X-Powered-By" in response.headers:
        issues.append({"type": "Vulnerable Components", "description": "Using outdated components revealed in headers."})
    return issues

def check_authentication_failures(url):
    issues = []
    if not is_valid_url(url):
        return [{"type": "Error", "description": "Invalid URL"}]

    response = requests.get(url)
    if "login" in response.text:
        issues.append({"type": "Authentication Failures", "description": "Login functionality detected, but no brute-force protection implemented."})
    return issues

def check_software_data_integrity(url):
    issues = []
    if "update" in url: 
        issues.append({"type": "Software and Data Integrity Failures", "description": "No validation for software updates."})
    return issues

def check_logging_failures(url):
    issues = []
    if not is_valid_url(url):
        return [{"type": "Error", "description": "Invalid URL"}]

    response = requests.get(url)
    if "404" in response.text:
        issues.append({"type": "Logging Failures", "description": "Possible logging failure, error pages not being logged."})
    return issues

def check_ssrf(url):
    issues = []
    if "http://" in url:  
        issues.append({"type": "SSRF", "description": "Potential SSRF vulnerability due to unfiltered URL input."})
    return issues

def check_code_injection(code):
    issues = []
    if "' OR '1'='1" in code:  
        issues.append({"type": "SQL Injection", "description": "Possible SQL Injection vulnerability in code."})
    if "<script>" in code:  
        issues.append({"type": "XSS", "description": "Possible Cross-Site Scripting (XSS) vulnerability in code."})
    return issues

def perform_dynamic_analysis(input_data, is_code=False):
    issues = []

    if is_code:  
        issues.extend(check_code_injection(input_data))
    else: 
        if not is_valid_url(input_data): 
            return [{"type": "Error", "description": "Invalid URL"}]

        if '/admin/' in input_data:
            issues.extend(check_broken_access_control(input_data))
            issues.extend(check_insecure_design(input_data))

        if "http://" in input_data:
            issues.extend(check_cryptographic_failures(input_data))
            issues.extend(check_ssrf(input_data)) 

        if "login" in input_data:
            issues.extend(check_authentication_failures(input_data))

        issues.extend(check_security_misconfiguration(input_data))
        issues.extend(check_outdated_components(input_data))
        issues.extend(check_sql_injection(input_data))
        issues.extend(check_software_data_integrity(input_data))
        issues.extend(check_logging_failures(input_data))

    return issues