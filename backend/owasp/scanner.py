import socket
import requests
import re
import ssl
import jwt
import xml.etree.ElementTree as ET
import subprocess
import json
import hashlib
from datetime import datetime
from urllib.parse import urljoin, urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor
from bs4 import BeautifulSoup
import base64
import logging

class EnhancedWebSecurityScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.findings = []
        self.headers = {
            'User-Agent': 'Security-Scanner-v1.0'
        }
        self.session = requests.Session()
    
    def scan(self):
        """scanning function for OWASP Top 10"""
        print(f"Starting comprehensive security scan for {self.target_url}")
        
        # A01:2021 - Broken Access Control
        self.check_broken_access_control()
        
        # A02:2021 - Cryptographic Failures
        self.check_crypto_failures()
        
        # A03:2021 - Injection
        self.check_injection_vulnerabilities()
        
        # A04:2021 - Insecure Design
        self.check_insecure_design()
        
        # A05:2021 - Security Misconfiguration
        self.check_security_misconfig()
        
        # A06:2021 - Vulnerable Components
        self.check_vulnerable_components()
        
        # A07:2021 - Authentication Failures
        self.check_auth_failures()
        
        # A08:2021 - Software and Data Integrity Failures
        self.check_integrity_failures()
        
        # A09:2021 - Security Logging and Monitoring Failures
        self.check_logging_failures()
        
        # A10:2021 - Server-Side Request Forgery
        self.check_ssrf()
        
        self.generate_report()

    def check_broken_access_control(self):
        """Broken Access Control"""
        # Directory Traversal Detection
        traversal_paths = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\win.ini",
            "../../../../../../etc/shadow",
            "/../../../../../../etc/group"
        ]
        for path in traversal_paths:
            try:
                response = self.session.get(f"{self.target_url}/{path}")
                if any(indicator in response.text for indicator in ["root:", "[extensions]", "shadow:", "group:"]):
                    self.findings.append({
                        'type': 'Broken Access Control',
                        'severity': 'High',
                        'description': f'Directory traversal vulnerability detected with payload: {path}',
                        'recommendation': 'Implement proper path validation, sanitize input, and restrict file access to necessary directories'
                    })
            except:
                pass

        # Expanded IDOR Detection
        ids = [1, 2, 3, 9999, "admin", "user", "guest"]
        sensitive_data_keywords = ["password", "token", "email", "private"]
        for id in ids:
            try:
                response = self.session.get(f"{self.target_url}/api/user/{id}")
                if response.status_code == 200 and any(keyword in response.text.lower() for keyword in sensitive_data_keywords):
                    self.findings.append({
                        'type': 'Broken Access Control',
                        'severity': 'Critical',
                        'description': f'Potential IDOR vulnerability detected for ID: {id}',
                        'recommendation': 'Ensure proper authorization checks are implemented and avoid exposing sensitive user data without permissions.'
                    })
            except:
                pass

        # Testing Access-Control-Allow-Origin for CORS Misconfiguration
        try:
            response = self.session.options(self.target_url, headers={"Origin": "http://malicious-site.com"})
            if "Access-Control-Allow-Origin" in response.headers:
                allowed_origin = response.headers.get("Access-Control-Allow-Origin")
                if allowed_origin == "*" or "malicious-site.com" in allowed_origin:
                    self.findings.append({
                        'type': 'Broken Access Control',
                        'severity': 'High',
                        'description': 'CORS misconfiguration detected allowing unauthorized origins',
                        'recommendation': 'Restrict allowed origins in CORS settings to trusted domains only.'
                    })
        except:
            pass

        # Testing Restricted Administrative Endpoints
        admin_endpoints = ["/admin", "/settings", "/manage", "/superuser"]
        for endpoint in admin_endpoints:
            try:
                response = self.session.get(f"{self.target_url}{endpoint}")
                if response.status_code == 200 and "admin" in response.text.lower():
                    self.findings.append({
                        'type': 'Broken Access Control',
                        'severity': 'Critical',
                        'description': f'Unrestricted access to administrative endpoint: {endpoint}',
                        'recommendation': 'Implement role-based access control (RBAC) and restrict access to administrative endpoints.'
                    })
            except:
                pass

        # Testing with Alternative HTTP Methods
        http_methods = ["POST", "PUT", "DELETE", "PATCH"]
        for method in http_methods:
            try:
                response = self.session.request(method, self.target_url)
                if response.status_code in [200, 201, 204]:
                    self.findings.append({
                        'type': 'Broken Access Control',
                        'severity': 'High',
                        'description': f'Improper access control for {method} method detected',
                        'recommendation': f'Ensure {method} method is properly secured and used only where necessary.'
                    })
            except:
                pass

    def check_crypto_failures(self):
        """Cryptographic Failures"""
        try:
            # Check for sensitive data in HTML comments
            response = self.session.get(self.target_url)
            if '<!--' in response.text and any(word in response.text.lower() for word in ['password', 'token', 'key', 'secret', 'credential']):
                self.findings.append({
                    'type': 'Cryptographic Failures',
                    'severity': 'Medium',
                    'description': 'Sensitive data found in HTML comments',
                    'recommendation': 'Remove sensitive data from HTML comments'
                })

            # Check for weak SSL/TLS configurations
            hostname = urlparse(self.target_url).hostname
            context = ssl.create_default_context()
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED

            with socket.create_connection((hostname, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cipher = ssock.cipher()
                    protocol = ssock.version()
                    if protocol in ['TLSv1.0', 'TLSv1.1']:
                        self.findings.append({
                            'type': 'Cryptographic Failures',
                            'severity': 'High',
                            'description': f'Weak SSL/TLS version in use: {protocol}',
                            'recommendation': 'Upgrade to TLS 1.2 or higher'
                        })

                    # Check for weak ciphers
                    weak_ciphers = ['DES', '3DES', 'RC4']
                    if any(weak_cipher in cipher[0] for weak_cipher in weak_ciphers):
                        self.findings.append({
                            'type': 'Cryptographic Failures',
                            'severity': 'High',
                            'description': f'Weak cipher detected: {cipher[0]}',
                            'recommendation': 'Use modern ciphers such as AES-GCM or ChaCha20.'
                        })

            # Check for missing HSTS header
            if 'Strict-Transport-Security' not in response.headers:
                self.findings.append({
                    'type': 'Cryptographic Failures',
                    'severity': 'Medium',
                    'description': 'HSTS header is missing',
                    'recommendation': 'Implement the HTTP Strict Transport Security (HSTS) header.'
                })

            # Check for exposed private keys or certificates in the page content
            if any(keyword in response.text.lower() for keyword in ['-----BEGIN PRIVATE KEY-----', '-----BEGIN CERTIFICATE-----']):
                self.findings.append({
                    'type': 'Cryptographic Failures',
                    'severity': 'Critical',
                    'description': 'Exposed private key or certificate detected',
                    'recommendation': 'Remove private keys or certificates from public-facing pages.'
                })

        except Exception as e:
            pass

    def check_injection_vulnerabilities(self):
        """Injection"""
        try:
            # SQL Injection
            sql_payloads = [
                "' OR '1'='1", 
                "' OR 1=1 --", 
                "' OR 'x'='x", 
                "1; DROP TABLE users;", 
                "' UNION SELECT null,null,null--", 
                "' AND SLEEP(5)--"
            ]
            for payload in sql_payloads:
                response = self.session.get(f"{self.target_url}?id={payload}")
                if any(error in response.text.lower() for error in ['mysql', 'sqlite', 'ora-', 'syntax error']):
                    self.findings.append({
                        'type': 'SQL Injection',
                        'severity': 'High',
                        'description': f'SQL Injection vulnerability detected with payload: {payload}',
                        'recommendation': 'Use parameterized queries and input validation'
                    })

            # NoSQL Injection
            nosql_payloads = [
                '{"$gt":""}', 
                '{"$ne":null}', 
                '{"$or":[{},{}]}', 
                '{"$and":[{"a":"b"}, {"c":"d"}]}', 
                '{"username":{"$regex":""}}'
            ]
            for payload in nosql_payloads:
                response = self.session.get(f"{self.target_url}?query={payload}")
                if response.status_code == 200 and 'error' not in response.text.lower():
                    self.findings.append({
                        'type': 'NoSQL Injection',
                        'severity': 'High',
                        'description': f'Potential NoSQL Injection vulnerability detected with payload: {payload}',
                        'recommendation': 'Implement proper input validation and sanitization for NoSQL queries'
                    })

            # Command Injection
            cmd_payloads = [
                '; ls', 
                '& dir', 
                '| whoami', 
                '&& cat /etc/passwd', 
                '|| shutdown -h now', 
                '`cat /etc/passwd`', 
                '$(ls)'
            ]
            for payload in cmd_payloads:
                response = self.session.get(f"{self.target_url}?cmd={payload}")
                if any(term in response.text.lower() for term in ['root:', 'volume', 'admin', 'user']):
                    self.findings.append({
                        'type': 'Command Injection',
                        'severity': 'Critical',
                        'description': f'Command Injection vulnerability detected with payload: {payload}',
                        'recommendation': 'Never pass user input directly to system commands; validate and sanitize inputs'
                    })

            # LDAP Injection
            ldap_payloads = [
                "(|(user=*))", 
                "(&(objectClass=*))", 
                "*)(&))(&(objectclass=*", 
                "*)(&(objectClass=*)", 
                "*(|(password=*))"
            ]
            for payload in ldap_payloads:
                response = self.session.get(f"{self.target_url}?filter={payload}")
                if response.status_code == 200 and "ldap" in response.text.lower():
                    self.findings.append({
                        'type': 'LDAP Injection',
                        'severity': 'High',
                        'description': f'LDAP Injection vulnerability detected with payload: {payload}',
                        'recommendation': 'Sanitize inputs before processing LDAP queries'
                    })

            # XML External Entity (XXE) Injection
            xxe_payloads = [
                '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///etc/passwd" >]><foo>&xxe;</foo>',
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://example.com/">]><foo>&xxe;</foo>'
            ]
            for payload in xxe_payloads:
                headers = {'Content-Type': 'application/xml'}
                response = self.session.post(self.target_url, data=payload, headers=headers)
                if 'root:' in response.text or 'HTTP' in response.text:
                    self.findings.append({
                        'type': 'XML External Entity (XXE) Injection',
                        'severity': 'Critical',
                        'description': f'XXE vulnerability detected with payload: {payload}',
                        'recommendation': 'Disable external entity processing and validate XML inputs'
                    })

            # Cross-Site Scripting (XSS) Injection
            xss_payloads = [
                '<script>alert("XSS")</script>', 
                '<img src=x onerror=alert(1)>', 
                '"><script>alert(1)</script>', 
                '<svg/onload=alert(1)>'
            ]
            for payload in xss_payloads:
                response = self.session.get(f"{self.target_url}?q={payload}")
                if payload in response.text:
                    self.findings.append({
                        'type': 'Cross-Site Scripting (XSS)',
                        'severity': 'High',
                        'description': f'XSS vulnerability detected with payload: {payload}',
                        'recommendation': 'Sanitize and escape all user inputs and outputs'
                    })

        except Exception as e:
            pass

    def check_insecure_design(self):
        """Insecure Design"""
        try:
            # Check for common insecure design patterns

            # 1. Rate Limiting
            requests_count = 0
            for _ in range(50):
                response = self.session.get(self.target_url)
                if response.status_code == 200:
                    requests_count += 1

            if requests_count >= 50:
                self.findings.append({
                    'type': 'Insecure Design',
                    'severity': 'Medium',
                    'description': 'No rate limiting detected',
                    'recommendation': 'Implement rate limiting to prevent abuse'
                })

            # 2. Sensitive Operations Without Confirmation
            response = self.session.get(f"{self.target_url}/delete")
            if response.status_code == 200:
                self.findings.append({
                    'type': 'Insecure Design',
                    'severity': 'Medium',
                    'description': 'Sensitive operations performed without user confirmation',
                    'recommendation': 'Implement confirmation steps (e.g., captcha, password re-entry) for sensitive actions'
                })

            # 3. Lack of Multi-Factor Authentication (MFA)
            response = self.session.get(f"{self.target_url}/login")
            if "password" in response.text.lower() and "otp" not in response.text.lower():
                self.findings.append({
                    'type': 'Insecure Design',
                    'severity': 'High',
                    'description': 'No Multi-Factor Authentication (MFA) implemented for login',
                    'recommendation': 'Implement MFA to enhance account security'
                })

            # 4. Missing Logout or Session Management
            response = self.session.get(f"{self.target_url}/session")
            if "active sessions" not in response.text.lower():
                self.findings.append({
                    'type': 'Insecure Design',
                    'severity': 'High',
                    'description': 'No session management or logout functionality detected',
                    'recommendation': 'Implement proper session management with logout functionality'
                })

            # 5. Inadequate Input Validation
            test_payload = "<script>alert('test')</script>"
            response = self.session.get(f"{self.target_url}?input={test_payload}")
            if test_payload in response.text:
                self.findings.append({
                    'type': 'Insecure Design',
                    'severity': 'High',
                    'description': 'Input is not properly validated or sanitized',
                    'recommendation': 'Implement strong input validation and sanitization for user inputs'
                })

            # 6. Insecure Direct Object References (IDOR)
            response = self.session.get(f"{self.target_url}/api/resource/1")
            if response.status_code == 200 and "private" in response.text.lower():
                self.findings.append({
                    'type': 'Insecure Design',
                    'severity': 'High',
                    'description': 'Potential IDOR vulnerability detected',
                    'recommendation': 'Ensure proper authorization checks for accessing sensitive resources'
                })

            # 7. Lack of Secure Password Policies
            response = self.session.get(f"{self.target_url}/register")
            if "password" in response.text.lower() and "length" not in response.text.lower():
                self.findings.append({
                    'type': 'Insecure Design',
                    'severity': 'Medium',
                    'description': 'No password policy requirements detected',
                    'recommendation': 'Enforce secure password policies, including minimum length, complexity, and expiration'
                })

            # 8. Inadequate Error Handling
            response = self.session.get(f"{self.target_url}/unknownendpoint")
            if response.status_code >= 500 and "exception" in response.text.lower():
                self.findings.append({
                    'type': 'Insecure Design',
                    'severity': 'Medium',
                    'description': 'Detailed error messages exposed to users',
                    'recommendation': 'Ensure error messages do not reveal sensitive information'
                })

            # 9. Lack of Secure Default Configurations
            response = self.session.get(f"{self.target_url}/admin")
            if response.status_code == 200 and "default password" in response.text.lower():
                self.findings.append({
                    'type': 'Insecure Design',
                    'severity': 'High',
                    'description': 'Default credentials or insecure default configurations detected',
                    'recommendation': 'Ensure secure default settings and require users to change default credentials'
                })

            # 10. Open Redirects
            redirect_payload = "/redirect?url=https://malicious-site.com"
            response = self.session.get(f"{self.target_url}{redirect_payload}")
            if response.status_code == 302 and "malicious-site.com" in response.headers.get("Location", ""):
                self.findings.append({
                    'type': 'Insecure Design',
                    'severity': 'Medium',
                    'description': 'Open redirect vulnerability detected',
                    'recommendation': 'Validate and restrict allowed redirect URLs'
                })

        except Exception as e:
            pass

    def check_security_misconfig(self):
        """Security Misconfiguration"""
        try:
            # 1. Exposed Configuration Files
            common_configs = [
                '/config.php', '/wp-config.php', '/config.yml',
                '/.env', '/web.config', '/robots.txt', '/sitemap.xml',
                '/settings.json', '/database.yml'
            ]
            for config in common_configs:
                response = self.session.get(self.target_url + config)
                if response.status_code == 200 and not response.is_redirect:
                    self.findings.append({
                        'type': 'Security Misconfiguration',
                        'severity': 'High',
                        'description': f'Exposed configuration file: {config}',
                        'recommendation': 'Restrict access to configuration files'
                    })

            # 2. Directory Listing
            common_dirs = ['/assets/', '/uploads/', '/files/', '/images/', '/backup/']
            for directory in common_dirs:
                response = self.session.get(self.target_url + directory)
                if 'Index of' in response.text or '<title>Index of' in response.text:
                    self.findings.append({
                        'type': 'Security Misconfiguration',
                        'severity': 'Medium',
                        'description': f'Directory listing enabled for {directory}',
                        'recommendation': 'Disable directory listing for sensitive directories'
                    })

            # 3. Default Credentials
            common_creds = [
                ('admin', 'admin'), ('root', 'root'), ('admin', 'password'),
                ('user', 'user'), ('test', 'test'), ('guest', 'guest')
            ]
            for username, password in common_creds:
                response = self.session.post(
                    f"{self.target_url}/login",
                    data={'username': username, 'password': password}
                )
                if response.status_code == 200 and 'welcome' in response.text.lower():
                    self.findings.append({
                        'type': 'Security Misconfiguration',
                        'severity': 'Critical',
                        'description': f'Default credentials in use: {username}/{password}',
                        'recommendation': 'Change default credentials and enforce strong passwords'
                    })

            # 4. HTTP Security Headers
            response = self.session.get(self.target_url)
            missing_headers = []
            required_headers = {
                'Strict-Transport-Security': 'Enforce HTTPS',
                'Content-Security-Policy': 'Prevent XSS and data injection',
                'X-Content-Type-Options': 'Prevent MIME-type sniffing',
                'X-Frame-Options': 'Prevent clickjacking',
                'Referrer-Policy': 'Restrict referrer information',
                'Permissions-Policy': 'Restrict browser features'
            }
            for header, description in required_headers.items():
                if header not in response.headers:
                    missing_headers.append(header)
            
            if missing_headers:
                self.findings.append({
                    'type': 'Security Misconfiguration',
                    'severity': 'High',
                    'description': f'Missing HTTP security headers: {", ".join(missing_headers)}',
                    'recommendation': 'Configure the following HTTP headers: ' +
                                    ', '.join([f'{header} ({desc})' for header, desc in required_headers.items()])
                })

            # 5. Exposed Debug Information
            debug_indicators = ['debug=true', 'stack trace', 'traceback', 'exception']
            if any(indicator in response.text.lower() for indicator in debug_indicators):
                self.findings.append({
                    'type': 'Security Misconfiguration',
                    'severity': 'High',
                    'description': 'Debugging information exposed in responses',
                    'recommendation': 'Disable debug mode and ensure stack traces are not exposed'
                })

            # 6. Exposed Backup Files
            common_backup_files = [
                '/backup.zip', '/db_backup.sql', '/website.bak', '/backup.tar.gz'
            ]
            for backup in common_backup_files:
                response = self.session.get(self.target_url + backup)
                if response.status_code == 200:
                    self.findings.append({
                        'type': 'Security Misconfiguration',
                        'severity': 'Critical',
                        'description': f'Exposed backup file: {backup}',
                        'recommendation': 'Restrict access to backup files or store them securely'
                    })

        except Exception as e:
            pass

    def check_vulnerable_components(self):
        """Vulnerable Components"""
        try:
            response = self.session.get(self.target_url)

            # 1. Check for known vulnerable JavaScript libraries
            vulnerable_libs = {
                'jquery-1.': 'jQuery 1.x',
                'jquery-2.': 'jQuery 2.x',
                'bootstrap-2': 'Bootstrap 2.x',
                'angular.js/1.': 'AngularJS 1.x',
                'react-0.': 'React 0.x',
                'vue-0.': 'Vue.js 0.x'
            }
            for lib, name in vulnerable_libs.items():
                if lib in response.text:
                    self.findings.append({
                        'type': 'Vulnerable Components',
                        'severity': 'High',
                        'description': f'Outdated {name} detected',
                        'recommendation': f'Update {name} to the latest version'
                    })

            # 2. Check HTTP response headers for server software version
            if 'Server' in response.headers:
                server = response.headers['Server']
                known_vulnerable_servers = {
                    'apache/2.2': 'Apache 2.2',
                    'nginx/1.8': 'Nginx 1.8',
                    'php/5.': 'PHP 5.x',
                    'tomcat/7.': 'Apache Tomcat 7.x',
                    'iis/6.': 'Microsoft IIS 6.x'
                }
                for old_version, name in known_vulnerable_servers.items():
                    if old_version in server.lower():
                        self.findings.append({
                            'type': 'Vulnerable Components',
                            'severity': 'High',
                            'description': f'Outdated server software detected: {name}',
                            'recommendation': f'Upgrade {name} to a secure, supported version'
                        })

            # 3. Check for exposed framework or CMS versions in HTML
            cms_indicators = {
                'wp-content': 'WordPress',
                'Drupal.settings': 'Drupal',
                'Magento': 'Magento',
                'Joomla!': 'Joomla'
            }
            for indicator, cms in cms_indicators.items():
                if indicator in response.text:
                    self.findings.append({
                        'type': 'Vulnerable Components',
                        'severity': 'Medium',
                        'description': f'CMS or framework detected: {cms}. Version exposure possible.',
                        'recommendation': 'Avoid exposing CMS or framework version details in public responses'
                    })

            # 4. Check for outdated dependencies in meta tags or script files
            dependency_indicators = {
                'meta name="generator"': 'Potentially outdated CMS version in generator meta tag',
                'script src="/vendor/old': 'Outdated library in script source'
            }
            for indicator, description in dependency_indicators.items():
                if indicator in response.text:
                    self.findings.append({
                        'type': 'Vulnerable Components',
                        'severity': 'Medium',
                        'description': description,
                        'recommendation': 'Update dependencies and sanitize public metadata'
                    })

            # 5. Detect known vulnerable APIs in use
            known_vulnerable_apis = ['Stripe 1.x', 'PayPal Classic', 'Old REST API endpoints']
            for api in known_vulnerable_apis:
                if api.lower() in response.text.lower():
                    self.findings.append({
                        'type': 'Vulnerable Components',
                        'severity': 'High',
                        'description': f'Usage of deprecated or vulnerable API: {api}',
                        'recommendation': f'Migrate to the latest version of {api}'
                    })

        except Exception as e:
            pass

    def check_auth_failures(self):
        """Authentication Failures"""
        try:
            # 1. Check for weak password policies
            weak_passwords = ['password123', '123456', 'qwerty', 'admin', 'letmein']
            for password in weak_passwords:
                response = self.session.post(
                    f"{self.target_url}/register",
                    data={'username': 'test_user', 'password': password}
                )
                if response.status_code == 200:
                    self.findings.append({
                        'type': 'Authentication Failures',
                        'severity': 'High',
                        'description': 'Weak password policy detected',
                        'recommendation': 'Enforce strong password requirements: minimum length, complexity, and blacklist common passwords'
                    })
                    break

            # 2. Check for missing brute force protection
            login_attempts = 10
            successful_attempts = 0
            for _ in range(login_attempts):
                response = self.session.post(
                    f"{self.target_url}/login",
                    data={'username': 'admin', 'password': 'wrong'}
                )
                if response.status_code == 200:
                    successful_attempts += 1
            if successful_attempts == login_attempts:
                self.findings.append({
                    'type': 'Authentication Failures',
                    'severity': 'High',
                    'description': 'No brute force protection detected',
                    'recommendation': 'Implement account lockout, CAPTCHA, or rate limiting after multiple failed login attempts'
                })

            # 3. Check for missing MFA/2FA
            response = self.session.get(f"{self.target_url}/login")
            if "two-factor" not in response.text.lower() and "2fa" not in response.text.lower():
                self.findings.append({
                    'type': 'Authentication Failures',
                    'severity': 'Medium',
                    'description': 'Two-factor authentication (2FA) not available',
                    'recommendation': 'Add support for 2FA to enhance account security'
                })

            # 4. Check for token-based authentication flaws
            response = self.session.post(
                f"{self.target_url}/login",
                data={'username': 'admin', 'password': 'password123'}
            )
            if 'Set-Cookie' in response.headers:
                cookies = response.headers.get('Set-Cookie', '')
                if 'HttpOnly' not in cookies or 'Secure' not in cookies:
                    self.findings.append({
                        'type': 'Authentication Failures',
                        'severity': 'High',
                        'description': 'Session cookies lack secure flags',
                        'recommendation': 'Ensure cookies are marked with HttpOnly, Secure, and SameSite attributes'
                    })

            # 5. Check for credentials in URL
            sensitive_endpoints = ["/login", "/register"]
            for endpoint in sensitive_endpoints:
                url = f"{self.target_url}{endpoint}?username=admin&password=password123"
                response = self.session.get(url)
                if response.status_code == 200:
                    self.findings.append({
                        'type': 'Authentication Failures',
                        'severity': 'High',
                        'description': 'Credentials passed via URL query parameters',
                        'recommendation': 'Avoid passing credentials in URLs; use POST requests for sensitive data'
                    })

        except Exception as e:
            pass

    def check_integrity_failures(self):
        """Software and Data Integrity Failures"""
        try:
            # 1. Check for insecure deserialization
            payload = base64.b64encode(b'{"user": "admin"}').decode()
            response = self.session.get(f"{self.target_url}?data={payload}")
            if 'admin' in response.text:
                self.findings.append({
                    'type': 'Integrity Failures',
                    'severity': 'High',
                    'description': 'Potential insecure deserialization vulnerability detected',
                    'recommendation': 'Validate, sanitize, and sign serialized data. Avoid using insecure formats like JSON, XML, or binary for sensitive operations.'
                })

            # 2. Check for unsafe file uploads
            file_payloads = {
                'PHP file': ('test.php', '<?php echo "test"; ?>'),
                'HTML file': ('test.html', '<html><body>Test</body></html>'),
                'Executable': ('test.exe', 'ThisIsABinaryContent')
            }
            for file_type, file_data in file_payloads.items():
                files = {'file': file_data}
                response = self.session.post(f"{self.target_url}/upload", files=files)
                if response.status_code == 200:
                    self.findings.append({
                        'type': 'Integrity Failures',
                        'severity': 'High',
                        'description': f'Unsafe file upload detected ({file_type})',
                        'recommendation': 'Validate file extensions, mime types, and content. Restrict executable file uploads.'
                    })

            # 3. Check for unsigned software packages
            response = self.session.get(f"{self.target_url}/downloads/software.zip")
            if response.status_code == 200 and 'checksum' not in response.text.lower():
                self.findings.append({
                    'type': 'Integrity Failures',
                    'severity': 'Medium',
                    'description': 'Unsigned software package detected',
                    'recommendation': 'Include digital signatures or checksums for verifying package integrity.'
                })

            # 4. Check for unprotected configuration endpoints
            config_endpoints = ['/config', '/settings']
            for endpoint in config_endpoints:
                response = self.session.get(f"{self.target_url}{endpoint}")
                if response.status_code == 200 and 'config' in response.text.lower():
                    self.findings.append({
                        'type': 'Integrity Failures',
                        'severity': 'High',
                        'description': f'Unprotected configuration endpoint: {endpoint}',
                        'recommendation': 'Restrict access to configuration endpoints and sensitive files.'
                    })

            # 5. Check for insecure update mechanisms
            response = self.session.get(f"{self.target_url}/update")
            if response.status_code == 200 and 'http://' in response.text.lower():
                self.findings.append({
                    'type': 'Integrity Failures',
                    'severity': 'High',
                    'description': 'Insecure update mechanism detected (HTTP instead of HTTPS)',
                    'recommendation': 'Use secure channels (HTTPS) for software updates.'
                })

            # 6. Check for vulnerable third-party dependencies
            response = self.session.get(self.target_url)
            vulnerable_dependencies = {
                'log4j': 'Log4Shell vulnerability (CVE-2021-44228)',
                'struts2': 'Apache Struts RCE vulnerability (CVE-2017-5638)',
                'spring': 'Spring4Shell vulnerability (CVE-2022-22965)'
            }
            for dep, description in vulnerable_dependencies.items():
                if dep.lower() in response.text.lower():
                    self.findings.append({
                        'type': 'Integrity Failures',
                        'severity': 'Critical',
                        'description': f'Vulnerable dependency detected: {dep} ({description})',
                        'recommendation': 'Update or patch the dependency to the latest secure version.'
                    })

        except Exception as e:
            pass

    def check_logging_failures(self):
        """Security Logging and Monitoring Failures"""
        try:
            # 1. Check for error exposure
            response = self.session.get(f"{self.target_url}/error")
            if any(term in response.text for term in ['stack trace', 'exception', 'error', 'SQL', 'NullPointerException']):
                self.findings.append({
                    'type': 'Logging Failures',
                    'severity': 'Medium',
                    'description': 'Detailed error messages exposed',
                    'recommendation': 'Implement proper error handling, suppress sensitive details, and log errors securely.'
                })

            # 2. Check for exposed debug endpoints
            debug_endpoints = ['/debug', '/trace', '/status', '/health', '/logs']
            for endpoint in debug_endpoints:
                response = self.session.get(self.target_url + endpoint)
                if response.status_code == 200 and 'debug' in response.text.lower():
                    self.findings.append({
                        'type': 'Logging Failures',
                        'severity': 'High',
                        'description': f'Debug endpoint exposed: {endpoint}',
                        'recommendation': 'Disable or restrict access to debug endpoints.'
                    })

            # 3. Check for verbose logging of sensitive data
            sensitive_keywords = ['password', 'token', 'secret', 'key', 'credit card']
            for keyword in sensitive_keywords:
                if keyword in response.text.lower():
                    self.findings.append({
                        'type': 'Logging Failures',
                        'severity': 'Critical',
                        'description': f'Sensitive data logged: {keyword}',
                        'recommendation': 'Avoid logging sensitive information. Mask or redact sensitive details if needed.'
                    })

            # 4. Check for lack of log monitoring and alerting mechanisms
            response = self.session.get(f"{self.target_url}/monitoring")
            if response.status_code == 404:
                self.findings.append({
                    'type': 'Logging Failures',
                    'severity': 'Medium',
                    'description': 'No monitoring or alerting system detected',
                    'recommendation': 'Implement centralized logging and real-time monitoring for incident detection.'
                })

            # 5. Check for insufficient log retention policies
            response = self.session.get(f"{self.target_url}/logs")
            if 'retention policy' not in response.text.lower():
                self.findings.append({
                    'type': 'Logging Failures',
                    'severity': 'Low',
                    'description': 'Log retention policy not clearly defined',
                    'recommendation': 'Define and enforce log retention policies to balance security and compliance.'
                })

            # 6. Check for lack of tamper-proof logging
            response = self.session.get(f"{self.target_url}/logs")
            if 'tamper-proof' not in response.text.lower():
                self.findings.append({
                    'type': 'Logging Failures',
                    'severity': 'High',
                    'description': 'Logs are not tamper-proof',
                    'recommendation': 'Use secure logging mechanisms such as write-once storage or cryptographic integrity checks.'
                })

            # 7. Check for missing log anonymization
            if any(ip in response.text for ip in ['192.168.1.1', '10.0.0.1']):
                self.findings.append({
                    'type': 'Logging Failures',
                    'severity': 'Medium',
                    'description': 'Unanonymized user data detected in logs (e.g., IP addresses)',
                    'recommendation': 'Ensure sensitive user data in logs is anonymized or pseudonymized.'
                })

        except Exception as e:
            pass

    def check_ssrf(self):
        """Server-Side Request Forgery (SSRF)"""
        try:
            # 1. Common SSRF target URLs
            ssrf_urls = [
                'http://localhost',          # Localhost
                'http://127.0.0.1',          # Local loopback
                'http://169.254.169.254',    # AWS metadata service
                'http://192.168.1.1',        # Common private network gateway
                'http://10.0.0.1',           # Private network
                'http://[::1]',              # IPv6 localhost
                'ftp://127.0.0.1',           # FTP protocol test
                'file:///etc/passwd',        # File protocol
                'http://evil.com'            # External server (for testing open outbound requests)
            ]

            # 2. Headers to simulate real-world SSRF exploitation scenarios
            custom_headers = {
                "X-Forwarded-For": "127.0.0.1",
                "X-Real-IP": "127.0.0.1",
                "Referer": "http://127.0.0.1",
                "Host": "169.254.169.254"
            }

            for url in ssrf_urls:
                response = self.session.get(
                    f"{self.target_url}?url={url}", headers=custom_headers, timeout=5
                )
                if response.status_code in [200, 301, 302] and any(
                    keyword in response.text.lower() for keyword in ["metadata", "root:", "admin"]
                ):
                    self.findings.append({
                        'type': 'SSRF',
                        'severity': 'Critical',
                        'description': f'Potential SSRF vulnerability detected with URL: {url}',
                        'recommendation': 'Implement strict URL validation, restrict protocols, and use network segmentation.'
                    })
                    break

            #3. Blind SSRF detection
            blind_ssrf_test_url = "http://example-burpcollaborator.com"
            response = self.session.get(f"{self.target_url}?url={blind_ssrf_test_url}")
            if response.status_code == 200:
                self.findings.append({
                    'type': 'SSRF',
                    'severity': 'High',
                    'description': 'Potential blind SSRF vulnerability detected',
                    'recommendation': 'Implement DNS resolution restrictions and monitor for unexpected outbound requests.'
                })

            # 4. URL parsing misconfigurations
            malicious_urls = [
                "http://127.0.0.1@evil.com",  # Bypasses host validation
                "http://evil.com#@127.0.0.1", # Exploits URL fragments
                "http://evil.com?@127.0.0.1"  # Exploits query string
            ]
            for malicious_url in malicious_urls:
                response = self.session.get(f"{self.target_url}?url={malicious_url}")
                if response.status_code == 200:
                    self.findings.append({
                        'type': 'SSRF',
                        'severity': 'High',
                        'description': f'Potential SSRF vulnerability with URL parsing: {malicious_url}',
                        'recommendation': 'Use robust libraries to parse and validate URLs securely.'
                    })

            # 5.Detecting improper handling of protocols
            dangerous_protocols = [
                "file://",
                "gopher://",
                "ftp://",
                "dict://"
            ]
            for protocol in dangerous_protocols:
                response = self.session.get(f"{self.target_url}?url={protocol}127.0.0.1")
                if response.status_code == 200:
                    self.findings.append({
                        'type': 'SSRF',
                        'severity': 'Critical',
                        'description': f'Potential SSRF vulnerability exploiting {protocol} protocol',
                        'recommendation': 'Restrict allowed protocols to HTTP and HTTPS only.'
                    })

        except Exception as e:
            pass

    def generate_report(self):
        """Generate comprehensive security report"""
        report = {
            'scan_target': self.target_url,
            'scan_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'findings': self.findings,
            'summary': {
                'critical': len([f for f in self.findings if f['severity'] == 'Critical']),
                'high': len([f for f in self.findings if f['severity'] == 'High']),
                'medium': len([f for f in self.findings if f['severity'] == 'Medium']),
                'low': len([f for f in self.findings if f['severity'] == 'Low']),
                'info': len([f for f in self.findings if f['severity'] == 'Info'])
            }
        }
        
        # Save report to file
        with open('security_report.json', 'w') as f:
            json.dump(report, f, indent=4)
        
        print("\nSecurity Scan Complete!")
        print(f"Total findings: {len(self.findings)}")
        print(f"Critical: {report['summary']['critical']}")
        print(f"High: {report['summary']['high']}")
        print(f"Medium: {report['summary']['medium']}")
        print(f"Low: {report['summary']['low']}")
        print(f"Info: {report['summary']['info']}")
        print("\nDetailed report saved to 'security_report.json'")

def main():
    target = input("Enter target URL to scan (e.g., https://example.com): ")
    scanner = EnhancedWebSecurityScanner(target)
    scanner.scan()

if __name__ == "__main__":
    main()