import requests
from bs4 import BeautifulSoup
import re
import time
from urllib.parse import urljoin, urlparse
import warnings
warnings.filterwarnings('ignore')

class VulnerabilityScanner:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        self.results = []
        
    def scan(self, url):
        """Main scanning function"""
        print(f"Scanning {url}...")
        self.results = []
        
        # Basic checks
        self.check_sql_injection(url)
        self.check_xss(url)
        self.check_csrf(url)
        self.check_security_headers(url)
        self.check_directory_traversal(url)
        self.check_file_inclusion(url)
        self.check_open_redirect(url)
        self.check_ssl_tls(url)
        self.check_server_info_disclosure(url)
        self.check_clickjacking(url)
        
        return self.results
    
    def check_sql_injection(self, url):
        """Check for SQL injection vulnerabilities"""
        payloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "' UNION SELECT NULL--",
            "'; DROP TABLE users--"
        ]
        
        for payload in payloads:
            test_url = f"{url}?id={payload}"
            try:
                response = self.session.get(test_url, timeout=5)
                if response.status_code == 200:
                    errors = [
                        "sql syntax", "mysql_fetch", "ora-", 
                        "microsoft ole db", "sql server", 
                        "postgresql", "sqlite", "you have an error"
                    ]
                    for error in errors:
                        if error.lower() in response.text.lower():
                            self.results.append({
                                'type': 'SQL Injection',
                                'severity': 'High',
                                'url': test_url,
                                'description': f"Potential SQL injection vulnerability detected with payload: {payload}",
                                'evidence': error
                            })
                            break
            except Exception as e:
                continue
    
    def check_xss(self, url):
        """Check for Cross-Site Scripting (XSS) vulnerabilities"""
        payloads = [
            "<script>alert('XSS')</script>",
            "javascript:alert('XSS')",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>"
        ]
        
        for payload in payloads:
            test_url = f"{url}?q={payload}"
            try:
                response = self.session.get(test_url, timeout=5)
                if response.status_code == 200 and payload in response.text:
                    self.results.append({
                        'type': 'Cross-Site Scripting (XSS)',
                        'severity': 'High',
                        'url': test_url,
                        'description': f"Potential XSS vulnerability detected with payload: {payload}",
                        'evidence': payload
                    })
            except Exception as e:
                continue
    
    def check_csrf(self, url):
        """Check for Cross-Site Request Forgery (CSRF) vulnerabilities"""
        try:
            response = self.session.get(url, timeout=5)
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                forms = soup.find_all('form')
                
                for form in forms:
                    action = form.get('action', '')
                    method = form.get('method', 'get').lower()
                    csrf_found = False
                    
                    # Check for common CSRF token names
                    inputs = form.find_all('input')
                    for input_tag in inputs:
                        name = input_tag.get('name', '').lower()
                        if 'csrf' in name or 'token' in name:
                            csrf_found = True
                            break
                    
                    if not csrf_found and method == 'post':
                        self.results.append({
                            'type': 'Cross-Site Request Forgery (CSRF)',
                            'severity': 'Medium',
                            'url': urljoin(url, action),
                            'description': "Form without CSRF protection detected",
                            'evidence': f"Form action: {action}"
                        })
        except Exception as e:
            pass
    
    def check_security_headers(self, url):
        """Check for missing security headers"""
        try:
            response = self.session.get(url, timeout=5)
            headers = response.headers
            
            security_headers = {
                'X-Content-Type-Options': 'Missing X-Content-Type-Options header',
                'X-Frame-Options': 'Missing X-Frame-Options header',
                'X-XSS-Protection': 'Missing X-XSS-Protection header',
                'Strict-Transport-Security': 'Missing Strict-Transport-Security header',
                'Content-Security-Policy': 'Missing Content-Security-Policy header',
                'Referrer-Policy': 'Missing Referrer-Policy header'
            }
            
            for header, description in security_headers.items():
                if header not in headers:
                    severity = 'Medium'
                    if header == 'Strict-Transport-Security':
                        severity = 'High'
                    
                    self.results.append({
                        'type': 'Missing Security Header',
                        'severity': severity,
                        'url': url,
                        'description': description,
                        'evidence': f"Header {header} not found"
                    })
        except Exception as e:
            pass
    
    def check_directory_traversal(self, url):
        """Check for directory traversal vulnerabilities"""
        payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "....//....//....//etc/passwd"
        ]
        
        for payload in payloads:
            test_url = f"{url}?file={payload}"
            try:
                response = self.session.get(test_url, timeout=5)
                if response.status_code == 200:
                    if "root:" in response.text or "localhost" in response.text:
                        self.results.append({
                            'type': 'Directory Traversal',
                            'severity': 'High',
                            'url': test_url,
                            'description': f"Potential directory traversal vulnerability with payload: {payload}",
                            'evidence': "System file content detected in response"
                        })
            except Exception as e:
                continue
    
    def check_file_inclusion(self, url):
        """Check for file inclusion vulnerabilities"""
        payloads = [
            "http://example.com/malicious.txt",
            "ftp://example.com/malicious.txt",
            "php://filter/convert.base64-encode/resource=index.php"
        ]
        
        for payload in payloads:
            test_url = f"{url}?page={payload}"
            try:
                response = self.session.get(test_url, timeout=5)
                if response.status_code == 200:
                    if "base64" in response.text or "malicious" in response.text:
                        self.results.append({
                            'type': 'File Inclusion',
                            'severity': 'High',
                            'url': test_url,
                            'description': f"Potential file inclusion vulnerability with payload: {payload}",
                            'evidence': "Remote file content detected in response"
                        })
            except Exception as e:
                continue
    
    def check_open_redirect(self, url):
        """Check for open redirect vulnerabilities"""
        payloads = [
            "//evil.com",
            "/\\evil.com",
            "https://evil.com"
        ]
        
        for payload in payloads:
            test_url = f"{url}?redirect={payload}"
            try:
                response = self.session.get(test_url, timeout=5, allow_redirects=False)
                if response.status_code in [301, 302, 307, 308]:
                    location = response.headers.get('Location', '')
                    if 'evil.com' in location:
                        self.results.append({
                            'type': 'Open Redirect',
                            'severity': 'Medium',
                            'url': test_url,
                            'description': f"Potential open redirect vulnerability with payload: {payload}",
                            'evidence': f"Redirecting to: {location}"
                        })
            except Exception as e:
                continue
    
    def check_ssl_tls(self, url):
        """Check for SSL/TLS vulnerabilities"""
        if url.startswith('https://'):
            try:
                response = self.session.get(url, timeout=5)
                cert = response.raw.connection.sock.getpeercert()
                
                # Check for weak protocols
                if 'version' in cert:
                    if cert['version'] < 2:
                        self.results.append({
                            'type': 'Weak SSL/TLS Version',
                            'severity': 'High',
                            'url': url,
                            'description': f"Weak SSL/TLS version detected: {cert['version']}",
                            'evidence': "SSL/TLS version is outdated"
                        })
                
                # Check for weak ciphers (simplified check)
                cipher = response.raw.connection.sock.cipher()
                if cipher and cipher[1] < 128:
                    self.results.append({
                        'type': 'Weak Cipher',
                        'severity': 'Medium',
                        'url': url,
                        'description': f"Weak cipher detected: {cipher[0]}",
                        'evidence': "Cipher strength is less than 128 bits"
                    })
            except Exception as e:
                self.results.append({
                    'type': 'SSL/TLS Issue',
                    'severity': 'Medium',
                    'url': url,
                    'description': "SSL/TLS configuration issue detected",
                    'evidence': str(e)
                })
        else:
            self.results.append({
                'type': 'No HTTPS',
                'severity': 'Medium',
                'url': url,
                'description': "Site is not using HTTPS",
                'evidence': "URL starts with http://"
            })
    
    def check_server_info_disclosure(self, url):
        """Check for server information disclosure"""
        try:
            response = self.session.get(url, timeout=5)
            server = response.headers.get('Server', '')
            powered_by = response.headers.get('X-Powered-By', '')
            
            if server:
                self.results.append({
                    'type': 'Server Information Disclosure',
                    'severity': 'Low',
                    'url': url,
                    'description': f"Server header reveals: {server}",
                    'evidence': "Server header present"
                })
            
            if powered_by:
                self.results.append({
                    'type': 'Technology Disclosure',
                    'severity': 'Low',
                    'url': url,
                    'description': f"X-Powered-By header reveals: {powered_by}",
                    'evidence': "X-Powered-By header present"
                })
        except Exception as e:
            pass
    
    def check_clickjacking(self, url):
        """Check for clickjacking vulnerabilities"""
        try:
            response = self.session.get(url, timeout=5)
            if 'X-Frame-Options' not in response.headers:
                self.results.append({
                    'type': 'Clickjacking',
                    'severity': 'Medium',
                    'url': url,
                    'description': "Missing X-Frame-Options header makes site vulnerable to clickjacking",
                    'evidence': "X-Frame-Options header not found"
                })
        except Exception as e:
            pass