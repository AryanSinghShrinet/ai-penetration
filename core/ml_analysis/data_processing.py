import requests
import pandas as pd
import numpy as np
import re
from sklearn.feature_extraction.text import TfidfVectorizer

class LegalDataCollector:
    """Collect legal datasets for training"""
    
    def get_nvd_cves(self, max_results=200):
        """Get CVE data from NVD (COMPLETELY LEGAL)"""
        print("[*] Fetching CVE data from NVD...")
        
        cves = []
        start_index = 0
        results_per_page = 50
        # B-10 FIX: Hard exit to prevent infinite loop when API returns continuous results
        max_pages = (max_results // results_per_page) + 1
        
        while len(cves) < max_results:
            # B-10 FIX: Break if we've already requested more pages than needed
            if start_index >= max_pages * results_per_page:
                print("[!] Max page limit reached, stopping NVD fetch.")
                break

            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0"
            params = {
                'startIndex': start_index,
                'resultsPerPage': results_per_page
            }
            
            try:
                response = requests.get(url, params=params, timeout=30)
                data = response.json()
                
                for item in data.get('vulnerabilities', []):
                    cve = item['cve']
                    description = cve['descriptions'][0]['value']
                    
                    metrics = cve.get('metrics', {})
                    cvss_score = 0.0
                    
                    if 'cvssMetricV31' in metrics:
                        cvss_score = metrics['cvssMetricV31'][0]['cvssData']['baseScore']
                    elif 'cvssMetricV30' in metrics:
                        cvss_score = metrics['cvssMetricV30'][0]['cvssData']['baseScore']
                    elif 'cvssMetricV2' in metrics:
                        cvss_score = metrics['cvssMetricV2'][0]['cvssData']['baseScore']
                    
                    cves.append({
                        'id': cve['id'],
                        'description': description,
                        'cvss_score': cvss_score,
                        'is_vulnerability': 1  # Label: 1 = vulnerable
                    })
                
                start_index += results_per_page
                print(f"[+] Collected {len(cves)} CVEs so far...")
                
                if 'vulnerabilities' not in data or len(data['vulnerabilities']) == 0:
                    break
                    
            except Exception as e:
                print(f"[!] Error fetching data: {e}")
                break
        
        return cves[:max_results]
    
    def get_owasp_examples(self):
        """Get OWASP example vulnerabilities"""
        print("[*] Loading OWASP examples...")
        return [
            {'description': 'SQL Injection: User input directly concatenated into SQL query without sanitization', 'cvss_score': 8.8, 'is_vulnerability': 1},
            {'description': 'Cross-Site Scripting (XSS): User input reflected in response without encoding', 'cvss_score': 7.5, 'is_vulnerability': 1},
            {'description': 'Broken Authentication: Weak password policy allowing common passwords', 'cvss_score': 8.1, 'is_vulnerability': 1},
            {'description': 'Sensitive Data Exposure: Credit card numbers stored without encryption', 'cvss_score': 8.2, 'is_vulnerability': 1},
            {'description': 'XML External Entities (XXE): XML parser processing external entities', 'cvss_score': 7.5, 'is_vulnerability': 1}
        ]
    
    def get_secure_examples(self):
        """Get examples of secure code/normal behavior (negative class)"""
        print("[*] Loading secure code examples...")
        return [
            {'description': 'User input sanitized using parameterized queries', 'cvss_score': 0.0, 'is_vulnerability': 0},
            {'description': 'Output encoding applied to all user-controlled data', 'cvss_score': 0.0, 'is_vulnerability': 0},
            {'description': 'Multi-factor authentication implemented for sensitive operations', 'cvss_score': 0.0, 'is_vulnerability': 0},
            {'description': 'Data encrypted using AES-256 with proper key management', 'cvss_score': 0.0, 'is_vulnerability': 0},
            {'description': 'XML parsing configured to disable external entity processing', 'cvss_score': 0.0, 'is_vulnerability': 0},
            {'description': 'Normal HTTP request to homepage', 'cvss_score': 0.0, 'is_vulnerability': 0},
            {'description': 'API endpoint with proper authentication and rate limiting', 'cvss_score': 0.0, 'is_vulnerability': 0},
            {'description': 'Logout functionality with session destruction', 'cvss_score': 0.0, 'is_vulnerability': 0}
        ]

class DatasetBuilder:
    """Build and preprocess the training dataset"""
    
    def __init__(self):
        self.collector = LegalDataCollector()
    
    def build_dataset(self, num_cves=200):
        """Build balanced dataset"""
        print("[*] Building dataset...")
        
        cves = self.collector.get_nvd_cves(max_results=num_cves)
        if not cves:
            print("[!] NVD fetch failed or empty, using synthetic fallbacks for robustness.")
            cves = self.get_synthetic_cves()

        owasp = self.collector.get_owasp_examples()
        secure = self.collector.get_secure_examples()
        
        data = cves + owasp + secure
        df = pd.DataFrame(data)
        
        synthetic_negative = self.generate_synthetic_negative(len(df))
        df = pd.concat([df, pd.DataFrame(synthetic_negative)], ignore_index=True)
        
        print(f"[*] Dataset built: {len(df)} total examples")
        return df

    def get_synthetic_cves(self):
        return [
             {"description": "SQL injection in login form", "cvss_score": 8.5, "is_vulnerability": 1},
             {"description": "XSS vulnerability in search box", "cvss_score": 7.0, "is_vulnerability": 1},
             {"description": "Buffer overflow in image parser", "cvss_score": 9.0, "is_vulnerability": 1}
        ]
    
    def generate_synthetic_negative(self, target_count):
        """Generate synthetic negative examples to balance the dataset.
        
        B-08 FIX: Now scales output to target_count instead of always returning
        the fixed 20 items — preventing class imbalance when positive examples
        number in the hundreds.
        """
        import itertools
        synthetic = []
        
        # Normal behaviors (non-vulnerable)
        normal_behaviors = [
            "Regular user login with correct credentials",
            "Fetching public API data with valid parameters",
            "Uploading file with proper size validation",
            "Downloading document from authorized repository",
            "Searching with alphanumeric keywords only",
            "Submitting contact form with valid email",
            "Viewing product catalog with category filter",
            "Adding item to shopping cart with valid SKU",
            "Checking order status with valid order number",
            "Updating profile with sanitized input fields",
            "Password reset with verified email token",
            "Session terminated after logout request",
            "File download with proper authorization check",
            "API rate limiting applied correctly",
            "CSRF token validated before form submission",
            "Input length validated against maximum limit",
            "File type validated using magic bytes",
            "User role checked before admin action",
            "Database query using prepared statements",
            "Response headers include security policies",
        ]
        
        # B-08 FIX: Cycle through the base list until we reach target_count
        for behavior in itertools.islice(itertools.cycle(normal_behaviors), target_count):
            synthetic.append({'description': behavior, 'cvss_score': 0.0, 'is_vulnerability': 0})
        
        return synthetic
    
    def get_real_vulnerability_patterns(self):
        """Get patterns from actual vulnerability scenarios"""
        return [
            # SQL Injection patterns
            {'description': 'User input passed directly to SQL query: SELECT * FROM users WHERE id=' + "'" + 'user_input', 'cvss_score': 9.0, 'is_vulnerability': 1},
            {'description': 'Error message reveals SQL syntax: You have an error in your SQL syntax near', 'cvss_score': 7.5, 'is_vulnerability': 1},
            {'description': 'Time-based blind SQL injection: response delay of 5 seconds with SLEEP payload', 'cvss_score': 8.5, 'is_vulnerability': 1},
            
            # XSS patterns
            {'description': 'Reflected input in HTML without encoding: <script>alert(1)</script> appears in response', 'cvss_score': 6.5, 'is_vulnerability': 1},
            {'description': 'User input in onclick attribute: <button onclick="handler(user_input)">', 'cvss_score': 6.0, 'is_vulnerability': 1},
            {'description': 'Stored XSS in comment field: persistent script execution on page load', 'cvss_score': 7.0, 'is_vulnerability': 1},
            
            # SSRF patterns
            {'description': 'Server makes request to internal IP: connection to 127.0.0.1 from user-supplied URL', 'cvss_score': 8.0, 'is_vulnerability': 1},
            {'description': 'AWS metadata endpoint accessible: response contains aws_access_key_id', 'cvss_score': 9.5, 'is_vulnerability': 1},
            
            # IDOR patterns
            {'description': 'Accessing other user data by changing ID: /api/user/123 returns data for user 456', 'cvss_score': 7.0, 'is_vulnerability': 1},
            {'description': 'Document download without ownership check: any user can download invoice/1234.pdf', 'cvss_score': 6.5, 'is_vulnerability': 1},
            
            # Command Injection patterns
            {'description': 'OS command execution: response contains /etc/passwd contents', 'cvss_score': 9.5, 'is_vulnerability': 1},
            {'description': 'Ping command injection: semicolon in hostname parameter executes additional commands', 'cvss_score': 9.0, 'is_vulnerability': 1},
            
            # Authentication issues
            {'description': 'JWT signature not verified: alg=none accepted by server', 'cvss_score': 9.0, 'is_vulnerability': 1},
            {'description': 'Password reset token predictable: sequential or timestamp-based tokens', 'cvss_score': 8.5, 'is_vulnerability': 1},
            {'description': 'Session fixation: session ID not regenerated after login', 'cvss_score': 7.0, 'is_vulnerability': 1},
            
            # File upload issues
            {'description': 'PHP file uploaded and executed: webshell accessible at /uploads/shell.php', 'cvss_score': 9.5, 'is_vulnerability': 1},
            {'description': 'SVG with embedded JavaScript accepted: XSS via uploaded image', 'cvss_score': 6.5, 'is_vulnerability': 1},
            
            # CORS issues
            {'description': 'Access-Control-Allow-Origin reflects any origin with credentials', 'cvss_score': 8.0, 'is_vulnerability': 1},
            {'description': 'CORS allows null origin with Access-Control-Allow-Credentials: true', 'cvss_score': 7.5, 'is_vulnerability': 1},
        ]
    
    def preprocess_text(self, text):
        if not isinstance(text, str): return ""
        text = text.lower()
        text = re.sub(r'[^\w\s\'\"\-\=\<\>\(\)\;]', ' ', text)
        text = ' '.join(text.split())
        return text
    
    def prepare_features(self, df):
        print("[*] Preparing features...")
        df['processed_text'] = df['description'].apply(self.preprocess_text)
        
        vectorizer = TfidfVectorizer(max_features=500, stop_words='english', ngram_range=(1, 2))
        X_text = vectorizer.fit_transform(df['processed_text'])
        
        df['cvss_score'] = pd.to_numeric(df['cvss_score'], errors='coerce').fillna(0)
        df['text_length'] = df['processed_text'].apply(len)
        
        security_keywords = ['injection', 'xss', 'sql', 'buffer', 'overflow', 'vulnerability', 'exploit', 'attack', 'bypass', 'privilege']
        df['security_keyword_count'] = df['processed_text'].apply(lambda x: sum(1 for word in security_keywords if word in x))
        
        X_numerical = df[['cvss_score', 'text_length', 'security_keyword_count']].values
        X_combined = np.hstack([X_text.toarray(), X_numerical])
        y = df['is_vulnerability'].values
        
        return X_combined, y, vectorizer
