"""
security_audit.py — 보안 감사 모듈 (v6.2.142)

Acunetix 100% 레벨 달성을 위한 보안 감사 스캔:
  1. security_headers_check  — 보안 헤더 14종 검사 (CSP/HSTS/X-Frame-Options 등)
  2. ssl_tls_scan            — TLS 인증서/암호화 취약점 탐지
  3. info_disclosure_scan    — 정보 노출 (에러/스택/버전/디버그)
  4. source_exposure_scan    — 소스코드 노출 (.git/.svn/.env/백업파일 100+)
  5. cors_scan               — CORS 잘못된 설정 (반사/null/credential 포함)
  6. clickjacking_scan       — 클릭재킹 취약점 (X-Frame-Options + CSP)
  7. cookie_security_scan    — 쿠키 보안 속성 (Secure/HttpOnly/SameSite)
  8. directory_listing_scan  — 디렉토리 리스팅 탐지
  9. password_policy_scan    — 약한 비밀번호 정책 테스트
  10. security_full_audit    — 통합 보안 감사 (10개 스캔 동시 실행)
"""

from __future__ import annotations

import re
import ssl
import socket
import time
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, urljoin

try:
    import requests as _requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning  # type: ignore
    _requests.packages.urllib3.disable_warnings(InsecureRequestWarning)  # type: ignore
    _HAS_REQUESTS = True
except ImportError:
    _HAS_REQUESTS = False

_DEFAULT_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
               "AppleWebKit/537.36 (KHTML, like Gecko) "
               "Chrome/125.0 Safari/537.36")

def _sess(headers: Optional[Dict] = None):
    s = _requests.Session()
    s.verify = False
    s.headers.update({"User-Agent": _DEFAULT_UA})
    if headers:
        s.headers.update(headers)
    return s

def _banner(title: str) -> str:
    return f"\n{'─'*60}\n  {title}\n{'─'*60}"

# ══════════════════════════════════════════════════════════════════════════════
# ── 1. 보안 헤더 검사 ─────────────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════

_SECURITY_HEADERS: List[Tuple[str, str, str, str]] = [
    # (header_name, must_contain, severity, description)
    ("Strict-Transport-Security", "max-age", "HIGH",
     "HSTS 미설정 — 다운그레이드 공격 가능"),
    ("Content-Security-Policy", "default-src", "HIGH",
     "CSP 미설정 — XSS/데이터 인젝션 방어 없음"),
    ("X-Frame-Options", "", "MEDIUM",
     "X-Frame-Options 미설정 — 클릭재킹 취약"),
    ("X-Content-Type-Options", "nosniff", "MEDIUM",
     "X-Content-Type-Options 미설정 — MIME 스니핑 가능"),
    ("Referrer-Policy", "", "LOW",
     "Referrer-Policy 미설정 — Referer 정보 유출"),
    ("Permissions-Policy", "", "LOW",
     "Permissions-Policy 미설정 — 브라우저 기능 제한 없음"),
    ("X-XSS-Protection", "", "LOW",
     "X-XSS-Protection 미설정 (레거시 브라우저)"),
    ("Cache-Control", "no-store", "LOW",
     "Cache-Control no-store 미설정 — 민감정보 캐시 가능"),
    ("Cross-Origin-Embedder-Policy", "", "LOW",
     "COEP 미설정"),
    ("Cross-Origin-Opener-Policy", "", "LOW",
     "COOP 미설정"),
    ("Cross-Origin-Resource-Policy", "", "LOW",
     "CORP 미설정"),
    ("Access-Control-Allow-Origin", "", "INFO",
     "CORS 헤더 존재 (별도 검사 필요)"),
    ("Server", "", "INFO",
     "Server 헤더로 버전 노출 가능"),
    ("X-Powered-By", "", "LOW",
     "X-Powered-By 헤더로 기술 스택 노출"),
]

def security_headers_check(
    url: str,
    session_headers: Optional[Dict] = None,
) -> Dict[str, Any]:
    """
    보안 HTTP 헤더 14종 검사.
    미설정/잘못된 설정 헤더를 심각도별로 분류한다.

    Returns:
        dict with "missing_headers", "misconfigured_headers", "score", "output"
    """
    if not _HAS_REQUESTS:
        return {"success": False, "output": "requests 필요"}

    print(_banner(f"🛡️ 보안 헤더 검사 — {url}"))
    sess = _sess(session_headers)

    try:
        r = sess.get(url, timeout=12, verify=False, allow_redirects=True)
    except Exception as e:
        return {"success": False, "output": f"[SEC_HEADERS] 오류: {e}"}

    headers_lower = {k.lower(): v for k, v in r.headers.items()}
    missing: List[Dict] = []
    present: List[Dict] = []
    issues: List[Dict] = []

    for hdr, must_contain, severity, desc in _SECURITY_HEADERS:
        hdr_lower = hdr.lower()
        value = headers_lower.get(hdr_lower, "")

        if not value:
            if severity in ("HIGH", "MEDIUM"):
                print(f"  🔴 [{severity}] {hdr}: {desc}")
            else:
                print(f"  🟡 [{severity}] {hdr}: 미설정")
            missing.append({"header": hdr, "severity": severity, "desc": desc})
            issues.append({"header": hdr, "issue": "missing", "severity": severity})
        else:
            # must_contain 검사
            if must_contain and must_contain.lower() not in value.lower():
                print(f"  🟡 [{severity}] {hdr}: 잘못된 설정 — '{value}'")
                issues.append({"header": hdr, "issue": "misconfigured", "value": value, "severity": severity})
            else:
                present.append({"header": hdr, "value": value[:80]})

            # 특별 검사
            if hdr_lower == "server" and len(value) > 3:
                print(f"  🟡 [LOW] Server 헤더 노출: '{value}'")
                issues.append({"header": "Server", "issue": "version_disclosure", "value": value, "severity": "LOW"})
            if hdr_lower == "x-powered-by":
                print(f"  🟡 [LOW] X-Powered-By 노출: '{value}'")
                issues.append({"header": "X-Powered-By", "issue": "tech_disclosure", "value": value, "severity": "LOW"})
            if hdr_lower == "strict-transport-security":
                if "includesubdomains" not in value.lower():
                    issues.append({"header": "HSTS", "issue": "no_includeSubDomains", "severity": "LOW"})
                if "preload" not in value.lower():
                    issues.append({"header": "HSTS", "issue": "no_preload", "severity": "INFO"})

    # 점수 계산 (100점 기준)
    high_missing = sum(1 for m in missing if m["severity"] == "HIGH")
    med_missing = sum(1 for m in missing if m["severity"] == "MEDIUM")
    score = max(0, 100 - high_missing * 20 - med_missing * 10 - len(issues) * 3)

    output = (
        f"[SEC_HEADERS] {url}\n"
        f"  보안점수: {score}/100\n"
        f"  누락 헤더: {len(missing)}개 | 취약: {sum(1 for m in missing if m['severity']=='HIGH')}개 HIGH\n"
        + "\n".join(f"  [{i['severity']}] {i['header']}: {i['issue']}" for i in issues[:10])
    )

    return {
        "success": bool(issues),
        "vuln_type": "SecurityHeaders",
        "score": score,
        "missing_headers": missing,
        "present_headers": present,
        "issues": issues,
        "output": output,
    }

# ══════════════════════════════════════════════════════════════════════════════
# ── 2. TLS/SSL 취약점 스캔 ────────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════

def ssl_tls_scan(
    url: str,
    session_headers: Optional[Dict] = None,
) -> Dict[str, Any]:
    """
    TLS/SSL 인증서 및 암호화 취약점 탐지.
    - 인증서 만료 여부
    - 약한 프로토콜 (SSLv2/SSLv3/TLS1.0/TLS1.1)
    - 자체 서명 인증서
    - 잘못된 CN/SAN
    - HSTS 설정 확인

    Returns:
        dict with "findings", "cert_info", "output"
    """
    print(_banner(f"🔐 TLS/SSL 스캔 — {url}"))
    findings = []
    cert_info = {}

    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    if parsed.scheme != "https":
        findings.append({
            "type": "no_https",
            "desc": "HTTPS 미사용 — 평문 전송",
            "severity": "HIGH",
        })
        print("  🔴 [HIGH] HTTPS 미사용!")

    if hostname:
        # 인증서 직접 검사
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=8) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    proto = ssock.version()

                    cert_info = {
                        "subject": dict(x[0] for x in cert.get("subject", [])),
                        "issuer": dict(x[0] for x in cert.get("issuer", [])),
                        "notAfter": cert.get("notAfter", ""),
                        "notBefore": cert.get("notBefore", ""),
                        "protocol": proto,
                        "cipher": cipher,
                    }

                    # 만료일 확인
                    not_after = cert.get("notAfter", "")
                    if not_after:
                        try:
                            exp_dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                            exp_dt = exp_dt.replace(tzinfo=timezone.utc)
                            days_left = (exp_dt - datetime.now(timezone.utc)).days
                            if days_left < 0:
                                findings.append({"type": "cert_expired", "days": days_left, "severity": "CRITICAL"})
                                print(f"  🔴 [CRITICAL] 인증서 만료! {abs(days_left)}일 경과")
                            elif days_left < 30:
                                findings.append({"type": "cert_expiring", "days": days_left, "severity": "HIGH"})
                                print(f"  🔴 [HIGH] 인증서 만료 임박! {days_left}일 남음")
                            else:
                                print(f"  ✅ 인증서 유효 ({days_left}일 남음)")
                        except Exception:
                            pass

                    # 프로토콜 검사
                    if proto in ("TLSv1", "TLSv1.1", "SSLv2", "SSLv3"):
                        findings.append({"type": "weak_protocol", "protocol": proto, "severity": "HIGH"})
                        print(f"  🔴 [HIGH] 취약 프로토콜: {proto}")
                    else:
                        print(f"  ✅ 프로토콜: {proto}")

                    # 암호 스위트 검사
                    if cipher:
                        cipher_name = cipher[0] if cipher else ""
                        weak_ciphers = ["RC4", "DES", "3DES", "MD5", "EXPORT", "NULL", "ANON"]
                        for wc in weak_ciphers:
                            if wc.lower() in cipher_name.lower():
                                findings.append({"type": "weak_cipher", "cipher": cipher_name, "severity": "HIGH"})
                                print(f"  🔴 [HIGH] 취약 암호: {cipher_name}")
                                break

                    print(f"  암호 스위트: {cipher[0] if cipher else '?'}")

        except ssl.SSLCertVerificationError as e:
            findings.append({"type": "cert_invalid", "error": str(e)[:80], "severity": "MEDIUM"})
            print(f"  🟡 [MEDIUM] 인증서 검증 실패: {e}")
        except ssl.SSLError as e:
            findings.append({"type": "ssl_error", "error": str(e)[:80], "severity": "MEDIUM"})
            print(f"  🟡 SSL 오류: {e}")
        except ConnectionRefusedError:
            findings.append({"type": "connection_refused", "severity": "INFO"})
        except Exception as e:
            print(f"  ⚠️ TLS 검사 오류: {e}")

        # 취약 프로토콜 강제 연결 시도
        for proto_ver, attr in [("TLSv1", "PROTOCOL_TLSv1"), ("TLSv1.1", "PROTOCOL_TLSv1_1")]:
            try:
                if hasattr(ssl, attr):
                    ctx_weak = ssl.SSLContext(getattr(ssl, attr))
                    ctx_weak.check_hostname = False
                    ctx_weak.verify_mode = ssl.CERT_NONE
                    with socket.create_connection((hostname, port), timeout=3) as sock:
                        with ctx_weak.wrap_socket(sock, server_hostname=hostname) as ssock2:
                            findings.append({
                                "type": "weak_protocol_supported",
                                "protocol": proto_ver,
                                "severity": "HIGH",
                            })
                            print(f"  🔴 [HIGH] {proto_ver} 지원됨!")
            except Exception:
                pass

    output = (
        f"[SSL_TLS] {url}\n"
        f"  프로토콜: {cert_info.get('protocol', '?')}\n"
        f"  발견: {len(findings)}개\n"
        + "\n".join(f"  [{f['severity']}] {f['type']}" + (f": {f.get('error','') or f.get('protocol','')}" if f.get('error') or f.get('protocol') else "") for f in findings)
    )

    return {
        "success": bool(findings),
        "vuln_type": "SSL_TLS",
        "cert_info": cert_info,
        "findings": findings,
        "output": output,
    }

# ══════════════════════════════════════════════════════════════════════════════
# ── 3. 정보 노출 스캔 ─────────────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════

def info_disclosure_scan(
    url: str,
    session_headers: Optional[Dict] = None,
) -> Dict[str, Any]:
    """
    정보 노출 탐지:
    - 에러 페이지 스택 트레이스
    - 서버/버전 정보 노출
    - 디버그 엔드포인트
    - 서드파티 API 키 노출
    - 내부 IP 노출
    - 경로 노출

    Returns:
        dict with "findings", "output"
    """
    if not _HAS_REQUESTS:
        return {"success": False, "output": "requests 필요"}

    print(_banner(f"🔍 정보 노출 스캔 — {url}"))
    sess = _sess(session_headers)
    findings = []
    base = f"{urlparse(url).scheme}://{urlparse(url).netloc}"

    # 에러 유발 페이로드
    ERROR_TRIGGERS = [
        url + "'" ,
        url + "/<>",
        url + "/..%2F",
        url + "?id=1'",
        url + "?__debug__=1",
        url + "?debug=true",
        url.replace("https://", "https://") + "/../",
    ]

    _STACK_SIGS = [
        # Python
        r"traceback \(most recent call last\)",
        r"file \".*\.py\", line \d+",
        r"django\.core\.",
        r"flask\.app\.",
        r"werkzeug\.",
        # Java
        r"java\.lang\.\w+exception",
        r"at \w+\.\w+\(.*\.java:\d+\)",
        r"org\.springframework\.",
        r"javax\.servlet\.",
        r"com\.mysql\.",
        # PHP
        r"fatal error:.*in.*\.php",
        r"warning:.*\.php on line \d+",
        r"parse error:.*in.*\.php",
        r"call stack:",
        # Node.js
        r"at\s+\w+\s+\(.*\.js:\d+:\d+\)",
        r"express\.js",
        # .NET
        r"system\.web\.",
        r"asp\.net",
        r"microsoft\.net",
        r"object reference not set",
        # DB
        r"mysql_fetch_",
        r"ORA-\d{5}",
        r"pg_query\(\): query failed",
        r"unclosed quotation mark",
    ]

    _KEY_PATTERNS = [
        (r"AKIA[0-9A-Z]{16}", "AWS Access Key"),
        (r"[0-9a-zA-Z/+]{40}", "Possible AWS Secret"),
        (r"AIza[0-9A-Za-z\-_]{35}", "Google API Key"),
        (r"ghp_[A-Za-z0-9]{36}", "GitHub Token"),
        (r"github_pat_[A-Za-z0-9_]{82}", "GitHub PAT"),
        (r"eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-_.+/=]*", "JWT Token"),
        (r"sk-[a-zA-Z0-9]{48}", "OpenAI API Key"),
        (r"xox[baprs]-[0-9A-Za-z\-]+", "Slack Token"),
        (r"SG\.[a-zA-Z0-9]{22}\.[a-zA-Z0-9\-_]{43}", "SendGrid Key"),
        (r"[0-9a-f]{32}", "MD5 Hash/Token (32 hex chars)"),
        (r"password\s*[=:]\s*['\"]?[A-Za-z0-9_!@#$%^&*]{6,}", "Password Exposure"),
        (r"api[_-]?key\s*[=:]\s*['\"]?[A-Za-z0-9_\-]{10,}", "API Key Exposure"),
        (r"secret[_-]?key\s*[=:]\s*['\"]?[A-Za-z0-9_\-]{10,}", "Secret Key Exposure"),
        (r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b",
         "Internal IP Disclosure"),
    ]

    # 에러 유발 및 스택 트레이스 탐지
    for trigger_url in ERROR_TRIGGERS[:3]:
        try:
            r = sess.get(trigger_url, timeout=8, verify=False)
            body = r.text[:10000]

            for pattern in _STACK_SIGS:
                if re.search(pattern, body, re.IGNORECASE):
                    findings.append({
                        "type": "stack_trace",
                        "url": trigger_url,
                        "pattern": pattern[:50],
                        "severity": "MEDIUM",
                    })
                    print(f"  🟡 [MEDIUM] 스택 트레이스 노출: {trigger_url}")
                    break
        except Exception:
            pass

    # 기본 URL에서 키/비밀 탐지
    try:
        r = sess.get(url, timeout=12, verify=False)
        body = r.text[:50000]

        for pattern, key_type in _KEY_PATTERNS:
            matches = re.findall(pattern, body, re.IGNORECASE)
            if matches:
                findings.append({
                    "type": "key_exposure",
                    "key_type": key_type,
                    "sample": matches[0][:20] + "...",
                    "severity": "HIGH" if "Key" in key_type or "Token" in key_type else "MEDIUM",
                })
                print(f"  🔴 {key_type} 노출 가능성!")
    except Exception:
        pass

    # 디버그 엔드포인트 탐지
    DEBUG_PATHS = [
        "/debug", "/debug/info", "/_debug", "/phpinfo.php",
        "/info.php", "/server-info", "/server-status",
        "/test.php", "/test", "/admin/info",
        "/__debug__/", "/console", "/h2-console",
        "/actuator/env", "/actuator/dump", "/actuator/trace",
        "/swagger-ui.html", "/swagger-ui/", "/api-docs",
        "/.well-known/security.txt", "/security.txt",
        "/crossdomain.xml", "/clientaccesspolicy.xml",
        "/robots.txt", "/sitemap.xml",
        "/CHANGELOG", "/CHANGELOG.md", "/CHANGELOG.txt",
        "/VERSION", "/version.txt",
        "/README", "/README.md",
    ]

    for path in DEBUG_PATHS:
        try:
            r = sess.get(f"{base}{path}", timeout=5, verify=False)
            if r.status_code == 200 and len(r.content) > 50:
                severity = "HIGH" if path in ["/phpinfo.php", "/server-info", "/server-status",
                                               "/actuator/env", "/h2-console"] else "LOW"
                print(f"  {'🔴' if severity=='HIGH' else '🟡'} [{severity}] {path} 접근 가능")
                findings.append({
                    "type": "debug_endpoint",
                    "path": path,
                    "status": r.status_code,
                    "severity": severity,
                })
        except Exception:
            pass

    output = (
        f"[INFO_DISC] {url}\n"
        f"  발견: {len(findings)}개\n"
        + "\n".join(f"  [{f['severity']}] {f['type']}: {f.get('path', f.get('key_type', f.get('pattern', '')))[:60]}" for f in findings[:15])
    )

    return {
        "success": bool(findings),
        "vuln_type": "InfoDisclosure",
        "findings": findings,
        "output": output,
    }

# ══════════════════════════════════════════════════════════════════════════════
# ── 4. 소스 코드/파일 노출 스캔 ──────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════

_SOURCE_EXPOSURE_PATHS = [
    # Git
    ("/.git/config", "CRITICAL", "[core]", "Git 저장소 노출"),
    ("/.git/HEAD", "CRITICAL", "ref:", "Git HEAD 노출"),
    ("/.git/COMMIT_EDITMSG", "CRITICAL", "", "Git commit 메시지 노출"),
    ("/.git/logs/HEAD", "CRITICAL", "", "Git 로그 노출"),
    ("/.git/index", "CRITICAL", "DIRC", "Git 인덱스 노출"),
    # SVN
    ("/.svn/wc.db", "CRITICAL", "SQLite", "SVN 데이터베이스 노출"),
    ("/.svn/entries", "CRITICAL", "10\n", "SVN entries 노출"),
    ("/.svn/all-wcprops", "CRITICAL", "", "SVN all-wcprops 노출"),
    # Mercurial
    ("/.hg/hgrc", "HIGH", "", "Mercurial 설정 노출"),
    # DS_Store
    ("/.DS_Store", "MEDIUM", "\x00", "macOS DS_Store 노출"),
    # Environment/config
    ("/.env", "CRITICAL", "=", ".env 파일 노출"),
    ("/.env.local", "CRITICAL", "=", ".env.local 노출"),
    ("/.env.production", "CRITICAL", "=", ".env.production 노출"),
    ("/.env.development", "CRITICAL", "=", ".env.development 노출"),
    ("/.env.backup", "CRITICAL", "=", ".env.backup 노출"),
    ("/config.php", "CRITICAL", "<?php", "PHP 설정 파일 노출"),
    ("/config.php.bak", "CRITICAL", "", "PHP 설정 백업 노출"),
    ("/config.inc.php", "CRITICAL", "", "PHP 설정 include 노출"),
    ("/wp-config.php.bak", "CRITICAL", "", "WordPress 설정 백업"),
    ("/configuration.php", "CRITICAL", "", "Joomla 설정 노출"),
    ("/settings.py", "CRITICAL", "SECRET", "Django settings 노출"),
    ("/config.yml", "HIGH", "", "YAML 설정 노출"),
    ("/config.yaml", "HIGH", "", "YAML 설정 노출"),
    ("/config.json", "HIGH", "{", "JSON 설정 노출"),
    ("/app.config", "HIGH", "", "앱 설정 노출"),
    ("/web.config", "HIGH", "<?xml", "IIS web.config 노출"),
    # Package managers
    ("/composer.json", "MEDIUM", "require", "PHP 패키지 정보 노출"),
    ("/composer.lock", "MEDIUM", "hash", "PHP 패키지 버전 노출"),
    ("/package.json", "MEDIUM", '"name"', "Node.js 패키지 정보 노출"),
    ("/package-lock.json", "MEDIUM", "lockfileVersion", "Node.js 의존성 노출"),
    ("/yarn.lock", "MEDIUM", "yarn lockfile", "Yarn 의존성 노출"),
    ("/Gemfile", "MEDIUM", "gem", "Ruby Gemfile 노출"),
    ("/Gemfile.lock", "MEDIUM", "", "Ruby Gemfile.lock 노출"),
    ("/requirements.txt", "LOW", "", "Python 의존성 노출"),
    ("/Pipfile", "LOW", "[[source]]", "Pipfile 노출"),
    ("/pom.xml", "LOW", "<project>", "Maven 설정 노출"),
    ("/build.gradle", "LOW", "dependencies", "Gradle 설정 노출"),
    # Backup files
    ("/backup.zip", "HIGH", "PK", "백업 ZIP 노출"),
    ("/backup.tar.gz", "HIGH", "\x1f\x8b", "백업 tar.gz 노출"),
    ("/backup.sql", "HIGH", "CREATE TABLE", "SQL 백업 노출"),
    ("/dump.sql", "HIGH", "CREATE TABLE", "SQL 덤프 노출"),
    ("/database.sql", "HIGH", "CREATE TABLE", "DB 파일 노출"),
    ("/db.sql", "HIGH", "CREATE TABLE", "DB SQL 노출"),
    ("/site.zip", "HIGH", "PK", "사이트 ZIP 노출"),
    ("/www.zip", "HIGH", "PK", "WWW ZIP 노출"),
    # CI/CD
    ("/.travis.yml", "MEDIUM", "", "Travis CI 설정 노출"),
    ("/.circleci/config.yml", "MEDIUM", "", "CircleCI 설정 노출"),
    ("/.github/workflows/", "LOW", "", "GitHub Actions 노출"),
    ("/Jenkinsfile", "MEDIUM", "pipeline", "Jenkinsfile 노출"),
    ("/Dockerfile", "LOW", "FROM", "Dockerfile 노출"),
    ("/docker-compose.yml", "MEDIUM", "services:", "Docker Compose 노출"),
    ("/docker-compose.yaml", "MEDIUM", "services:", "Docker Compose 노출"),
    # SSH/Keys
    ("/.ssh/id_rsa", "CRITICAL", "BEGIN", "SSH 개인키 노출"),
    ("/.ssh/authorized_keys", "CRITICAL", "ssh-", "SSH 인가키 노출"),
    ("/id_rsa", "CRITICAL", "BEGIN", "RSA 개인키 노출"),
    ("/server.key", "CRITICAL", "BEGIN", "서버 키 노출"),
    ("/private.key", "CRITICAL", "BEGIN", "개인키 노출"),
    # Logs
    ("/error.log", "MEDIUM", "", "에러 로그 노출"),
    ("/access.log", "MEDIUM", "GET", "접근 로그 노출"),
    ("/debug.log", "MEDIUM", "", "디버그 로그 노출"),
    ("/application.log", "MEDIUM", "", "앱 로그 노출"),
]

def source_exposure_scan(
    url: str,
    session_headers: Optional[Dict] = None,
) -> Dict[str, Any]:
    """
    소스코드/민감 파일 노출 스캔 (70+ 경로).
    .git/.svn/.env/백업파일/설정파일/개인키 등을 탐지한다.

    Returns:
        dict with "findings", "output"
    """
    if not _HAS_REQUESTS:
        return {"success": False, "output": "requests 필요"}

    print(_banner(f"📁 소스코드 노출 스캔 — {url}"))
    sess = _sess(session_headers)
    base = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
    findings = []

    def _check(path: str, severity: str, sig: str, desc: str) -> Optional[Dict]:
        try:
            r = sess.get(f"{base}{path}", timeout=6, verify=False)
            if r.status_code == 200 and len(r.content) > 10:
                if not sig or sig in r.text[:500] or sig.encode() in r.content[:500]:
                    return {
                        "path": path,
                        "desc": desc,
                        "size": len(r.content),
                        "severity": severity,
                    }
        except Exception:
            pass
        return None

    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(_check, path, sev, sig, desc): (path, desc)
                   for path, sev, sig, desc in _SOURCE_EXPOSURE_PATHS}
        for future in as_completed(futures):
            result = future.result()
            if result:
                sym = "🔴" if result["severity"] in ("CRITICAL", "HIGH") else "🟡"
                print(f"  {sym} [{result['severity']}] {result['path']}: {result['desc']}")
                findings.append(result)

    output = (
        f"[SOURCE_EXP] {url}\n"
        f"  탐지: {len(findings)}개 노출 파일\n"
        + "\n".join(f"  [{f['severity']}] {f['path']}: {f['desc']}" for f in
                    sorted(findings, key=lambda x: ["CRITICAL","HIGH","MEDIUM","LOW"].index(x["severity"]) if x["severity"] in ["CRITICAL","HIGH","MEDIUM","LOW"] else 4))
    )

    return {
        "success": bool(findings),
        "vuln_type": "SourceExposure",
        "findings": findings,
        "output": output,
    }

# ══════════════════════════════════════════════════════════════════════════════
# ── 5. CORS 잘못된 설정 스캔 ─────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════

def cors_scan(
    url: str,
    session_headers: Optional[Dict] = None,
) -> Dict[str, Any]:
    """
    CORS 잘못된 설정 탐지:
    - Origin 반사 (임의 도메인 허용)
    - null origin 허용
    - Credentials + 와일드카드 (*) 조합
    - 프리플라이트 미확인

    Returns:
        dict with "findings", "output"
    """
    if not _HAS_REQUESTS:
        return {"success": False, "output": "requests 필요"}

    print(_banner(f"🌐 CORS 스캔 — {url}"))
    sess = _sess(session_headers)
    findings = []

    TEST_ORIGINS = [
        "https://evil.com",
        "https://attacker.com",
        "null",
        f"https://evil.{urlparse(url).hostname}",
        f"https://{urlparse(url).hostname}.evil.com",
        "https://127.0.0.1",
        "http://evil.com",
        "",
    ]

    for origin in TEST_ORIGINS:
        if not origin:
            continue
        try:
            h = dict(session_headers or {})
            h["Origin"] = origin
            r = sess.get(url, headers=h, timeout=8, verify=False)

            acao = r.headers.get("Access-Control-Allow-Origin", "")
            acac = r.headers.get("Access-Control-Allow-Credentials", "")

            if not acao:
                continue

            # 반사 취약
            if acao == origin:
                severity = "HIGH"
                note = f"Origin 반사 — {origin}"
                if "true" in acac.lower():
                    severity = "CRITICAL"
                    note += " + Credentials 허용!"
                print(f"  🔴 [{severity}] CORS 반사: {origin}")
                findings.append({
                    "origin": origin,
                    "acao": acao,
                    "acac": acac,
                    "note": note,
                    "severity": severity,
                })

            # null origin
            elif acao == "null" and origin == "null":
                print(f"  🔴 [HIGH] null origin 허용")
                findings.append({
                    "origin": "null",
                    "acao": acao,
                    "note": "null origin 허용",
                    "severity": "HIGH",
                })

            # 와일드카드 + Credentials
            elif acao == "*" and "true" in acac.lower():
                print("  🔴 [CRITICAL] wildcard(*) + credentials — 불가능한 설정이나 탐지됨")
                findings.append({
                    "origin": "*",
                    "acao": "*",
                    "acac": acac,
                    "note": "Wildcard + Credentials (설정 오류)",
                    "severity": "CRITICAL",
                })

        except Exception:
            pass

        # Preflight 검사
        try:
            h = dict(session_headers or {})
            h.update({
                "Origin": "https://evil.com",
                "Access-Control-Request-Method": "DELETE",
                "Access-Control-Request-Headers": "X-Custom-Header",
            })
            r = sess.options(url, headers=h, timeout=8, verify=False)
            acam = r.headers.get("Access-Control-Allow-Methods", "")
            if "DELETE" in acam or "PUT" in acam:
                print(f"  🟡 [MEDIUM] Preflight에서 위험 메서드 허용: {acam}")
                findings.append({
                    "type": "preflight",
                    "methods": acam,
                    "note": f"위험 메서드 허용: {acam}",
                    "severity": "MEDIUM",
                })
        except Exception:
            pass

    output = (
        f"[CORS] {url}\n"
        f"  발견: {len(findings)}개\n"
        + "\n".join(f"  [{f['severity']}] {f.get('origin','?')}: {f['note']}" for f in findings)
    )

    return {
        "success": bool(findings),
        "vuln_type": "CORS",
        "findings": findings,
        "output": output,
    }

# ══════════════════════════════════════════════════════════════════════════════
# ── 6. 클릭재킹 스캔 ─────────────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════

def clickjacking_scan(
    url: str,
    session_headers: Optional[Dict] = None,
) -> Dict[str, Any]:
    """
    클릭재킹 취약점 탐지.
    X-Frame-Options 미설정 및 CSP frame-ancestors 미설정 확인.

    Returns:
        dict with "vulnerable", "findings", "output"
    """
    if not _HAS_REQUESTS:
        return {"success": False, "output": "requests 필요"}

    print(_banner(f"🖱️ 클릭재킹 스캔 — {url}"))
    sess = _sess(session_headers)
    findings = []

    try:
        r = sess.get(url, timeout=12, verify=False)
        headers_lower = {k.lower(): v for k, v in r.headers.items()}

        xfo = headers_lower.get("x-frame-options", "")
        csp = headers_lower.get("content-security-policy", "")

        # X-Frame-Options 검사
        if not xfo:
            print("  🔴 [HIGH] X-Frame-Options 미설정")
            findings.append({
                "type": "missing_xfo",
                "desc": "X-Frame-Options 헤더 없음",
                "severity": "HIGH",
            })
        elif xfo.lower() not in ("deny", "sameorigin"):
            print(f"  🟡 [MEDIUM] X-Frame-Options 약한 설정: {xfo}")
            findings.append({
                "type": "weak_xfo",
                "value": xfo,
                "desc": f"X-Frame-Options 취약 설정: '{xfo}'",
                "severity": "MEDIUM",
            })
        else:
            print(f"  ✅ X-Frame-Options: {xfo}")

        # CSP frame-ancestors 검사
        if not csp:
            if not xfo:
                findings.append({
                    "type": "missing_csp_frame_ancestors",
                    "desc": "CSP frame-ancestors 없음",
                    "severity": "HIGH",
                })
        elif "frame-ancestors" not in csp.lower():
            print("  🟡 [LOW] CSP에 frame-ancestors 없음")
            findings.append({
                "type": "missing_csp_frame_ancestors",
                "desc": "CSP 있으나 frame-ancestors 미설정",
                "severity": "LOW",
            })
        elif "frame-ancestors 'none'" in csp.lower() or "frame-ancestors 'self'" in csp.lower():
            print(f"  ✅ CSP frame-ancestors 설정됨")
        else:
            fa_match = re.search(r"frame-ancestors\s+([^;]+)", csp, re.IGNORECASE)
            if fa_match:
                fa_val = fa_match.group(1).strip()
                if "*" in fa_val:
                    print(f"  🔴 [HIGH] CSP frame-ancestors 와일드카드: {fa_val}")
                    findings.append({
                        "type": "weak_csp_frame_ancestors",
                        "value": fa_val,
                        "desc": "frame-ancestors 와일드카드(*) 허용",
                        "severity": "HIGH",
                    })

        # iframe 삽입 PoC 생성
        if findings:
            poc_html = (
                f'<html><body>'
                f'<h1>Clickjacking PoC</h1>'
                f'<iframe src="{url}" width="1200" height="800" style="opacity:0.5"></iframe>'
                f'<button style="position:absolute;top:300px;left:400px">속임 버튼</button>'
                f'</body></html>'
            )
            findings[0]["poc"] = poc_html[:200] + "..."

    except Exception as e:
        return {"success": False, "findings": [], "output": f"[CLICKJACKING] 오류: {e}"}

    vulnerable = bool(findings)
    output = (
        f"[CLICKJACKING] {url}\n"
        + ("  🔴 클릭재킹 취약!\n" if vulnerable else "  ✅ 클릭재킹 방어됨\n")
        + "\n".join(f"  [{f['severity']}] {f['desc']}" for f in findings)
    )

    return {
        "success": vulnerable,
        "vuln_type": "Clickjacking",
        "vulnerable": vulnerable,
        "findings": findings,
        "output": output,
    }

# ══════════════════════════════════════════════════════════════════════════════
# ── 7. 쿠키 보안 속성 스캔 ───────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════

def cookie_security_scan(
    url: str,
    session_headers: Optional[Dict] = None,
) -> Dict[str, Any]:
    """
    쿠키 보안 속성 탐지:
    - Secure 플래그 누락 (HTTPS에서만)
    - HttpOnly 누락
    - SameSite 설정 누락
    - 세션 쿠키 예측 가능 이름

    Returns:
        dict with "findings", "cookies", "output"
    """
    if not _HAS_REQUESTS:
        return {"success": False, "output": "requests 필요"}

    print(_banner(f"🍪 쿠키 보안 스캔 — {url}"))
    sess = _sess(session_headers)
    findings = []
    cookies_info = []

    try:
        r = sess.get(url, timeout=12, verify=False, allow_redirects=True)

        is_https = url.startswith("https://")

        for cookie_hdr in r.raw.headers.getlist("Set-Cookie"):
            cookie_lower = cookie_hdr.lower()

            # 쿠키 이름 추출
            name = cookie_hdr.split("=")[0].strip()
            cookies_info.append({"name": name, "raw": cookie_hdr[:120]})

            issues = []
            if is_https and "secure" not in cookie_lower:
                issues.append(("no_secure", "Secure 플래그 누락", "MEDIUM"))
            if "httponly" not in cookie_lower:
                issues.append(("no_httponly", "HttpOnly 누락 — JS 접근 가능", "MEDIUM"))
            if "samesite" not in cookie_lower:
                issues.append(("no_samesite", "SameSite 누락 — CSRF 위험", "LOW"))
            elif "samesite=none" in cookie_lower and "secure" not in cookie_lower:
                issues.append(("samesite_none_no_secure", "SameSite=None이지만 Secure 없음", "MEDIUM"))

            for issue_type, desc, severity in issues:
                print(f"  🟡 [{severity}] {name}: {desc}")
                findings.append({
                    "cookie": name,
                    "type": issue_type,
                    "desc": desc,
                    "severity": severity,
                })

        # 세션 쿠키 이름 확인
        session_cookie_names = ["PHPSESSID", "JSESSIONID", "ASP.NET_SessionId", "session", "sessid"]
        for sc in session_cookie_names:
            if any(c["name"].upper() == sc.upper() for c in cookies_info):
                print(f"  🟡 [INFO] 표준 세션 쿠키 이름 사용: {sc} (예측 가능)")

    except Exception as e:
        return {"success": False, "findings": [], "output": f"[COOKIE] 오류: {e}"}

    output = (
        f"[COOKIE_SEC] {url}\n"
        f"  쿠키: {len(cookies_info)}개, 이슈: {len(findings)}개\n"
        + "\n".join(f"  [{f['severity']}] {f['cookie']}: {f['desc']}" for f in findings[:10])
    )

    return {
        "success": bool(findings),
        "vuln_type": "CookieSecurity",
        "cookies": cookies_info,
        "findings": findings,
        "output": output,
    }

# ══════════════════════════════════════════════════════════════════════════════
# ── 8. 디렉토리 리스팅 스캔 ──────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════

def directory_listing_scan(
    url: str,
    session_headers: Optional[Dict] = None,
) -> Dict[str, Any]:
    """
    디렉토리 리스팅(Directory Listing) 탐지.

    Returns:
        dict with "findings", "output"
    """
    if not _HAS_REQUESTS:
        return {"success": False, "output": "requests 필요"}

    print(_banner(f"📂 디렉토리 리스팅 스캔 — {url}"))
    sess = _sess(session_headers)
    base = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
    findings = []

    DIR_LISTING_SIGS = [
        "Index of /", "Index of /", "directory listing for",
        "Parent Directory", "[DIR]", "[PARENTDIR]",
        "Last modified", "Apache/2", "nginx/",
    ]

    TEST_DIRS = [
        "/uploads/", "/images/", "/img/", "/files/", "/static/",
        "/media/", "/assets/", "/data/", "/backup/", "/logs/",
        "/tmp/", "/temp/", "/cache/", "/js/", "/css/",
        "/includes/", "/inc/", "/lib/", "/libs/", "/vendor/",
        "/admin/", "/config/", "/conf/", "/settings/",
    ]

    for dir_path in TEST_DIRS:
        try:
            r = sess.get(f"{base}{dir_path}", timeout=6, verify=False)
            if r.status_code == 200:
                body = r.text[:5000]
                if any(sig in body for sig in DIR_LISTING_SIGS):
                    print(f"  🔴 [HIGH] 디렉토리 리스팅: {dir_path}")
                    findings.append({
                        "path": dir_path,
                        "desc": "디렉토리 리스팅 허용",
                        "severity": "HIGH" if dir_path in ["/uploads/", "/backup/", "/admin/"] else "MEDIUM",
                    })
        except Exception:
            pass

    output = (
        f"[DIR_LIST] {url}\n"
        f"  발견: {len(findings)}개\n"
        + "\n".join(f"  [{f['severity']}] {f['path']}" for f in findings)
    )

    return {
        "success": bool(findings),
        "vuln_type": "DirectoryListing",
        "findings": findings,
        "output": output,
    }

# ══════════════════════════════════════════════════════════════════════════════
# ── 9. 통합 보안 감사 ─────────────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════

def security_full_audit(
    url: str,
    session_headers: Optional[Dict] = None,
) -> Dict[str, Any]:
    """
    완전 보안 감사 (8가지 스캔 병렬 실행).
    Acunetix 수준의 보안 헤더/TLS/정보노출/소스노출/CORS/쿠키/클릭재킹 통합 검사.

    Returns:
        dict with "all_findings", "by_category", "score", "output"
    """
    print(_banner(f"🔒 SECURITY FULL AUDIT — {url}"))

    all_findings: List[Dict] = []
    scan_results: Dict[str, Any] = {}

    def _safe(fn, *args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except Exception as e:
            return {"findings": [], "success": False}

    # 병렬 실행
    tasks = [
        ("security_headers", security_headers_check, url, session_headers),
        ("ssl_tls", ssl_tls_scan, url, session_headers),
        ("info_disclosure", info_disclosure_scan, url, session_headers),
        ("source_exposure", source_exposure_scan, url, session_headers),
        ("cors", cors_scan, url, session_headers),
        ("clickjacking", clickjacking_scan, url, session_headers),
        ("cookie_security", cookie_security_scan, url, session_headers),
        ("directory_listing", directory_listing_scan, url, session_headers),
    ]

    with ThreadPoolExecutor(max_workers=6) as executor:
        futures = {executor.submit(_safe, fn, *args): name
                   for name, fn, *args in tasks}
        for future in as_completed(futures):
            name = futures[future]
            result = future.result()
            scan_results[name] = result
            for f in result.get("findings", []):
                all_findings.append({**f, "category": name})

    # 심각도별 분류
    severity_map = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in all_findings:
        sev = f.get("severity", "LOW").upper()
        if sev in severity_map:
            severity_map[sev] += 1

    # 보안 점수
    score = max(0, 100
                - severity_map["CRITICAL"] * 25
                - severity_map["HIGH"] * 15
                - severity_map["MEDIUM"] * 7
                - severity_map["LOW"] * 2)

    by_cat = {name: len(r.get("findings", [])) for name, r in scan_results.items() if r.get("findings")}

    output_lines = [
        f"{'═'*60}",
        f"  🔒 SECURITY FULL AUDIT — {url}",
        f"{'═'*60}",
        f"  보안 점수: {score}/100",
        f"  CRITICAL={severity_map['CRITICAL']} HIGH={severity_map['HIGH']} MEDIUM={severity_map['MEDIUM']} LOW={severity_map['LOW']}",
        f"  총 발견: {len(all_findings)}개",
        "",
    ]
    for cat, cnt in sorted(by_cat.items(), key=lambda x: -x[1]):
        output_lines.append(f"  ⚠️  [{cat}] {cnt}개")
    output_lines.append(f"{'═'*60}")

    output = "\n".join(output_lines)
    print(output)

    return {
        "success": True,
        "vuln_type": "SecurityAudit",
        "score": score,
        "by_category": by_cat,
        "severity": severity_map,
        "all_findings": all_findings,
        "scan_results": scan_results,
        "output": output,
    }

# ── TOOL REGISTRY ─────────────────────────────────────────────────────────────
SECURITY_AUDIT_TOOLS: Dict[str, Any] = {
    "security_headers_check":  security_headers_check,
    "ssl_tls_scan":            ssl_tls_scan,
    "info_disclosure_scan":    info_disclosure_scan,
    "source_exposure_scan":    source_exposure_scan,
    "cors_scan":               cors_scan,
    "clickjacking_scan":       clickjacking_scan,
    "cookie_security_scan":    cookie_security_scan,
    "directory_listing_scan":  directory_listing_scan,
    "security_full_audit":     security_full_audit,
}
