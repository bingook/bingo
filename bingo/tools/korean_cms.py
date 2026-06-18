"""
Korean CMS Vulnerability Engine — 한국 특화 CMS 취약점 자동화
=============================================================
지원 CMS:
  1. GnuBoard5 / XpressEngine (XE) / Rhymix
  2. Cafe24 쇼핑몰
  3. 영카트5 (Young Cart)
  4. 그누보드5 파생 (최신버전 포함)
  5. Wordpress (한국 플러그인 특화)

취약점 유형:
  - 관리자 페이지 경로 노출
  - 파일 업로드 우회
  - SQL 인젝션 포인트
  - 세션 고정 / 인증 우회
  - 숨겨진 API 엔드포인트
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable


# ══════════════════════════════════════════════════════════════
# CMS 지문 탐지
# ══════════════════════════════════════════════════════════════

CMS_FINGERPRINTS = {
    "gnuboard5": [
        "gnuboard5", "그누보드", "/bbs/board.php", "g5_",
        "/theme/", "skin/board/", "/adm/",
    ],
    "xe": [
        "XpressEngine", "XE", "xe_", "/index.php?mid=",
        "xe/index.php", "/files/attach/", "xe_session",
    ],
    "rhymix": [
        "Rhymix", "rhymix", "rx_", "/common/js/rhymix",
    ],
    "cafe24": [
        "cafe24", "Cafe24", "ECSHOP", "ec-", "/shop/",
        "order_id", "member_id", "cafe24.com",
    ],
    "youngcart": [
        "영카트", "youngcart", "ycart", "yc_",
        "/shop/item.php", "/shop/cart.php",
    ],
    "wordpress": [
        "WordPress", "wp-content", "wp-login.php",
        "wp-admin", "wp-includes",
    ],
}


@dataclass
class CmsInfo:
    cms_type: str
    version: str = ""
    confidence: float = 0.0
    fingerprints_matched: list[str] = field(default_factory=list)


def detect_cms(html: str, headers: dict, url: str) -> CmsInfo:
    """CMS 자동 탐지"""
    best: CmsInfo | None = None
    best_score = 0

    for cms, fps in CMS_FINGERPRINTS.items():
        score = 0
        matched: list[str] = []
        for fp in fps:
            if fp.lower() in html.lower() or fp.lower() in str(headers).lower():
                score += 1
                matched.append(fp)
        if score > best_score:
            best_score = score
            best = CmsInfo(cms_type=cms, confidence=score / len(fps), fingerprints_matched=matched)

    return best or CmsInfo(cms_type="unknown")


# ══════════════════════════════════════════════════════════════
# GnuBoard5 / XE / Rhymix 취약점
# ══════════════════════════════════════════════════════════════

GNUBOARD_VULNS = {
    "admin_paths": [
        "/adm/",
        "/adm/index.php",
        "/adm/board_list.php",
        "/adm/member_list.php",
        "/bbs/adm/",
        "/admin/",
        "/admin/index.php",
    ],
    "sqli_points": [
        ("/bbs/board.php", "GET", "bo_table", "free"),
        ("/bbs/view.php", "GET", "bo_table", "free"),
        ("/bbs/view.php", "GET", "wr_id", "1"),
        ("/bbs/member_confirm.php", "POST", "mb_id", "admin"),
        ("/bbs/login_check.php", "POST", "mb_id", "admin"),
        ("/bbs/write.php", "GET", "bo_table", "free"),
    ],
    "lfi_points": [
        ("/bbs/board.php", "GET", "skin", "../../etc/passwd"),
        ("/bbs/board.php", "GET", "bo_skin_path", "../../etc/passwd"),
    ],
    "file_upload": [
        ("/bbs/write_update.php", "POST", "bf_file_1"),
        ("/adm/board_list_update.php", "POST", "thumbnail"),
    ],
    "info_exposure": [
        "/config.php",
        "/common/config.php",
        "/gnu/config.php",
        "/.env",
        "/phpinfo.php",
        "/info.php",
        "/bbs/setup.php",
    ],
}

XE_VULNS = {
    "admin_paths": [
        "/index.php?module=admin",
        "/index.php?act=dispAdminIndex",
        "/xe/index.php?module=admin",
        "/admin/",
        "/files/config/",
    ],
    "sqli_points": [
        ("/index.php?mid=board&document_srl=", "GET", "document_srl", "1"),
        ("/index.php?act=dispBoardContent&document_srl=", "GET", "document_srl", "1"),
    ],
    "file_upload": [
        ("/index.php?act=procFileUpload", "POST", "user_file"),
        ("/index.php?act=procEditorUpload", "POST", "editor_file"),
    ],
    "rce_candidates": [
        # 설치 파일 남겨둔 경우
        ("/install/",),
        ("/xe/install/",),
        ("/update/",),
    ],
}


# ══════════════════════════════════════════════════════════════
# Cafe24 취약점
# ══════════════════════════════════════════════════════════════

CAFE24_VULNS = {
    "idor_points": [
        ("/shop/mypage.php", "GET", "order_id"),
        ("/shop/mypage/order_detail.php", "GET", "order_id"),
        ("/member/memberinfo.php", "GET", "member_id"),
        ("/myshop/order_list.php", "GET", "order_id"),
    ],
    "admin_paths": [
        "/admin/shop1/",
        "/admin/shop1/index.php",
        "/dipadmin/",
        "/manager/",
    ],
    "api_endpoints": [
        "/api/v2/products",
        "/api/v2/orders",
        "/api/v2/customers",
        "/api/orders",
        "/api/members",
    ],
}

# ══════════════════════════════════════════════════════════════
# 영카트5 취약점
# ══════════════════════════════════════════════════════════════

YOUNGCART_VULNS = {
    "sqli_points": [
        ("/shop/item.php", "GET", "it_id"),
        ("/shop/list.php", "GET", "ca_id"),
        ("/shop/cart.php", "POST", "it_id"),
        ("/order/order_form.php", "POST", "it_id"),
    ],
    "admin_paths": [
        "/adm/",
        "/adm/index.php",
        "/adm/shop_list.php",
        "/adm/member_list.php",
    ],
    "idor_points": [
        ("/mypage/order_view.php", "GET", "od_id"),
        ("/mypage/member_info.php", "GET", "mb_id"),
    ],
}


# ══════════════════════════════════════════════════════════════
# CMS 자동 스캐너
# ══════════════════════════════════════════════════════════════

@dataclass
class CmsFinding:
    cms_type: str
    vuln_category: str
    endpoint: str
    method: str = "GET"
    param: str = ""
    payload: str = ""
    status: int = 0
    evidence: str = ""
    severity: str = "HIGH"


class KoreanCmsScanner:
    """한국 특화 CMS 취약점 자동 스캐너"""

    def __init__(
        self,
        request_fn: Callable[[str, str, dict, dict | None], tuple[int, str]],
        base_url: str,
        log_fn: Callable[[str], None] | None = None,
    ):
        self._req = request_fn
        self.base = base_url.rstrip("/")
        self.log = log_fn or (lambda s: None)

    def scan(self, cms_type: str = "auto", html: str = "") -> list[CmsFinding]:
        """CMS 취약점 자동 스캔"""
        if cms_type == "auto":
            _, html_body = self._req(self.base, "GET", {}, None)
            info = detect_cms(html_body or html, {}, self.base)
            cms_type = info.cms_type
            self.log(f"[CMS] 탐지: {cms_type} (신뢰도: {info.confidence:.0%})")

        findings: list[CmsFinding] = []

        if cms_type in ("gnuboard5",):
            findings.extend(self._scan_gnuboard())
        elif cms_type in ("xe", "rhymix"):
            findings.extend(self._scan_xe())
        elif cms_type == "cafe24":
            findings.extend(self._scan_cafe24())
        elif cms_type == "youngcart":
            findings.extend(self._scan_youngcart())
        elif cms_type == "wordpress":
            findings.extend(self._scan_wordpress())

        # 공통: 정보 노출 파일 체크
        findings.extend(self._check_info_exposure())

        self.log(f"[CMS✓] {cms_type} 취약점: {len(findings)}건")
        return findings

    def _scan_gnuboard(self) -> list[CmsFinding]:
        findings: list[CmsFinding] = []

        # 관리자 경로 체크
        for path in GNUBOARD_VULNS["admin_paths"]:
            url = self.base + path
            status, body = self._req(url, "GET", {}, None)
            if status == 200 and ("로그인" in body or "관리자" in body or "admin" in body.lower()):
                findings.append(CmsFinding(
                    cms_type="gnuboard5",
                    vuln_category="admin_path_exposed",
                    endpoint=url,
                    status=status,
                    evidence=body[:200],
                    severity="HIGH",
                ))
                self.log(f"[CMS] 관리자 경로 노출: {url}")

        # SQL 인젝션 포인트 기초 체크
        for path, method, param, default_val in GNUBOARD_VULNS["sqli_points"]:
            test_val = default_val + "'"
            url = self.base + path
            if method == "GET":
                test_url = f"{url}?{param}={test_val}"
                status, body = self._req(test_url, "GET", {}, None)
            else:
                test_url = url
                status, body = self._req(url, "POST", {}, {param: test_val})

            if status in (500, 200) and re.search(
                r"SQL syntax|mysql_fetch|ORA-\d+|syntax error|Warning.*mysql_",
                body, re.I
            ):
                findings.append(CmsFinding(
                    cms_type="gnuboard5",
                    vuln_category="sqli",
                    endpoint=test_url,
                    method=method,
                    param=param,
                    payload=test_val,
                    status=status,
                    evidence=re.findall(r"(?:SQL|mysql|error)[^\n]{0,100}", body, re.I)[0][:200],
                    severity="CRITICAL",
                ))

        return findings

    def _scan_xe(self) -> list[CmsFinding]:
        findings: list[CmsFinding] = []
        for path in XE_VULNS["admin_paths"]:
            url = self.base + path
            status, body = self._req(url, "GET", {}, None)
            if status == 200 and len(body) > 100:
                findings.append(CmsFinding(
                    cms_type="xe",
                    vuln_category="admin_path_exposed",
                    endpoint=url,
                    status=status,
                    evidence=body[:100],
                ))
        return findings

    def _scan_cafe24(self) -> list[CmsFinding]:
        findings: list[CmsFinding] = []
        for path, method, param in CAFE24_VULNS["idor_points"]:
            for test_id in ["1", "2", "100", "9999"]:
                url = f"{self.base}{path}?{param}={test_id}"
                status, body = self._req(url, "GET", {}, None)
                if status == 200 and len(body) > 200:
                    if re.search(r"(?:이름|name|email|주소|address|결제)", body):
                        findings.append(CmsFinding(
                            cms_type="cafe24",
                            vuln_category="idor",
                            endpoint=url,
                            method=method,
                            param=param,
                            payload=test_id,
                            status=status,
                            evidence="개인정보 포함 응답",
                            severity="HIGH",
                        ))
        return findings

    def _scan_youngcart(self) -> list[CmsFinding]:
        findings: list[CmsFinding] = []
        for path, method, param in YOUNGCART_VULNS["sqli_points"]:
            test_url = f"{self.base}{path}?{param}=1'"
            status, body = self._req(test_url, "GET", {}, None)
            if status in (200, 500) and re.search(r"SQL|mysql|syntax", body, re.I):
                findings.append(CmsFinding(
                    cms_type="youngcart",
                    vuln_category="sqli",
                    endpoint=test_url,
                    param=param,
                    status=status,
                    evidence="SQL 오류 탐지",
                    severity="CRITICAL",
                ))
        return findings

    def _scan_wordpress(self) -> list[CmsFinding]:
        findings: list[CmsFinding] = []
        wp_paths = [
            "/wp-login.php",
            "/wp-admin/",
            "/wp-json/wp/v2/users",
            "/xmlrpc.php",
            "/wp-config.php.bak",
            "/.env",
        ]
        for path in wp_paths:
            url = self.base + path
            status, body = self._req(url, "GET", {}, None)
            if status in (200, 301, 302):
                if "wp-login" in path or "wp-admin" in path:
                    sev = "MEDIUM"
                elif "users" in path and status == 200:
                    sev = "HIGH"
                    self.log(f"[CMS] WordPress 사용자 열거 API 노출: {url}")
                else:
                    sev = "MEDIUM"
                findings.append(CmsFinding(
                    cms_type="wordpress",
                    vuln_category="admin_or_api",
                    endpoint=url,
                    status=status,
                    evidence=body[:100],
                    severity=sev,
                ))
        return findings

    def _check_info_exposure(self) -> list[CmsFinding]:
        """공통 정보 노출 파일 체크"""
        findings: list[CmsFinding] = []
        paths = [
            "/.env", "/config.php", "/database.php", "/.git/config",
            "/phpinfo.php", "/info.php", "/.htaccess", "/robots.txt",
            "/backup.sql", "/backup.zip", "/db.sql",
        ]
        for path in paths:
            url = self.base + path
            status, body = self._req(url, "GET", {}, None)
            if status == 200 and len(body) > 20:
                if re.search(
                    r"(?:DB_PASS|DB_PASSWORD|password|secret|key|mysql|root:x)",
                    body, re.I
                ):
                    findings.append(CmsFinding(
                        cms_type="common",
                        vuln_category="info_exposure",
                        endpoint=url,
                        status=status,
                        evidence=body[:200],
                        severity="CRITICAL",
                    ))
                    self.log(f"[CMS!] 민감 파일 노출: {url}")
        return findings


KOREAN_CMS_SUMMARY = """
=== KOREAN CMS SCANNER (AI AUTO-SELECT) ===

Trigger: Korean site detected OR gnuboard/XE/cafe24/youngcart keywords in HTML

from bingo.tools.korean_cms import KoreanCmsScanner
scanner = KoreanCmsScanner(request_fn, base_url=TARGET)
findings = scanner.scan(cms_type="auto")  # auto-detect CMS type

Supported: gnuboard5, xe/rhymix, cafe24, youngcart, wordpress
"""
