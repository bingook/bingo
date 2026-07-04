"""bingo/tools/findings_exporter.py — 실시간 취약점 발견 자동 저장 엔진

실제 침투 테스트 중 코드 실행 결과에서 유의미한 발견을 자동으로 감지하고
JSON 파일로 누적 저장. 세션 종료 후 바로 리포팅/후속 분석에 활용.

지원 패턴:
  - SQL 인젝션: DB명/테이블/컬럼/계정 추출 결과
  - XSS: payload 실행 확인 (alert, DOM mutation)
  - SSRF: 내부망 응답 / cloud metadata 획득
  - 파일 읽기 (LFI/RFI): /etc/passwd, config 등
  - 인증 우회: 관리자 패널 접근, 토큰 탈취
  - RCE: 명령 실행 결과
  - 자격 증명: 아이디/비밀번호 추출
"""
from __future__ import annotations

import json
import os
import re
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional


# ─── 발견 유형 ───────────────────────────────────────────────────────────────
FINDING_SQLI        = "sqli"
FINDING_XSS         = "xss"
FINDING_SSRF        = "ssrf"
FINDING_LFI         = "lfi"
FINDING_RCE         = "rce"
FINDING_AUTH_BYPASS = "auth_bypass"
FINDING_CREDENTIAL  = "credential"
FINDING_INFO_DISC   = "info_disclosure"

SEVERITY_CRITICAL = "CRITICAL"
SEVERITY_HIGH     = "HIGH"
SEVERITY_MEDIUM   = "MEDIUM"
SEVERITY_LOW      = "LOW"


@dataclass
class Finding:
    id: str
    vuln_type: str
    severity: str
    target: str
    payload: str
    evidence: str           # 실제 응답/결과 (잘린 최대 2000자)
    timestamp: float = field(default_factory=time.time)
    confirmed: bool = False  # Playwright 등으로 2차 검증 완료 여부
    screenshot_path: str = ""
    notes: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["timestamp_str"] = time.strftime(
            "%Y-%m-%d %H:%M:%S", time.localtime(self.timestamp)
        )
        return d


# ─── 패턴 탐지 규칙 ──────────────────────────────────────────────────────────

_SQLI_PATTERNS = [
    # DB명 / 테이블명 추출 결과
    re.compile(r'\b(master|tempdb|model|msdb|information_schema|mysql|postgres|public)\b', re.I),
    re.compile(r'\b(dbo|sysobjects|syscolumns|sys\.tables|sys\.columns)\b', re.I),
    # 자격 증명 추출
    re.compile(r'\b(admin|administrator|root|sa|dba|superuser)\b.*?(password|passwd|pwd|hash)', re.I),
    # 구체적 추출 패턴
    re.compile(r'(table_name|column_name|table_schema)\s*[=:]\s*[\'"]?\w', re.I),
    re.compile(r'extractvalue|updatexml|group_concat.*from', re.I),
]

_XSS_PATTERNS = [
    re.compile(r'<script[^>]*>.*?</script>', re.I | re.DOTALL),
    re.compile(r'alert\s*\(\s*["\']?[^)]{0,50}["\']?\s*\)', re.I),
    re.compile(r'onerror\s*=|onload\s*=|onfocus\s*=', re.I),
    re.compile(r'\bXSS\b.*?(confirmed|실행|성공|detected)', re.I),
    re.compile(r'window\.__BINGO_XSS__\s*=\s*1', re.I),
]

_XSS_URL_PATTERN = re.compile(
    r'https?://[^\s"\'<>]+(?:%3C|<)(?:script|img|svg|body)[^\s"\'<>]*',
    re.I
)

_SSRF_PATTERNS = [
    re.compile(r'169\.254\.169\.254'),                           # AWS metadata
    re.compile(r'metadata\.google\.internal', re.I),
    re.compile(r'169\.254\.170\.2'),                             # ECS metadata
    re.compile(r'fd00:ec2::254'),                                # IPv6 metadata
    re.compile(r'(internal|intranet|localhost|127\.0\.0\.).*?(200 OK|\bOK\b)', re.I),
]

_LFI_PATTERNS = [
    re.compile(r'root:[^:]+:[^:]+:[^:]+:[^:]+:/\w'),           # /etc/passwd
    re.compile(r'\[global\].*?\[database\]', re.I | re.DOTALL),
    re.compile(r'(DB_HOST|DB_PASSWORD|DB_USER|SECRET_KEY|APP_KEY)\s*=', re.I),
    re.compile(r'<?php\s', re.I),
    re.compile(r'(mysql|pdo|database).*?password', re.I),
]

_RCE_PATTERNS = [
    re.compile(r'\buid=\d+\([^)]+\)\s+gid=\d+', re.I),        # id 명령어
    re.compile(r'(Linux|Darwin|Windows)\s+\S+\s+\S+\s+\S+\s+(x86_64|arm)', re.I),  # uname
    re.compile(r'whoami.*:\s*\w+', re.I),
    re.compile(r'cat /etc/(passwd|shadow|hosts)', re.I),
    re.compile(r'web\.config|system\.ini|boot\.ini', re.I),
]

_CRED_PATTERNS = [
    re.compile(r'(?:password|passwd|pwd)\s*[=:]\s*[\'"]?([^\s\'"]{4,})', re.I),
    re.compile(r'(?:admin|root|sa)\s*[/|:]\s*([^\s]{4,})', re.I),
    re.compile(r'\$2[aby]\$\d+\$[./A-Za-z0-9]{53}'),          # bcrypt
    # v4.8.0: MD5/SHA 해시 — 독립적으로 등장한 경우만 매칭 (URL인코딩/SQL 인젝션 출력 오탐 방지)
    # 이전: r'[0-9a-f]{32,}' → URL 인코딩(%XX), SQL EXTRACTVALUE 출력에서 오탐 발생
    # 수정: 앞뒤에 non-hex 경계 요구 + 최소 32자 완전 hex 문자열만 허용
    re.compile(r'(?<![%a-zA-Z0-9/])[0-9a-f]{32,64}(?![0-9a-f])', re.I),  # MD5/SHA hash
]

# v4.8.0: SQLi 컨텍스트 키워드 — 코드에 이것이 있으면 credential보다 sqli 우선
_SQLI_CONTEXT_KEYWORDS = re.compile(
    r'extractvalue|updatexml|information_schema|group_concat|sleep\s*\('
    r'|waitfor\s+delay|union\s+select|blind\s+sqli|time.?based|boolean.?based'
    r'|time_based|sqli|sql.?inject',
    re.I
)

_AUTH_BYPASS_PATTERNS = [
    re.compile(r'(관리자|admin)\s*(패널|panel|dashboard|로그인|login)\s*(성공|접근|완료|OK)', re.I),
    re.compile(r'HTTP/\d.*?200.*?admin', re.I),
    re.compile(r'Set-Cookie:.*?(admin|session|auth|jwt)', re.I),
    re.compile(r'(welcome|dashboard|admin)\s*-\s*(admin|root|manager)', re.I),
]


def _detect_vuln_type(output: str, code_snippet: str = "") -> tuple[str, str] | None:
    """출력 텍스트에서 취약점 유형과 심각도 탐지. 없으면 None.
    우선순위: RCE > LFI > AUTH_BYPASS > CREDENTIAL > SSRF > XSS > SQLi

    v4.8.0 수정: SQLi 컨텍스트(code_snippet에 EXTRACTVALUE/SLEEP 등) 포함 시
    CREDENTIAL보다 SQLi를 우선 분류 — 오분류 방지.
    """
    # v4.8.0: SQLi 컨텍스트 사전 검사 — code_snippet 또는 output에 SQLi 키워드가 있으면
    # credential 검사를 SQLi 이후로 순서 변경하여 오분류 방지
    _sqli_context = (
        _SQLI_CONTEXT_KEYWORDS.search(code_snippet)
        or _SQLI_CONTEXT_KEYWORDS.search(output)
    )

    if _sqli_context:
        # SQLi 컨텍스트 확인됨 → SQLi 패턴 먼저, credential은 SQLi 없을 때만
        checks = [
            (FINDING_RCE,         SEVERITY_CRITICAL, _RCE_PATTERNS),
            (FINDING_LFI,         SEVERITY_CRITICAL, _LFI_PATTERNS),
            (FINDING_AUTH_BYPASS, SEVERITY_CRITICAL, _AUTH_BYPASS_PATTERNS),
            (FINDING_SQLI,        SEVERITY_HIGH,     _SQLI_PATTERNS),   # SQLi 우선
            (FINDING_CREDENTIAL,  SEVERITY_CRITICAL, _CRED_PATTERNS),   # credential 후순위
            (FINDING_SSRF,        SEVERITY_HIGH,     _SSRF_PATTERNS),
            (FINDING_XSS,         SEVERITY_HIGH,     _XSS_PATTERNS),
        ]
    else:
        checks = [
            (FINDING_RCE,         SEVERITY_CRITICAL, _RCE_PATTERNS),
            (FINDING_LFI,         SEVERITY_CRITICAL, _LFI_PATTERNS),
            (FINDING_AUTH_BYPASS, SEVERITY_CRITICAL, _AUTH_BYPASS_PATTERNS),
            (FINDING_CREDENTIAL,  SEVERITY_CRITICAL, _CRED_PATTERNS),
            (FINDING_SSRF,        SEVERITY_HIGH,     _SSRF_PATTERNS),
            (FINDING_XSS,         SEVERITY_HIGH,     _XSS_PATTERNS),
            (FINDING_SQLI,        SEVERITY_HIGH,     _SQLI_PATTERNS),
        ]

    for vtype, sev, patterns in checks:
        for pat in patterns:
            if pat.search(output):
                return (vtype, sev)
    return None


def _extract_payload(output: str) -> str:
    """출력에서 페이로드/쿼리 라인 추출 (최대 300자)"""
    # payload = 또는 query = 또는 url = 로 시작하는 라인 우선
    for line in output.splitlines():
        stripped = line.strip()
        if re.match(r'^(payload|query|url|request|inject)\s*[=:]', stripped, re.I):
            return stripped[:300]
    # 없으면 URL 패턴에서
    m = re.search(r'https?://\S+', output)
    if m:
        return m.group(0)[:300]
    return output[:300].strip()


# ─── FindingsExporter ──────────────────────────────────────────────────────────

class FindingsExporter:
    """실시간 발견 누적 저장기.

    사용법:
        exporter = FindingsExporter(target="http://target.com")
        exporter.process(code_output_str)   # 매 코드 실행 후 호출
        exporter.save()                     # 세션 종료 시 저장
    """

    def __init__(self, target: str = "", output_dir: str | None = None) -> None:
        self.target = target
        self._findings: list[Finding] = []
        self._finding_hashes: set[str] = set()   # 중복 방지

        if output_dir:
            self._dir = Path(output_dir)
        else:
            # Desktop/dump/<target> 에 저장
            import platform
            safe = (target or "unknown").replace("https://", "").replace("http://", "").replace("/", "_")[:40]
            if platform.system() == "Darwin":
                base = Path.home() / "Desktop" / "dump" / safe
            elif platform.system() == "Windows":
                try:
                    import winreg
                    k = winreg.OpenKey(
                        winreg.HKEY_CURRENT_USER,
                        r"Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
                    )
                    base = Path(winreg.QueryValueEx(k, "Desktop")[0]) / "dump" / safe
                except Exception:
                    base = Path.home() / "Desktop" / "dump" / safe
            else:
                base = Path(os.environ.get("XDG_DESKTOP_DIR", str(Path.home() / "Desktop"))) / "dump" / safe

            _env_dir = os.environ.get("BINGO_REPORTS_DIR", "").strip()
            self._dir = Path(_env_dir) / safe if _env_dir else base

        try:
            self._dir.mkdir(parents=True, exist_ok=True)
        except Exception:
            self._dir = Path.cwd()

    # ── 공개 API ──────────────────────────────────────────────────────────────

    def process(
        self,
        output: str,
        code_snippet: str = "",
        extra_notes: str = "",
    ) -> Optional[Finding]:
        """코드 실행 출력에서 발견 탐지 후 내부 저장. 발견 시 Finding 반환."""
        if not output or len(output.strip()) < 10:
            return None

        # v4.8.0: code_snippet 전달 — SQLi 컨텍스트 기반 우선순위 조정
        detected = _detect_vuln_type(output, code_snippet=code_snippet)
        if not detected:
            return None

        vtype, severity = detected
        payload = code_snippet or _extract_payload(output)
        evidence = output[:2000]

        # 중복 제거: evidence 앞 200자 해시
        import hashlib
        _hash = hashlib.md5(
            (vtype + evidence[:200]).encode("utf-8", errors="ignore")
        ).hexdigest()[:12]
        if _hash in self._finding_hashes:
            return None
        self._finding_hashes.add(_hash)

        finding = Finding(
            id=f"BINGO-{len(self._findings)+1:04d}",
            vuln_type=vtype,
            severity=severity,
            target=self.target,
            payload=payload[:500],
            evidence=evidence,
            notes=extra_notes,
        )
        self._findings.append(finding)
        return finding

    def mark_confirmed(self, finding: Finding, screenshot_path: str = "") -> None:
        """Playwright 등 2차 검증 후 confirmed 플래그 세팅."""
        finding.confirmed = True
        if screenshot_path:
            finding.screenshot_path = screenshot_path

    def save(self) -> Path | None:
        """JSON 파일로 저장 후 경로 반환. 발견이 없으면 None."""
        if not self._findings:
            return None
        ts = time.strftime("%Y%m%d_%H%M%S")
        safe = (self.target or "unknown").replace("https://", "").replace("http://", "").replace("/", "_")[:30]
        path = self._dir / f"findings_{safe}_{ts}.json"
        data = {
            "bingo_version": _get_version(),
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "target": self.target,
            "total": len(self._findings),
            "critical": sum(1 for f in self._findings if f.severity == SEVERITY_CRITICAL),
            "high": sum(1 for f in self._findings if f.severity == SEVERITY_HIGH),
            "confirmed": sum(1 for f in self._findings if f.confirmed),
            "findings": [f.to_dict() for f in self._findings],
        }
        try:
            path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        except Exception as e:
            # fallback to cwd
            path = Path.cwd() / f"findings_{safe}_{ts}.json"
            try:
                path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
            except Exception:
                return None
        return path

    def summary(self) -> str:
        """발견 요약 1줄"""
        total = len(self._findings)
        if not total:
            return ""
        crit = sum(1 for f in self._findings if f.severity == SEVERITY_CRITICAL)
        high = sum(1 for f in self._findings if f.severity == SEVERITY_HIGH)
        conf = sum(1 for f in self._findings if f.confirmed)
        parts = []
        if crit:
            parts.append(f"CRITICAL:{crit}")
        if high:
            parts.append(f"HIGH:{high}")
        if conf:
            parts.append(f"confirmed:{conf}")
        return f"[FINDINGS] total={total} " + " ".join(parts)

    @property
    def findings(self) -> list[Finding]:
        return list(self._findings)

    def extract_xss_urls(self, output: str) -> list[str]:
        """출력에서 XSS payload가 포함된 URL 추출 (Playwright 검증용)"""
        urls = []
        # <script>, %3Cscript, onerror= 등이 포함된 URL
        for m in _XSS_URL_PATTERN.finditer(output):
            urls.append(m.group(0))
        # 일반 URL + XSS 패턴
        for line in output.splitlines():
            stripped = line.strip()
            if re.search(r'https?://', stripped) and re.search(
                r'(<|%3C|%22|javascript:|onerror=|onload=)', stripped, re.I
            ):
                m_url = re.search(r'https?://\S+', stripped)
                if m_url and m_url.group(0) not in urls:
                    urls.append(m_url.group(0))
        return urls[:5]  # 최대 5개


def _get_version() -> str:
    try:
        from .. import __version__
        return __version__
    except Exception:
        return "unknown"
