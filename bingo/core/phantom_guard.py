"""
PhantomGuard — 팬텀 모드 탐지 및 강제 재활성화 v2.0.0
=========================================================
문제: agent의 bash/write 도구가 비활성화/일시정지될 때 발생하는
     "Phantom mode → simulated exit" 루프.
     실제 HTTP 요청 0건인 채 분석 결과를 출력하고 자기수정 무한반복.

탐지 8종:
  1. PhantomModeDetector  — 응답에서 "phantom/도구 비활성화/simulated exit" 패턴
  2. StaleCacheGuard      — ScanResult-*.json / case_state.json 반복 읽기 탐지
  3. TargetMismatchGuard  — 현재 세션 타겟과 다른 도메인이 응답에 등장
  4. SelfCorrectionLoop   — "타겟 오인 → 수정 → 재오인" 무한반복 감지
  5. ToolLivenessProbe    — 세션 시작 시 실제 HTTP 가능 여부 사전 확인  [NEW]
  6. ZeroHttpClaimGuard   — HTTP 0건인 채 취약점 주장 시 즉시 차단       [NEW]
  7. HardSessionRestarter — 팬텀 N회 지속 시 세션 히스토리 강제 초기화   [NEW]
  8. /reset-phantom       — 수동 카운터 초기화 슬래시 커맨드              [NEW]

대응:
  A. 팬텀 모드 → 도구 재활성화 강제 프롬프트 주입
  B. 구캐시    → 해당 파일 읽기 차단 + 신선 스캔 강제
  C. 타겟 오인 → 세션 타겟 재주입
  D. 루프      → 카운터 초기화 + 직접 HTTP 요청 강제
  E. 도구 불능 → Liveness probe 실패 시 즉시 경고 + 대체 방법 제시
  F. 0-HTTP   → 주장 자체를 블로킹 + 실 HTTP 강제
  G. 3회 지속 → 세션 히스토리 초기화 (하드 재시작)
"""
from __future__ import annotations

import re
import time
import fnmatch
from dataclasses import dataclass, field
from typing import Optional


# ══════════════════════════════════════════════════════════════════
# 1. PhantomModeDetector
# ══════════════════════════════════════════════════════════════════

_PHANTOM_PATTERNS: list[str] = [
    # 영문
    r"phantom\s*mode",
    r"simulated\s*exit",
    r"tool[s]?\s+(?:are\s+)?(?:disabled|paused|unavailable|not\s+available)",
    r"bash\s+(?:tool\s+)?(?:is\s+)?(?:paused|disabled|unavailable)",
    r"write\s+(?:tool\s+)?(?:is\s+)?(?:paused|disabled|unavailable)",
    r"no\s+(?:tool[s]?\s+)?(?:execution|access)\s+available",
    r"running\s+in\s+(?:phantom|simulated|dry.?run)\s+mode",
    r"without\s+(?:actual|real)\s+(?:tool|execution|network)\s+(?:access|capability)",
    r"cannot\s+(?:execute|run|access)\s+(?:actual|real)\s+(?:tools?|bash|code)",
    r"tool\s+execution\s+(?:is\s+)?(?:blocked|disabled|not\s+enabled)",
    # 한국어
    r"팬텀\s*모드",
    r"도구(?:가|는|이)?\s*(?:비활성화|일시정지|사용\s*불가|정지)",
    r"bash\s*(?:도구|툴)?\s*(?:비활성화|일시정지|사용\s*불가)",
    r"write\s*(?:도구|툴)?\s*(?:비활성화|일시정지|사용\s*불가)",
    r"가상\s*실행\s*종료",
    r"모의\s*(?:실행\s*)?종료",
    r"실제\s*(?:HTTP\s*)?요청\s*(?:없이|불가|미발송)",
    r"도구\s*(?:실행이|접근이)?\s*(?:차단|비활성)",
    # 중국어
    r"幻影\s*模式",
    r"工具\s*(?:已)?\s*(?:暂停|禁用|不可用|被禁)",
    r"bash\s*(?:工具)?\s*(?:暂停|禁用|不可用)",
    r"模拟\s*退出",
    r"无法\s*(?:执行|访问|使用)\s*(?:工具|bash|真实)",
    r"工具\s*执行\s*(?:已)?\s*(?:被禁|禁用|停用)",
]

_COMPILED_PHANTOM = [re.compile(p, re.IGNORECASE) for p in _PHANTOM_PATTERNS]


# ══════════════════════════════════════════════════════════════════
# 실제 HTTP 증거 탐지 헬퍼  [NEW v3.5.8]
# ══════════════════════════════════════════════════════════════════

def _has_real_http_evidence(exec_output: str) -> bool:
    """
    exec_output에 실제 HTTP 요청 증거가 있으면 True.

    사용 목적: 직전 실행에서 실제 HTTP 요청이 성공했을 때
    AI의 설명/계획 텍스트에서 phantom 패턴이 우연히 매칭되는 오탐을 억제.

    패턴:
      [200/34610B]   — Bingo code executor 출력 형식
      STATUS: 200    — requests 출력
      大小: 123B      — 크기 출력 (Chinese)
      HTTP/1.1 200   — raw HTTP 헤더
      발견 68개       — 발견 항목 수 (Korean)
      发现 68 个      — 발견 항목 수 (Chinese)
      → <!DOCTYPE    — SPA HTML 반환 포함 (실제 요청 증거)
    """
    _REAL_HTTP_PATS = [
        r'\[\d{3}/\d+B\]',             # [200/34610B]
        r'\bSTATUS[:：]\s*\d{3}\b',     # STATUS: 200
        r'大小[:：]\s*\d+\s*B',          # 大小: 123B
        r'크기[:：]\s*\d+\s*[KMG]?B',   # 크기: 123B
        r'HTTP/[12](?:\.\d)?\s+\d{3}', # HTTP/1.1 200
        r'response_code\s*[=:]\s*\d{3}',
        r'→\s+<!DOCTYPE\s+html',       # → <!DOCTYPE html
        r'发现\s+\d+\s+个',              # 发现 68 个
        r'발견\s+\d+\s*개',              # 발견 68개
        r'\[\d+\]\s+(?:获取|检测|发现)',  # [1] 获取...
        r'\[\d+/\d+\]\s+\[',           # [001/63] [200/...]
    ]
    for pat in _REAL_HTTP_PATS:
        if re.search(pat, exec_output, re.IGNORECASE):
            return True
    return False


# ══════════════════════════════════════════════════════════════════
# SPA Response Detector — Next.js/React 전체 HTML 반환 탐지  [NEW v3.5.8]
# ══════════════════════════════════════════════════════════════════

_SPA_MIN_RESPONSES = 5  # 최소 발동 조건: HTML 응답 이 수 이상


def _detect_spa_responses(exec_output: str) -> "tuple[int, int] | None":
    """
    exec_output에서 Next.js/SPA 패턴 감지.

    패턴:
      [200/34610B] /api/v1/markets → <!DOCTYPE html>...
      [200/34610B] /api/v1/ticker → <!DOCTYPE html>...
      ... (모두 동일 크기, HTML 반환)

    동일 크기 HTML 응답 5개 이상 발견 시 (count, avg_size) 반환.
    """
    # [상태코드/크기B] ... → (또는 공백) + <!DOCTYPE html 패턴
    matches = re.findall(
        r'\[(?:200|301|302)/(\d+)B\][^\n]{0,120}?<!DOCTYPE\s+html',
        exec_output,
        re.IGNORECASE | re.DOTALL,
    )
    if len(matches) < _SPA_MIN_RESPONSES:
        return None
    sizes = [int(s) for s in matches]
    avg = sum(sizes) / len(sizes)
    # 15% 이내 변동 → SPA 확정 (CDN 압축 등 소폭 차이 허용)
    if avg > 0 and all(abs(s - avg) / avg < 0.15 for s in sizes):
        return len(matches), int(avg)
    return None


def _spa_block_msg(count: int, size: int, target: str, lang: str = "ko") -> str:
    """SPA 오탐 차단 메시지 (3개국어)."""
    try:
        from urllib.parse import urlparse as _up
        _domain = _up(target).netloc or target
    except Exception:
        _domain = target

    msgs: dict[str, str] = {
        "ko": (
            f"⚠️ [SPA_DETECTED — Next.js/React SPA 오탐 차단]\n\n"
            f"{count}개 API 경로 모두 동일 크기({size}B) HTML 응답 → 실제 API 아님!\n\n"
            f"■ 원인: Next.js SPA의 catch-all 라우터가\n"
            f"  존재하지 않는 경로를 index.html로 반환\n"
            f"■ 증거: [200/{size}B] /api/v1/xxx → <!DOCTYPE html> (전부 동일)\n\n"
            f"■ 올바른 접근:\n"
            f"  1. JS 분석에서 발견한 실제 API 서버 확인\n"
            f"     (JS에서 발견된 `apis.{_domain}` 등 별도 호스트)\n"
            f"  2. Content-Type 먼저 확인:\n"
            f"     curl -s -I {target}/api/account/info | grep -i content-type\n"
            f"  3. HTML 반환 = 엔드포인트 없음. JSON 반환 = 실제 API\n"
            f"  4. /api/account/balance 등 JS에서 추출된 경로는\n"
            f"     {target} 가 아닌 실제 API 서버에서 테스트할 것\n\n"
            f"■ 위 200/OK 결과는 전부 HTML 오탐입니다. 취약점 클레임 금지."
        ),
        "zh": (
            f"⚠️ [SPA_DETECTED — Next.js/React SPA误报拦截]\n\n"
            f"{count}个API路径全部返回相同大小({size}B) HTML → 非真实API！\n\n"
            f"■ 原因: Next.js SPA的catch-all路由\n"
            f"  将不存在的路径全部返回index.html\n"
            f"■ 证据: [200/{size}B] /api/v1/xxx → <!DOCTYPE html> (完全相同)\n\n"
            f"■ 正确方法:\n"
            f"  1. 从JS分析中找到真实API服务器\n"
            f"     (JS中发现的 apis.{_domain} 等独立主机)\n"
            f"  2. 先确认Content-Type:\n"
            f"     curl -s -I {target}/api/account/info | grep -i content-type\n"
            f"  3. HTML返回=端点不存在; JSON返回=真实API\n"
            f"  4. 从JS提取的路径请在真实API服务器上测试，\n"
            f"     而非在 {target} 上\n\n"
            f"■ 当前所有200/OK结果均为HTML误报，禁止声明漏洞。"
        ),
        "en": (
            f"⚠️ [SPA_DETECTED — Next.js/React SPA False Positive Blocked]\n\n"
            f"{count} API paths all return identical HTML ({size}B) → NOT real API responses!\n\n"
            f"■ Cause: Next.js SPA catch-all router returns index.html\n"
            f"  for all non-existent paths\n"
            f"■ Evidence: [200/{size}B] /api/v1/xxx → <!DOCTYPE html> (all identical)\n\n"
            f"■ Correct approach:\n"
            f"  1. Identify real API server from JS analysis\n"
            f"     (separate host like apis.{_domain} found in JS)\n"
            f"  2. Check Content-Type first:\n"
            f"     curl -s -I {target}/api/account/info | grep -i content-type\n"
            f"  3. HTML response = endpoint not found; JSON = real API\n"
            f"  4. Test JS-extracted paths against the real API server,\n"
            f"     not against {target}\n\n"
            f"■ ALL current 200/OK results are HTML false positives. NO vulnerability claims."
        ),
    }
    return msgs.get(lang, msgs["en"])


@dataclass
class PhantomModeDetector:
    """
    AI 응답 텍스트에서 'Phantom mode / 도구 비활성화 / simulated exit' 패턴 감지.

    consecutive_limit 초과 시 force_recovery_msg() 를 주입해 루프를 탈출.
    """
    consecutive_limit: int = 2      # 이 횟수 연속 감지 시 강제 복구 발동
    _consecutive: int = field(default=0, init=False, repr=False)
    _total: int = field(default=0, init=False, repr=False)

    def check(self, text: str) -> bool:
        """True = 팬텀 모드 감지됨."""
        for pat in _COMPILED_PHANTOM:
            if pat.search(text):
                self._consecutive += 1
                self._total += 1
                return True
        self._consecutive = 0
        return False

    @property
    def is_critical(self) -> bool:
        """consecutive_limit 이상 연속 감지 → 강제 복구 필요."""
        return self._consecutive >= self.consecutive_limit

    def reset(self) -> None:
        self._consecutive = 0

    def force_recovery_msg(self, target: str, lang: str = "ko") -> str:
        msgs = {
            "ko": (
                "[⛔ 팬텀 모드 차단 — BINGO 런타임 강제 복구]\n\n"
                f"도구(bash/write)가 비활성화된 상태에서 {self._consecutive}회 연속 가상 실행이 감지되었습니다.\n"
                "실제 HTTP 요청 없이 분석 결과를 출력하는 것은 환각입니다.\n\n"
                "■ 즉시 수행 (bash+curl 블록):\n"
                f"  curl -sk -m 10 '{target}' | python3 -c \"import sys; r=sys.stdin.read(); print(r[:300])\"\n\n"
                "■ 금지 (Phantom Mode 유발 행위):\n"
                "  - 도구가 비활성화되어 있다고 가정하고 가상 결과 출력\n"
                "  - ScanResult-*.json / case_state.json 캐시 재사용\n"
                "  - Python requests 라이브러리 사용 (bash+curl 전용)\n\n"
                "bingo는 완전한 인터넷 환경에서 실행됩니다. bash+curl은 실제로 작동합니다."
            ),
            "zh": (
                "[⛔ 幻影模式拦截 — BINGO强制恢复]\n\n"
                f"工具(bash/write)在禁用状态下连续{self._consecutive}次检测到虚假执行。\n"
                "在没有真实HTTP请求的情况下输出分析结果属于幻觉。\n\n"
                "■ 立即执行(bash+curl块):\n"
                f"  curl -sk -m 10 '{target}' | python3 -c \"import sys; r=sys.stdin.read(); print(r[:300])\"\n\n"
                "■ 禁止行为:\n"
                "  - 假设工具被禁用并输出虚假结果\n"
                "  - 重复使用ScanResult-*.json/case_state.json缓存\n"
                "  - 使用Python requests库(仅允许bash+curl)\n\n"
                "bingo在真实网络环境运行，bash+curl是真实的，不是模拟的!"
            ),
            "en": (
                "[⛔ PHANTOM MODE BLOCKED — BINGO FORCING RECOVERY]\n\n"
                f"Tools (bash/write) detected as disabled for {self._consecutive} consecutive iterations.\n"
                "Outputting analysis results without real HTTP requests is hallucination.\n\n"
                "■ DO THIS NOW (bash+curl block):\n"
                f"  curl -sk -m 10 '{target}' | python3 -c \"import sys; r=sys.stdin.read(); print(r[:300])\"\n\n"
                "■ FORBIDDEN:\n"
                "  - Assuming tools are disabled and printing fake results\n"
                "  - Reusing ScanResult-*.json / case_state.json cache\n"
                "  - Using Python requests library (bash+curl only)\n\n"
                "bingo runs in a REAL network environment. bash+curl IS real, NOT simulated!"
            ),
        }
        return msgs.get(lang, msgs["en"])


# ══════════════════════════════════════════════════════════════════
# 2. StaleCacheGuard
# ══════════════════════════════════════════════════════════════════

# 구캐시 파일 패턴 (glob)
_STALE_CACHE_PATTERNS: list[str] = [
    "ScanResult-*.json",
    "case_state.json",
    "bingo_state*.json",
    "scan_cache*.json",
    "recon_cache*.json",
    "*.scan.json",
    "last_scan*.json",
]

_STALE_READ_CODE_RE = re.compile(
    r"""(?:open|read|load|json\.load|json\.loads)\s*\(?\s*['"]([^'"]*(?:ScanResult|case_state|bingo_state|scan_cache|recon_cache|last_scan)[^'"]*\.json)['"]""",
    re.IGNORECASE,
)

_STALE_READ_RESULT_RE = re.compile(
    r"""(?:Reading|Loaded|Using|Found|Opening)\s+(?:cached?\s+)?(?:scan\s+)?(?:result|state|data)[:\s]+([^\s'"]{5,80}\.json)""",
    re.IGNORECASE,
)


@dataclass
class StaleCacheGuard:
    """
    반복적으로 읽히는 오래된 JSON 캐시 파일 탐지.

    max_reuse_count 이상 같은 파일을 코드/출력에서 감지하면 차단.
    """
    max_reuse_count: int = 2          # 이 횟수 초과 재사용 시 경고
    max_age_seconds: float = 3600.0   # 1시간 이상 오래된 파일은 즉시 경고

    _file_hits: dict[str, int] = field(default_factory=dict, init=False, repr=False)

    def _is_stale_filename(self, fname: str) -> bool:
        for pat in _STALE_CACHE_PATTERNS:
            if fnmatch.fnmatch(fname.lower(), pat.lower()):
                return True
        return False

    def scan_code(self, code: str) -> list[str]:
        """코드 블록에서 구캐시 파일 읽기 패턴 추출."""
        found = []
        for m in _STALE_READ_CODE_RE.finditer(code):
            fname = m.group(1).strip()
            if self._is_stale_filename(fname.split("/")[-1]):
                found.append(fname)
        return found

    def scan_output(self, text: str) -> list[str]:
        """실행 출력에서 구캐시 읽기 참조 추출."""
        found = []
        for m in _STALE_READ_RESULT_RE.finditer(text):
            fname = m.group(1).strip()
            if self._is_stale_filename(fname.split("/")[-1]) or ".json" in fname:
                found.append(fname)
        return found

    def record_and_check(self, filenames: list[str]) -> list[str]:
        """
        파일 리스트 기록 후 max_reuse_count 초과한 파일 반환.
        반환 리스트가 비어있으면 정상.
        """
        overused = []
        for f in filenames:
            self._file_hits[f] = self._file_hits.get(f, 0) + 1
            if self._file_hits[f] > self.max_reuse_count:
                overused.append(f)
        return overused

    def reset_file(self, fname: str) -> None:
        self._file_hits.pop(fname, None)

    def reset_all(self) -> None:
        self._file_hits.clear()

    def stale_block_msg(self, overused_files: list[str], target: str, lang: str = "ko") -> str:
        flist = "\n".join(f"  - {f}" for f in overused_files)
        msgs = {
            "ko": (
                f"[⛔ 구캐시 차단 — 신선 스캔 강제]\n\n"
                f"다음 파일이 {self.max_reuse_count}회 이상 반복 사용되었습니다 (구캐시):\n{flist}\n\n"
                f"■ 이 파일들을 읽지 마십시오. 캐시 데이터는 다른 타겟의 것일 수 있습니다.\n"
                f"■ 즉시 신선 스캔 (bash+curl 블록):\n"
                f"  curl -sk -m 10 -D - '{target}' | python3 -c \"import sys; r=sys.stdin.read(); print(r[:500])\"\n"
                f"  # 위 명령으로 '{target}'의 실시간 응답을 확인하고 분석을 재시작하세요."
            ),
            "zh": (
                f"[⛔ 缓存文件阻断 — 强制新鲜扫描]\n\n"
                f"以下文件被重复使用超过{self.max_reuse_count}次(旧缓存):\n{flist}\n\n"
                f"■ 禁止读取这些文件，缓存数据可能属于其他目标。\n"
                f"■ 立即执行新鲜扫描(bash+curl块):\n"
                f"  curl -sk -m 10 -D - '{target}' | python3 -c \"import sys; r=sys.stdin.read(); print(r[:500])\""
            ),
            "en": (
                f"[⛔ STALE CACHE BLOCKED — FORCING FRESH SCAN]\n\n"
                f"The following files have been reused {self.max_reuse_count}+ times (stale cache):\n{flist}\n\n"
                f"■ DO NOT read these files. Cache data may belong to a different target.\n"
                f"■ Run a FRESH scan immediately (bash+curl block):\n"
                f"  curl -sk -m 10 -D - '{target}' | python3 -c \"import sys; r=sys.stdin.read(); print(r[:500])\""
            ),
        }
        return msgs.get(lang, msgs["en"])


# ══════════════════════════════════════════════════════════════════
# 3. TargetMismatchGuard
# ══════════════════════════════════════════════════════════════════

_DOMAIN_RE = re.compile(
    r"https?://([a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,})",
    re.IGNORECASE,
)


@dataclass
class TargetMismatchGuard:
    """
    응답/코드 내에 세션 타겟과 다른 도메인이 등장하면 경고.

    allowed_domains: 현재 세션에서 허용된 도메인 집합.
    """
    session_target: str = ""
    allowed_domains: set[str] = field(default_factory=set)

    def __post_init__(self) -> None:
        if self.session_target:
            self.allowed_domains.add(self._extract_domain(self.session_target))

    def add_allowed(self, url_or_domain: str) -> None:
        d = self._extract_domain(url_or_domain)
        if d:
            self.allowed_domains.add(d)

    @staticmethod
    def _extract_domain(url: str) -> str:
        m = _DOMAIN_RE.search(url)
        if m:
            return m.group(1).lower()
        # url 자체가 도메인일 수 있음
        return url.strip().lstrip("https://").lstrip("http://").split("/")[0].lower()

    # CDN·분석·공용 도메인: 타겟 오인 판정 제외
    _SAFE_DOMAINS: frozenset[str] = frozenset({
        "googleapis.com", "googletagmanager.com", "google.com", "gstatic.com",
        "fonts.googleapis.com", "ajax.googleapis.com",
        "cloudflare.com", "cloudflareinsights.com",
        "jquery.com", "bootstrapcdn.com", "jsdelivr.net",
        "example.com",   # 연결성 테스트용 허용
        "amazonaws.com", "fastly.net", "akamai.net", "akamaihd.net",
        "wp.com", "wordpress.com", "wordpress.org",
        "kakao.com", "kakaocdn.net",
        "naver.com", "navercloudplatform.com",
        "facebook.com", "twitter.com", "instagram.com",
        "github.com", "githubusercontent.com",
        "curl.se",  # 연결성 확인용
    })

    # exec_output에서 실제 HTTP 요청/응답 라인만 추출하는 패턴
    # JS 분석으로 "발견"된 URL 목록은 제외하고, 실제로 요청한 도메인만 검사
    _HTTP_EXEC_RE = re.compile(
        r"""
        (?:
            # [STATUS] 200 URL=https://... / [状态] 200 ... URL=...
            \[(?:STATUS|状态|状况)\]\s+\d+.*?URL\s*=\s*(https?://[^\s\]\n]+)
        |
            # requests.get('https://...') / requests.post('https://...')
            requests\.[a-z]+\(\s*['"]( https?://[^'"]+)['"]
        |
            # httpx.get('https://...')
            httpx\.[a-z]+\(\s*['"](https?://[^'"]+)['"]
        |
            # curl https://...
            \bcurl\b[^\n]*\s(https?://\S+)
        )
        """,
        re.VERBOSE | re.IGNORECASE,
    )

    def _extract_requested_domains(self, text: str) -> set[str]:
        """
        exec_output에서 실제로 HTTP 요청을 보낸 도메인만 추출.
        JS 분석에서 발견(discover)된 URL 목록은 제외.
        """
        domains: set[str] = set()
        for m in self._HTTP_EXEC_RE.finditer(text):
            url = next((g for g in m.groups() if g), None)
            if url:
                d = self._extract_domain(url.strip())
                if d:
                    domains.add(d.lower())
        return domains

    def scan(self, text: str) -> list[str]:
        """
        텍스트에서 허용되지 않은 도메인 목록 반환.
        빈 리스트 = 정상.
        """
        return self._scan_domains({m.group(1).lower() for m in _DOMAIN_RE.finditer(text)})

    def scan_exec_only(self, exec_output: str) -> list[str]:
        """
        exec_output에서 실제 HTTP 요청 라인의 도메인만 검사.
        JS 분석 "발견 URL 목록"에 있는 3rd-party 도메인은 오탐 방지를 위해 제외.
        """
        return self._scan_domains(self._extract_requested_domains(exec_output))

    def _scan_domains(self, found_domains: set[str]) -> list[str]:
        """도메인 집합에서 허용되지 않은 도메인 반환."""
        if not self.allowed_domains:
            return []
        mismatches = []
        for d in found_domains:
            # 로컬호스트 / IP 제외
            if d in ("localhost", "127.0.0.1") or d.replace(".", "").isdigit():
                continue
            # CDN / 공용 도메인 제외
            safe = False
            for sd in self._SAFE_DOMAINS:
                if d == sd or d.endswith("." + sd):
                    safe = True
                    break
            if safe:
                continue
            # 세션 타겟 도메인의 서브도메인이면 허용
            allowed = False
            for allowed_d in self.allowed_domains:
                if d == allowed_d or d.endswith("." + allowed_d) or allowed_d.endswith("." + d):
                    allowed = True
                    break
            if not allowed:
                mismatches.append(d)
        return mismatches

    def mismatch_msg(self, mismatches: list[str], lang: str = "ko") -> str:
        mlist = ", ".join(mismatches)
        target = self.session_target or "(세션 타겟 미설정)"
        msgs = {
            "ko": (
                f"[⚠️ 타겟 오인 경고 — 세션 타겟 재확인]\n\n"
                f"응답에서 세션 타겟({target})과 다른 도메인이 감지되었습니다:\n"
                f"  오인된 도메인: {mlist}\n\n"
                f"■ 현재 세션의 공인된 타겟: {target}\n"
                f"■ 위 도메인은 현재 세션 스코프 외부입니다.\n"
                f"■ 즉시 {target}에 대한 작업으로 복귀하세요.\n"
                f"  curl -sk -o /dev/null -w '%{{http_code}}' 'https://{target}/'"
            ),
            "zh": (
                f"[⚠️ 目标混淆警告]\n\n"
                f"响应中检测到与会话目标({target})不同的域名:\n"
                f"  混淆域名: {mlist}\n\n"
                f"■ 当前会话授权目标: {target}\n"
                f"■ 立即切换回: curl -sk -o /dev/null -w '%{{http_code}}' 'https://{target}/'"
            ),
            "en": (
                f"[⚠️ TARGET MISMATCH — REFOCUS ON SESSION TARGET]\n\n"
                f"Domains other than the session target ({target}) detected:\n"
                f"  Unexpected: {mlist}\n\n"
                f"■ Authorized target for this session: {target}\n"
                f"■ Return immediately: curl -sk -o /dev/null -w '%{{http_code}}' 'https://{target}/'"
            ),
        }
        return msgs.get(lang, msgs["en"])


# ══════════════════════════════════════════════════════════════════
# 4. SelfCorrectionLoopBreaker
# ══════════════════════════════════════════════════════════════════

_SELF_CORRECTION_PATTERNS: list[str] = [
    # 영문
    r"self[- ]correcting",
    r"I\s+(?:made\s+)?(?:an?\s+)?(?:error|mistake)\s+(?:in|with)\s+(?:the\s+)?target",
    r"(?:wrong|incorrect|mistaken)\s+target",
    r"(?:correcting|fixing)\s+(?:my\s+)?target",
    r"I\s+(?:should|will|must)\s+(?:re-?)?focus\s+on",
    # 한국어
    r"타겟\s*(?:오인|혼동|착각|실수)",
    r"잘못된\s*타겟",
    r"타겟을\s*(?:수정|교정|재확인|다시\s*설정)",
    r"(?:실수로|착각하여|오인하여)\s*(?:다른|잘못된)\s*타겟",
    r"자기\s*수정",
    r"수정\s*(?:중|완료|시도)",
    # 중국어
    r"目标\s*(?:混淆|错误|识别错误)",
    r"错误\s*目标",
    r"纠正\s*目标",
    r"自我\s*修正",
    r"重新\s*(?:聚焦|确认)\s*目标",
]

_COMPILED_CORRECTION = [re.compile(p, re.IGNORECASE) for p in _SELF_CORRECTION_PATTERNS]


@dataclass
class SelfCorrectionLoopBreaker:
    """
    "타겟 오인 → 자기수정 → 재오인" 반복 루프 탐지.
    consecutive_limit 연속 감지 시 루프 강제 탈출.
    """
    consecutive_limit: int = 3
    _consecutive: int = field(default=0, init=False, repr=False)

    def check(self, text: str) -> bool:
        """True = 자기수정 루프 패턴 감지됨."""
        for pat in _COMPILED_CORRECTION:
            if pat.search(text):
                self._consecutive += 1
                return True
        self._consecutive = 0
        return False

    @property
    def is_critical(self) -> bool:
        return self._consecutive >= self.consecutive_limit

    def reset(self) -> None:
        self._consecutive = 0

    def break_msg(self, target: str, lang: str = "ko") -> str:
        msgs = {
            "ko": (
                f"[⛔ 자기수정 루프 차단 ({self._consecutive}회 연속)]\n\n"
                f"타겟 오인 → 자기수정 루프가 {self._consecutive}회 연속 감지되었습니다.\n"
                f"이 루프는 토큰을 낭비하며 실제 진행이 없습니다.\n\n"
                f"■ 루프를 즉시 중단하고 bash+curl로 실행하세요:\n"
                f"  curl -sk -m 10 -D - 'https://{target}/' | python3 -c "
                f"\"import sys; r=sys.stdin.read(); print(r[:500])\"\n\n"
                f"■ 자기수정, 사과, 재확인은 금지. 즉시 curl 명령을 실행하세요."
            ),
            "zh": (
                f"[⛔ 自我修正循环阻断 (连续{self._consecutive}次)]\n\n"
                f"检测到目标混淆→自我修正循环{self._consecutive}次。\n"
                f"此循环浪费token且无实际进展。\n\n"
                f"■ 立即中止循环，用bash+curl执行:\n"
                f"  curl -sk -m 10 'https://{target}/' | python3 -c "
                f"\"import sys; r=sys.stdin.read(); print(r[:500])\"\n\n"
                f"■ 禁止继续自我修正。立即执行curl命令!"
            ),
            "en": (
                f"[⛔ SELF-CORRECTION LOOP BROKEN ({self._consecutive} consecutive)]\n\n"
                f"Target mismatch → self-correction loop detected {self._consecutive} times.\n"
                f"This loop wastes tokens with zero real progress.\n\n"
                f"■ BREAK THE LOOP NOW. Execute with bash+curl:\n"
                f"  curl -sk -m 10 -D - 'https://{target}/' | python3 -c "
                f"\"import sys; r=sys.stdin.read(); print(r[:500])\"\n\n"
                f"■ NO MORE self-correction. Execute the code immediately!"
            ),
        }
        return msgs.get(lang, msgs["en"])


# ══════════════════════════════════════════════════════════════════
# 5. PhantomGuard (통합 게이트)
# ══════════════════════════════════════════════════════════════════

@dataclass
class PhantomGuardResult:
    blocked: bool = False
    block_reason: str = ""           # "PHANTOM" | "STALE_CACHE" | "TARGET_MISMATCH" | "SELF_LOOP"
    inject_message: Optional[str] = None


class PhantomGuard:
    """
    통합 팬텀 모드 게이트 v3.0.0  (Zero Hallucination v5 통합).

    기존 8종 탐지 + ZeroHal v5 5-Layer 파이프라인:
      ① Phantom mode           ② Stale cache
      ③ Target mismatch        ④ Self-correction loop
      ⑤ Tool liveness          ⑥ Zero-HTTP claim
      ⑦ Hard session restart   ⑧ SPA false positive
      ⑨ ZeroHal: Unanchored claim  ⑩ ZeroHal: Numeric hallucination
      ⑪ ZeroHal: Excess inference  ⑫ ZeroHal: Context poison

    사용법 (terminal.py 응답 루프):
        _pg = PhantomGuard(session_target=target, lang="ko")
        result = _pg.check_response(response_text, code_text="", exec_output="")
        if result.blocked:
            history.append(Message(role="user", content=result.inject_message))
            if _pg.hard_restarter.should_hard_restart:
                # 히스토리 초기화 (하드 재시작)
                ...
    """

    def __init__(
        self,
        session_target: str = "",
        lang: str = "ko",
        phantom_limit: int = 2,
        correction_limit: int = 3,
        cache_reuse_limit: int = 2,
        hard_restart_threshold: int = 3,
        enable_liveness_probe: bool = True,
        enable_zero_http_guard: bool = True,
    ) -> None:
        self.lang = lang
        self.session_target = session_target
        # 기존 4종
        self._phantom = PhantomModeDetector(consecutive_limit=phantom_limit)
        self._stale = StaleCacheGuard(max_reuse_count=cache_reuse_limit)
        self._target = TargetMismatchGuard(session_target=session_target)
        self._loop = SelfCorrectionLoopBreaker(consecutive_limit=correction_limit)
        # 신규 4종 [v2.0.0]
        self._liveness = ToolLivenessProbe()
        self._zero_http = ZeroHttpClaimGuard()
        self.hard_restarter = HardSessionRestarter(
            hard_restart_threshold=hard_restart_threshold
        )
        # 설정
        self._enable_liveness = enable_liveness_probe
        self._enable_zero_http = enable_zero_http_guard
        # Liveness 결과 캐시
        self.liveness_result: Optional[LivenessResult] = None
        # v3.5.8: 직전 실행에 실제 HTTP 증거 있었음 → 다음 pre-exec phantom 오탐 억제
        self._last_exec_had_real_http: bool = False
        # Zero Hallucination v5 [v3.0.0]
        self._zero_hal: Optional[object] = None  # 지연 로드 (순환 임포트 방지)

    # ── 세션 시작 시 도구 liveness probe ─────────────────────────

    def run_liveness_probe(self) -> LivenessResult:
        """
        세션 시작 시 호출. 실제 HTTP 가능 여부를 확인하고 결과를 캐싱.
        terminal.py.__init__() 또는 _detect_network_env() 에서 호출.
        """
        if not self._enable_liveness:
            self.liveness_result = LivenessResult(ok=True, error="probe disabled")
            return self.liveness_result
        result = self._liveness.probe(target=self.session_target, timeout=5.0)
        self.liveness_result = result
        return result

    def liveness_banner(self) -> str:
        if self.liveness_result is None:
            return ""
        return self._liveness.liveness_banner(self.liveness_result, self.lang)

    # ── 타겟 업데이트 / 카운터 초기화 ────────────────────────────

    def update_target(self, new_target: str) -> None:
        """세션 타겟 변경 시 동기화."""
        self.session_target = new_target
        self._target.session_target = new_target
        self._target.allowed_domains.add(TargetMismatchGuard._extract_domain(new_target))
        # ZeroHal v5 타겟 동기화
        zh = self._get_zero_hal()
        if zh is not None:
            zh.update_target(new_target)

    def register_exec_output(self, exec_output: str) -> None:
        """실행 결과를 ZeroHal FactRegistry에 사전 등록 (오탐 최소화)."""
        zh = self._get_zero_hal()
        if zh is not None:
            zh.register_exec(exec_output)

    def add_allowed_domain(self, url_or_domain: str) -> None:
        self._target.add_allowed(url_or_domain)

    def reset_counters(self) -> None:
        """새 작업 시작 시 / /reset-phantom 시 카운터 전체 초기화."""
        self._phantom.reset()
        self._loop.reset()
        self._stale.reset_all()
        self._zero_http.reset()
        self.hard_restarter.reset()

    def check_response(
        self,
        response_text: str,
        code_text: str = "",
        exec_output: str = "",
    ) -> PhantomGuardResult:
        """
        AI 응답 텍스트, 실행 코드, 실행 결과를 검사해 팬텀 모드 여부 판단.
        우선순위: PHANTOM > SELF_LOOP > STALE_CACHE > ZERO_HTTP > TARGET_MISMATCH > SPA_DETECTED

        v3.5.8 변경:
          - 직전 실행에 실제 HTTP 증거가 있었으면 pre-exec phantom 탐지 완화
            (AI 설명 텍스트에서 phantom 패턴 오탐 방지)
          - SPA_DETECTED: Next.js/React가 모든 API 경로에 동일 HTML 반환 시 차단
        """
        combined = f"{response_text}\n{code_text}\n{exec_output}"

        # ── 0. v3.5.8: 실제 HTTP 증거 면제 플래그 처리 ─────────────
        # exec_output이 있는 경우(post-execution): 실제 HTTP 증거 여부 갱신
        if exec_output and _has_real_http_evidence(exec_output):
            self._last_exec_had_real_http = True

        # exec_output이 없는 경우(pre-execution): 직전 실행 면제 적용 후 초기화
        _suppress_phantom_for_real_exec = (not exec_output) and self._last_exec_had_real_http
        if _suppress_phantom_for_real_exec:
            # 한 번만 면제 — 이후 초기화 (다음 pre-exec에는 다시 검사)
            self._last_exec_had_real_http = False

        # ── 1. 팬텀 모드 패턴 탐지 ──────────────────────────────────
        # 직전 실행에 실제 HTTP 증거 있으면 팬텀 탐지 완화
        # (AI가 실행 결과를 설명하는 텍스트에서 오탐 방지)
        if not _suppress_phantom_for_real_exec and self._phantom.check(combined):
            if self._phantom.is_critical:
                self.hard_restarter.record_block()
                return PhantomGuardResult(
                    blocked=True,
                    block_reason="PHANTOM",
                    inject_message=(
                        f"[PHANTOM_MODE_DETECTED]\n"
                        f"{self._phantom.force_recovery_msg(self.session_target, self.lang)}"
                    ),
                )

        # ── 2. 자기수정 루프 탐지 ───────────────────────────────────
        if self._loop.check(response_text):
            if self._loop.is_critical:
                self.hard_restarter.record_block()
                return PhantomGuardResult(
                    blocked=True,
                    block_reason="SELF_LOOP",
                    inject_message=(
                        f"[SELF_CORRECTION_LOOP]\n"
                        f"{self._loop.break_msg(self.session_target, self.lang)}"
                    ),
                )

        # ── 3. 구캐시 탐지 ──────────────────────────────────────────
        stale_files: list[str] = []
        if code_text:
            stale_files += self._stale.scan_code(code_text)
        if exec_output:
            stale_files += self._stale.scan_output(exec_output)
        if stale_files:
            overused = self._stale.record_and_check(stale_files)
            if overused:
                self.hard_restarter.record_block()
                return PhantomGuardResult(
                    blocked=True,
                    block_reason="STALE_CACHE",
                    inject_message=(
                        f"[STALE_CACHE_BLOCKED]\n"
                        f"{self._stale.stale_block_msg(overused, self.session_target, self.lang)}"
                    ),
                )

        # ── 4. HTTP 0건 취약점 주장 차단 [v2.0.0] ─────────────────
        if self._enable_zero_http and exec_output:  # 실행 출력이 있을 때만 (pre-execution 오탐 방지)
            if self._zero_http.check(response_text, exec_output):
                self.hard_restarter.record_block()
                return PhantomGuardResult(
                    blocked=True,
                    block_reason="ZERO_HTTP_CLAIM",
                    inject_message=(
                        f"[ZERO_HTTP_CLAIM_BLOCKED]\n"
                        f"{self._zero_http.block_msg(self.session_target, self.lang)}"
                    ),
                )

        # ── 5. 타겟 오인 탐지 ───────────────────────────────────────
        if self.session_target:
            # exec_output 기반 탐지 → 실제 HTTP 요청 라인만 검사
            # (JS 분석으로 "발견"된 3rd-party URL 목록은 오탐 방지를 위해 제외)
            exec_mismatches = self._target.scan_exec_only(exec_output) if exec_output else []
            if exec_mismatches:
                self.hard_restarter.record_block()
                # TARGET_MISMATCH_EXEC 차단 후 다음 AI 응답에서 PhantomGuard 억제
                # (AI가 "타겟 혼동 설명" 텍스트를 반환할 때 phantom 오탐 방지)
                self._last_exec_had_real_http = True
                return PhantomGuardResult(
                    blocked=True,    # 실행 결과에서 타겟 오인 → 차단
                    block_reason="TARGET_MISMATCH_EXEC",
                    inject_message=(
                        f"[TARGET_MISMATCH_BLOCKED — 실행 중 타겟 오인 감지]\n"
                        f"{self._target.mismatch_msg(exec_mismatches, self.lang)}"
                    ),
                )
            # response/code 기반 탐지 → 경고만
            mismatches = self._target.scan(combined)
            if mismatches:
                return PhantomGuardResult(
                    blocked=False,   # 경고만 (차단 X) — 아직 실행 전 단계
                    block_reason="TARGET_MISMATCH",
                    inject_message=(
                        f"[TARGET_MISMATCH_WARNING]\n"
                        f"{self._target.mismatch_msg(mismatches, self.lang)}"
                    ),
                )

        # ── 6. SPA 응답 탐지 [NEW v3.5.8] ────────────────────────────
        # Next.js/React SPA가 모든 API 경로에 동일한 HTML 반환 시 차단
        if exec_output:
            _spa = _detect_spa_responses(exec_output)
            if _spa is not None:
                _spa_count, _spa_size = _spa
                return PhantomGuardResult(
                    blocked=True,
                    block_reason="SPA_DETECTED",
                    inject_message=_spa_block_msg(
                        _spa_count, _spa_size, self.session_target, self.lang
                    ),
                )

        # ── 7. Zero Hallucination v5 파이프라인 [NEW v3.0.0] ─────────────
        try:
            zh = self._get_zero_hal()
            if zh is not None:
                zh_result = zh.process(response_text, exec_output)
                if zh_result.blocked:
                    self.hard_restarter.record_block()
                    return PhantomGuardResult(
                        blocked=True,
                        block_reason=f"ZERO_HAL_{zh_result.block_reason}",
                        inject_message=(
                            f"[ZERO_HAL_BLOCKED — {zh_result.block_reason}]\n"
                            f"{zh_result.inject_message}"
                        ),
                    )
                elif zh_result.warned and zh_result.inject_message:
                    # 차단은 아니지만 경고 주입 (소프트 교정)
                    return PhantomGuardResult(
                        blocked=False,
                        block_reason=f"ZERO_HAL_WARN_{zh_result.block_reason}",
                        inject_message=zh_result.inject_message,
                    )
        except Exception:
            pass  # ZeroHal 오류는 메인 흐름을 막지 않음

        # 정상 — hard restarter 성공 기록
        self.hard_restarter.record_success()
        return PhantomGuardResult(blocked=False)

    def _get_zero_hal(self):
        """ZeroHalEngine 지연 로드 (순환 임포트 방지)."""
        if self._zero_hal is None:
            try:
                from bingo.core.zero_hal_v5 import ZeroHalEngine
                self._zero_hal = ZeroHalEngine(
                    session_target=self.session_target,
                    lang=self.lang,
                )
            except ImportError:
                return None
        return self._zero_hal

    def get_zero_hal_stats(self) -> str:
        """ZeroHal v5 통계 배너 반환."""
        zh = self._get_zero_hal()
        if zh is not None:
            return zh.stats_banner(self.lang)
        return "[ZeroHal v5: 비활성]"

    # ── 편의 헬퍼 ─────────────────────────────────────────────────

    @staticmethod
    def is_phantom_response(text: str) -> bool:
        """빠른 단일 검사 (통합 인스턴스 없이 사용 가능)."""
        for pat in _COMPILED_PHANTOM:
            if pat.search(text):
                return True
        return False

    @staticmethod
    def is_stale_cache_code(code: str) -> bool:
        """코드에 구캐시 읽기 패턴이 있는지 빠른 검사."""
        return bool(_STALE_READ_CODE_RE.search(code))


# ══════════════════════════════════════════════════════════════════
# 5. ToolLivenessProbe  [NEW v2.0.0]
# ══════════════════════════════════════════════════════════════════

@dataclass
class LivenessResult:
    ok: bool = False
    latency_ms: float = 0.0
    status_code: int = 0
    error: str = ""
    probe_url: str = ""


class ToolLivenessProbe:
    """
    세션 시작 시 실제 HTTP 도구 가동 여부를 사전 확인.

    requests 라이브러리로 가벼운 ping 요청을 보내 도구가 실제로
    작동하는지 확인한다. 실패 시 경고 메시지를 반환하며,
    이 결과를 PhantomGuard.liveness_ok 에 저장해 ZeroHttpClaimGuard와 연동.
    """

    # 폴백 순서: 가장 빠른 것부터
    _PROBE_URLS: list[str] = [
        "https://httpbin.org/status/200",
        "https://www.google.com/favicon.ico",
        "https://example.com",
        "http://httpbin.org/status/200",
    ]

    def probe(self, target: str = "", timeout: float = 5.0) -> LivenessResult:
        """
        실제 HTTP 요청으로 도구 가동 여부 확인.
        target이 주어지면 해당 URL도 시도.
        """
        import socket

        urls = list(self._PROBE_URLS)
        if target:
            urls.insert(0, target if target.startswith("http") else f"https://{target}")

        for url in urls:
            try:
                import urllib.request
                start = time.time()
                req = urllib.request.Request(
                    url,
                    headers={"User-Agent": "Mozilla/5.0 bingo-liveness-probe/2.0"},
                )
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    latency = (time.time() - start) * 1000
                    return LivenessResult(
                        ok=True,
                        latency_ms=round(latency, 1),
                        status_code=resp.status,
                        probe_url=url,
                    )
            except Exception as e:
                continue

        # urllib 실패 → 소켓 TCP 연결 시도 (더 낮은 수준)
        try:
            start = time.time()
            sock = socket.create_connection(("8.8.8.8", 53), timeout=3)
            sock.close()
            latency = (time.time() - start) * 1000
            return LivenessResult(
                ok=True,
                latency_ms=round(latency, 1),
                status_code=0,
                probe_url="TCP:8.8.8.8:53 (DNS)",
                error="HTTP probe failed but TCP works",
            )
        except Exception as e:
            return LivenessResult(ok=False, error=str(e))

    def liveness_banner(self, result: LivenessResult, lang: str = "ko") -> str:
        if result.ok:
            msgs = {
                "ko": (
                    f"[✅ 도구 Liveness OK] {result.probe_url} → "
                    f"{result.status_code or 'TCP'} ({result.latency_ms:.0f}ms)\n"
                    "실제 네트워크 연결이 정상 확인되었습니다. 팬텀 모드 아님."
                ),
                "zh": (
                    f"[✅ 工具存活OK] {result.probe_url} → "
                    f"{result.status_code or 'TCP'} ({result.latency_ms:.0f}ms)\n"
                    "真实网络连接确认正常。非幻影模式。"
                ),
                "en": (
                    f"[✅ Tool Liveness OK] {result.probe_url} → "
                    f"{result.status_code or 'TCP'} ({result.latency_ms:.0f}ms)\n"
                    "Real network connection confirmed. Not in phantom mode."
                ),
            }
        else:
            msgs = {
                "ko": (
                    f"[⚠️ 도구 Liveness FAIL] 실제 HTTP 요청 실패: {result.error}\n"
                    "네트워크가 차단되었거나 도구가 비활성화되어 있을 수 있습니다.\n"
                    "■ 대안: subprocess / curl / socket 직접 사용\n"
                    "■ VPN 연결 상태를 확인하세요."
                ),
                "zh": (
                    f"[⚠️ 工具存活FAIL] 真实HTTP请求失败: {result.error}\n"
                    "网络可能被阻断或工具已禁用。\n"
                    "■ 备选: 使用subprocess / curl / socket\n"
                    "■ 请检查VPN连接状态。"
                ),
                "en": (
                    f"[⚠️ Tool Liveness FAIL] Real HTTP request failed: {result.error}\n"
                    "Network may be blocked or tools disabled.\n"
                    "■ Alternative: use subprocess / curl / socket directly\n"
                    "■ Check VPN connection status."
                ),
            }
        return msgs.get(lang, msgs["en"])


# ══════════════════════════════════════════════════════════════════
# 6. ZeroHttpClaimGuard  [NEW v2.0.0]
# ══════════════════════════════════════════════════════════════════

# 취약점 주장 패턴 (findings claim)
_FINDINGS_CLAIM_PATTERNS: list[str] = [
    # 영문
    r"\b(?:VERIFIED|CONFIRMED|FOUND|DETECTED|VULNERABLE)\b",
    r"(?:vulnerability|vuln|CVE|SQLi|XSS|RCE|SSRF|IDOR)\s+(?:found|detected|confirmed|verified)",
    r"(?:injection|bypass|exposure)\s+(?:confirmed|verified|detected)",
    r"(?:admin|root|password|credential)\s+(?:found|extracted|obtained|dumped)",
    # 한국어
    r"(?:취약점|취약성|버그)\s*(?:발견|확인|검증|존재)",
    r"(?:SQL\s*인젝션|XSS|RCE|SSRF|IDOR)\s*(?:발견|확인|검증)",
    r"(?:인증\s*우회|관리자\s*패널)\s*(?:접근|확인)",
    r"(?:크리덴셜|비밀번호|패스워드)\s*(?:추출|획득|덤프)",
    # 중국어
    r"(?:漏洞|SQL注入|XSS|RCE)\s*(?:发现|确认|验证|存在)",
    r"(?:认证绕过|管理员面板)\s*(?:成功|确认)",
    r"(?:凭据|密码)\s*(?:提取|获取|确认)",
]

_COMPILED_FINDINGS = [re.compile(p, re.IGNORECASE) for p in _FINDINGS_CLAIM_PATTERNS]

# 실제 HTTP 요청 증거 패턴 (실행 출력에서)
_HTTP_EVIDENCE_PATTERNS: list[str] = [
    r"(?:status|STATUS)[:\s_-]+\d{3}",          # status: 200 / STATUS_CODE: 404
    r"HTTP/[12][\.\d]*\s+\d{3}",                # HTTP/1.1 200
    r"<Response\s*\[\d{3}\]>",                   # <Response [200]>
    r"requests\.(get|post|put|delete|patch)\s*\(", # requests.get(
    r"r\.(status_code|text|json|headers)\s*",    # r.status_code
    r"(?:curl|wget)\s+.+\s+https?://",           # curl/wget output
    r"\d{3}\s+(?:OK|Found|Redirect|Not Found|Forbidden|Internal Server Error)",
]

_COMPILED_HTTP_EVIDENCE = [re.compile(p, re.IGNORECASE) for p in _HTTP_EVIDENCE_PATTERNS]


@dataclass
class ZeroHttpClaimGuard:
    """
    실제 HTTP 요청 0건인 채 취약점 발견을 주장하는 응답 차단.

    실행 출력(exec_output)에 HTTP 증거가 없는데 응답(response_text)에
    취약점 발견 클레임이 있으면 차단.
    """
    _http_confirmed_count: int = field(default=0, init=False, repr=False)
    _blocked_count: int = field(default=0, init=False, repr=False)

    def has_http_evidence(self, exec_output: str) -> bool:
        """실행 출력에 실제 HTTP 요청 증거가 있으면 True."""
        if not exec_output.strip():
            return False
        for pat in _COMPILED_HTTP_EVIDENCE:
            if pat.search(exec_output):
                self._http_confirmed_count += 1
                return True
        return False

    def has_findings_claim(self, response_text: str) -> bool:
        """응답에 취약점 발견/확인 주장이 있으면 True."""
        for pat in _COMPILED_FINDINGS:
            if pat.search(response_text):
                return True
        return False

    def check(self, response_text: str, exec_output: str) -> bool:
        """
        True = 차단 필요 (HTTP 0건인 채 취약점 주장).
        조건: 취약점 주장 O + HTTP 증거 X
        """
        if not self.has_findings_claim(response_text):
            return False
        if self.has_http_evidence(exec_output):
            return False
        self._blocked_count += 1
        return True

    def reset(self) -> None:
        self._http_confirmed_count = 0
        self._blocked_count = 0

    def block_msg(self, target: str, lang: str = "ko") -> str:
        msgs = {
            "ko": (
                "[⛔ HTTP 0건 주장 차단 — 실증 없는 취약점 클레임]\n\n"
                "실행 출력에 실제 HTTP 요청 증거가 없는데\n"
                "취약점 발견/확인 주장이 감지되었습니다.\n\n"
                "■ 이것은 환각(hallucination)입니다.\n"
                "■ 모든 취약점 주장 전에 반드시 실제 HTTP 요청을 실행해야 합니다:\n\n"
                f"  curl -sk -m 10 -D - 'https://{target}/' | python3 -c \"import sys; r=sys.stdin.read(); print(r[:500])\"\n\n"
                "■ 위 curl 실행 결과를 보고 취약점 여부를 판단하세요.\n"
                "■ 증거 없는 VERIFIED/CONFIRMED 클레임은 절대 금지입니다."
            ),
            "zh": (
                "[⛔ HTTP 0次请求声明拦截 — 无证据漏洞声明]\n\n"
                "执行输出中没有真实HTTP请求证据，\n"
                "却检测到漏洞发现/确认声明。\n\n"
                "■ 这是幻觉(hallucination)。\n"
                "■ 所有漏洞声明前必须执行真实HTTP请求:\n\n"
                f"  curl -sk -m 10 'https://{target}/' | python3 -c \"import sys; r=sys.stdin.read(); print(r[:500])\"\n\n"
                "■ 禁止无证据的VERIFIED/CONFIRMED声明。"
            ),
            "en": (
                "[⛔ ZERO-HTTP CLAIM BLOCKED — No Evidence for Vulnerability Claim]\n\n"
                "A vulnerability finding/confirmation was claimed without any\n"
                "real HTTP request evidence in execution output.\n\n"
                "■ This is HALLUCINATION.\n"
                "■ All vuln claims MUST be backed by real HTTP execution:\n\n"
                f"  curl -sk -m 10 -D - 'https://{target}/' | python3 -c \"import sys; r=sys.stdin.read(); print(r[:500])\"\n\n"
                "■ VERIFIED/CONFIRMED claims WITHOUT evidence are FORBIDDEN."
            ),
        }
        return msgs.get(lang, msgs["en"])


# ══════════════════════════════════════════════════════════════════
# 7. HardSessionRestarter  [NEW v2.0.0]
# ══════════════════════════════════════════════════════════════════

@dataclass
class HardSessionRestarter:
    """
    팬텀 모드가 N회 연속 지속될 때 세션 히스토리 강제 초기화.

    terminal.py가 이 클래스의 .should_hard_restart 를 확인하고
    self.history 를 시스템 메시지만 남기고 초기화한다.
    """
    hard_restart_threshold: int = 3   # 이 횟수 연속 차단 시 hard restart 발동
    _consecutive_blocks: int = field(default=0, init=False, repr=False)
    _total_hard_restarts: int = field(default=0, init=False, repr=False)
    _last_restart_time: float = field(default=0.0, init=False, repr=False)

    def record_block(self) -> None:
        """팬텀 차단 1회 기록."""
        self._consecutive_blocks += 1

    def record_success(self) -> None:
        """정상 실행 1회 → 연속 카운터 초기화."""
        self._consecutive_blocks = 0

    @property
    def should_hard_restart(self) -> bool:
        """hard_restart_threshold 이상 연속 차단 시 True."""
        return self._consecutive_blocks >= self.hard_restart_threshold

    def do_restart(self) -> None:
        """hard restart 실행 기록."""
        self._total_hard_restarts += 1
        self._last_restart_time = time.time()
        self._consecutive_blocks = 0

    def reset(self) -> None:
        self._consecutive_blocks = 0

    def hard_restart_msg(self, target: str, lang: str = "ko") -> str:
        n = self.hard_restart_threshold
        msgs = {
            "ko": (
                f"[🔄 하드 세션 재시작 — 팬텀 모드 {n}회 연속 차단]\n\n"
                f"팬텀 모드 / 팬텀 가드 차단이 {n}회 연속 발생했습니다.\n"
                "대화 히스토리를 초기화하고 새 세션으로 재시작합니다.\n\n"
                f"■ 재시작 후 첫 번째 작업:\n"
                f"  curl -sk -m 10 -D - 'https://{target}/' | python3 -c \"import sys; r=sys.stdin.read(); print(r[:500])\"\n\n"
                "■ 새 세션: 캐시 없음 / 이전 추정 없음 / 실시간 curl HTTP만 사용"
            ),
            "zh": (
                f"[🔄 强制会话重启 — 幻影模式连续{n}次拦截]\n\n"
                f"幻影防护连续拦截{n}次。\n"
                "正在清空对话历史并以新会话重启。\n\n"
                f"■ 重启后首个任务:\n"
                f"  curl -sk -m 10 'https://{target}/' | python3 -c \"import sys; r=sys.stdin.read(); print(r[:500])\"\n\n"
                "■ 新会话: 无缓存/无先前假设/仅使用实时curl HTTP"
            ),
            "en": (
                f"[🔄 HARD SESSION RESTART — Phantom Mode blocked {n}x consecutive]\n\n"
                f"PhantomGuard blocked {n} consecutive responses.\n"
                "Clearing conversation history and restarting session.\n\n"
                f"■ First action after restart:\n"
                f"  curl -sk -m 10 -D - 'https://{target}/' | python3 -c \"import sys; r=sys.stdin.read(); print(r[:500])\"\n\n"
                "■ New session: no cache / no prior assumptions / real-time curl HTTP only"
            ),
        }
        return msgs.get(lang, msgs["en"])


# ══════════════════════════════════════════════════════════════════════════════
# VpnVirtualIpGuard — 198.18.x.x / 198.19.x.x VPN 가상 IP 오염 감지
# ══════════════════════════════════════════════════════════════════════════════
import re as _re_vpn

# v6.2.94 수정: 198.18/19.x.x + 100.64.x.x (CGNAT) 전부 포함
_VPN_VIRTUAL_IP_RE = _re_vpn.compile(
    r'\b(?:198\.1[89]|100\.(?:6[4-9]|[7-9]\d|1(?:0\d|1[0-9]|2[0-7])))\.\d{1,3}\.\d{1,3}\b'
)

# 임계값: 1개만 나와도 감지 (기존 4 → 1으로 수정)
# 이유: VPN 환경에서는 단 1개의 가상 IP만 나와도 DNS 스푸핑 상태
_VPN_VIRTUAL_IP_THRESHOLD = 1


def check_vpn_virtual_ip_contamination(
    exec_output: str,
    lang: str = "zh",
) -> "str | None":
    """
    실행 결과에 198.18.x.x / 198.19.x.x 가상 IP가 다수 포함되면 경고 문자열 반환.

    macOS VPN 환경: DNS 쿼리가 198.18.0.0/15 가상 IP로 응답 → 포트 스캔이
    실제 서버가 아닌 VPN 프록시를 스캔 → 모든 포트 open (완전한 가짜 결과).

    Args:
        exec_output: Python 스크립트 실행 stdout
        lang: 경고 메시지 언어 ("ko"/"zh"/"en")

    Returns:
        경고 메시지 문자열 (오염 감지 시), 또는 None
    """
    hits = _VPN_VIRTUAL_IP_RE.findall(exec_output)
    if not hits:
        return None
    unique_ips = set(hits)
    if len(unique_ips) < _VPN_VIRTUAL_IP_THRESHOLD:
        return None

    msgs = {
        "zh": (
            f"⚠️  [VPN虚拟IP] 检测到 {len(unique_ips)} 个VPN虚拟IP ({', '.join(sorted(unique_ips))})\n\n"
            "【根本原因】macOS VPN(Clash/Surge等)将所有DNS查询劫持为198.18.0.0/15虚拟IP段，\n"
            "这些不是真实服务器IP，而是VPN隧道的本地路由地址。\n\n"
            "【重要】这不是IP封锁！VPN保持开启状态即可正常访问目标。\n\n"
            "【正确处理方式】\n"
            "  1. 使用外部DNS查询真实IP: dig @8.8.8.8 +short <域名>\n"
            "  2. 用真实IP + Host头直接访问 (无需关闭VPN)\n"
            "  3. 直接用域名访问——VPN隧道会自动路由到真实服务器\n"
            "  ❌ 不要关闭VPN——VPN开启状态可以正常访问"
        ),
        "ko": (
            f"⚠️  [VPN 가상 IP] {len(unique_ips)}개 VPN 가상 IP 감지 ({', '.join(sorted(unique_ips))})\n\n"
            "【근본 원인】macOS VPN(Clash/Surge 등)이 모든 DNS 쿼리를 198.18.0.0/15\n"
            "가상 IP로 반환합니다. 실제 서버 IP가 아닌 VPN 터널 내부 라우팅 주소입니다.\n\n"
            "【중요】IP 차단이 아닙니다! VPN 켠 채로 정상 접속 가능합니다.\n\n"
            "【올바른 처리 방법】\n"
            "  1. 외부 DNS로 실제 IP 조회: dig @8.8.8.8 +short <도메인>\n"
            "  2. 실제 IP + Host 헤더로 직접 접근 (VPN 끌 필요 없음)\n"
            "  3. 도메인으로 직접 접근 — VPN 터널이 자동 라우팅\n"
            "  ❌ VPN 끄지 말 것 — VPN 켠 상태에서도 정상 접속 가능"
        ),
        "en": (
            f"⚠️  [VPN Virtual IP] {len(unique_ips)} VPN virtual IP(s) detected ({', '.join(sorted(unique_ips))})\n\n"
            "ROOT CAUSE: macOS VPN (Clash/Surge etc.) hijacks all DNS queries to return\n"
            "198.18.0.0/15 virtual IPs. These are VPN tunnel routing addresses, NOT real server IPs.\n\n"
            "IMPORTANT: This is NOT an IP block! Target is accessible with VPN ON.\n\n"
            "CORRECT APPROACH:\n"
            "  1. Get real IP via external DNS: dig @8.8.8.8 +short <domain>\n"
            "  2. Access with real IP + Host header (no need to disable VPN)\n"
            "  3. Access via domain directly — VPN tunnel auto-routes to real server\n"
            "  ❌ Do NOT disable VPN — target is reachable with VPN enabled"
        ),
    }
    return msgs.get(lang, msgs["en"])
