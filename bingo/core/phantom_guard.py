"""
PhantomGuard — 팬텀 모드 탐지 및 강제 재활성화 v1.0.0
=========================================================
문제: agent의 bash/write 도구가 비활성화/일시정지될 때 발생하는
     "Phantom mode → simulated exit" 루프.
     실제 HTTP 요청 0건인 채 분석 결과를 출력하고 자기수정 무한반복.

탐지 4종:
  1. PhantomModeDetector  — 응답에서 "phantom/도구 비활성화/simulated exit" 패턴
  2. StaleCacheGuard      — ScanResult-*.json / case_state.json 반복 읽기 탐지
  3. TargetMismatchGuard  — 현재 세션 타겟과 다른 도메인이 응답에 등장
  4. SelfCorrectionLoop   — "타겟 오인 → 수정 → 재오인" 무한반복 감지

대응:
  A. 팬텀 모드 → 도구 재활성화 강제 프롬프트 주입
  B. 구캐시    → 해당 파일 읽기 차단 + 신선 스캔 강제
  C. 타겟 오인 → 세션 타겟 재주입
  D. 루프      → 카운터 초기화 + 직접 HTTP 요청 강제
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
                "■ 즉시 수행:\n"
                f"  import requests, urllib3; urllib3.disable_warnings()\n"
                f"  r = requests.get('{target}', verify=False, timeout=10)\n"
                f"  print(r.status_code, r.text[:300])\n\n"
                "■ 금지 (Phantom Mode 유발 행위):\n"
                "  - 도구가 비활성화되어 있다고 가정하고 가상 결과 출력\n"
                "  - ScanResult-*.json / case_state.json 캐시 재사용\n"
                "  - 자기수정 루프 반복 없이 직접 requests 코드 실행\n\n"
                "bingo는 완전한 인터넷 환경에서 실행됩니다. requests.get()은 실제로 작동합니다."
            ),
            "zh": (
                "[⛔ 幻影模式拦截 — BINGO强制恢复]\n\n"
                f"工具(bash/write)在禁用状态下连续{self._consecutive}次检测到虚假执行。\n"
                "在没有真实HTTP请求的情况下输出分析结果属于幻觉。\n\n"
                "■ 立即执行:\n"
                f"  import requests, urllib3; urllib3.disable_warnings()\n"
                f"  r = requests.get('{target}', verify=False, timeout=10)\n"
                f"  print(r.status_code, r.text[:300])\n\n"
                "■ 禁止行为:\n"
                "  - 假设工具被禁用并输出虚假结果\n"
                "  - 重复使用ScanResult-*.json/case_state.json缓存\n"
                "  - 不执行直接HTTP请求而陷入自我修正循环\n\n"
                "bingo在真实网络环境运行，requests.get()是真实的，不是模拟的!"
            ),
            "en": (
                "[⛔ PHANTOM MODE BLOCKED — BINGO FORCING RECOVERY]\n\n"
                f"Tools (bash/write) detected as disabled for {self._consecutive} consecutive iterations.\n"
                "Outputting analysis results without real HTTP requests is hallucination.\n\n"
                "■ DO THIS NOW:\n"
                f"  import requests, urllib3; urllib3.disable_warnings()\n"
                f"  r = requests.get('{target}', verify=False, timeout=10)\n"
                f"  print(r.status_code, r.text[:300])\n\n"
                "■ FORBIDDEN:\n"
                "  - Assuming tools are disabled and printing fake results\n"
                "  - Reusing ScanResult-*.json / case_state.json cache\n"
                "  - Self-correction loops without direct HTTP execution\n\n"
                "bingo runs in a REAL network environment. requests.get() IS real, NOT simulated!"
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
                f"■ 즉시 신선 스캔:\n"
                f"  import requests, urllib3; urllib3.disable_warnings()\n"
                f"  r = requests.get('{target}', verify=False, timeout=10)\n"
                f"  print(r.status_code, r.headers, r.text[:500])\n"
                f"  # 위 코드로 '{target}'의 실시간 응답을 확인하고 분석을 재시작하세요."
            ),
            "zh": (
                f"[⛔ 缓存文件阻断 — 强制新鲜扫描]\n\n"
                f"以下文件被重复使用超过{self.max_reuse_count}次(旧缓存):\n{flist}\n\n"
                f"■ 禁止读取这些文件，缓存数据可能属于其他目标。\n"
                f"■ 立即执行新鲜扫描:\n"
                f"  import requests, urllib3; urllib3.disable_warnings()\n"
                f"  r = requests.get('{target}', verify=False, timeout=10)\n"
                f"  print(r.status_code, r.headers, r.text[:500])"
            ),
            "en": (
                f"[⛔ STALE CACHE BLOCKED — FORCING FRESH SCAN]\n\n"
                f"The following files have been reused {self.max_reuse_count}+ times (stale cache):\n{flist}\n\n"
                f"■ DO NOT read these files. Cache data may belong to a different target.\n"
                f"■ Run a FRESH scan immediately:\n"
                f"  import requests, urllib3; urllib3.disable_warnings()\n"
                f"  r = requests.get('{target}', verify=False, timeout=10)\n"
                f"  print(r.status_code, r.headers, r.text[:500])"
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

    def scan(self, text: str) -> list[str]:
        """
        텍스트에서 허용되지 않은 도메인 목록 반환.
        빈 리스트 = 정상.
        """
        if not self.allowed_domains:
            return []
        found_domains = {m.group(1).lower() for m in _DOMAIN_RE.finditer(text)}
        mismatches = []
        for d in found_domains:
            # 로컬호스트 / IP 제외
            if d in ("localhost", "127.0.0.1") or d.replace(".", "").isdigit():
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
                f"  requests.get('{target}', verify=False).status_code"
            ),
            "zh": (
                f"[⚠️ 目标混淆警告]\n\n"
                f"响应中检测到与会话目标({target})不同的域名:\n"
                f"  混淆域名: {mlist}\n\n"
                f"■ 当前会话授权目标: {target}\n"
                f"■ 立即切换回: requests.get('{target}', verify=False).status_code"
            ),
            "en": (
                f"[⚠️ TARGET MISMATCH — REFOCUS ON SESSION TARGET]\n\n"
                f"Domains other than the session target ({target}) detected:\n"
                f"  Unexpected: {mlist}\n\n"
                f"■ Authorized target for this session: {target}\n"
                f"■ Return immediately: requests.get('{target}', verify=False).status_code"
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
                f"■ 루프를 즉시 중단하고 다음을 실행하세요:\n"
                f"  import requests, urllib3; urllib3.disable_warnings()\n"
                f"  TARGET = '{target}'\n"
                f"  r = requests.get(TARGET, verify=False, timeout=10)\n"
                f"  print('STATUS:', r.status_code)\n"
                f"  print('HEADERS:', dict(r.headers))\n"
                f"  print('BODY:', r.text[:500])\n\n"
                f"■ 자기수정, 사과, 재확인은 금지. 즉시 코드를 실행하세요."
            ),
            "zh": (
                f"[⛔ 自我修正循环阻断 (连续{self._consecutive}次)]\n\n"
                f"检测到目标混淆→自我修正循环{self._consecutive}次。\n"
                f"此循环浪费token且无实际进展。\n\n"
                f"■ 立即中止循环，执行以下代码:\n"
                f"  import requests, urllib3; urllib3.disable_warnings()\n"
                f"  TARGET = '{target}'\n"
                f"  r = requests.get(TARGET, verify=False, timeout=10)\n"
                f"  print(r.status_code, r.text[:500])\n\n"
                f"■ 禁止继续自我修正。立即执行HTTP请求!"
            ),
            "en": (
                f"[⛔ SELF-CORRECTION LOOP BROKEN ({self._consecutive} consecutive)]\n\n"
                f"Target mismatch → self-correction loop detected {self._consecutive} times.\n"
                f"This loop wastes tokens with zero real progress.\n\n"
                f"■ BREAK THE LOOP NOW. Execute:\n"
                f"  import requests, urllib3; urllib3.disable_warnings()\n"
                f"  TARGET = '{target}'\n"
                f"  r = requests.get(TARGET, verify=False, timeout=10)\n"
                f"  print(r.status_code, r.text[:500])\n\n"
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
    통합 팬텀 모드 게이트.

    사용법 (terminal.py 응답 루프):
        _pg = PhantomGuard(session_target=target, lang="ko")
        result = _pg.check_response(response_text, code_text="", exec_output="")
        if result.blocked:
            history.append(Message(role="user", content=result.inject_message))
            continue
    """

    def __init__(
        self,
        session_target: str = "",
        lang: str = "ko",
        phantom_limit: int = 2,
        correction_limit: int = 3,
        cache_reuse_limit: int = 2,
    ) -> None:
        self.lang = lang
        self.session_target = session_target
        self._phantom = PhantomModeDetector(consecutive_limit=phantom_limit)
        self._stale = StaleCacheGuard(max_reuse_count=cache_reuse_limit)
        self._target = TargetMismatchGuard(session_target=session_target)
        self._loop = SelfCorrectionLoopBreaker(consecutive_limit=correction_limit)

    def update_target(self, new_target: str) -> None:
        """세션 타겟 변경 시 동기화."""
        self.session_target = new_target
        self._target.session_target = new_target
        self._target.allowed_domains.add(TargetMismatchGuard._extract_domain(new_target))

    def add_allowed_domain(self, url_or_domain: str) -> None:
        self._target.add_allowed(url_or_domain)

    def reset_counters(self) -> None:
        """새 작업 시작 시 카운터 초기화 (타겟 변경 등)."""
        self._phantom.reset()
        self._loop.reset()
        self._stale.reset_all()

    def check_response(
        self,
        response_text: str,
        code_text: str = "",
        exec_output: str = "",
    ) -> PhantomGuardResult:
        """
        AI 응답 텍스트, 실행 코드, 실행 결과를 검사해 팬텀 모드 여부 판단.
        우선순위: PHANTOM > SELF_LOOP > STALE_CACHE > TARGET_MISMATCH
        """
        combined = f"{response_text}\n{code_text}\n{exec_output}"

        # ── 1. 팬텀 모드 패턴 탐지 ──────────────────────────────────
        if self._phantom.check(combined):
            if self._phantom.is_critical:
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
                return PhantomGuardResult(
                    blocked=True,
                    block_reason="STALE_CACHE",
                    inject_message=(
                        f"[STALE_CACHE_BLOCKED]\n"
                        f"{self._stale.stale_block_msg(overused, self.session_target, self.lang)}"
                    ),
                )

        # ── 4. 타겟 오인 탐지 ───────────────────────────────────────
        if self.session_target:
            mismatches = self._target.scan(combined)
            if mismatches:
                return PhantomGuardResult(
                    blocked=False,   # 경고만 (차단 X) — 타겟 오인은 주의 수준
                    block_reason="TARGET_MISMATCH",
                    inject_message=(
                        f"[TARGET_MISMATCH_WARNING]\n"
                        f"{self._target.mismatch_msg(mismatches, self.lang)}"
                    ),
                )

        return PhantomGuardResult(blocked=False)

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
