"""
ExecutionAnchor — 실행 결과 앵커링 엔진 v1.0.0
================================================
원칙: LLM 출력은 반드시 직접 실행한 결과에만 기반해야 한다.
      추측 언어("아마도", "可能", "probably") + 기술 주장 = 즉시 차단.
      실행 증거 없는 기술 주장 = 즉시 차단.
      채팅 모드, 오케스트레이터 모드, 모든 모듈에 동일 적용.

3-Layer 시스템:
  Layer A: SpeculationLanguageFilter
    — 추측 언어 + 기술 주장 조합을 감지해 즉시 차단
    — "아마도 SQLi가 있을 것 같습니다" → BLOCKED
    — "SQLi를 발견했습니다. 증거: [200/..." → ALLOWED

  Layer B: UnexecutedClaimBlocker
    — exec_output 없이 기술 주장 = 실행하지 않은 채 말하는 것 = 차단
    — "이 사이트에 XSS가 있습니다" (실행 출력 없음) → BLOCKED
    — "실행 결과: STATUS 200, body에 <script> 반영 확인" → ALLOWED

  Layer C: ExecutionAnchorEngine (통합 파이프라인)
    — Layer A → Layer B 순서 실행
    — PhantomGuard.check_response() 이후에 적용 (중복 탐지 방지)
    — chat_mode=True 시 exec_output 없이 기술 주장도 차단

설계 의도:
  기존 ZeroHalEngine v5 (ClaimAnchorValidator, ZeroHttpClaimGuard) 는
  취약점 발견 "주장"에 초점. 이 모듈은 추측 언어 자체를 하드 블록.
  → 두 시스템이 상호 보완적으로 동작.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional


# ══════════════════════════════════════════════════════════════════════════════
# 추측 언어 패턴 — 단독 OK, 기술 주장과 함께 나타나면 BLOCK
# ══════════════════════════════════════════════════════════════════════════════

_SPECULATION_PATTERNS: list[str] = [
    # ── 한국어 ──
    r'\b아마도\b',
    r'\b아마\s+(?=\S)',               # "아마 SQL" 형태
    r'\b것\s*같(?:다|습니다|아요|네요|은데|아서|으니)',
    r'\b것\s*으로\s*(?:보입니다|생각됩니다|판단됩니다)',
    r'\b가능성이\s*(?:있|높|있을)',
    r'\b(?:있을|존재할|발견될)\s*(?:수\s*있|것\s*같)',
    r'\b(?:취약할|취약한)\s*(?:것\s*같|가능성)',
    r'\b추측(?:됩니다|컨대|하건대)?\b',
    r'\b(?:일\s*것|있을\s*것|존재할\s*것)\s*(?:같습니다|이라고\s*생각)',
    r'\b(?:발견될|노출될|존재할)\s*수\s*있',
    r'\b보입니다\b',
    r'\b판단됩니다\b',
    r'\b예상됩니다\b',
    r'\b생각됩니다\b',
    r'\b(?:~일|~있을|~존재)\s*수\s*있',
    r'\b(?:할\s*것\s*같|될\s*것\s*같)\b',
    r'\b(?:있어\s*보|있는\s*것\s*같)(?:이|)\b',

    # ── 영문 ──
    r'\bprobably\b',
    r'\blikely\b',
    r'\bmight\s+(?:be|have|contain|exist|indicate)',
    r'\bmay\s+(?:be|have|contain|exist|indicate)',
    r'\bcould\s+(?:be|have|contain|exist|indicate)',
    r'\bpossibly\b',
    r'\bperhaps\b',
    r'\bseems?\s+(?:to\s+)?(?:be|have|indicate)',
    r'\bappears?\s+(?:to\s+)?(?:be|have|indicate)',
    r'\bI\s+(?:think|believe|suspect|assume|guess)',
    r'\bsuggests?\s+(?:that\s+)?(?:there|it|this)',
    r'\bpotentially\b',
    r'\bcould\s+indicate\b',
    r'\bwould\s+(?:suggest|indicate|imply)',
    r'\bseems\s+vulnerable\b',
    r'\blooks?\s+(?:like|vulnerable)',
    r'\bthis\s+(?:could|might|may)\s+be',

    # ── 중국어 ──
    r'可能(?:存在|有|是|含有|导致|引起)',
    r'也许(?:存在|有|是|可以)',
    r'应该(?:存在|有|是|可以)',
    r'似乎(?:存在|有|是|存在)',
    r'看起来(?:像|是|有|存在)',
    r'我(?:认为|觉得|猜测|估计)',
    r'疑似(?:存在|有|是)',
    r'估计(?:存在|有|是)',
    r'推测(?:为|是|存在)',
    r'感觉(?:存在|有|是)',
]

_COMPILED_SPECULATION = [re.compile(p, re.IGNORECASE) for p in _SPECULATION_PATTERNS]


# ══════════════════════════════════════════════════════════════════════════════
# 기술 주장 패턴 — 보안 관련 구체적 주장
# ══════════════════════════════════════════════════════════════════════════════

_TECH_CLAIM_PATTERNS: list[str] = [
    # ── 취약점 유형 — \b 대신 공백/특수문자/문장끝/한국어조사 허용 경계 사용
    r'(?:SQL\s*[Ii]njection|SQLi|SQL인젝션|SQL\s*주입)',
    r'(?:XSS|Cross\s*[Ss]ite\s*[Ss]cripting|크로스\s*사이트\s*스크립팅)',
    r'(?:RCE|Remote\s*Code\s*Execution|원격\s*코드\s*실행)',
    r'(?:SSRF|Server\s*[Ss]ide\s*Request\s*Forgery)',
    r'(?:IDOR|Insecure\s*Direct\s*Object)',
    r'(?:LFI|RFI|Local\s*File\s*Inclusion|Remote\s*File\s*Inclusion)',
    r'(?:XXE|XML\s*External\s*Entity)',
    r'(?:CSRF|Cross\s*[Ss]ite\s*Request\s*Forgery)',
    r'Command\s*[Ii]njection',
    r'(?:인증\s*우회|Authentication\s*[Bb]ypass|认证绕过)',
    r'(?:권한\s*상승|Privilege\s*[Ee]scalation|权限提升)',
    r'(?:파일\s*업로드\s*취약|File\s*upload\s*vuln|文件上传漏洞)',
    # ── 보안 결론 주장
    r'(?:취약점|vulnerability|vuln|漏洞)\s*(?:발견|존재|확인|있|detected|found|exists)',
    r'(?:취약하다|취약합니다|vulnerable|易受攻击)',
    r'(?:어드민|관리자|管理员)\s*(?:패널|panel|页面)\s*(?:접근|access|访问)',
    r'(?:로그인\s*성공|인증\s*성공|login\s*success|认证成功)',
    r'(?:크리덴셜|자격\s*증명|credential)\s*(?:획득|발견|추출|found|extracted|obtained)',
    # ── HTTP 수치 주장
    r'HTTP\s*[45]\d{2}',
    r'(?:상태\s*코드|status\s*code|状态码)\s*[=:]\s*\d{3}',
    r'포트\s*\d+\s*(?:열림|open|开放)',
    # ── 보안 평가 주장
    r'(?:안전하지\s*않|insecure|不安全)\s*(?:하다|합니다|한\s)',
    r'(?:노출|exposed|暴露)\s*(?:되어|되었|있)',
    r'(?:취약\s*점수|CVSS)\s*\d',
    # ── 한국어 취약점 발견 직접 표현
    r'취약점이\s*(?:있|존재|발견)',
    r'취약점을\s*(?:발견|확인)',
    r'인젝션이\s*(?:있|존재|가능)',
    r'해킹이\s*(?:가능|됩니다)',
    r'취약(?:하다|합니다|한\s|할\s)',      # "취약할 것으로", "취약한 파라미터"
    r'취약\s*(?:할|한|하다|합니다)',
    # ── 중국어 취약점 표현 (한자)
    r'SQL\s*注入',                         # SQL注入, SQL 注入
    r'XSS\s*漏洞',
    r'远程\s*代码\s*执行',                  # RCE
    r'命令\s*注入',                         # Command Injection
    r'漏洞\s*(?:存在|被发现|发现|确认)',
    r'存在\s*(?:漏洞|注入|安全)',
    r'注入\s*漏洞',
    r'绕过\s*认证',
    r'权限\s*提升',
    r'文件\s*上传\s*漏洞',
]

_COMPILED_TECH_CLAIMS = [re.compile(p, re.IGNORECASE) for p in _TECH_CLAIM_PATTERNS]

_DEFINITE_CLAIM_PATTERNS = [
    re.compile(
        r'(?:SQLi?|SQL\s*injection|XSS|RCE|SSRF|IDOR|LFI|XXE|CSRF)'
        r'.{0,50}(?:confirmed|verified|found|detected|exploitable|취약|확인|발견|存在|确认|发现)',
        re.IGNORECASE,
    ),
    re.compile(
        r'(?:vulnerability|vuln|취약점|漏洞).{0,40}'
        r'(?:confirmed|verified|found|detected|exists|확인|발견|존재|确认|发现|存在)',
        re.IGNORECASE,
    ),
    re.compile(
        r'(?:attack|exploit|bypass|login|공격|우회|로그인|攻击|绕过|登录)'
        r'.{0,40}(?:successful|succeeded|success|성공|成功)',
        re.IGNORECASE,
    ),
    re.compile(
        r'(?:credential|password|hash|자격증명|비밀번호|凭据|密码)'
        r'.{0,40}(?:extracted|obtained|found|추출|획득|발견|提取|获取|发现)',
        re.IGNORECASE,
    ),
]


# ══════════════════════════════════════════════════════════════════════════════
# 실행 증거 패턴 — exec_output에서 실제 실행 여부 확인
# ══════════════════════════════════════════════════════════════════════════════

_EXEC_EVIDENCE_PATTERNS: list[str] = [
    r'\[\d{3}/\d+[BKM]?\]',              # [200/34610B] — bingo scanner 형식
    r'\bSTATUS[:：\s_\-]+\d{3}\b',        # STATUS: 200
    r'HTTP/[12](?:\.\d)?\s+\d{3}',       # HTTP/1.1 200
    r'<Response\s*\[\d{3}\]>',           # <Response [200]>
    r'\bstatus_code\s*[=:]\s*\d{3}\b',   # status_code = 200
    r'\[\d+/\d+\]\s+\[',                 # [001/63] [200/...] (bingo 대량 스캔)
    r'\bPORT\s+\d+\s+(?:OPEN|CLOSED)',  # PORT 80 OPEN (포트 스캔 결과)
    r'\[\d{3}\]\s+\d+\s+bytes',         # [200] 12345 bytes
    r'---HTTP_STATUS:\d{3}---SIZE:\d+---TIME:',
    r'=== RUNTIME_RESULT:[\s\S]{0,240}?exit_code=0',
]

_COMPILED_EXEC_EVIDENCE = [re.compile(p, re.IGNORECASE) for p in _EXEC_EVIDENCE_PATTERNS]


def _has_speculation(text: str) -> bool:
    """추측 언어 감지."""
    for pat in _COMPILED_SPECULATION:
        if pat.search(text):
            return True
    return False


def _has_tech_claim(text: str) -> bool:
    """기술 보안 주장 감지."""
    for pat in _COMPILED_TECH_CLAIMS:
        if pat.search(text):
            return True
    return False


def _has_definite_claim(text: str) -> bool:
    """Return True only for a claimed result, not an attack hypothesis."""
    return any(pattern.search(text) for pattern in _DEFINITE_CLAIM_PATTERNS)


def _has_exec_evidence(exec_output: str) -> bool:
    """exec_output에 실제 실행 증거가 있으면 True."""
    if not exec_output.strip():
        return False
    for pat in _COMPILED_EXEC_EVIDENCE:
        if pat.search(exec_output):
            return True
    return False


# ══════════════════════════════════════════════════════════════════════════════
# AnchorResult — 앵커링 검사 결과
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class AnchorResult:
    blocked: bool = False
    warned: bool = False
    block_reason: str = ""           # "SPECULATION_CLAIM" | "UNEXECUTED_CLAIM"
    inject_message: Optional[str] = None


# ══════════════════════════════════════════════════════════════════════════════
# Layer A: SpeculationLanguageFilter
# ══════════════════════════════════════════════════════════════════════════════

class SpeculationLanguageFilter:
    """
    추측 언어 + 기술 주장 조합 감지 → 즉시 차단.

    판단 기준:
      - 추측 언어가 있고
      - 같은 응답에 기술적 보안 주장이 있으면
      → BLOCK: 실행 없이 추측으로 보안 결론을 내리는 것 = 환각

    예외 (허용):
      - 추측 언어만 (기술 주장 없음) → 일반 설명 가능
      - 기술 주장만 (추측 언어 없음) → exec_output이 있으면 정상
    """

    def check(self, response_text: str) -> bool:
        """True = 차단 필요."""
        return _has_speculation(response_text) and _has_tech_claim(response_text)

    def block_msg(self, target: str, lang: str = "ko") -> str:
        msgs = {
            "ko": (
                "[⛔ 실행 앵커 차단 — 추측 언어 + 기술 주장 감지]\n\n"
                "응답에 추측 언어(아마도/것 같다/가능성이/보입니다)와\n"
                "기술 보안 주장(SQLi/XSS/취약점/상태코드)이 동시에 감지됐습니다.\n\n"
                "■ 이것은 0-환각 위반입니다. 직접 실행 없이 보안 결론을 내리는 것은 환각입니다.\n"
                "■ 금지 예시: '아마도 SQLi가 있을 것 같습니다'\n"
                "■ 금지 예시: 'XSS가 존재할 가능성이 높습니다'\n"
                "■ 금지 예시: '이 파라미터는 취약할 것으로 보입니다'\n\n"
                "■ 올바른 방법: 추측 없이 즉시 bash+curl로 실행하고 결과로만 말하십시오:\n\n"
                f"  curl -sk -m 10 -D - '{target}' | python3 -c \\"
                f"\"import sys; r=sys.stdin.read(); print(r[:500])\"\n\n"
                "■ 실행 결과가 나온 후, 그 결과만으로 말하십시오. 추측 언어 금지."
            ),
            "zh": (
                "[⛔ 执行锚定拦截 — 检测到推测语言+技术声明]\n\n"
                "响应中同时出现推测语言(可能/也许/似乎/我认为)和\n"
                "技术安全声明(SQLi/XSS/漏洞/状态码)。\n\n"
                "■ 这违反了零幻觉规则。在没有实际执行的情况下得出安全结论即为幻觉。\n"
                "■ 禁止示例: '可能存在SQL注入'\n"
                "■ 禁止示例: 'XSS漏洞存在的可能性较高'\n"
                "■ 禁止示例: '此参数看起来存在漏洞'\n\n"
                "■ 正确方式: 无推测，用bash+curl直接执行，仅依据结果陈述:\n\n"
                f"  curl -sk -m 10 '{target}' | python3 -c "
                f"\"import sys; r=sys.stdin.read(); print(r[:500])\"\n\n"
                "■ 仅根据执行结果进行陈述。禁止推测。"
            ),
            "en": (
                "[⛔ EXECUTION ANCHOR BLOCK — Speculation + Technical Claim Detected]\n\n"
                "Response contains BOTH speculation language (probably/might/seems/likely)\n"
                "AND technical security claims (SQLi/XSS/vulnerability/status codes).\n\n"
                "■ This VIOLATES the zero-hallucination rule.\n"
                "■ FORBIDDEN: 'there might be SQLi here'\n"
                "■ FORBIDDEN: 'XSS vulnerability likely exists'\n"
                "■ FORBIDDEN: 'this parameter seems vulnerable'\n\n"
                "■ CORRECT: No guessing. Execute with bash+curl and report ONLY actual results:\n\n"
                f"  curl -sk -m 10 -D - '{target}' | python3 -c "
                f"\"import sys; r=sys.stdin.read(); print(r[:500])\"\n\n"
                "■ Report ONLY from actual execution results. NO speculation."
            ),
        }
        return msgs.get(lang, msgs["en"])


# ══════════════════════════════════════════════════════════════════════════════
# Layer B: UnexecutedClaimBlocker
# ══════════════════════════════════════════════════════════════════════════════

class UnexecutedClaimBlocker:
    """
    실행 출력(exec_output)이 없는데 기술 보안 주장이 있으면 차단.

    적용 조건:
      exec_output이 비어 있고 + 기술 주장이 있으면 → BLOCK

    제외 조건 (차단하지 않음):
      exec_output이 있으면 → ZeroHalEngine v5 (ClaimAnchorValidator)가 처리
      → 중복 차단 방지

    예시:
      exec_output=""  + response="이 사이트에 XSS가 있습니다" → BLOCKED
      exec_output="STATUS:200\n..." + response="XSS 발견" → ZeroHalEngine이 처리
    """

    def check(self, response_text: str, exec_output: str) -> bool:
        """True = 차단 필요."""
        # exec_output이 있으면 ZeroHalEngine이 처리 → 여기서는 스킵
        if _has_exec_evidence(exec_output):
            return False
        # 공격 가설/테스트 계획은 허용하고, 실행 결과를 단정한 경우만 차단한다.
        return _has_definite_claim(response_text)

    def block_msg(self, target: str, lang: str = "ko") -> str:
        msgs = {
            "ko": (
                "[⛔ 미실행 주장 차단 — 실행 증거 없이 기술 주장 감지]\n\n"
                "실행 출력(execution output)이 없는데 기술 보안 주장이 감지됐습니다.\n\n"
                "■ 이것은 0-환각 위반입니다.\n"
                "■ 모든 기술적 보안 주장(SQLi/XSS/취약점/상태코드 등)은\n"
                "  반드시 직접 실행 결과에 기반해야 합니다.\n"
                "■ 실행 결과 없이 이야기하는 것은 '말만 하는 것(unexecuted claim)'입니다.\n\n"
                "■ 즉시 bash+curl로 실행하고 결과를 확인하십시오:\n\n"
                f"  curl -sk -m 10 -D - '{target}' | python3 -c "
                f"\"import sys; r=sys.stdin.read(); print(r[:500])\"\n\n"
                "■ 위 curl 명령을 실행한 후, 그 출력만으로 보안 판단을 내리십시오."
            ),
            "zh": (
                "[⛔ 未执行声明拦截 — 无执行证据的技术声明]\n\n"
                "在没有执行输出的情况下检测到技术安全声明。\n\n"
                "■ 这违反了零幻觉规则。\n"
                "■ 所有技术安全声明(SQLi/XSS/漏洞/状态码等)\n"
                "  必须基于实际执行结果。\n"
                "■ 没有执行结果的声明是'空口声明(unexecuted claim)'。\n\n"
                "■ 立即用bash+curl执行并验证结果:\n\n"
                f"  curl -sk -m 10 '{target}' | python3 -c "
                f"\"import sys; r=sys.stdin.read(); print(r[:500])\"\n\n"
                "■ 仅根据curl执行输出做出安全判断。"
            ),
            "en": (
                "[⛔ UNEXECUTED CLAIM BLOCKED — Technical Claim Without Execution Evidence]\n\n"
                "Technical security claims detected with NO execution output present.\n\n"
                "■ This VIOLATES the zero-hallucination rule.\n"
                "■ ALL technical security claims (SQLi/XSS/vulnerability/status codes)\n"
                "  MUST be based on direct execution results.\n"
                "■ Making claims without execution output is an 'unexecuted claim' — FORBIDDEN.\n\n"
                "■ Execute immediately with bash+curl and verify:\n\n"
                f"  curl -sk -m 10 -D - '{target}' | python3 -c "
                f"\"import sys; r=sys.stdin.read(); print(r[:500])\"\n\n"
                "■ Make security judgments ONLY from the curl execution output above."
            ),
        }
        return msgs.get(lang, msgs["en"])


# ══════════════════════════════════════════════════════════════════════════════
# Layer C: ExecutionAnchorEngine (통합 파이프라인)
# ══════════════════════════════════════════════════════════════════════════════

class ExecutionAnchorEngine:
    """
    실행 결과 앵커링 통합 파이프라인.

    모든 LLM 응답 경로에 적용:
      - chat_mode (채팅 모드)
      - orchestrator_mode (오케스트레이터 모드)
      - 취약점 스캐너 모듈
      - 기타 모든 LLM 출력

    사용법 (engine.py 또는 terminal.py):
        _anchor = ExecutionAnchorEngine(session_target=target, lang="ko")

        # PhantomGuard.check_response() 이후에 호출
        anchor_result = _anchor.check(
            response_text=llm_response,
            exec_output=execution_output,  # 없으면 ""
        )
        if anchor_result.blocked:
            # 차단 메시지를 LLM에 다시 주입
            history.append(Message(role="user", content=anchor_result.inject_message))

    통계:
        _anchor.stats()  → 차단 현황 반환
    """

    def __init__(
        self,
        session_target: str = "",
        lang: str = "ko",
    ) -> None:
        self._target = session_target
        self._lang = lang
        self._speculation_filter = SpeculationLanguageFilter()
        self._unexecuted_blocker = UnexecutedClaimBlocker()
        # 통계
        self._speculation_blocks: int = 0
        self._unexecuted_blocks: int = 0
        self._total_checked: int = 0

    def update_target(self, new_target: str) -> None:
        """세션 타겟 변경 시 동기화."""
        self._target = new_target

    def check(
        self,
        response_text: str,
        exec_output: str = "",
    ) -> AnchorResult:
        """
        LLM 응답을 검사하고 AnchorResult 반환.

        우선순위:
          1. UNEXECUTED_CLAIM — 실행 증거 없는 확정 주장
          2. HYPOTHESIS       — 공격 가설은 허용하되 즉시 검증 요구

        Args:
            response_text: LLM 응답 텍스트 전체
            exec_output:   직전 코드 실행 출력 (없으면 빈 문자열)

        Returns:
            AnchorResult(blocked=True/False, block_reason=..., inject_message=...)
        """
        self._total_checked += 1

        # ── Layer A: 실행 증거 없는 확정 주장 ───────────────────────────────
        if self._unexecuted_blocker.check(response_text, exec_output):
            self._unexecuted_blocks += 1
            return AnchorResult(
                blocked=True,
                block_reason="UNEXECUTED_CLAIM",
                inject_message=(
                    "[EXECUTION_ANCHOR: UNEXECUTED_CLAIM]\n"
                    + self._unexecuted_blocker.block_msg(self._target, self._lang)
                ),
            )

        # ── Layer B: 공격 가설은 차단하지 않고 실행 검증을 요구 ─────────────
        if self._speculation_filter.check(response_text):
            self._speculation_blocks += 1
            return AnchorResult(
                blocked=False,
                warned=True,
                block_reason="HYPOTHESIS_REQUIRES_TEST",
                inject_message=(
                    "[EXECUTION_ANCHOR: HYPOTHESIS_ACCEPTED]\n"
                    "Keep this attack hypothesis and execute a type-specific positive/negative "
                    "control now. Do not claim confirmation and do not abandon the vector."
                ),
            )

        return AnchorResult(blocked=False)

    def stats(self) -> dict:
        """통계 딕셔너리 반환."""
        return {
            "total_checked": self._total_checked,
            "speculation_blocks": self._speculation_blocks,
            "unexecuted_blocks": self._unexecuted_blocks,
            "total_blocks": self._speculation_blocks + self._unexecuted_blocks,
        }

    def stats_banner(self, lang: str = "ko") -> str:
        """통계 배너 문자열 반환."""
        s = self.stats()
        msgs = {
            "ko": (
                f"[ExecutionAnchor v1.0.0 통계]\n"
                f"  검사: {s['total_checked']}회 | "
                f"추측차단: {s['speculation_blocks']}회 | "
                f"미실행차단: {s['unexecuted_blocks']}회 | "
                f"총차단: {s['total_blocks']}회"
            ),
            "zh": (
                f"[ExecutionAnchor v1.0.0 统计]\n"
                f"  检查: {s['total_checked']}次 | "
                f"推测拦截: {s['speculation_blocks']}次 | "
                f"未执行拦截: {s['unexecuted_blocks']}次 | "
                f"总拦截: {s['total_blocks']}次"
            ),
            "en": (
                f"[ExecutionAnchor v1.0.0 Stats]\n"
                f"  Checked: {s['total_checked']} | "
                f"SpeculationBlocks: {s['speculation_blocks']} | "
                f"UnexecutedBlocks: {s['unexecuted_blocks']} | "
                f"TotalBlocks: {s['total_blocks']}"
            ),
        }
        return msgs.get(lang, msgs["en"])


# ══════════════════════════════════════════════════════════════════════════════
# 편의 함수 — 빠른 단일 검사
# ══════════════════════════════════════════════════════════════════════════════

def is_speculative_technical_claim(text: str) -> bool:
    """
    빠른 단일 검사: 추측 언어 + 기술 주장이 있으면 True.
    PhantomGuard 없이 단독으로 호출 가능.
    """
    return _has_speculation(text) and _has_tech_claim(text)


def has_exec_evidence(exec_output: str) -> bool:
    """빠른 단일 검사: exec_output에 실행 증거가 있으면 True."""
    return _has_exec_evidence(exec_output)
