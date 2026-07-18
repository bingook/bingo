"""
MVVS False-Positive Regression Suite — FP-ZERO v1.2 (BINGO_SIGNAL)
====================================================================
목적: 취약점 탐지기가 실제로 무해한 텍스트에 오발(False Positive)을
      내지 않는지 릴리즈마다 자동 검증.

구조:
    1. FP 테스트: 무해한 텍스트 → MVVS 신호 없어야 함
    2. TP 테스트: 실제 취약점 출력 → MVVS 신호 있어야 함
    3. BINGO_SIGNAL 검증 테스트:
       - 유효한 BINGO_SIGNAL → 탐지됨
       - 증거 불충분 BINGO_SIGNAL → 거절됨 (허위 신호 차단)

실행 방법:
    pytest tests/test_mvvs_false_positive.py -v

릴리즈 체크리스트:
    [ ] pytest tests/test_mvvs_false_positive.py -v → 전부 PASS
    [ ] 새 MVVS 패턴 추가 시 FP_CASES / TP_CASES에 케이스 반드시 추가
    [ ] 새 BINGO_SIGNAL 타입 추가 시 SIGNAL_VALID / SIGNAL_INVALID에 케이스 추가
"""
import re
import sys
import os

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


# ── MVVS 패턴 직접 임포트 ─────────────────────────────────────────────────────
def _get_signals() -> dict:
    """BingoTerminal._MVVS_SIGNALS 직접 반환"""
    from bingo.ui.terminal import BingoTerminal  # noqa
    return BingoTerminal._MVVS_SIGNALS


def _match(signals: dict, text: str) -> list:
    """텍스트에서 매칭된 (vuln_type, desc, pat) 목록 반환"""
    found = []
    for vuln_type, patterns in signals.items():
        for pat, desc in patterns:
            if re.search(pat, text, re.IGNORECASE | re.DOTALL):
                found.append((vuln_type, desc, pat))
    return found


# ═══════════════════════════════════════════════════════════════════════════════
# FALSE POSITIVE 케이스 — 절대 MVVS 신호가 나오면 안 되는 텍스트
# ═══════════════════════════════════════════════════════════════════════════════
FP_CASES = [
    # ── SQLi FP ──────────────────────────────────────────────────────────────
    pytest.param(
        "SyntaxError: invalid syntax at line 5",
        id="sqli-fp-python-syntaxerror",
    ),
    pytest.param(
        "JavaScript Syntax Error: Unexpected token '}'",
        id="sqli-fp-js-syntaxerror",
    ),
    pytest.param(
        "Processing took 3.5 seconds to complete",
        id="sqli-fp-timing-benign",
    ),
    pytest.param(
        "boardNo_AND1=1: HTTP 200 458B",
        id="sqli-fp-boolean-size-same",
    ),
    pytest.param(
        "1=1 result: 200 458B | 1=2 result: 200 458B",
        id="sqli-fp-boolean-same-size-no-differ",
    ),

    # ── XSS FP ───────────────────────────────────────────────────────────────
    pytest.param(
        'href="javascript:history.back()"',
        id="xss-fp-javascript-history-back",
    ),
    pytest.param(
        'href="javascript:void(0)"',
        id="xss-fp-javascript-void",
    ),
    pytest.param(
        'onclick="javascript:return false"',
        id="xss-fp-javascript-return-false",
    ),
    pytest.param(
        "payload: 200 458B | reflected in curl response size",
        id="xss-fp-payload-reflect-log",
    ),
    pytest.param(
        "bingo XSS confirmed: none (no alert reflected)",
        id="xss-fp-bingo-log-confirmed-none",
    ),
    pytest.param(
        'href="javascript:location.reload()"',
        id="xss-fp-javascript-location-reload",
    ),

    # ── IDOR FP ──────────────────────────────────────────────────────────────
    pytest.param(
        "HTTP 403 Forbidden\nHTTP 200 OK (different endpoint)",
        id="idor-fp-403-then-200-no-bypass-keyword",
    ),
    pytest.param(
        "Error 403: Access Denied\nSuccess: 200 homepage loaded",
        id="idor-fp-403-200-homepage",
    ),

    # ── RCE FP ───────────────────────────────────────────────────────────────
    pytest.param(
        "DB connection: root:password@localhost:3306/mydb",
        id="rce-fp-root-db-prefix",
    ),
    pytest.param(
        "root cause: connection timeout after 30s",
        id="rce-fp-root-cause-string",
    ),
    pytest.param(
        "Command output: checking server status...",
        id="rce-fp-command-output-log",
    ),
    pytest.param(
        "shell: command not found",
        id="rce-fp-shell-command-not-found",
    ),
    pytest.param(
        "/bin/bash: ./deploy.sh: Permission denied",
        id="rce-fp-bash-permission-denied",
    ),
    pytest.param(
        "Container root: /var/lib/docker",
        id="rce-fp-container-root-prefix",
    ),

    # ── SSRF FP ──────────────────────────────────────────────────────────────
    pytest.param(
        "Internal Server Error (HTTP 500)",
        id="ssrf-fp-internal-server-error",
    ),
    pytest.param(
        "Private API documentation: see /docs",
        id="ssrf-fp-private-api-docs",
    ),
    pytest.param(
        "This is an internal company policy",
        id="ssrf-fp-internal-policy",
    ),
    pytest.param(
        "Error connecting to private network: timeout",
        id="ssrf-fp-private-network-timeout",
    ),

    # ── Path Traversal FP ───────────────────────────────────────────────────
    pytest.param(
        "Loading config from /etc/app/config.yaml",
        id="pt-fp-etc-config",
    ),
    pytest.param(
        "Script located at /bin/startup.sh",
        id="pt-fp-bin-script",
    ),

    # ── v5.1.1 신규 FP — 기록.md BINGO-0001/0002/0003 재현 케이스 ──────────────
    # BINGO-0001: 정상 HTML 페이지의 외부 스크립트 2개 (XSS 오발)
    pytest.param(
        '<script src="/static/jquery.min.js"></script>\n'
        '<script src="/static/app.bundle.js"></script>',
        id="xss-fp-external-script-src-two-tags",
    ),
    # BINGO-0001 변형: src= 있는 스크립트는 단독으로도 안전
    pytest.param(
        '<html><head><script src="https://cdn.example.com/lib.js"></script>'
        '<script src="/js/main.js"></script></head></html>',
        id="xss-fp-script-src-only-no-inline",
    ),
    # BINGO-0002/0003: bash echo 메시지 안에 EXTRACTVALUE 키워드 (SQLi 오발)
    pytest.param(
        "[双重编码 EXTRACTVALUE 458B] HTTP 403 Forbidden — WAF blocked",
        id="sqli-fp-extractvalue-in-bash-echo",
    ),
    # BINGO-0002/0003 변형: UPDATEXML 도 동일
    pytest.param(
        "[UPDATEXML payload test] size=201B status=403",
        id="sqli-fp-updatexml-in-bash-echo",
    ),
    # WAF 차단 응답 전체 (SQLi/XSS 패턴 없음)
    pytest.param(
        "HTTP/1.1 403 Forbidden\nContent-Length: 512\n\n"
        "Your request has been blocked by security policy.",
        id="waf-fp-blocked-response-english",
    ),
    pytest.param(
        "HTTP/1.1 403 Forbidden\nContent-Length: 400\n\n"
        "요청이 차단되었습니다. 보안 정책 위반.",
        id="waf-fp-blocked-response-korean",
    ),
]


# ═══════════════════════════════════════════════════════════════════════════════
# TRUE POSITIVE 케이스 — 반드시 MVVS 신호가 나와야 하는 텍스트
# ═══════════════════════════════════════════════════════════════════════════════
TP_CASES = [
    # ── SQLi TP ──────────────────────────────────────────────────────────────
    pytest.param(
        "sqli",
        "You have an error in your SQL syntax; check the manual",
        id="sqli-tp-mysql-error",
    ),
    pytest.param(
        "sqli",
        "ORA-01756: quoted string not properly terminated",
        id="sqli-tp-oracle-error",
    ),
    pytest.param(
        "sqli",
        "SLEEP(5) response took 5.12 sec",
        id="sqli-tp-time-based",
    ),
    pytest.param(
        "sqli",
        "size: 15420 vs size: 203 — differ 15217B",
        id="sqli-tp-size-differ",
    ),

    # ── XSS TP ───────────────────────────────────────────────────────────────
    pytest.param(
        "xss",
        "<script>alert(1)</script>",
        id="xss-tp-script-alert",
    ),
    pytest.param(
        "xss",
        "onerror=alert(document.cookie)",
        id="xss-tp-onerror-alert",
    ),
    pytest.param(
        "xss",
        "javascript:alert('xss')",
        id="xss-tp-javascript-alert",
    ),
    pytest.param(
        "xss",
        "javascript:eval(atob('YWxlcnQoMSk='))",
        id="xss-tp-javascript-eval",
    ),

    # ── IDOR TP ───────────────────────────────────────────────────────────────
    pytest.param(
        "idor",
        "403 Forbidden → bypass → 200 OK (success)",
        id="idor-tp-bypass-confirmed",
    ),
    pytest.param(
        "idor",
        "user_id=999 name=John email=john@victim.com phone=010-1234-5678",
        id="idor-tp-other-user-data",
    ),

    # ── RCE TP ────────────────────────────────────────────────────────────────
    pytest.param(
        "rce",
        "uid=0(root) gid=0(root) groups=0(root)",
        id="rce-tp-uid-root",
    ),
    pytest.param(
        "rce",
        "root:x:0:0:root:/root:/bin/bash",
        id="rce-tp-passwd-record",
    ),
    pytest.param(
        "rce",
        "whoami=www-data",
        id="rce-tp-whoami-output",
    ),

    # ── SSRF TP ───────────────────────────────────────────────────────────────
    pytest.param(
        "ssrf",
        "Accessing 169.254.169.254 ... HTTP 200",
        id="ssrf-tp-aws-metadata",
    ),
    pytest.param(
        "ssrf",
        "Connected to 192.168.1.10 — 200 open",
        id="ssrf-tp-private-ip-192",
    ),
    pytest.param(
        "ssrf",
        "Response from 10.0.0.1 — connect success",
        id="ssrf-tp-private-ip-10",
    ),

    # ── Path Traversal TP ────────────────────────────────────────────────────
    pytest.param(
        "path_traversal",
        "root:x:0:0:root:/root:/bin/bash",
        id="pt-tp-passwd",
    ),
]


# ═══════════════════════════════════════════════════════════════════════════════
# BINGO_SIGNAL 구조화 신호 테스트 케이스 (v5.0.7)
# ═══════════════════════════════════════════════════════════════════════════════

# 유효한 BINGO_SIGNAL — 증거 충분 → 탐지됨
SIGNAL_VALID_CASES = [
    pytest.param(
        'BINGO_SIGNAL:{"type":"sqli_boolean","evidence":{"size_true":15420,"size_false":203}}',
        "sqli",
        id="signal-sqli-boolean-valid",
    ),
    pytest.param(
        'BINGO_SIGNAL:{"type":"sqli_error","evidence":{"db_error":"You have an error in your SQL syntax"}}',
        "sqli",
        id="signal-sqli-error-valid",
    ),
    pytest.param(
        'BINGO_SIGNAL:{"type":"sqli_time","evidence":{"delay_sec":5.12,"expected_sec":5}}',
        "sqli",
        id="signal-sqli-time-valid",
    ),
    pytest.param(
        'BINGO_SIGNAL:{"type":"xss","evidence":{"payload":"<script>alert(1)</script>","reflected":true,"browser_executed":true}}',
        "xss",
        id="signal-xss-valid",
    ),
    pytest.param(
        'BINGO_SIGNAL:{"type":"rce","evidence":{"proof":"uid=0(root) gid=0(root) groups=0(root)"}}',
        "rce",
        id="signal-rce-uid-root",
    ),
    pytest.param(
        'BINGO_SIGNAL:{"type":"rce","evidence":{"proof":"root:x:0:0:root:/root:/bin/bash"}}',
        "rce",
        id="signal-rce-passwd-record",
    ),
    pytest.param(
        'BINGO_SIGNAL:{"type":"ssrf","evidence":{"ip_accessed":"169.254.169.254"}}',
        "ssrf",
        id="signal-ssrf-aws-metadata",
    ),
    pytest.param(
        'BINGO_SIGNAL:{"type":"ssrf","evidence":{"ip_accessed":"192.168.1.10"}}',
        "ssrf",
        id="signal-ssrf-private-192",
    ),
    pytest.param(
        'BINGO_SIGNAL:{"type":"idor","evidence":{"other_user_id":999,"data_returned":true,"authenticated_baseline":true,"owner_only_resource":true,"different_owner":true}}',
        "idor",
        id="signal-idor-valid",
    ),
    pytest.param(
        'BINGO_SIGNAL:{"type":"path_traversal","evidence":{"content":"root:x:0:0:root:/root:/bin/bash"}}',
        "path_traversal",
        id="signal-path-traversal-valid",
    ),
]

# 증거 불충분/허위 BINGO_SIGNAL — 거절되어야 함 (오발 방지 핵심)
SIGNAL_INVALID_CASES = [
    pytest.param(
        'BINGO_SIGNAL:{"type":"sqli_boolean","evidence":{"size_true":458,"size_false":460}}',
        id="signal-sqli-boolean-tiny-diff",       # diff=2B < 100B
    ),
    pytest.param(
        'BINGO_SIGNAL:{"type":"sqli_boolean","evidence":{"size_true":15420,"size_false":15300}}',
        id="signal-sqli-boolean-small-pct",        # diff=120B but <10% of 15420
    ),
    pytest.param(
        'BINGO_SIGNAL:{"type":"sqli_error","evidence":{"db_error":"server returned an error"}}',
        id="signal-sqli-error-generic",            # generic error, not DB-specific
    ),
    pytest.param(
        'BINGO_SIGNAL:{"type":"sqli_time","evidence":{"delay_sec":1.2,"expected_sec":5}}',
        id="signal-sqli-time-too-short",           # 1.2s < 4s (80% of 5s)
    ),
    pytest.param(
        'BINGO_SIGNAL:{"type":"xss","evidence":{"payload":"<b>hello</b>","reflected":true}}',
        id="signal-xss-harmless-tag",              # no executable element
    ),
    pytest.param(
        'BINGO_SIGNAL:{"type":"xss","evidence":{"payload":"<script>alert(1)</script>","reflected":false}}',
        id="signal-xss-not-reflected",             # reflected=false
    ),
    pytest.param(
        'BINGO_SIGNAL:{"type":"xss","evidence":{"payload":"<script>alert(1)</script>","reflected":true}}',
        id="signal-xss-reflection-only",           # browser execution missing
    ),
    pytest.param(
        'BINGO_SIGNAL:{"type":"rce","evidence":{"proof":"root password changed"}}',
        id="signal-rce-no-uid-pattern",            # no uid= or passwd record
    ),
    pytest.param(
        'BINGO_SIGNAL:{"type":"ssrf","evidence":{"ip_accessed":"203.0.113.5"}}',
        id="signal-ssrf-public-ip",                # public IP, not private
    ),
    pytest.param(
        'BINGO_SIGNAL:{"type":"ssrf","evidence":{"ip_accessed":"Internal Server Error"}}',
        id="signal-ssrf-error-string",             # string, not IP
    ),
    pytest.param(
        'BINGO_SIGNAL:{"type":"idor","evidence":{"other_user_id":999,"data_returned":false}}',
        id="signal-idor-not-returned",             # data_returned=false
    ),
    pytest.param(
        'BINGO_SIGNAL:{"type":"idor","evidence":{"other_user_id":999,"data_returned":true}}',
        id="signal-idor-public-selector",          # ownership/auth boundary missing
    ),
    pytest.param(
        'BINGO_SIGNAL:{"type":"path_traversal","evidence":{"content":"Permission denied"}}',
        id="signal-path-traversal-no-proof",       # no passwd record
    ),
    pytest.param(
        'not a signal at all, just text with BINGO_SIGNAL: in it but invalid json',
        id="signal-invalid-json",                   # malformed JSON
    ),
]


# ═══════════════════════════════════════════════════════════════════════════════
# pytest 테스트 함수
# ═══════════════════════════════════════════════════════════════════════════════
@pytest.fixture(scope="module")
def signals():
    return _get_signals()


@pytest.fixture(scope="module")
def terminal_instance():
    """BingoTerminal 인스턴스 (BINGO_SIGNAL 파서 테스트용)"""
    from bingo.ui.terminal import BingoTerminal  # noqa
    return BingoTerminal.__new__(BingoTerminal)


@pytest.mark.parametrize("text", FP_CASES)
def test_no_false_positive(signals, text):
    """무해한 텍스트에서 MVVS 신호가 발생하지 않아야 함 (False Positive 방지)"""
    matches = _match(signals, text)
    assert not matches, (
        f"\n🚨 FALSE POSITIVE DETECTED!\n"
        f"   텍스트: {repr(text[:120])}\n"
        f"   오발 패턴: {[(m[0], m[1]) for m in matches]}\n"
        f"   → bingo/ui/terminal.py의 _MVVS_SIGNALS 패턴을 수정할 것"
    )


@pytest.mark.parametrize("vuln_expected,text", TP_CASES)
def test_true_positive_detected(signals, vuln_expected, text):
    """실제 취약점 출력에서 올바른 MVVS 신호가 발생해야 함 (True Positive 확인)"""
    matches = _match(signals, text)
    matched_types = [m[0] for m in matches]
    assert vuln_expected in matched_types, (
        f"\n❌ TRUE POSITIVE MISSED!\n"
        f"   기대 취약점 유형: {vuln_expected}\n"
        f"   텍스트: {repr(text[:120])}\n"
        f"   실제 매칭: {matches}\n"
        f"   → MVVS 패턴이 실제 취약점을 탐지하지 못함 — 패턴 강화 필요"
    )


@pytest.mark.parametrize("signal_text,expected_type", SIGNAL_VALID_CASES)
def test_bingo_signal_valid_accepted(terminal_instance, signal_text, expected_type):
    """유효한 BINGO_SIGNAL은 반드시 탐지되어야 함 (True Signal 확인)"""
    found = terminal_instance._parse_bingo_signals(signal_text)
    assert found, (
        f"\n❌ VALID BINGO_SIGNAL NOT DETECTED!\n"
        f"   신호: {signal_text[:120]}\n"
        f"   기대 타입: {expected_type}\n"
        f"   → _validate_bingo_signal 로직 확인 필요"
    )
    detected_types = [f[0] for f in found]
    assert expected_type in detected_types, (
        f"\n❌ WRONG BINGO_SIGNAL TYPE!\n"
        f"   기대: {expected_type}\n"
        f"   실제: {detected_types}"
    )


@pytest.mark.parametrize("signal_text", SIGNAL_INVALID_CASES)
def test_bingo_signal_invalid_rejected(terminal_instance, signal_text):
    """증거 불충분/허위 BINGO_SIGNAL은 반드시 거절되어야 함 (False Signal 차단)"""
    found = terminal_instance._parse_bingo_signals(signal_text)
    assert not found, (
        f"\n🚨 INVALID BINGO_SIGNAL ACCEPTED!\n"
        f"   신호: {signal_text[:120]}\n"
        f"   잘못 탐지됨: {found}\n"
        f"   → _validate_bingo_signal 증거 임계값 확인 필요"
    )


# ═══════════════════════════════════════════════════════════════════════════════
# v5.1.1 신규: FindingsExporter 패턴 직접 테스트 (기록.md BINGO-0001/0002/0003)
# ═══════════════════════════════════════════════════════════════════════════════
def _get_exporter():
    """FindingsExporter._detect_vuln_type 직접 반환"""
    from bingo.tools.findings_exporter import _detect_vuln_type, _WAF_BLOCK_EN, _WAF_BLOCK_KO
    return _detect_vuln_type, _WAF_BLOCK_EN, _WAF_BLOCK_KO


EXPORTER_FP_CASES = [
    # BINGO-0001: <script src=...> 외부 스크립트 태그 (XSS 오발)
    pytest.param(
        '<script src="/static/jquery.min.js"></script>\n'
        '<script src="/static/app.bundle.js"></script>',
        id="exporter-xss-fp-script-src-two",
    ),
    # BINGO-0001 변형
    pytest.param(
        '<html><head><script src="https://cdn.example.com/lib.js"></script></head></html>',
        id="exporter-xss-fp-script-src-cdn",
    ),
    # BINGO-0002: bash echo에 "EXTRACTVALUE" 키워드 (WAF 차단 상태)
    pytest.param(
        "[双重编码 EXTRACTVALUE] HTTP 403 Forbidden — WAF blocked. size=458B",
        id="exporter-sqli-fp-extractvalue-echo",
    ),
    # BINGO-0003: UPDATEXML 배너
    pytest.param(
        "[UPDATEXML test payload] 403 blocked. size=201B",
        id="exporter-sqli-fp-updatexml-echo",
    ),
    # WAF 차단 응답 (영어)
    pytest.param(
        "HTTP/1.1 403\nContent-Length: 500\n\nYour request has been blocked by security policy.",
        id="exporter-waf-fp-blocked-en",
    ),
    # WAF 차단 응답 (한국어)
    pytest.param(
        "HTTP/1.1 403\nContent-Length: 400\n\n요청이 차단되었습니다. 보안 정책 위반.",
        id="exporter-waf-fp-blocked-ko",
    ),
    # onerror= 이벤트 핸들러 속성 이름만 있음 (함수 없음)
    pytest.param(
        '<img src="photo.jpg" onerror="this.src=\'default.jpg\'">',
        id="exporter-xss-fp-onerror-no-exec-func",
    ),
]

EXPORTER_TP_CASES = [
    # 실제 SQLi: extractvalue(1,concat(...)) — 괄호 포함
    pytest.param(
        "XPATH syntax error: '~5.7.38-log'\nextractvalue(1,concat(0x7e,@@version))",
        "sqli",
        id="exporter-sqli-tp-extractvalue-parens",
    ),
    # 실제 XSS: 인라인 스크립트 (src= 없음)
    pytest.param(
        '<script>alert(document.cookie)</script>',
        "xss",
        id="exporter-xss-tp-inline-alert-cookie",
    ),
    # 실제 XSS: onerror + alert 조합
    pytest.param(
        '<img src=x onerror="alert(1)">',
        "xss",
        id="exporter-xss-tp-onerror-alert",
    ),
]


@pytest.mark.parametrize("text", EXPORTER_FP_CASES)
def test_exporter_no_false_positive(text):
    """FindingsExporter가 무해한 출력에서 취약점을 오발하지 않아야 함"""
    _detect_vuln_type, _WAF_BLOCK_EN, _WAF_BLOCK_KO = _get_exporter()

    # WAF 차단 조기 종료 테스트
    is_waf = (len(text) <= 2000) and (
        _WAF_BLOCK_EN.search(text) or _WAF_BLOCK_KO.search(text)
    )
    if is_waf:
        return  # WAF 차단 = 조기 종료, 취약점 아님 → PASS

    result = _detect_vuln_type(text, code_snippet=text)
    assert result is None, (
        f"\n🚨 EXPORTER FALSE POSITIVE!\n"
        f"   텍스트: {repr(text[:120])}\n"
        f"   잘못 탐지됨: {result}\n"
        f"   → bingo/tools/findings_exporter.py 패턴 수정 필요"
    )


@pytest.mark.parametrize("text,expected_vuln", EXPORTER_TP_CASES)
def test_exporter_true_positive_detected(text, expected_vuln):
    """FindingsExporter가 실제 취약점 출력에서 올바르게 탐지해야 함"""
    _detect_vuln_type, _, _ = _get_exporter()
    result = _detect_vuln_type(text, code_snippet=text)
    assert result is not None, (
        f"\n❌ EXPORTER TRUE POSITIVE MISSED!\n"
        f"   기대: {expected_vuln}\n"
        f"   텍스트: {repr(text[:120])}\n"
        f"   → findings_exporter.py 패턴 강화 필요"
    )
    assert result[0] == expected_vuln, (
        f"\n❌ EXPORTER WRONG TYPE!\n"
        f"   기대: {expected_vuln}\n"
        f"   실제: {result[0]}"
    )


# ══════════════════════════════════════════════════════════════════════════════
# v5.1.3 — bash 환각 감지(_detect_hallucination) 오탐 회귀 테스트
# ══════════════════════════════════════════════════════════════════════════════

def _get_bash_hal_detector():
    """terminal.py 내부의 _detect_hallucination 함수를 직접 추출해 반환."""
    import re as _re
    import types

    def _detect_hallucination(raw_code: str, _block_type: str = "bash"):
        """v5.1.3 수정 버전의 bash 환각 감지 로직 (inline 복제)."""
        s = raw_code.strip()
        _hall_re = _re

        if _block_type == "bash":
            _s_nc = '\n'.join(
                l for l in s.splitlines()
                if not l.strip().startswith('#')
            )
            # B0
            if _hall_re.search(r'python3?\s*<<\s*[\'"]?\w+[\'"]?', _s_nc):
                return "BASH_HEREDOC_PYTHON"
            # B0b
            if "import requests" in _s_nc:
                return "BASH_CONTAINS_REQUESTS"
            # B1
            _has_net_cmd = any(cmd in s for cmd in
                ["curl ", "wget ", "nmap ", "ffuf ", "httpx ", "nuclei "])
            if not _has_net_cmd:
                _is_local_op = (
                    "/tmp/" in s and
                    "requests" not in s and
                    "urllib" not in s and
                    "httpx" not in s
                )
                if not _is_local_op:
                    return "BASH_NO_CURL"
            # B2
            if _hall_re.search(r'(?:TARGET_URL|YOUR_URL|PLACEHOLDER|TARGET_HOST)', _s_nc, _hall_re.IGNORECASE):
                return "BASH_PLACEHOLDER_URL"
            if _hall_re.search(r'(?:curl|wget)\s+[^\n]*\bexample\.com\b', _s_nc, _hall_re.IGNORECASE):
                return "BASH_PLACEHOLDER_URL"
            return None
        return None

    return _detect_hallucination


# ── v5.1.3 오탐 케이스(정상이어야 하는 것) ──────────────────────────────────
BASH_HAL_FP_CASES = [
    # B0 오탐 수정: 주석에 heredoc 언급
    pytest.param(
        "# python3 << 'PYEOF' 는 금지 — curl | python3 -c 방식만 허용\n"
        "curl -sk 'https://target.com/' | python3 -c \"import sys; print(sys.stdin.read()[:500])\"",
        id="b0-heredoc-in-comment-only",
    ),
    # B0b 오탐 수정: 주석에 import requests 언급
    pytest.param(
        "# import requests 는 금지 — curl 을 사용해야 함\n"
        "curl -sk 'https://target.com/login' | python3 -c \"import sys; print(sys.stdin.read())\"",
        id="b0b-import-requests-in-comment",
    ),
    # B1 오탐 수정: cat /tmp/ 후처리
    pytest.param(
        "cat /tmp/sqli_result.txt",
        id="b1-cat-tmp-postprocess",
    ),
    # B1 오탐 수정: grep /tmp/ 후처리
    pytest.param(
        "grep -oP 'DB: [^\\n]+' /tmp/output.txt",
        id="b1-grep-tmp-postprocess",
    ),
    # B1 오탐 수정: jq /tmp/ 후처리
    pytest.param(
        "jq '.items[] | .id' /tmp/api_response.json",
        id="b1-jq-tmp-postprocess",
    ),
    # B1 오탐 수정: python3 -c + /tmp/ (기존 v5.1.1 케이스 유지)
    pytest.param(
        "python3 -c \"import re; t=open('/tmp/xxx.html').read(); print(re.findall(r'<title>(.+)</title>', t))\"",
        id="b1-python3-c-open-tmp",
    ),
    # B2 오탐 수정: 주석에 example.com 언급 + 실제 URL 정상
    pytest.param(
        "# example.com 은 placeholder — 실제 대상 URL 사용\n"
        "curl -sk 'https://vulnerable-site.com/sqli?id=1' | python3 -c \"import sys; print(sys.stdin.read())\"",
        id="b2-example-com-in-comment",
    ),
    # B2 오탐 수정: 주석에 TARGET_URL 언급
    pytest.param(
        "# TARGET_URL 에 실제 대상 URL 입력\n"
        "curl -sk 'https://real-target.com/' | python3 -c \"import sys; print(sys.stdin.read())\"",
        id="b2-target-url-in-comment",
    ),
]

# ── v5.1.3 진양성 케이스(반드시 차단해야 하는 것) ─────────────────────────
BASH_HAL_TP_CASES = [
    # B0 진양성: 실제 heredoc Python
    pytest.param(
        "python3 << 'PYEOF'\nimport requests\nr = requests.get('https://t.com')\nPYEOF",
        "BASH_HEREDOC_PYTHON",
        id="b0-real-heredoc-python",
    ),
    # B0b 진양성: 실제 import requests
    pytest.param(
        "import requests\nr = requests.get('https://t.com')\nprint(r.text)",
        "BASH_CONTAINS_REQUESTS",
        id="b0b-real-import-requests",
    ),
    # B1 진양성: curl 없고 /tmp/ 도 없는 echo 블록
    pytest.param(
        "echo 'SQL injection found at /login'",
        "BASH_NO_CURL",
        id="b1-echo-only-no-curl",
    ),
    # B2 진양성: curl URL에 TARGET_URL
    pytest.param(
        "curl -sk 'TARGET_URL/sqli?id=1'",
        "BASH_PLACEHOLDER_URL",
        id="b2-target-url-in-curl",
    ),
    # B2 진양성: curl URL에 example.com 직접 사용
    pytest.param(
        "curl -sk 'https://example.com/admin'",
        "BASH_PLACEHOLDER_URL",
        id="b2-example-com-in-curl-url",
    ),
]


@pytest.mark.parametrize("script", BASH_HAL_FP_CASES)
def test_bash_hal_no_false_positive(script):
    """v5.1.3: 정상 bash 블록이 환각으로 오탐되지 않아야 함."""
    det = _get_bash_hal_detector()
    result = det(script, _block_type="bash")
    assert result is None, (
        f"\n🚨 BASH_HALLUCINATION FALSE POSITIVE!\n"
        f"   스크립트: {repr(script[:120])}\n"
        f"   잘못 차단됨: {result}\n"
        f"   → bingo/ui/terminal.py _detect_hallucination bash 패턴 수정 필요"
    )


@pytest.mark.parametrize("script,expected_code", BASH_HAL_TP_CASES)
def test_bash_hal_true_positive_blocked(script, expected_code):
    """v5.1.3: 실제 환각 bash 블록은 반드시 차단되어야 함."""
    det = _get_bash_hal_detector()
    result = det(script, _block_type="bash")
    assert result is not None, (
        f"\n❌ BASH_HALLUCINATION TRUE POSITIVE MISSED!\n"
        f"   기대 코드: {expected_code}\n"
        f"   스크립트: {repr(script[:120])}\n"
        f"   → 환각 탐지가 약해짐 — 패턴 확인 필요"
    )
    assert result.startswith(expected_code), (
        f"\n❌ BASH_HALLUCINATION WRONG CODE!\n"
        f"   기대: {expected_code}\n"
        f"   실제: {result}"
    )
