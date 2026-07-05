"""
MVVS False-Positive Regression Suite — FP-ZERO v1.1
=====================================================
목적: MVVS 취약점 신호 감지기(_MVVS_SIGNALS)가 실제로 무해한 텍스트에
      오발(False Positive)을 내지 않는지 릴리즈마다 자동 검증.

실행 방법:
    pytest tests/test_mvvs_false_positive.py -v

규칙:
    - FP 테스트: 무해한 텍스트 → MVVS 신호 없어야 함  (아래 FP_CASES)
    - TP 테스트: 실제 취약점 출력 → MVVS 신호 있어야 함 (아래 TP_CASES)

릴리즈 체크리스트:
    [ ] pytest tests/test_mvvs_false_positive.py -v → 전부 PASS
    [ ] 새 규칙 추가 시 FP_CASES / TP_CASES에 케이스 반드시 추가
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
# pytest 테스트 함수
# ═══════════════════════════════════════════════════════════════════════════════
@pytest.fixture(scope="module")
def signals():
    return _get_signals()


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
