"""
bingo/core/code_guard.py — 실행 전 AST 정적 분석 모듈 (v4.7.0)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
【설계 원칙】
  LLM 이 생성한 Python 코드를 **실행 전** 에 AST(Abstract Syntax Tree)로
  파싱하여 무한루프 패턴을 탐지 → 실행을 선제적으로 차단.
  Regex 방식보다 정확하며 false positive / false negative 모두 최소화.

【탐지 패턴】
  A. while True / while 1 / while <constant true expression>
      → 루프 본문 어디에도 break / return / raise / sys.exit 없으면 차단
  B. for X in itertools.cycle(...) / itertools.count(...)
      → 명백한 무한 이터레이터 → 즉시 차단
  C. range(N) where N ≥ 10^8 (사실상 무한)
      → 경고 레벨 — 너무 큰 range 는 실질적 timeout 유발
  D. 재귀 함수 (Recursive Function) — 자기 자신 호출 있고
      모든 분기에 base case 없음 → 차단

【반환】
  `check(code)` → `None` (안전) | `str` (차단 이유)
  str 포맷:  "INFINITE_LOOP_RISK: ..."
"""

from __future__ import annotations

import ast
import sys
from typing import Callable


# ─────────────────────────────────────────────────────────────────
# 헬퍼: 노드 내부에 특정 노드 타입 존재 여부 확인
# ─────────────────────────────────────────────────────────────────
def _contains(node: ast.AST, pred: Callable[[ast.AST], bool]) -> bool:
    """AST 서브트리를 DFS 탐색 — pred 를 만족하는 노드 하나라도 있으면 True."""
    for child in ast.walk(node):
        if pred(child):
            return True
    return False


def _has_break(node: ast.AST) -> bool:
    return _contains(node, lambda n: isinstance(n, ast.Break))


def _has_return(node: ast.AST) -> bool:
    return _contains(node, lambda n: isinstance(n, ast.Return))


def _has_raise(node: ast.AST) -> bool:
    return _contains(node, lambda n: isinstance(n, ast.Raise))


def _has_sys_exit(node: ast.AST) -> bool:
    """sys.exit() / os._exit() / exit() / quit() 호출 감지."""
    for child in ast.walk(node):
        if not isinstance(child, ast.Call):
            continue
        func = child.func
        # sys.exit(...)  or  os._exit(...)
        if isinstance(func, ast.Attribute) and func.attr in ("exit", "_exit"):
            return True
        # exit() / quit() 단독 호출
        if isinstance(func, ast.Name) and func.id in ("exit", "quit"):
            return True
    return False


def _has_escape(node: ast.AST) -> bool:
    """루프 탈출 수단 (break / return / raise / exit) 중 하나라도 있으면 True."""
    return (
        _has_break(node)
        or _has_return(node)
        or _has_raise(node)
        or _has_sys_exit(node)
    )


# ─────────────────────────────────────────────────────────────────
# 패턴 A: while True / while 1 + 탈출 없음
# ─────────────────────────────────────────────────────────────────
def _is_always_true(test: ast.expr) -> bool:
    """while 조건이 항상 참인지 판단."""
    # while True:  /  while 1:
    if isinstance(test, ast.Constant):
        return bool(test.value)
    # while not False:  (UnaryOp Not + Constant False)
    if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
        if isinstance(test.operand, ast.Constant) and not test.operand.value:
            return True
    return False


def _check_while_loops(tree: ast.AST) -> str | None:
    for node in ast.walk(tree):
        if not isinstance(node, ast.While):
            continue
        if not _is_always_true(node.test):
            continue
        # 루프 본문 + orelse 전체에서 탈출 수단 탐색
        body_nodes = ast.Module(body=node.body + node.orelse, type_ignores=[])
        if not _has_escape(body_nodes):
            lineno = getattr(node, "lineno", "?")
            return (
                f"INFINITE_LOOP_RISK: 'while True' at line {lineno} has no "
                f"break/return/raise/exit — will run forever. "
                f"Add a break condition or rewrite with a finite loop."
            )
    return None


# ─────────────────────────────────────────────────────────────────
# 패턴 B: for x in itertools.cycle / itertools.count
# ─────────────────────────────────────────────────────────────────
_INFINITE_ITERS = {
    "cycle",    # itertools.cycle
    "count",    # itertools.count (no stop)
    "repeat",   # itertools.repeat without times arg
}


def _is_infinite_iter_call(call: ast.Call) -> bool:
    func = call.func
    # itertools.cycle(...)  /  itertools.count(...)  /  itertools.repeat(...)
    if isinstance(func, ast.Attribute) and func.attr in _INFINITE_ITERS:
        if func.attr == "repeat":
            # repeat(x, times) 는 유한 — times 인자 없으면 무한
            if len(call.args) < 2 and not call.keywords:
                return True
            # repeat(x, times=N) 는 유한
            return not any(kw.arg == "times" for kw in call.keywords)
        return True  # cycle, count 는 무조건 무한
    # cycle(...) 단독 (import cycle from itertools 후 사용)
    if isinstance(func, ast.Name) and func.id in _INFINITE_ITERS:
        if func.id == "repeat":
            if len(call.args) < 2 and not call.keywords:
                return True
            return not any(kw.arg == "times" for kw in call.keywords)
        return True
    return False


def _check_infinite_for_iters(tree: ast.AST) -> str | None:
    for node in ast.walk(tree):
        if not isinstance(node, ast.For):
            continue
        iter_node = node.iter
        if isinstance(iter_node, ast.Call) and _is_infinite_iter_call(iter_node):
            # 탈출 수단 있으면 허용
            body_nodes = ast.Module(body=node.body + node.orelse, type_ignores=[])
            if not _has_escape(body_nodes):
                lineno = getattr(node, "lineno", "?")
                return (
                    f"INFINITE_LOOP_RISK: 'for' loop at line {lineno} iterates "
                    f"over an infinite iterator (itertools.cycle/count/repeat) "
                    f"with no break — will run forever. Use a finite range or add break."
                )
    return None


# ─────────────────────────────────────────────────────────────────
# 패턴 C: range(N) where N ≥ 10^8
# ─────────────────────────────────────────────────────────────────
_MAX_SAFE_RANGE = 10 ** 8  # 1억 이상은 실질적 timeout 유발


def _eval_const_int(node: ast.expr) -> int | None:
    """단순 상수 정수 표현식 평가. 복잡한 표현식은 None 반환."""
    if isinstance(node, ast.Constant) and isinstance(node.value, int):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Pow):
        left = _eval_const_int(node.left)
        right = _eval_const_int(node.right)
        if left is not None and right is not None:
            try:
                result = left ** right
                # 지수가 너무 크면 평가 중단
                return result if result < 10 ** 20 else 10 ** 20
            except Exception:
                return None
    return None


def _check_huge_range(tree: ast.AST) -> str | None:
    for node in ast.walk(tree):
        if not isinstance(node, ast.For):
            continue
        iter_node = node.iter
        if not isinstance(iter_node, ast.Call):
            continue
        func = iter_node.func
        if not (isinstance(func, ast.Name) and func.id == "range"):
            continue
        args = iter_node.args
        # range(stop)  /  range(start, stop)  /  range(start, stop, step)
        stop_arg = args[0] if len(args) == 1 else (args[1] if len(args) >= 2 else None)
        if stop_arg is None:
            continue
        n = _eval_const_int(stop_arg)
        if n is not None and n >= _MAX_SAFE_RANGE:
            lineno = getattr(node, "lineno", "?")
            return (
                f"INFINITE_LOOP_RISK: 'for' loop at line {lineno} uses "
                f"range({n:,}) — {n:.2e} iterations will cause timeout. "
                f"Use a cursor/pagination approach instead of single large range."
            )
    return None


# ─────────────────────────────────────────────────────────────────
# 패턴 D: 무제한 재귀 함수 (base case 없음)
# ─────────────────────────────────────────────────────────────────
def _check_unbounded_recursion(tree: ast.AST) -> str | None:
    """함수 정의 수집 → 자기 자신 호출 여부 확인 → if 분기 없이 재귀 → 차단."""
    # 최상위 및 중첩 함수 모두 수집
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        fname = node.name
        # 함수 본문에서 자기 자신 호출 탐색
        self_calls = []
        for child in ast.walk(ast.Module(body=node.body, type_ignores=[])):
            if isinstance(child, ast.Call):
                func = child.func
                if isinstance(func, ast.Name) and func.id == fname:
                    self_calls.append(child)
        if not self_calls:
            continue  # 재귀 없음
        # 본문에 if 조건문(base case 가능성) 있으면 허용
        has_if = any(isinstance(c, ast.If) for c in ast.walk(
            ast.Module(body=node.body, type_ignores=[])
        ))
        # try/except 도 base case 로 인정
        has_try = any(isinstance(c, ast.Try) for c in ast.walk(
            ast.Module(body=node.body, type_ignores=[])
        ))
        if not has_if and not has_try:
            lineno = getattr(node, "lineno", "?")
            return (
                f"INFINITE_LOOP_RISK: function '{fname}' at line {lineno} "
                f"calls itself recursively with no if/try base-case — "
                f"will cause RecursionError/stack overflow. "
                f"Add a termination condition."
            )
    return None


# ─────────────────────────────────────────────────────────────────
# 공개 인터페이스
# ─────────────────────────────────────────────────────────────────
def check(code: str) -> str | None:
    """
    LLM 생성 Python 코드를 AST 파싱 후 무한루프 패턴 검사.

    Parameters
    ----------
    code : str
        검사할 Python 소스 코드 문자열.

    Returns
    -------
    None
        코드가 안전함 (무한루프 없음).
    str
        탐지된 무한루프 이유 — "INFINITE_LOOP_RISK: ..." 형식.
        이 값을 '__BLOCKED__:' 접두사와 함께 _precheck_python_code 에서 반환.
    """
    try:
        tree = ast.parse(code)
    except SyntaxError:
        # 구문 오류는 기존 __SYNTAX_ERR__ 경로에서 처리 → 여기서는 무시
        return None

    # 패턴 A: while True 루프
    reason = _check_while_loops(tree)
    if reason:
        return reason

    # 패턴 B: 무한 이터레이터 for 루프
    reason = _check_infinite_for_iters(tree)
    if reason:
        return reason

    # 패턴 C: 과도하게 큰 range
    reason = _check_huge_range(tree)
    if reason:
        return reason

    # 패턴 D: 무제한 재귀
    reason = _check_unbounded_recursion(tree)
    if reason:
        return reason

    return None  # 안전


# ─────────────────────────────────────────────────────────────────
# 직접 실행 시 간단한 자가 테스트
# ─────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    _tests = [
        # (코드, 차단 여부)
        ("while True:\n    pass\n", True),
        ("while True:\n    if x: break\n", False),
        ("while 1:\n    pass\n", True),
        ("for x in range(10):\n    print(x)\n", False),
        ("for x in range(10**9):\n    print(x)\n", True),
        ("import itertools\nfor x in itertools.cycle([1,2]):\n    print(x)\n", True),
        ("import itertools\nfor x in itertools.cycle([1,2]):\n    if x>5: break\n", False),
        ("def foo():\n    foo()\n", True),
        ("def foo(n):\n    if n<=0: return\n    foo(n-1)\n", False),
    ]
    _pass = _fail = 0
    for _code, _should_block in _tests:
        _result = check(_code)
        _blocked = _result is not None
        _ok = _blocked == _should_block
        print(f"{'✅' if _ok else '❌'} {'BLOCKED' if _blocked else 'OK':7s} | "
              f"{'expected BLOCK' if _should_block else 'expected OK':16s} | "
              f"{_code.strip()[:60]}")
        if _ok:
            _pass += 1
        else:
            _fail += 1
            if _result:
                print(f"    reason: {_result}")
    print(f"\n{_pass}/{_pass+_fail} tests passed")
    sys.exit(0 if _fail == 0 else 1)
