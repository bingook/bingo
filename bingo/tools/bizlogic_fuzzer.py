"""bingo/tools/bizlogic_fuzzer.py — 비즈니스 로직 취약점 퍼저 (v2.6.0)"""
from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Callable


@dataclass
class BizlogicFinding:
    finding_type: str
    endpoint: str
    payload: str
    baseline: str
    result: str
    severity: str
    confirmed: bool
    notes: str = ""


@dataclass
class BizlogicReport:
    target: str
    findings: list[BizlogicFinding] = field(default_factory=list)

    @property
    def critical(self) -> list[BizlogicFinding]:
        return [f for f in self.findings if f.severity == "CRITICAL" and f.confirmed]


# ── 부정 금액 / 정수 오버플로우 값 ────────────────────────────────────────────
NEGATIVE_VALUES = [
    "-1", "-0.01", "-100", "-9999",
    "0", "0.00", "0.001",
    "2147483647", "2147483648", "-2147483649",   # INT32 경계
    "9999999999", "99999999999",
    "0.0000001",
]

# ── 쿠폰/할인 코드 퍼징 ────────────────────────────────────────────────────────
COUPON_WORDLIST = [
    "ADMIN", "TEST", "FREE", "DISCOUNT100", "SAVE100",
    "0", "NULL", "NONE", "UNDEFINED",
    "' OR '1'='1",  # SQLi 탐지 겸용
    "../",          # 경로 조작
]

# ── 워크플로우 스킵 테스트 경로 ───────────────────────────────────────────────
SKIP_PATHS = [
    "/checkout/confirm",
    "/order/complete",
    "/payment/success",
    "/checkout/step3",
    "/order/final",
    "/buy/confirm",
    "/purchase/done",
]


class BizlogicFuzzer:
    """비즈니스 로직 취약점: 음수 금액, 워크플로우 스킵, 쿠폰 재사용, 수량 조작"""

    def __init__(
        self,
        request_fn: Callable[[str, str, dict, str], tuple[int, str]],
        base_url: str,
        headers: dict | None = None,
    ) -> None:
        self.req = request_fn
        self.base = base_url.rstrip("/")
        self.headers = headers or {}

    # ── 음수/이상 금액 주입 ───────────────────────────────────────────────────
    def test_negative_amount(
        self,
        endpoint: str,
        price_param: str = "price",
        qty_param: str = "quantity",
        extra_body: str = "",
    ) -> list[BizlogicFinding]:
        findings = []
        # 베이스라인
        try:
            base_body = f"{price_param}=100&{qty_param}=1"
            if extra_body:
                base_body += f"&{extra_body}"
            base_status, base_resp = self.req(endpoint, "POST", self.headers, base_body)
        except Exception:
            return findings

        for val in NEGATIVE_VALUES:
            body = f"{price_param}={val}&{qty_param}=1"
            if extra_body:
                body += f"&{extra_body}"
            try:
                status, resp = self.req(endpoint, "POST", self.headers, body)
                success_signals = ["success", "complete", "order_id", "주문", "완료", "결제"]
                if status in (200, 201, 302) and any(s in resp.lower() for s in success_signals):
                    findings.append(BizlogicFinding(
                        finding_type="negative_amount",
                        endpoint=endpoint,
                        payload=f"{price_param}={val}",
                        baseline=f"status {base_status}",
                        result=f"status {status} → success signal detected",
                        severity="CRITICAL",
                        confirmed=True,
                        notes=f"Negative/invalid amount {val} accepted — refund exploit possible",
                    ))
            except Exception:
                pass
        return findings

    # ── 워크플로우 스킵 ───────────────────────────────────────────────────────
    def test_workflow_skip(self, cart_items: dict | None = None) -> list[BizlogicFinding]:
        findings = []
        for skip_path in SKIP_PATHS:
            url = self.base + skip_path
            try:
                status, resp = self.req(url, "GET", self.headers, "")
                if status == 200 and any(
                    kw in resp.lower() for kw in ["order", "confirm", "complete", "receipt", "주문완료"]
                ):
                    findings.append(BizlogicFinding(
                        finding_type="workflow_skip",
                        endpoint=url,
                        payload="Direct GET to checkout completion",
                        baseline="Expected: redirect to cart/login",
                        result=f"HTTP 200 with completion content",
                        severity="HIGH",
                        confirmed=True,
                        notes="Checkout step can be skipped — order may complete without payment",
                    ))
            except Exception:
                pass
        return findings

    # ── 쿠폰 재사용 / 우회 ────────────────────────────────────────────────────
    def test_coupon_abuse(
        self,
        endpoint: str,
        coupon_param: str = "coupon_code",
        extra_body: str = "",
    ) -> list[BizlogicFinding]:
        findings = []
        for code in COUPON_WORDLIST:
            body = f"{coupon_param}={urllib.parse.quote(code)}"
            if extra_body:
                body += f"&{extra_body}"
            try:
                status, resp = self.req(endpoint, "POST", self.headers, body)
                if status == 200 and any(
                    kw in resp.lower() for kw in ["discount", "applied", "saved", "valid", "할인", "적용"]
                ):
                    findings.append(BizlogicFinding(
                        finding_type="coupon_abuse",
                        endpoint=endpoint,
                        payload=f"{coupon_param}={code}",
                        baseline="Invalid coupon → reject",
                        result=f"Coupon accepted: {resp[:100]}",
                        severity="HIGH",
                        confirmed=True,
                        notes=f"Coupon '{code}' accepted — may be valid test/admin coupon",
                    ))
            except Exception:
                pass
        return findings

    # ── 수량 조작 ─────────────────────────────────────────────────────────────
    def test_quantity_manipulation(
        self,
        endpoint: str,
        qty_param: str = "quantity",
        extra_body: str = "",
    ) -> list[BizlogicFinding]:
        findings = []
        extreme_values = ["0", "-1", "99999", "1.5", "1e10", "NaN", "Infinity"]
        for val in extreme_values:
            body = f"{qty_param}={val}"
            if extra_body:
                body += f"&{extra_body}"
            try:
                base_body = f"{qty_param}=1"
                _, base_resp = self.req(endpoint, "POST", self.headers, base_body)
                status, resp = self.req(endpoint, "POST", self.headers, body)
                if status in (200, 201) and resp != base_resp:
                    findings.append(BizlogicFinding(
                        finding_type="quantity_manipulation",
                        endpoint=endpoint,
                        payload=f"{qty_param}={val}",
                        baseline="quantity=1 response",
                        result=f"Accepted qty={val}: {resp[:100]}",
                        severity="HIGH",
                        confirmed=True,
                        notes=f"Unusual quantity {val} accepted",
                    ))
            except Exception:
                pass
        return findings

    def full_scan(
        self,
        price_endpoint: str | None = None,
        coupon_endpoint: str | None = None,
    ) -> BizlogicReport:
        report = BizlogicReport(target=self.base)
        pe = price_endpoint or self.base + "/cart/update"
        ce = coupon_endpoint or self.base + "/coupon/apply"

        report.findings.extend(self.test_negative_amount(pe))
        report.findings.extend(self.test_workflow_skip())
        report.findings.extend(self.test_coupon_abuse(ce))
        report.findings.extend(self.test_quantity_manipulation(pe))

        return report
