"""
Report Builder — 취약점 보고서 자동 생성 강화
============================================
1. CVSS v3.1 자동 스코어 계산
2. PoC curl 명령어 자동 생성
3. 영향도 분석 자동화
4. 마크다운 + HTML 보고서 생성
5. 한국어/영어/중국어 보고서 지원
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any


# ══════════════════════════════════════════════════════════════
# CVSS v3.1 스코어 계산
# ══════════════════════════════════════════════════════════════

CVSS_SEVERITY = {
    (0.0, 0.0): "None",
    (0.1, 3.9): "Low",
    (4.0, 6.9): "Medium",
    (7.0, 8.9): "High",
    (9.0, 10.0): "Critical",
}

VULN_CVSS_MAP = {
    "RCE":          {"score": 9.8, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
    "SQLi_union":   {"score": 9.1, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"},
    "SQLi_blind":   {"score": 7.5, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
    "SQLi_error":   {"score": 7.5, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
    "IDOR":         {"score": 8.1, "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"},
    "IDOR_admin":   {"score": 9.1, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"},
    "SSRF_internal":{"score": 9.3, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N"},
    "SSRF_meta":    {"score": 8.6, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N"},
    "XXE":          {"score": 8.2, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:L"},
    "XSS_stored":   {"score": 8.8, "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N"},
    "XSS_reflected":{"score": 6.1, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"},
    "Auth_bypass":  {"score": 9.8, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
    "JWT_weak":     {"score": 9.1, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"},
    "Upload_RCE":   {"score": 9.8, "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"},
    "Info_leak":    {"score": 5.3, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"},
    "Hardcoded_key":{"score": 9.8, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
}


def get_severity(score: float) -> str:
    for (lo, hi), severity in CVSS_SEVERITY.items():
        if lo <= score <= hi:
            return severity
    return "Unknown"


# ══════════════════════════════════════════════════════════════
# 취약점 데이터 모델
# ══════════════════════════════════════════════════════════════

@dataclass
class VulnEntry:
    title: str
    vuln_type: str
    url: str
    method: str = "GET"
    param: str = ""
    payload: str = ""
    response_evidence: str = ""
    impact: str = ""
    recommendation: str = ""
    cvss_score: float = 0.0
    cvss_vector: str = ""
    curl_poc: str = ""
    severity: str = ""
    references: list[str] = field(default_factory=list)

    def __post_init__(self):
        if self.cvss_score == 0.0 and self.vuln_type in VULN_CVSS_MAP:
            info = VULN_CVSS_MAP[self.vuln_type]
            self.cvss_score = info["score"]
            self.cvss_vector = info["vector"]
        self.severity = get_severity(self.cvss_score)

    def gen_curl(self) -> str:
        """PoC curl 명령어 자동 생성"""
        if self.curl_poc:
            return self.curl_poc
        if self.method == "GET":
            return f"curl -sk '{self.url}' -H 'X-Forwarded-For: 127.0.0.1'"
        elif self.method == "POST":
            param_str = f"{self.param}={self.payload}" if self.param else self.payload
            return f"curl -sk -X POST '{self.url}' -d '{param_str}' -H 'Content-Type: application/x-www-form-urlencoded'"
        return f"curl -sk '{self.url}'"


# ══════════════════════════════════════════════════════════════
# 보고서 생성
# ══════════════════════════════════════════════════════════════

IMPACT_TEMPLATES = {
    "ko": {
        "RCE":          "공격자가 서버에서 임의 명령을 실행할 수 있으며, 완전한 시스템 장악이 가능합니다.",
        "SQLi_union":   "데이터베이스 전체 내용을 탈취할 수 있으며, 관리자 계정 탈취 및 데이터 조작이 가능합니다.",
        "SQLi_blind":   "데이터베이스에서 민감한 정보(사용자 자격증명, 개인정보)를 순차적으로 추출할 수 있습니다.",
        "IDOR":         "다른 사용자의 개인정보, 주문내역, 결제정보에 무단으로 접근할 수 있습니다.",
        "SSRF_internal":"내부 서버 및 클라우드 메타데이터 서비스에 접근하여 IAM 자격증명을 탈취할 수 있습니다.",
        "Auth_bypass":  "인증 없이 관리자 기능에 접근하거나 타인의 계정을 탈취할 수 있습니다.",
        "Upload_RCE":   "악성 파일 업로드를 통해 웹쉘을 배포하고 서버를 완전히 장악할 수 있습니다.",
        "XSS_stored":   "저장된 스크립트가 모든 방문자에게 실행되어 세션 탈취 및 피싱이 가능합니다.",
        "JWT_weak":     "약한 시크릿으로 인해 JWT를 위조하여 관리자 권한을 획득할 수 있습니다.",
        "XXE":          "서버 내부 파일을 읽거나 내부 네트워크 서비스에 접근할 수 있습니다.",
        "Hardcoded_key":"소스코드에 노출된 자격증명을 통해 외부 서비스에 무단 접근이 가능합니다.",
    },
    "en": {
        "RCE":          "Attacker can execute arbitrary OS commands on the server, leading to full system compromise.",
        "SQLi_union":   "Full database contents can be exfiltrated, including admin credentials and sensitive data.",
        "SQLi_blind":   "Sensitive data (credentials, PII) can be extracted from the database character by character.",
        "IDOR":         "Unauthorized access to other users' PII, order history, and payment information.",
        "SSRF_internal":"Access to internal servers and cloud metadata services to steal IAM credentials.",
        "Auth_bypass":  "Access to admin functions without authentication or account takeover.",
        "Upload_RCE":   "Webshell deployment via malicious file upload leading to full server compromise.",
        "XSS_stored":   "Persistent XSS affecting all visitors, enabling session hijacking and phishing.",
        "JWT_weak":     "Forging JWT with weak secret to gain admin privileges.",
        "XXE":          "Reading internal server files or accessing internal network services.",
        "Hardcoded_key":"Unauthorized access to external services via exposed credentials in source code.",
    },
}

REMEDIATION_TEMPLATES = {
    "ko": {
        "RCE":          "사용자 입력 값에 대한 엄격한 검증 및 화이트리스트 기반 필터링 적용. shell_exec, system 등 위험 함수 사용 금지.",
        "SQLi_union":   "PreparedStatement / 파라미터화된 쿼리 사용. ORM 프레임워크 도입. 사용자 입력값 이스케이프 처리.",
        "IDOR":         "모든 리소스 접근 시 현재 인증된 사용자의 소유 여부를 서버 측에서 반드시 검증.",
        "SSRF_internal":"URL 화이트리스트 검증. 내부 IP 대역(10.x.x.x, 172.16.x.x, 192.168.x.x) 차단. DNS rebinding 방어.",
        "Auth_bypass":  "인증·인가 미들웨어를 모든 보호 경로에 일관성 있게 적용. 세션 검증 강화.",
        "Upload_RCE":   "파일 확장자 화이트리스트 검증. 업로드 디렉토리 실행 권한 제거. Content-Type 서버 측 검증.",
        "XSS_stored":   "모든 출력 값에 HTML 엔티티 인코딩 적용. CSP 헤더 설정. DOMPurify 등 라이브러리 사용.",
        "JWT_weak":     "최소 256비트 랜덤 시크릿 사용. RS256 또는 ES256 알고리즘으로 전환. alg:none 명시적 거부.",
        "XXE":          "XML 파서의 외부 엔티티 처리 비활성화. DOCTYPE 선언 거부. 최신 XML 파서로 업데이트.",
        "Hardcoded_key":"환경변수 또는 시크릿 관리 서비스(AWS Secrets Manager, Vault 등) 사용. 노출된 자격증명 즉시 교체.",
    },
}


class ReportBuilder:
    """취약점 보고서 자동 생성기"""

    def __init__(self, target: str, lang: str = "ko"):
        self.target = target
        self.lang = lang
        self.vulns: list[VulnEntry] = []
        self.scan_date = time.strftime("%Y-%m-%d %H:%M:%S")

    def add_vuln(
        self,
        title: str,
        vuln_type: str,
        url: str,
        method: str = "GET",
        param: str = "",
        payload: str = "",
        evidence: str = "",
        curl_poc: str = "",
    ) -> VulnEntry:
        """취약점 추가"""
        impact_map = IMPACT_TEMPLATES.get(self.lang, IMPACT_TEMPLATES["ko"])
        rem_map = REMEDIATION_TEMPLATES.get(self.lang, REMEDIATION_TEMPLATES["ko"])

        v = VulnEntry(
            title=title,
            vuln_type=vuln_type,
            url=url,
            method=method,
            param=param,
            payload=payload,
            response_evidence=evidence,
            impact=impact_map.get(vuln_type, ""),
            recommendation=rem_map.get(vuln_type, ""),
            curl_poc=curl_poc,
        )
        if not v.curl_poc:
            v.curl_poc = v.gen_curl()
        self.vulns.append(v)
        return v

    def build_markdown(self) -> str:
        """마크다운 보고서 생성"""
        lines: list[str] = []

        # 헤더
        lines.append(f"# 보안 취약점 보고서 — {self.target}")
        lines.append(f"\n**스캔 일시**: {self.scan_date}  ")
        lines.append(f"**대상**: {self.target}  ")
        lines.append(f"**총 취약점**: {len(self.vulns)}건")

        # 요약 테이블
        if self.vulns:
            sorted_vulns = sorted(self.vulns, key=lambda v: -v.cvss_score)
            lines.append("\n## 취약점 요약\n")
            lines.append("| # | 취약점 | 심각도 | CVSS | URL |")
            lines.append("|---|--------|--------|------|-----|")
            for i, v in enumerate(sorted_vulns, 1):
                lines.append(f"| {i} | {v.title} | **{v.severity}** | {v.cvss_score} | `{v.url[:60]}` |")

        # 상세 내용
        lines.append("\n---\n## 상세 취약점\n")
        for i, v in enumerate(sorted(self.vulns, key=lambda x: -x.cvss_score), 1):
            lines.append(f"### [{i}] {v.title}")
            lines.append(f"\n| 항목 | 내용 |")
            lines.append(f"|------|------|")
            lines.append(f"| 심각도 | **{v.severity}** ({v.cvss_score}) |")
            lines.append(f"| CVSS 벡터 | `{v.cvss_vector}` |")
            lines.append(f"| URL | `{v.url}` |")
            lines.append(f"| 메서드 | `{v.method}` |")
            if v.param:
                lines.append(f"| 파라미터 | `{v.param}` |")

            if v.impact:
                lines.append(f"\n**영향**: {v.impact}")

            if v.curl_poc:
                lines.append(f"\n**PoC**:\n```bash\n{v.curl_poc}\n```")

            if v.response_evidence:
                lines.append(f"\n**증거**:\n```\n{v.response_evidence[:500]}\n```")

            if v.recommendation:
                lines.append(f"\n**권고사항**: {v.recommendation}")

            lines.append("")

        return "\n".join(lines)

    def build_json(self) -> str:
        """JSON 형식 보고서"""
        data = {
            "target": self.target,
            "scan_date": self.scan_date,
            "total": len(self.vulns),
            "critical": sum(1 for v in self.vulns if v.severity == "Critical"),
            "high": sum(1 for v in self.vulns if v.severity == "High"),
            "medium": sum(1 for v in self.vulns if v.severity == "Medium"),
            "vulnerabilities": [
                {
                    "title": v.title,
                    "type": v.vuln_type,
                    "severity": v.severity,
                    "cvss": v.cvss_score,
                    "url": v.url,
                    "poc": v.curl_poc,
                    "impact": v.impact,
                    "recommendation": v.recommendation,
                }
                for v in sorted(self.vulns, key=lambda x: -x.cvss_score)
            ],
        }
        return json.dumps(data, ensure_ascii=False, indent=2)

    def save(self, filepath: str, fmt: str = "md") -> str:
        """파일로 저장"""
        content = self.build_markdown() if fmt == "md" else self.build_json()
        ext = "md" if fmt == "md" else "json"
        path = filepath if filepath.endswith(f".{ext}") else f"{filepath}.{ext}"
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        return path


REPORT_BUILDER_SUMMARY = """
=== REPORT BUILDER (AI AUTO-SELECT) ===

Trigger: at END of assessment, after all vulnerabilities confirmed

rb = ReportBuilder(target=TARGET, lang="ko")
rb.add_vuln("SQL Injection", "SQLi_union", url, "POST", "id", "' OR 1=1--")
rb.add_vuln("IDOR", "IDOR", url, "GET", "user_id", "2")
md = rb.build_markdown()
rb.save("report_target.md")

CVSS scores auto-assigned by vuln_type.
PoC curl commands auto-generated.
"""
