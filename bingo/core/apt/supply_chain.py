"""
APT Module 2 — Supply Chain Vulnerability Scanner  (v3.5.21)
=============================================================
채팅 모드에서 파일/경로 탐지 시 자동 활성화되는 공급망 취약점 스캐너.

기능:
  - npm (package.json / package-lock.json) 의존성 취약점 스캔
  - Python (requirements.txt / setup.py / pyproject.toml) 취약점 스캔
  - Dependency Confusion 공격 탐지 (내부 패키지 명 공개 레지스트리 등록 여부)
  - GitHub Actions 워크플로우 공급망 리스크 스캔
  - Typosquatting 패키지 탐지 (Levenshtein distance)
  - 악성 패키지 IOC 목록 대조

주의: 허가된 레드팀/침투테스트 환경에서만 사용할 것.
"""

from __future__ import annotations

import json
import os
import re
import textwrap
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class SupplyChainFinding:
    severity: str          # CRITICAL / HIGH / MEDIUM / LOW / INFO
    category: str          # dependency_confusion / typosquatting / malicious / workflow / outdated
    package: str
    version: str
    description: str
    remediation: str
    cve: list[str] = field(default_factory=list)


class SupplyChainScanner:
    """
    공급망 취약점 스캐너.
    네트워크 없이 정적 분석 가능, 네트워크 있으면 실시간 조회.
    """

    # ── 알려진 악성 패키지 IOC ──────────────────────────────────────────
    _MALICIOUS_PACKAGES: dict[str, list[str]] = {
        "npm": [
            "event-stream",        # 2018 공급망 공격
            "flatmap-stream",      # event-stream 내 악성 모듈
            "ua-parser-js",        # 2021 악성코드 삽입
            "coa",                 # 2021 계정 탈취
            "rc",                  # 2021 계정 탈취
            "colors",              # 2022 고의적 sabotage
            "faker",               # 2022 고의적 sabotage
            "node-ipc",            # 2022 러시아 타겟 sabotage
            "xz-utils",            # 2024 백도어 (CVE-2024-3094)
            "polyfill.io",         # 2024 CDN 공급망 공격
        ],
        "pypi": [
            "ctx",                 # 2022 환경변수 탈취
            "drgn",                # typosquatting
            "python-nmap",         # 악성 변종 존재
            "loguru-sink",         # typosquatting
            "colourama",           # colorama 타이포스쿼팅
            "requesst",            # requests 타이포스쿼팅
            "importantt",          # important 타이포스쿼팅
        ],
    }

    # ── 위험한 GitHub Actions 패턴 ──────────────────────────────────────
    _RISKY_ACTION_PATTERNS: list[tuple[str, str, str]] = [
        (r'uses:\s+\S+@(?![\da-f]{40})', "MEDIUM",
         "Action not pinned to full SHA — supply chain risk"),
        (r'\$\{\{.*github\.event\..*\}\}', "HIGH",
         "Untrusted input in expression — potential injection"),
        (r'run:.*\$\{\{.*\}\}', "HIGH",
         "Untrusted data in run step — command injection risk"),
        (r'curl.*\|\s*(bash|sh|python)', "HIGH",
         "Pipe to shell in CI — code execution risk"),
        (r'npm install --unsafe-perm', "MEDIUM",
         "unsafe-perm flag — postinstall script escalation"),
        (r'pip install.*--pre', "LOW",
         "Pre-release pip install — may pull unstable/malicious"),
        (r'secrets\.GITHUB_TOKEN.*write', "MEDIUM",
         "GITHUB_TOKEN with write permissions"),
    ]

    def scan_package_json(self, path: str) -> list[SupplyChainFinding]:
        """npm package.json 스캔."""
        findings: list[SupplyChainFinding] = []
        p = Path(path)
        if not p.exists():
            return findings

        try:
            data = json.loads(p.read_text(encoding="utf-8", errors="ignore"))
        except Exception:
            return findings

        all_deps: dict[str, str] = {}
        for key in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
            all_deps.update(data.get(key, {}))

        for pkg, ver in all_deps.items():
            # 악성 패키지 확인
            if pkg in self._MALICIOUS_PACKAGES.get("npm", []):
                findings.append(SupplyChainFinding(
                    severity="CRITICAL",
                    category="malicious",
                    package=pkg,
                    version=ver,
                    description=f"Known malicious npm package: {pkg}",
                    remediation=f"Remove {pkg} immediately and audit all dependents",
                ))
                continue

            # Typosquatting 탐지
            typo = self._detect_typosquatting(pkg, "npm")
            if typo:
                findings.append(SupplyChainFinding(
                    severity="HIGH",
                    category="typosquatting",
                    package=pkg,
                    version=ver,
                    description=f"Possible typosquatting of '{typo}'",
                    remediation=f"Verify '{pkg}' is intentional; consider using '{typo}'",
                ))

            # git URL 의존성 (고정되지 않은 커밋)
            if re.match(r'github:|git\+', ver) and "@" not in ver:
                findings.append(SupplyChainFinding(
                    severity="MEDIUM",
                    category="workflow",
                    package=pkg,
                    version=ver,
                    description="Git URL dependency without commit hash — mutable reference",
                    remediation=f"Pin {pkg} to a specific commit hash",
                ))

        # postinstall 스크립트 확인
        scripts = data.get("scripts", {})
        for script_name in ("postinstall", "preinstall", "install"):
            if script_name in scripts:
                findings.append(SupplyChainFinding(
                    severity="MEDIUM",
                    category="workflow",
                    package=data.get("name", "this-package"),
                    version=data.get("version", "unknown"),
                    description=f"'{script_name}' lifecycle script present — runs arbitrary code on install",
                    remediation=f"Review script: {scripts[script_name][:100]}",
                ))

        return findings

    def scan_requirements_txt(self, path: str) -> list[SupplyChainFinding]:
        """Python requirements.txt 스캔."""
        findings: list[SupplyChainFinding] = []
        p = Path(path)
        if not p.exists():
            return findings

        content = p.read_text(encoding="utf-8", errors="ignore")
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # 패키지명 추출
            m = re.match(r'^([A-Za-z0-9_\-\.]+)', line)
            if not m:
                continue
            pkg = m.group(1).lower()

            if pkg in [p.lower() for p in self._MALICIOUS_PACKAGES.get("pypi", [])]:
                findings.append(SupplyChainFinding(
                    severity="CRITICAL",
                    category="malicious",
                    package=pkg,
                    version=line,
                    description=f"Known malicious PyPI package: {pkg}",
                    remediation=f"Remove {pkg} and audit all code that imports it",
                ))
                continue

            typo = self._detect_typosquatting(pkg, "pypi")
            if typo:
                findings.append(SupplyChainFinding(
                    severity="HIGH",
                    category="typosquatting",
                    package=pkg,
                    version=line,
                    description=f"Possible typosquatting of '{typo}'",
                    remediation=f"Verify '{pkg}' is intentional; consider using '{typo}'",
                ))

            # 버전 고정 없음
            if "==" not in line and ">=" not in line and "~=" not in line:
                findings.append(SupplyChainFinding(
                    severity="LOW",
                    category="outdated",
                    package=pkg,
                    version="unpinned",
                    description=f"Package '{pkg}' not pinned to specific version",
                    remediation=f"Pin {pkg} to a known-good version",
                ))

        return findings

    def check_dependency_confusion(
        self, internal_packages: list[str], registries: Optional[list[str]] = None
    ) -> list[SupplyChainFinding]:
        """
        Dependency Confusion 공격 탐지.
        내부 패키지 이름이 공개 레지스트리에 등록되어 있으면 취약.
        """
        findings: list[SupplyChainFinding] = []
        if registries is None:
            registries = ["pypi", "npm"]

        for pkg in internal_packages:
            for registry in registries:
                available = self._check_public_registry(pkg, registry)
                if available is True:
                    findings.append(SupplyChainFinding(
                        severity="CRITICAL",
                        category="dependency_confusion",
                        package=pkg,
                        version="public",
                        description=(
                            f"Internal package '{pkg}' exists on public {registry} registry! "
                            "Dependency confusion attack possible."
                        ),
                        remediation=(
                            f"Claim namespace '{pkg}' on {registry}, use private registry, "
                            "or use scoped package names (@org/pkg)"
                        ),
                    ))
                elif available is None:
                    findings.append(SupplyChainFinding(
                        severity="MEDIUM",
                        category="dependency_confusion",
                        package=pkg,
                        version="unknown",
                        description=f"Could not verify '{pkg}' on {registry} (network timeout)",
                        remediation="Manually verify on " + registry + ".org",
                    ))
        return findings

    def scan_github_actions(self, workflow_path: str) -> list[SupplyChainFinding]:
        """GitHub Actions 워크플로우 공급망 리스크 스캔."""
        findings: list[SupplyChainFinding] = []
        p = Path(workflow_path)

        if p.is_dir():
            yaml_files = list(p.rglob("*.yml")) + list(p.rglob("*.yaml"))
        elif p.is_file():
            yaml_files = [p]
        else:
            return findings

        for yf in yaml_files:
            content = yf.read_text(encoding="utf-8", errors="ignore")
            for pattern, severity, desc in self._RISKY_ACTION_PATTERNS:
                matches = re.findall(pattern, content, re.IGNORECASE)
                if matches:
                    findings.append(SupplyChainFinding(
                        severity=severity,
                        category="workflow",
                        package=str(yf.name),
                        version="",
                        description=f"{desc} (matched: {matches[0][:80]})",
                        remediation="See OWASP top-10 CI/CD security risks",
                    ))

        return findings

    def format_report(self, findings: list[SupplyChainFinding], lang: str = "en") -> str:
        """스캔 결과 보고서 포맷."""
        if not findings:
            return "✅ No supply chain issues found."

        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        findings = sorted(findings, key=lambda f: sev_order.get(f.severity, 5))

        lines = ["━" * 60, f"⛓️  Supply Chain Scan — {len(findings)} finding(s)", "━" * 60]
        icons = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "⚪"}
        for f in findings:
            icon = icons.get(f.severity, "⚪")
            lines.append(f"\n{icon} [{f.severity}] {f.category.upper()}")
            lines.append(f"   Package : {f.package} {f.version}")
            lines.append(f"   Issue   : {f.description}")
            lines.append(f"   Fix     : {f.remediation}")
            if f.cve:
                lines.append(f"   CVE     : {', '.join(f.cve)}")
        lines.append("━" * 60)
        return "\n".join(lines)

    # ── 내부 헬퍼 ───────────────────────────────────────────────────────

    def _detect_typosquatting(self, pkg: str, ecosystem: str) -> str:
        """Levenshtein distance 1-2 이내 잘 알려진 패키지와 비교."""
        popular = {
            "pypi": ["requests", "numpy", "pandas", "flask", "django", "sqlalchemy",
                     "boto3", "pydantic", "fastapi", "urllib3", "cryptography",
                     "paramiko", "pillow", "matplotlib", "scipy"],
            "npm": ["lodash", "express", "react", "axios", "webpack", "moment",
                    "chalk", "commander", "dotenv", "typescript", "eslint",
                    "prettier", "babel", "jest", "next"],
        }
        for known in popular.get(ecosystem, []):
            if pkg != known and self._levenshtein(pkg, known) <= 2:
                return known
        return ""

    @staticmethod
    def _levenshtein(a: str, b: str) -> int:
        if a == b:
            return 0
        if len(a) < len(b):
            a, b = b, a
        prev = list(range(len(b) + 1))
        for i, ca in enumerate(a):
            curr = [i + 1]
            for j, cb in enumerate(b):
                curr.append(min(prev[j + 1] + 1, curr[j] + 1,
                                prev[j] + (0 if ca == cb else 1)))
            prev = curr
        return prev[-1]

    def _check_public_registry(self, pkg: str, registry: str) -> Optional[bool]:
        """공개 레지스트리 존재 여부 확인 (timeout=4s)."""
        urls = {
            "pypi": f"https://pypi.org/pypi/{urllib.parse.quote(pkg)}/json",
            "npm": f"https://registry.npmjs.org/{urllib.parse.quote(pkg)}",
        }
        url = urls.get(registry)
        if not url:
            return None
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            resp = urllib.request.urlopen(req, timeout=4)
            return resp.status == 200
        except urllib.error.HTTPError as e:
            return e.code != 404
        except Exception:
            return None
