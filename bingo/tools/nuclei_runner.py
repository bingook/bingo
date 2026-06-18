"""bingo/tools/nuclei_runner.py — Nuclei CVE 템플릿 러너 (v2.6.0)"""
from __future__ import annotations

import re
import subprocess
import json
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable


@dataclass
class NucleiFinding:
    template_id: str
    name: str
    severity: str
    url: str
    matched: str
    description: str = ""
    cvss_score: float = 0.0
    cve_id: str = ""
    tags: list[str] = field(default_factory=list)


@dataclass
class NucleiReport:
    target: str
    nuclei_available: bool = False
    findings: list[NucleiFinding] = field(default_factory=list)
    templates_run: int = 0
    error: str = ""

    @property
    def critical(self) -> list[NucleiFinding]:
        return [f for f in self.findings if f.severity.lower() == "critical"]

    @property
    def high(self) -> list[NucleiFinding]:
        return [f for f in self.findings if f.severity.lower() == "high"]


# ── 내장 경량 템플릿 (Nuclei 미설치 시 폴백) ──────────────────────────────────
BUILTIN_TEMPLATES: list[dict] = [
    {
        "id": "springboot-actuator",
        "name": "Spring Boot Actuator Exposed",
        "severity": "HIGH",
        "paths": ["/actuator", "/actuator/env", "/actuator/mappings", "/actuator/beans"],
        "match": lambda r: "spring" in r.lower() or "classpath" in r.lower() or '"env"' in r,
        "description": "Spring Boot Actuator endpoint exposed — env, beans, health data",
    },
    {
        "id": "phpinfo-disclosure",
        "name": "PHP Info Disclosure",
        "severity": "MEDIUM",
        "paths": ["/phpinfo.php", "/info.php", "/php.php", "/test.php", "/i.php"],
        "match": lambda r: "PHP Version" in r and "php.ini" in r.lower(),
        "description": "PHP configuration info exposed",
    },
    {
        "id": "git-config-exposure",
        "name": "Git Config Exposure",
        "severity": "HIGH",
        "paths": ["/.git/config", "/.git/HEAD", "/.git/COMMIT_EDITMSG"],
        "match": lambda r: "[core]" in r or "ref: refs/heads" in r,
        "description": "Git repository config exposed — source code may be retrievable",
    },
    {
        "id": "env-file-exposure",
        "name": ".env File Exposure",
        "severity": "CRITICAL",
        "paths": ["/.env", "/.env.local", "/.env.production", "/.env.backup"],
        "match": lambda r: ("DB_PASSWORD" in r or "SECRET_KEY" in r or "API_KEY" in r or "APP_KEY" in r),
        "description": "Environment file with credentials exposed",
    },
    {
        "id": "wp-config-exposure",
        "name": "WordPress Config Exposure",
        "severity": "CRITICAL",
        "paths": ["/wp-config.php.bak", "/wp-config.php~", "/wp-config.txt"],
        "match": lambda r: "DB_PASSWORD" in r or "DB_NAME" in r or "define" in r,
        "description": "WordPress configuration file exposed",
    },
    {
        "id": "jenkins-unauthenticated",
        "name": "Jenkins Unauthenticated Access",
        "severity": "CRITICAL",
        "paths": ["/jenkins/", "/jenkins/api/json", "/api/json"],
        "match": lambda r: "Jenkins" in r and ("jobs" in r or "builds" in r),
        "description": "Jenkins accessible without authentication",
    },
    {
        "id": "kibana-unauthenticated",
        "name": "Kibana Unauthenticated Access",
        "severity": "HIGH",
        "paths": ["/app/kibana", "/api/status"],
        "match": lambda r: "kibana" in r.lower() or "Elasticsearch" in r,
        "description": "Kibana dashboard accessible without auth",
    },
    {
        "id": "redis-unauthenticated",
        "name": "Redis Unauthenticated (HTTP probe)",
        "severity": "CRITICAL",
        "paths": ["/"],
        "match": lambda r: "+PONG" in r or "redis_version" in r.lower(),
        "description": "Redis responding without authentication",
    },
    {
        "id": "graphql-introspection",
        "name": "GraphQL Introspection Enabled",
        "severity": "MEDIUM",
        "paths": ["/graphql", "/api/graphql", "/v1/graphql", "/gql"],
        "match": lambda r: "__schema" in r or "__type" in r,
        "description": "GraphQL introspection enabled — schema disclosed",
    },
    {
        "id": "swagger-ui",
        "name": "Swagger UI Exposed",
        "severity": "MEDIUM",
        "paths": ["/swagger-ui.html", "/swagger-ui/", "/api-docs", "/v2/api-docs", "/openapi.json"],
        "match": lambda r: "swagger" in r.lower() or "openapi" in r.lower(),
        "description": "API documentation (Swagger/OpenAPI) exposed",
    },
    {
        "id": "aws-credentials",
        "name": "AWS Credentials Exposed",
        "severity": "CRITICAL",
        "paths": ["/aws.json", "/.aws/credentials", "/config/aws.json"],
        "match": lambda r: "aws_access_key_id" in r.lower() or "AKIA" in r,
        "description": "AWS credentials exposed in file",
    },
    {
        "id": "backup-file",
        "name": "Backup File Exposure",
        "severity": "HIGH",
        "paths": ["/backup.zip", "/backup.tar.gz", "/backup.sql", "/db.sql",
                   "/database.sql", "/dump.sql", "/site.zip", "/www.zip"],
        "match": lambda r: len(r) > 100,  # 파일이 존재하면
        "description": "Backup or database file accessible",
    },
    {
        "id": "admin-panel",
        "name": "Admin Panel Exposed",
        "severity": "HIGH",
        "paths": ["/admin", "/admin/", "/admin/login", "/administrator", "/wp-admin",
                   "/phpmyadmin", "/adminer.php", "/manager/html"],
        "match": lambda r: any(kw in r.lower() for kw in ["admin", "login", "password", "dashboard"]),
        "description": "Administrative panel accessible",
    },
    {
        "id": "cve-2021-41773-apache",
        "name": "Apache Path Traversal CVE-2021-41773",
        "severity": "CRITICAL",
        "paths": ["/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd"],
        "match": lambda r: "root:" in r or "daemon:" in r,
        "description": "Apache HTTP Server 2.4.49 path traversal to RCE",
    },
    {
        "id": "cve-2022-22965-spring4shell",
        "name": "Spring4Shell CVE-2022-22965",
        "severity": "CRITICAL",
        "paths": ["/?class.module.classLoader.resources.context.parent.pipeline.first.pattern=test"],
        "match": lambda r: "400" not in str(r) and len(r) > 0,
        "description": "Spring Framework RCE via data binding",
    },
]


class NucleiRunner:
    """Nuclei CVE 템플릿 러너 (nuclei 설치 시 사용, 미설치 시 내장 탬플릿 폴백)"""

    def __init__(
        self,
        request_fn: Callable[[str, str, dict, str], tuple[int, str]],
        target: str,
        headers: dict | None = None,
    ) -> None:
        self.req = request_fn
        self.target = target.rstrip("/")
        self.headers = headers or {}
        self.nuclei_path = shutil.which("nuclei")

    def run_nuclei_binary(
        self,
        severity: str = "critical,high,medium",
        rate_limit: int = 100,
        extra_args: list[str] | None = None,
    ) -> NucleiReport:
        report = NucleiReport(target=self.target, nuclei_available=True)
        if not self.nuclei_path:
            report.nuclei_available = False
            report.error = "nuclei binary not found — using built-in templates"
            return report

        cmd = [
            self.nuclei_path, "-u", self.target,
            "-severity", severity,
            "-rate-limit", str(rate_limit),
            "-json", "-silent",
            "-no-color",
        ]
        if extra_args:
            cmd.extend(extra_args)
        if self.headers:
            for k, v in self.headers.items():
                cmd += ["-H", f"{k}: {v}"]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            for line in result.stdout.splitlines():
                try:
                    data = json.loads(line)
                    report.findings.append(NucleiFinding(
                        template_id=data.get("template-id", ""),
                        name=data.get("info", {}).get("name", ""),
                        severity=data.get("info", {}).get("severity", "unknown"),
                        url=data.get("matched-at", ""),
                        matched=data.get("matched-at", ""),
                        description=data.get("info", {}).get("description", ""),
                        cvss_score=data.get("info", {}).get("classification", {}).get("cvss-score", 0),
                        cve_id=", ".join(data.get("info", {}).get("classification", {}).get("cve-id", [])),
                        tags=data.get("info", {}).get("tags", []),
                    ))
                except Exception:
                    pass
        except subprocess.TimeoutExpired:
            report.error = "Nuclei scan timed out (300s)"
        except Exception as e:
            report.error = str(e)

        return report

    def run_builtin(self) -> NucleiReport:
        """내장 경량 템플릿으로 빠른 스캔"""
        report = NucleiReport(target=self.target, nuclei_available=False)
        report.templates_run = len(BUILTIN_TEMPLATES)

        for tmpl in BUILTIN_TEMPLATES:
            for path in tmpl["paths"]:
                url = self.target + path
                try:
                    status, body = self.req(url, "GET", self.headers, "")
                    if status in (200, 301, 302, 401) and tmpl["match"](body):
                        report.findings.append(NucleiFinding(
                            template_id=tmpl["id"],
                            name=tmpl["name"],
                            severity=tmpl["severity"],
                            url=url,
                            matched=url,
                            description=tmpl["description"],
                        ))
                        break
                except Exception:
                    pass

        return report

    def scan(self, use_nuclei: bool = True) -> NucleiReport:
        if use_nuclei and self.nuclei_path:
            report = self.run_nuclei_binary()
            if not report.error:
                return report
        return self.run_builtin()
