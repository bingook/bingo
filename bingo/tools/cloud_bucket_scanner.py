"""bingo/tools/cloud_bucket_scanner.py — 클라우드 버킷 공개 노출 스캐너 (v2.6.0)"""
from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Callable


@dataclass
class BucketFinding:
    provider: str       # "AWS S3" | "GCS" | "Azure Blob"
    bucket_name: str
    url: str
    is_public: bool
    is_listable: bool
    files_preview: list[str]
    sensitive_files: list[str]
    severity: str
    notes: str = ""


@dataclass
class BucketReport:
    target: str
    findings: list[BucketFinding] = field(default_factory=list)

    @property
    def critical(self) -> list[BucketFinding]:
        return [f for f in self.findings if f.severity == "CRITICAL"]


# ── 민감 파일 패턴 ─────────────────────────────────────────────────────────────
SENSITIVE_PATTERNS = [
    r'\.env', r'backup\b', r'\.sql', r'\.bak', r'\.key', r'private\.pem',
    r'credentials', r'secret', r'password', r'config\.json', r'\.aws',
    r'database', r'dump', r'\.tar\.gz', r'\.zip', r'\.db',
    r'id_rsa', r'\.pfx', r'\.p12',
]


class CloudBucketScanner:
    """S3 / GCS / Azure Blob 공개 버킷 탐지"""

    def __init__(
        self,
        request_fn: Callable[[str, str, dict, str], tuple[int, str]],
        target_domain: str,
        headers: dict | None = None,
    ) -> None:
        self.req = request_fn
        self.domain = target_domain.lstrip("https://").lstrip("http://").split("/")[0]
        self.headers = headers or {}
        self._company = self.domain.split(".")[0]

    # ── 버킷 이름 변형 생성 ───────────────────────────────────────────────────
    def _generate_bucket_names(self) -> list[str]:
        c = self._company
        return list(set([
            c, f"{c}-assets", f"{c}-static", f"{c}-media", f"{c}-uploads",
            f"{c}-backup", f"{c}-backups", f"{c}-db", f"{c}-data",
            f"{c}-dev", f"{c}-staging", f"{c}-prod", f"{c}-production",
            f"{c}-logs", f"{c}-log", f"{c}-archive",
            f"{c}-public", f"{c}-private", f"{c}-internal",
            f"{c}-cdn", f"{c}-files", f"{c}-storage",
            f"assets.{c}", f"static.{c}", f"media.{c}",
            f"{c}assets", f"{c}backup", f"{c}files",
            # 한국 기업 특화
            f"{c}-kr", f"{c}-korea", f"{c}-ko",
        ]))

    # ── AWS S3 ────────────────────────────────────────────────────────────────
    def scan_s3(self, bucket_name: str) -> BucketFinding | None:
        urls = [
            f"https://{bucket_name}.s3.amazonaws.com/",
            f"https://s3.amazonaws.com/{bucket_name}/",
            f"https://{bucket_name}.s3.ap-northeast-2.amazonaws.com/",  # 서울 리전
        ]
        for url in urls:
            try:
                status, resp = self.req(url, "GET", self.headers, "")
                is_public = status in (200, 301, 403)
                is_listable = status == 200 and "<ListBucketResult" in resp

                if not is_public:
                    continue

                files = re.findall(r"<Key>([^<]+)</Key>", resp)
                sensitive = [f for f in files if any(re.search(p, f, re.I) for p in SENSITIVE_PATTERNS)]

                sev = "LOW"
                if is_listable:
                    sev = "HIGH"
                if sensitive:
                    sev = "CRITICAL"

                return BucketFinding(
                    provider="AWS S3", bucket_name=bucket_name,
                    url=url, is_public=is_public, is_listable=is_listable,
                    files_preview=files[:10], sensitive_files=sensitive,
                    severity=sev,
                    notes=f"Status: {status} | Files: {len(files)} | Sensitive: {len(sensitive)}",
                )
            except Exception:
                pass
        return None

    # ── Google Cloud Storage ──────────────────────────────────────────────────
    def scan_gcs(self, bucket_name: str) -> BucketFinding | None:
        urls = [
            f"https://storage.googleapis.com/{bucket_name}/",
            f"https://{bucket_name}.storage.googleapis.com/",
        ]
        for url in urls:
            try:
                status, resp = self.req(url, "GET", self.headers, "")
                is_public = status in (200, 403)
                is_listable = status == 200 and ("name" in resp or "<Contents>" in resp)

                if not is_public:
                    continue

                # GCS JSON API 응답에서 파일 추출
                files = re.findall(r'"name"\s*:\s*"([^"]+)"', resp)
                sensitive = [f for f in files if any(re.search(p, f, re.I) for p in SENSITIVE_PATTERNS)]

                return BucketFinding(
                    provider="GCS", bucket_name=bucket_name,
                    url=url, is_public=is_public, is_listable=is_listable,
                    files_preview=files[:10], sensitive_files=sensitive,
                    severity="CRITICAL" if sensitive else ("HIGH" if is_listable else "MEDIUM"),
                    notes=f"GCS bucket status: {status}",
                )
            except Exception:
                pass
        return None

    # ── Azure Blob Storage ────────────────────────────────────────────────────
    def scan_azure(self, account_name: str) -> BucketFinding | None:
        container_names = ["public", "assets", "media", "uploads", "backups", "$web"]
        for container in container_names:
            url = f"https://{account_name}.blob.core.windows.net/{container}?restype=container&comp=list"
            try:
                status, resp = self.req(url, "GET", self.headers, "")
                if status == 200:
                    files = re.findall(r"<Name>([^<]+)</Name>", resp)
                    sensitive = [f for f in files if any(re.search(p, f, re.I) for p in SENSITIVE_PATTERNS)]
                    return BucketFinding(
                        provider="Azure Blob", bucket_name=f"{account_name}/{container}",
                        url=url, is_public=True, is_listable=True,
                        files_preview=files[:10], sensitive_files=sensitive,
                        severity="CRITICAL" if sensitive else "HIGH",
                        notes=f"Azure container '{container}' publicly listable",
                    )
            except Exception:
                pass
        return None

    # ── HTML에서 버킷 URL 직접 추출 ──────────────────────────────────────────
    def extract_bucket_urls_from_html(self, html: str) -> list[BucketFinding]:
        findings = []
        s3_pattern = re.compile(r'https?://([a-z0-9\-\.]+)\.s3(?:-[a-z0-9-]+)?\.amazonaws\.com', re.I)
        gcs_pattern = re.compile(r'https?://storage\.googleapis\.com/([a-z0-9\-_]+)', re.I)
        azure_pattern = re.compile(r'https?://([a-z0-9]+)\.blob\.core\.windows\.net', re.I)

        for m in s3_pattern.finditer(html):
            bucket = m.group(1)
            f = self.scan_s3(bucket)
            if f:
                findings.append(f)

        for m in gcs_pattern.finditer(html):
            bucket = m.group(1)
            f = self.scan_gcs(bucket)
            if f:
                findings.append(f)

        for m in azure_pattern.finditer(html):
            account = m.group(1)
            f = self.scan_azure(account)
            if f:
                findings.append(f)

        return findings

    def full_scan(self) -> BucketReport:
        report = BucketReport(target=self.domain)
        names = self._generate_bucket_names()

        # HTML에서 직접 버킷 URL 추출
        try:
            _, html = self.req(f"https://{self.domain}", "GET", self.headers, "")
            report.findings.extend(self.extract_bucket_urls_from_html(html))
        except Exception:
            pass

        # 이름 변형으로 S3/GCS/Azure 순차 탐색
        for name in names:
            for scan_fn in (self.scan_s3, self.scan_gcs):
                finding = scan_fn(name)
                if finding and finding.is_public:
                    # 중복 제거
                    existing = {f.bucket_name for f in report.findings}
                    if finding.bucket_name not in existing:
                        report.findings.append(finding)

        return report
