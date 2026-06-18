<div align="center">

<img src="assets/logo.png" width="180" alt="bingo logo"/>

# bingo

**AI 驱动的红队终端**

[![Version](https://img.shields.io/badge/version-2.9.2-brightgreen?logo=github)](https://github.com/bingook/bingo/releases)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue?logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey)](https://github.com/bingook/bingo)

*DeepSeek · Claude · GPT · GLM · Qwen · Ollama · Custom*

**🌐 Language / 언어 / 语言:**
[English](README.md) · [한국어](README_ko.md) · [中文](README_zh.md)

> **v2.9.2 — 缺陷修复：CMS偏见消除 / 每目标独立检测**  
> XSS会话劫持 · 上传RCE · SSRF AWS/云凭证窃取 · 管理员面板自动化 · JS秘密探测 · HTTP走私 · GraphQL全攻 · OAuth/JWT伪造 · Playwright截图 · Slack/Discord告警

</div>

---

## 什么是 bingo？

bingo 是一个黑客风格的 AI 终端，自动化执行真实的渗透测试工作流程。  
输入目标 URL，bingo 自动运行完整红队流水线 —— WAF 检测、漏洞扫描、SQL 注入、文件上传利用、IDOR 枚举、哈希破解、自动生成报告 —— 全部由您选择的 AI 模型驱动。

**零幻觉引擎** (v2.3.13 — 四层验证): 每条 AI 响应必须通过四个独立层级验证后才被接受。
1. 代码块: 拒绝 JSON 字典、桩代码、模拟代码
2. 文本级别: 拦截 JSON 计划书、AI 自白文
3. 伪造凭据: 阻止无 HTTP 证据的密码/哈希声明
4. 未证明结论: 无代码块声明"发现SQLi"等 → 自动拦截，强制生成 Python requests 代码

**Burp 引擎** (v2.3): 纯 Python 实现的 Burp Suite 功能集，无需安装 Burp Suite。

| Burp 功能 | bingo 等价 | 说明 |
|---|---|---|
| Repeater | `burp_engine.repeater()` | 自定义请求头/正文重放 HTTP 请求 |
| Intruder | `burp_engine.intruder()` | 在 `§payload§` 标记处进行负载模糊测试 |
| Scanner (Active) | `burp_engine.scanner_active()` | 自动检测 SQLi / XSS / SSTI |
| Collaborator | `burp_engine.CollaboratorClient()` | 基于 interactsh 的带外检测 |
| Comparer | `burp_engine.comparer()` | 响应比对，确认布尔型 SQLi |

---

## 安装

### 方式 A — pip（推荐）

```bash
pip install bingo-ai
bingo
```

更新：
```bash
bingo --update
```

### 方式 B — git clone（macOS / Linux）

```bash
curl -fsSL https://raw.githubusercontent.com/bingook/bingo/main/install.sh | bash
```

### 方式 C — Windows

```powershell
pip install bingo-ai
bingo
```

---

## 快速开始

```
bingo
> 选择语言: zh
> 输入 API 密钥: sk-...
> 输入目标: https://target.com
```

剩下的交给 bingo 自动处理。

---

## 常用命令

| 命令 | 说明 |
|------|------|
| `/lang zh` | 切换语言 (ko / zh / en) |
| `/model deepseek` | 切换 AI 模型 |
| `/report` | 生成渗透测试报告 |
| `/history` | 查看会话历史 |
| `/clear` | 清除屏幕 |

---

## 支持的 AI 模型

| 模型 | 环境变量 |
|------|---------|
| DeepSeek | `DEEPSEEK_API_KEY` |
| Claude | `ANTHROPIC_API_KEY` |
| GPT-4o | `OPENAI_API_KEY` |
| GLM-4 | `ZHIPU_API_KEY` |
| Qwen | `DASHSCOPE_API_KEY` |
| Ollama | 自动检测本地实例 |

---

## 核心功能

### 零幻觉引擎
- 四层验证彻底阻止 AI 虚假报告
- 所有漏洞必须有真实 HTTP 响应证据

### 精密 SQLi 引擎
- 支持 MSSQL / MySQL / PostgreSQL / Oracle
- 自动选择 Boolean blind、Time-based、Error-based、UNION
- 自动生成 WAF 绕过载荷
- **v2.3.26 新增**: 无限循环防护 —— 重复结果 5 次 → 立即终止进程

### WAF 绕过
- 支持 Cloudflare · Safe3 · D盾 · 云锁
- 自动应用编码变形 / 注释插入 / HPP / chunked 编码

### 中国 WAF 专项
- Safe3 WAF → null byte unicode → overlong UTF-8 → 函数替换
- D盾 → 关键字混淆
- 云锁 → HTTP 参数污染

---

## v2.9.2 —— 缺陷修复：CMS偏见消除 *(2026-06)*

**问题**：AI基于历史扫描记录，对新目标自动假设Gnuboard/韩国CMS，
未获取HTML证据便尝试`/bbs/board.php`、`bo_table`等路径。

**2项核心修复**

| # | 缺陷 | 修复方案 |
|---|---|---|
| 1 | 仅凭`.kr`域名假设Gnuboard — 无HTML证据便执行韩国CMS专项逻辑 | 系统提示：新增`ZERO CMS BIAS`铁律规则块 + Gnuboard区段条件门控 |
| 2 | 切换目标时旧对话的CMS上下文残留，污染AI推断 | `terminal.py`：目标变更时仅保留最后4轮历史 + 注入`NEW TARGET RESET`通知 |

**零CMS偏见规则 (v2.9.2):**
```
每个新目标 → CMS = 完全未知 (UNKNOWN)
Gnuboard区段 → 仅在以下条件之一确认后适用：
  (a) check_gnuboard(TARGET) → True
  (b) CONFIRMED_TECH_STACK 显示 "Gnuboard"
  (c) HTML源码含 "bo_table=" 或 "/bbs/"
  (d) 响应体含 "gnuboard" 或 "g5_" 模式
.kr顶级域名单独存在 ≠ 证据。确认前视为自定义开发站点。
```

---

## v2.9.1 —— 缺陷修复版本 *(2026-06)*

**3项关键修复**

| # | 缺陷 | 修复方案 |
|---|---|---|
| 1 | `session_saved` i18n键被覆盖 — `{name}` / `{role}` 显示为原始占位符 | v2.9.0键重命名为`session_mgr_saved`；原始`session_saved`键已恢复 |
| 2 | `InsecureRequestWarning`垃圾信息淹没扫描日志 | `tools_header`自动注入`urllib3.disable_warnings()`到所有AI生成脚本 |
| 3 | 误报 — `/admin/` · `/bbs/` 返回200但实为"页面不存在"内容 | `http_probe`+`recon_tools`增加软404内容过滤器 |

**软404检测逻辑 (v2.9.1):**
```
触发关键词: 404 / not found / 페이지를 찾을 수 없 / 页面不存在 / 找不到页面
            该页面不存在 / page not found / error 404
响应体<500字节 且无<form>/<input> → 自动标记为误报并过滤
```

---

## v2.9.0 —— 7链高级攻击引擎 (+50%强化) *(2026-06)*

**11个新模块**

| 模块 | 功能 |
|---|---|
| `xss_exploiter` | 会话劫持 · 键盘记录器注入 · BeEF Hook · Stored XSS→CSRF链 · CSP绕过 |
| `upload_exploiter` | 30+扩展名绕过 · .htaccess覆写 · GIF/PHP多语言Shell · RCE自动确认 |
| `ssrf_advanced` | AWS IMDSv1/v2凭证窃取 · GCP/Azure元数据 · Gopher Redis WebShell · 内网扫描 |
| `admin_panel_auto` | 1000+路径探测 · CSRF令牌自动提取 · 凭证爆破 · 功能枚举 |
| `js_secret_finder` | 50+秘密模式 · 隐藏API提取 · JWT alg:none伪造 · 硬编码凭证检测 |
| `smuggling_exploiter` | CL.TE / TE.CL检测 · 时序盲检测 · 管理员请求投毒 |
| `graphql_advanced` | Schema转储 · 敏感变更检测 · 批量rate-limit绕过 · SQL/NoSQL注入 |
| `oauth_attacker` | JWT alg:none · RS256→HS256混淆 · kid SQL注入 · redirect_uri绕过 · state CSRF |
| `playwright_engine` | 登录+截图 · DOM XSS确认 · JS渲染 · requests回退 |
| `webhook_reporter` | Slack · Discord · Telegram · CRITICAL立即 / LOW批量 |
| `session_manager` | 多账户池 · 自动重新登录 · CSRF刷新 · Cookie序列化 |

**AI自动判断规则 (v2.9.0):**
- 检测到JWT/OAuth → 立即运行`OauthAttacker`
- 发现上传表单 → 立即运行`UploadExploiter`
- 检测到GraphQL → 立即运行`GraphqlAdvancedEngine`
- URL参数 → `SsrfAdvancedEngine` + AWS元数据检查
- XSS反射确认 → `XssExploiter` + 会话劫持链
- 获得凭证 → `AdminPanelAuto` + Playwright截图

## v2.8.0 —— 高级SQLi引擎：超越sqlmap *(2026-06)*

**新增模块:** `bingo/tools/sqli_advanced.py` — **SqliAdvancedEngine**

| 功能 | 详细说明 |
|---|---|
| Tamper脚本 | 60+个：空格替换(10+) · 编码(10+) · 关键字处理(15+) · WAF特化(韩国WAPPLES/GENIAN/Cloudbric/GnuBoard) |
| WAF自动匹配 | 检测WAF → 自动选择最优Tamper链（无需手动配置）|
| OOB外带提取 | DNS外带(MySQL LOAD_FILE UNC / MSSQL xp_dirtree / Oracle UTL_HTTP / PG COPY PROGRAM) |
| Level系统 | 1(仅GET) → 3(含Headers) → 5(全面+重量级Payload) |
| Risk系统 | 1(只读) → 2(OR型+写WebShell) → 3(破坏性:DROP/TRUNCATE) |
| LOAD_FILE | 自动读取/etc/passwd · /etc/my.cnf · config.php · wp-config.php · database.php |
| INTO OUTFILE | 自动尝试7个路径写入PHP WebShell |
| Stacked RCE | MSSQL xp_cmdshell · PG COPY TO PROGRAM · MySQL general_log Shell |
| UDF注入 | MySQL UDF DLL → sys_exec() OS命令执行 |
| 二阶注入 | 注册存储Payload → 个人中心/管理员页面触发 |
| Hash分析器 | 自动分类18种Hash类型(MD5/SHA1/bcrypt/MySQL-hash/PHPass等) |
| 快速破解 | 内存字典破解(含韩语常见密码) |
| DB指纹识别 | 精准版本/OS/架构检测 + MySQL漏洞CVE匹配 |
| Header注入 | Cookie · Referer · User-Agent · X-Forwarded-For · Host (Level≥3) |

---

## v2.7.0 —— DB全量自动转储引擎 *(2026-06)*

**新模块:**
- `bingo/tools/db_dumper.py` — **DB自动转储引擎**: SQLi确认/WebShell上传/RCE成功后立即触发，零人工干预全量转储数据库

**核心功能:**
| 功能 | 详情 |
|---|---|
| 数据库支持 | MySQL, MSSQL, PostgreSQL, SQLite, Oracle |
| 表自动分类 | 管理员(优先级100) → 会员(90) → 敏感(50) → 其他 |
| 会员表检测 | `member/user/account/g5_member/xe_member/mb_` 等20+模式 |
| 管理员表检测 | `admin/administrator/manager/g5_admin/xe_admin` 等 |
| 敏感表检测 | `payment/card/order/session/token/config` 等 |
| 凭据提取 | 自动识别ID/邮箱 + 密码/哈希列 → `CREDENTIALS_{table}.json` |
| 批量分页 | 每次500行，每表最多50,000行 |
| UNION SQLi转储 | `dump_via_sqli_union()` — GROUP_CONCAT + LIMIT/OFFSET分页 |
| WebShell转储 | `gen_webshell_dump_cmd()` — 生成mysqldump/sqlcmd/psql命令 |
| 保存格式 | 每表JSON + CSV (UTF-8 BOM) + DUMP_SUMMARY.txt |

**转储后自动行动:**
1. `CREDENTIALS_*.json` → 自动尝试在 `/admin`, `/manage` 登录管理员
2. 检测到密码哈希 → 建议 `hashcat -m {mode}` 破解命令
3. 会员邮件列表 → 记录用于凭据填充分析
4. 全量转储路径 → 自动添加到渗透测试报告

---

## v2.6.0 —— 高级攻击层：15个新引擎（SSTI/走私/侦察/Nuclei/业务逻辑/DOM-XSS/存储桶...） *(2026-06)*

**新增模块 — TIER 1（核心攻击原语）：**
- `ssti_scanner.py` — SSTI自动引擎：8个模板引擎多语言探测（Jinja2、Twig、Freemarker、Velocity、Smarty、Mako、Pebble、Thymeleaf），已验证RCE链
- `param_discovery.py` — 参数自动发现：200+词表+HTML/JS提取爆破、Header注入绕过（X-Forwarded-For、X-Original-URL）、HTTP参数污染
- `subdomain_takeover.py` — 子域名接管扫描器：悬空CNAME检测、23个服务指纹（AWS S3、GitHub Pages、Heroku、Netlify、Vercel、Azure、Cafe24...）
- `smuggling_scanner.py` — HTTP请求走私：CL.TE / TE.CL / TE.TE 原始Socket请求、时序检测、TE.TE混淆6种变体
- `race_condition.py` — 竞争条件引擎：线程并发（20个同时）+ 最后字节同步，针对优惠券/积分/支付的TOCTOU攻击

**新增模块 — TIER 2（协议与认证深度）：**
- `graphql_tester.py` — GraphQL深度测试器：内省转储、批量DoS、别名速率限制绕过、Schema感知IDOR检测
- `twofa_bypass.py` — 2FA/OTP绕过：暴力破解、响应篡改提示、OTP重用、备份码泄露、认证步骤跳过
- `cache_poison.py` — 缓存投毒/欺骗：14个非关键缓存头、Fat GET注入、路径后缀缓存欺骗（/profile.css、/data.js）
- `deserialize_tester.py` — 反序列化测试器：Java/PHP/Python Pickle/.NET ViewState/AMF魔术字节检测、ysoserial命令自动生成
- `recon_engine.py` — 域名侦察引擎：crt.sh子域名CT枚举、端口扫描、技术指纹识别、WAF/CDN检测、邮箱收集

**新增模块 — TIER 3（广覆盖自动化）：**
- `nuclei_runner.py` — Nuclei CVE运行器：nuclei二进制集成 OR 15个内置模板（.env、phpinfo、git、wp-config、Jenkins、Kibana、Swagger、Spring4Shell、Apache路径遍历...）
- `bizlogic_fuzzer.py` — 业务逻辑Fuzzer：负数/溢出金额、工作流跳过、优惠券滥用（ADMIN/FREE/TEST/NULL）、数量操控（0/-1/INT_MAX）
- `dom_xss_scanner.py` — DOM XSS扫描器：JS文件Source/Sink静态分析、易受攻击库检测（jQuery/AngularJS/Bootstrap）、URL片段反射测试
- `api_version_enum.py` — API版本枚举器：30+版本路径、各版本认证绕过、安全回归检测（SQL错误、调试信息、Swagger泄露）
- `cloud_bucket_scanner.py` — 云存储桶扫描器：AWS S3/GCS/Azure Blob公开访问与可列举性检查、20+名称排列、敏感文件检测（.env/.sql/.key/backup）

**集成：**
- 15个模块均通过`bingo/tools/__init__.py`懒加载注册
- `system_prompt.py`更新：`=== v2.6.0 ADVANCED ATTACK LAYER DECISION RULES ===` + 8阶段完整流水线

**多语言：** 40个新i18n字符串键（ko/zh/en）

**自动化编排流水线（v2.6.0）：**
```
PHASE 0: ReconEngine → SubdomainTakeover
PHASE 1: NucleiRunner（快速收益）
PHASE 2: JsAnalyzer → ParamDiscovery → ApiVersionEnum → CloudBucketScanner
PHASE 3: JWT/2FA/AuthBypass
PHASE 4: SQLi → SSTI → XXE → GraphQL
PHASE 5: BizLogic → RaceCondition → UploadBypass
PHASE 6: Smuggling → CachePoison → IDOR
PHASE 7: DomXSS → SSRF
PHASE 8: PostExploit → ReportBuilder
```

---

## v2.5.0 —— 全自动攻击套件：JS/IDOR/认证/SSRF/XXE/上传/报告/CMS/后渗透 *(2026-06)*

**新增模块（9个引擎）：**
- `js_analyzer.py` — JS自动分析器：API接口提取、硬编码密钥检测（AWS密钥、JWT Secret、数据库密码）、管理路径发现、GraphQL/WebSocket接口枚举
- `idor_scanner.py` — IDOR/越权自动扫描器：水平越权（用户→用户）+ 垂直越权（用户→管理员）自动检测，ID变异测试（±1、±2、常见ID）
- `auth_bypass.py` — 认证绕过自动化引擎：JWT漏洞（alg:none、弱密钥爆破、kid注入）、OAuth redirect_uri篡改、密码重置Host头注入、会话Token分析
- `ssrf_scanner.py` — SSRF自动扫描器：敏感URL参数检测、内网IP/云元数据探测（AWS/GCP/Azure 169.254.169.254）、协议包装器测试（file://、dict://、gopher://）、OOB回调
- `xxe_scanner.py` — XXE自动扫描器：带内文件读取Payload、OOB DNS回调、SVG/DOCX XXE Payload生成、SSRF-via-XXE链式利用
- `upload_bypass.py` — 上传绕过引擎：双重扩展名/null字节/大小写变形、MIME类型篡改、魔术字节伪造、GIF89a polyglot Webshell、RCE验证
- `report_builder.py` — 报告自动生成器：CVSS v3.1自动评分、cURL PoC自动生成、漏洞严重级别分类、Markdown/JSON输出
- `korean_cms.py` — 韩国CMS漏洞扫描器：GnuBoard5、XpressEngine、Rhymix、Cafe24、영카트、WordPress指纹识别、管理后台探测、CMS专属SQLi/LFI/IDOR检测
- `post_exploit.py` — 后渗透引擎：自动信息收集（系统、网络、用户、环境变量、历史命令）、SUID/sudo/Docker提权向量检测、crontab/SSH Key/Webshell持久化

**集成：**
- 9个模块均通过`bingo/tools/__init__.py`懒加载注册（零import开销）
- `system_prompt.py`新增`=== v2.5.0 EXPANDED AUTO-ENGINE DECISION RULES ===`：AI根据目标上下文自动选择引擎

**多语言：** 20个新i18n字符串键（ko/zh/en）

---

## v2.4.0 —— AI自动SQLi阶段切换 + 数据库提权 + Shell投放 + WAF++ *(2026-06)*

**新增模块：**
- `sqli_auto.py` — SQLi自动阶段切换引擎（报错→联合→布尔→时间→堆叠，按DB类型自动选择Payload）
- `db_privesc.py` — 数据库权限提升自动化（xp_cmdshell启用、EXECUTE AS、INTO OUTFILE、COPY TO PROGRAM）
- `shell_dropper.py` — Webshell投放 + 反弹Shell自动生成（certutil、PowerShell、bash/python/nc）

**新WAF指纹：** dotDefender、Imperva、Wallarm、360wzws、安全宝、Nginx WAF — 专属绕过策略

**多语言：** 14个新i18n字符串键（ko/zh/en）

**系统提示词：** 新增 `=== v2.4.0 AUTO-ENGINE DECISION RULES ===` 章节

## v2.3.33 —— 报告幻觉修复：会话状态隔离 *(2026-06)*

- **🔴 错误修复: 报告幻觉 — 上次会话数据泄漏已完全消除** — 用户选择`n`（不恢复）时，上次会话的凭据/表/数据库名残留在`_agent_state`中，导致新会话最终报告包含未经本次验证的旧数据（"报告幻觉"）。修复方式：`_offer_resume()`的`n`分支中立即调用`_reset_agent_state()`，完全清除上次会话状态。
- **🟢 新增当前会话追踪：`_session_tables` / `_session_credentials`** — 新增2个内存列表，仅累积本次会话实际发现的项目。`_parse_agent_state()`解析表/凭据时同步更新这两个列表。
- **🟢 报告Prompt强化** — `_auto_generate_report()`现在向AI分别传递"本次会话已确认项目"和"上次会话项目"。明确指示AI：*"凭据部分只报告本次会话的项目。上次会话项目标注为⚠️ 来自上次会话（未重新验证）。"*
- **🟡 多语言: 3个新增键** — `session_state_cleared`, `session_prev_data_warning`, `session_current_confirmed`（ko/zh/en）。

## v2.3.32 —— UTF-16LE哈希误报过滤 *(2026-06)*

- **🔴 哈希检测: UTF-16LE误报过滤** — `extract_hashes_from_text`现在能识别UTF-16LE编码字符串（如`25004D0065006D006200650072002500` = `%Member%`）与NTLM哈希的混淆。每个2字节对的高位或低位字节规律性出现`00`时判定为UTF-16LE编码并跳过破解。防止MSSQL/ASP Unicode列数据的无效token消耗。
- **🟡 多语言: 1个新增键** — `hash_utf16le_skipped`（ko/zh/en）。

## v2.3.31 —— urllib.parse自动import注入 *(2026-06)*

- **🔴 Precheck: `urllib.parse`自动注入** — AI代码使用`urllib.parse.quote/urlencode/urlparse`等但缺少`import urllib.parse`时，`_precheck_python_code`在执行前自动注入。彻底解决`NameError: name 'urllib' is not defined`（防止将`urllib3`与`urllib.parse`混淆）。
- **🔴 规则21: urllib.parse vs urllib3** — `import urllib3`不激活标准库`urllib.parse`。必须显式`import urllib.parse`或`from urllib.parse import quote`。
- **🟡 多语言: 1个新增键** — `urllib_parse_injected`（ko/zh/en）。

## v2.3.30 新功能 —— 响应编码自动检测、Banner版本修复、Syntax Precheck误报修复 *(2026-06)*

- **🔴 规则21: 响应编码自动检测** — AI不再直接使用`r.text`。自动检测EUC-KR/EUC-JP/GB2312等旧式韩日中网站编码，彻底解决乱码问题（`Է`等）。优先级：Content-Type头 → HTML meta charset → apparent_encoding → UTF-8。
- **🔴 Precheck: `r.text` → `smart_decode()`自动注入** — `_precheck_python_code`检测到`requests.get/post` + `.text`用法时，自动插入`_smart_decode()`辅助函数并替换所有`.text`调用。
- **🟠 Banner版本修复** — 终端Banner不再硬编码`v2.3.4`，改为动态读取`__version__`。
- **🟠 Syntax Precheck误报修复** — `None`返回值同时表示"正常"和"错误"导致每次都显示警告的问题已修复，分离为`None`（正常）vs `__SYNTAX_ERR__`（真实错误）。
- **🟡 多语言: 2个新增键** — `encoding_auto_detected`、`encoding_inject_notice`（ko/zh/en）。

## v2.3.29 —— WAF ReadTimeout防护、URL拼接修复、f-string自动修复 *(2026-06)*

- **🔴 规则19/20** — ReadTimeout=WAF静默丢弃判断；禁止`base_url + "https://..."`。
- **🟡 多语言: 2个新增键** — `waf_timeout_detected`、`url_concat_fixed`（ko/zh/en）。

## v2.3.26 新功能 —— 硬看门狗超时、pymssql VPN防护、Oracle验证 *(2026-06)*

### 错误修复

- **🔴 修复阻塞套接字无限等待（pymssql无限循环）** — 新增专用看门狗线程，即使子进程无任何stdout输出，也能在300秒后执行 `p.kill()`。旧版超时机制仅在 `for raw_line in p.stdout:` 循环内触发，当pymssql在TCP连接时无输出，循环永不推进，超时检查也永不执行。
- **🔴 规则13：pymssql/pyodbc强制超时** — AI必须始终设置 `timeout=10, login_timeout=10`，并在守护线程（`join(timeout=15)`）中运行。绝不能将VPN NAT IP（`198.18.x.x`、`192.168.x.x`等）用作SQL Server目标。
- **🟠 规则14：布尔Oracle事先验证** — 启动逐字符提取循环前，必须确认TRUE/FALSE响应大小差异 ≥ 10字节。相同则Oracle无效 → 切换技术。
- **🟠 规则15：WAITFOR严格阈值** — `WAITFOR 5s` 仅在响应时间 ≥ 4.0s时有效。1.36s响应为误报。
- **🟡 规则16：凭据优先攻击顺序** — 若已提取数据库凭据，必须先尝试所有识别到的登录表单，再继续复杂盲注。无 `<input type="password">` 的页面直接跳过。
- **i18n: 新增6个多语言键** — `script_watchdog_killed`、`pymssql_vpn_ip_warn`、`bool_oracle_invalid`、`waitfor_false_positive`、`cred_first_login_try`、`login_page_no_form`（ko/zh/en）。

## v2.3.25 新功能 —— SQL注入Oracle精度改进 & UnboundLocalError修复

### 错误修复

- **🔴 修复 `UnboundLocalError: cannot access local variable 't'`** — `_run_code_blocks` 中 `for t in threads:` 循环变量覆盖了全局 `t()` 翻译函数。已将3处全部改为 `for _th in threads:`。
- **🟠 修复 VBScript 800a01a8 误报警告** — 当同一批次结果中同时出现OLE DB SQL错误（`80040e14`、`80040e07`）时，抑制VBScript"不可注入"警告。正确识别混合结果。
- **🟠 修复 AI将800a01a8误判为WAF绕过成功** — 新增规则11：`800a01a8 = VBScript运行时错误 ≠ WAF绕过`。AI不再将800a01a8响应标记为注入成功。
- **🟡 修复 在类型化整数参数上浪费ORDER BY/UNION枚举** — 新增规则12：检测到类型错误时立即停止ORDER BY和UNION SELECT枚举。
- **i18n: 新增3个多语言键** — `mixed_sqli_result_title`、`mixed_sqli_result_detail`、`typed_param_skip`（ko/zh/en）。

---

## v2.3.26 早期功能 —— 无限循环终止器

旧版本中，表枚举循环曾连续运行 28 分钟，将同一张表输出 383 次。  
v2.3.26 新增三层防护：

| 层级 | 机制 | 触发条件 |
|------|------|---------|
| 执行前拦截 | 静态分析 | `for`+`range`+`TOP 1`+无`seen=set()` → 直接阻止执行 |
| 实时 KILL | 流式输出监控 | 同一行重复 5 次 → 立即终止进程 |
| 超时限制 | 硬性限制 | 脚本超过 300 秒 → 强制终止 |

**正确枚举模式（v2.3.26 强制要求）**：
```python
seen = set()
last_hex = ''
while True:
    cursor = f' AND name > {last_hex}' if last_hex else ''
    payload = f"AND(1)=(SELECT TOP 1 name FROM sysobjects WHERE xtype=0x55{cursor})"
    result = extract(payload)
    if not result or result in seen:
        break
    seen.add(result)
    last_hex = '0x' + result.encode().hex().upper()
    print(result)
# 输出: 不含重复的唯一表名列表
```

---

## SQL 注入 Oracle 规则 (v2.3.21+)

```
✅ 有效 oracle: TRUE/FALSE 载荷产生可预测的不同响应
❌ 无效: WAF 403/503 ≠ 布尔条件
❌ 无效: 仅凭响应大小判断（必须比对内容）

✅ 登录成功: 响应正文含退出登录链接或用户 ID
❌ 不算登录: 仅有 Set-Cookie 头部

✅ 数据库名来源: SQL 错误消息 (ORA-*, MySQL syntax error 等)
❌ 禁止从 URL 路径、域名猜测数据库名

⚠ VBScript 错误 = 非 SQLi:
   800a01a8, 800a0d5d, 8002000a, 800a000d → 参数化查询，停止测试
   
⚡ ADODB 800a0cc1 = 堆叠查询可执行信号 → 尝试 EXEC/INSERT
```

---

## 许可证

MIT License — 详见 [LICENSE](LICENSE)

---

<div align="center">

**[English](README.md) · [한국어](README_ko.md) · [中文](README_zh.md)**

</div>
