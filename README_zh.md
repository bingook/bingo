<div align="center">

<img src="assets/logo.png" width="150" alt="bingo logo"/>

# bingo

**AI 驱动的红队终端**

[![Version](https://img.shields.io/badge/version-3.0.6-brightgreen)](https://github.com/bingook/bingo/releases)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

**🌐 语言:** [English](README.md) · [한국어](README_ko.md) · [中文](README_zh.md)

*DeepSeek · Claude · GPT · GLM · Qwen · Ollama · Custom*

</div>

---

## 安装

```bash
pip install bingo-ai
bingo
```

**更新:**
```bash
bingo --update
```

**Git 克隆:**
```bash
git clone https://github.com/bingook/bingo.git
cd bingo && bash install.sh
```

**Windows (以管理员身份运行 PowerShell):**
```powershell
irm https://raw.githubusercontent.com/bingook/bingo/main/install.ps1 | iex
```

---

## 快速开始

```bash
bingo                        # 启动
bingo scan https://target    # 自动全量扫描
bingo --version
bingo --reset
```

首次启动: 选择语言 → 输入 API 密钥 → 开始。

---

## 使用说明

在聊天窗口中输入目标和任务即可，无需记忆命令。

**示例提示词 (粘贴到 bingo):**
```
目标: https://example.com

任务优先级:
1. 全站侦察 — 检测 WAF、数据库类型、技术栈
2. SQLi — 报错注入 → 联合注入 → 盲注 → 时间盲注
3. 管理员凭据 — 转储 admin/user/member 表
4. 管理员登录 — 截图证明
5. 数据库全量转储 — SQLi 确认后自动运行 DbDumper
```

> 只需描述你想要的，AI 自动判断并执行。

---

## 核心功能

| 领域 | bingo 的功能 |
|------|-------------|
| **侦察** | WAF 检测、技术指纹识别、爬取所有页面/JS/API 端点 |
| **SQLi** | 报错注入 → 联合注入 → 布尔盲注 → 时间盲注 (支持所有数据库) |
| **WAF 绕过** | Cloudflare / AWS WAF / ModSecurity — 自动选择绕过技术 |
| **XSS** | Stored / Reflected / DOM — 成功后自动会话劫持 |
| **SSRF** | 云元数据 (AWS/GCP/Azure) 端点测试 |
| **文件上传** | 扩展名绕过、Webshell 上传 |
| **认证攻击** | 登录爆破、SQLi 认证绕过、CAPTCHA 自动破解 |
| **IDOR/BOLA** | 对象 ID 枚举、水平权限提升 |
| **JWT/OAuth** | alg:none、弱密钥、redirect_uri 滥用 |
| **GraphQL** | 自省查询、批量攻击、字段注入 |
| **HTTP 走私** | CL.TE / TE.CL 反同步 |
| **凭据转储** | 提取哈希 → 自动建议 hashcat 命令 |
| **数据库转储** | SQLi 确认后全表转储 (DbDumper v2.7) |
| **截图** | 通过 Playwright 自动截图管理员面板 |
| **报告** | 含 CVSS 分数的 Markdown 报告自动保存 |

---

## 支持的 AI 模型

| 提供商 | 示例模型 |
|--------|---------|
| OpenAI | `gpt-4o`, `gpt-4-turbo`, `o1` |
| Anthropic | `claude-3-5-sonnet`, `claude-opus-4` |
| DeepSeek | `deepseek-chat`, `deepseek-reasoner` |
| GLM | `glm-4`, `glm-5` |
| Qwen | `qwen-max`, `qwen-plus` |
| Ollama | 所有本地模型 |
| Custom | 任何 OpenAI 兼容端点 |

---

## WAF 绕过 — 自动选择

| WAF | 使用的绕过技术 |
|-----|--------------|
| Cloudflare | 双重 URL 编码 → Unicode → UA 欺骗 |
| AWS WAF | 编码 → SLEEP→子查询 → XFF 头 |
| ModSecurity | 空格/**/ → IF→CASE WHEN → 大小写混合 |
| Nginx/OpenResty | `%0a` 换行 → 注释 → 混淆 |
| 国产 WAF | 空字节 → 超长 UTF-8 → 函数替换 |

---

## 反幻觉 — 四层验证

AI 响应必须通过全部 4 项检查才能输出:

1. **代码块守卫** — 拒绝空桩代码、JSON 计划
2. **文本拦截** — 拒绝 AI 自我坦白
3. **虚假凭据拦截** — 无 HTTP 证据不得输出账号密码
4. **未证实结论拦截** — 无代码执行不得输出"SQLi 已确认"

报告证据标签:

| 标签 | 含义 |
|------|------|
| `✅ VERIFIED` | 真实 HTTP 响应已确认 |
| `🟡 LIKELY` | 部分证据 |
| `🔍 INFERRED` | 仅推断 — 需人工验证 |

---

## `bingo scan` — 全自动流水线

```bash
bingo scan https://target.com
```

自动执行 5 个阶段，无需任何交互:

| 阶段 | 内容 |
|------|------|
| 1. 侦察 | 技术指纹、WAF 检测、端点映射 |
| 2. 收集 | 管理员面板、敏感文件、参数发现 |
| 3. 测试 | SQLi / LFI / XSS / SSRF / IDOR 探测 |
| 4. 利用 | WAF 绕过、数据提取、凭据转储 |
| 5. 报告 | 含 CVSS 分数 + 证据的 Markdown 报告 |

报告保存至: `~/.config/bingo/reports/report_<domain>.md`

---

## 命令列表

在聊天中输入 `/` 打开命令菜单 (方向键导航)。

| 命令 | 功能 |
|------|------|
| `/scan <url>` | 完整红队流水线 |
| `/waf <url>` | 仅 WAF 检测 + 绕过 |
| `/crack [hash]` | 哈希破解 — 在线查询 → 离线破解 |
| `/stop` | 停止当前任务 |
| `/tools` | 显示所有工具 + 安装状态 |
| `/tools install <名称>` | 安装指定工具 |
| `/tools install all` | 安装所有缺失工具 |
| `/model` | 添加或切换 AI 模型 |
| `/skill <关键词>` | 搜索技能知识库 |
| `/history` | 查看对话历史 |
| `/export` | 将对话保存为 `.md` |
| `/config` | 查看当前设置 |
| `/lang` | 切换语言 (ko / zh / en) |
| `/clear` | 清屏 |
| `/quit` | 退出 |

**工具安装示例:**
```bash
/tools                        # 查看所有工具
/tools install nmap           # 自动安装 nmap
/tools install nuclei ffuf    # 安装多个工具
/tools install all            # 安装全部
```

**哈希破解示例:**
```bash
/crack                              # 从上条响应中自动提取
/crack $2y$10$Eix...               # 破解指定哈希
/crack -w ~/rockyou.txt             # 使用自定义字典
```

---

## 配置与数据存储

| 路径 | 内容 |
|------|------|
| `~/.config/bingo/config.json` | API 密钥、模型、语言 |
| `~/.config/bingo/reports/` | 自动保存的扫描报告 |
| `~/.config/bingo/sessions/` | 聊天会话历史 |
| `~/.bingo/tools/` | 自动下载的 Go 工具 |
| `BINGO_REPORTS_DIR` | 覆盖报告路径 (环境变量) |

**各系统配置文件位置:**

| 操作系统 | 路径 |
|---------|------|
| macOS | `~/Library/Application Support/bingo/config.json` |
| Linux | `~/.config/bingo/config.json` |
| Windows | `%APPDATA%\bingo\config.json` |

---

## 移动端 — APK / IPA 分析 (v2.2.8)

可直接在聊天窗口中分析 Android APK 和 iOS IPA 文件。

### Android APK

```bash
# 在 bingo 聊天中
bingo> analyze target.apk
bingo> target.apk secret scan
bingo> pentest com.example.app
```

| 方式 | 速度 | 命令 |
|------|------|------|
| TruffleHog 原生 | ⚡ 快 9 倍 | `bingo> target.apk trufflehog` |
| jadx 完整反编译 | 精细 | `bingo> target.apk jadx full scan` |

**CLI / Python:**
```bash
trufflehog filesystem target.apk --json --no-verification
# Docker (无需安装):
docker run -v $(pwd):/work trufflesecurity/trufflehog:latest filesystem /work/target.apk --json
```

**安装 TruffleHog:**
```bash
brew install trufflesecurity/trufflehog/trufflehog   # macOS
curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin  # Linux
```

### iOS IPA

```bash
# 在 bingo 聊天中
bingo> analyze target.ipa
bingo> ios swift decompile target.ipa
bingo> malimite target.ipa
```

**依赖:** Java 17+ 和 Malimite.jar
```bash
brew install openjdk@17
# 从 https://github.com/LaurieWired/Malimite/releases 下载 Malimite.jar
mkdir -p ~/tools && mv ~/Downloads/Malimite.jar ~/tools/
java -jar ~/tools/Malimite.jar target.ipa --output ./decompiled/
trufflehog filesystem ./decompiled/ --json --no-verification
```

### 自动识别 (APK 或 IPA)

```bash
bingo> auto scan target.apk    # AI 自动选择合适方法
bingo> auto scan target.ipa
```

### bingo 提取的内容

| 项目 | 详情 |
|------|------|
| 硬编码密钥 | AWS 密钥、Google API、Firebase、Stripe、JWT、GitHub Token |
| 权限 | 所有声明权限 + 危险权限 |
| 导出组件 | Activities、Services、Receivers、Providers |
| 深链接 / URL Scheme | Intent 过滤器、自定义 Scheme 处理器 |
| 网络端点 | 从代码 + 资源中提取的 API URL |
| SSL 证书绑定 | 检测到 → 自动生成绕过指南 |
| 第三方 SDK | Firebase、Sentry、Analytics 等 |

---

## Windows EXE — 独立可执行文件构建

构建无需安装 Python 即可运行的 `.exe` 文件:

```bash
pip install pyinstaller
pyinstaller --onefile --name bingo bingo/__main__.py
# 输出: dist/bingo.exe
```

将 `dist/bingo.exe` 复制到任意 Windows 电脑 — 无需 Python。  
运行: `bingo.exe` 或 `bingo.exe scan https://target.com`

---

## EXE Phase 0 — Windows PE 静态分析 (v2.3.5)

**不执行**即可分析 Windows 可执行文件 (EXE / DLL / SYS)。

```bash
# 在 bingo 聊天中
bingo> analyze malware.exe
bingo> pe static analysis sample.dll
bingo> check this exe: payload.exe
```

| 分析项目 | 详情 |
|---------|------|
| 架构 | x86 / x64 / ARM，编译时间戳 |
| 节区熵值 | >7.0 = 加壳/加密/混淆 |
| 导入表 | 按攻击类别分类的 30+ 可疑 Windows API |
| 字符串 | C2 URL、硬编码 IP、API 密钥、互斥体名、Base64 数据 |
| 加壳检测 | UPX、Themida、VMProtect、MPRESS、ASPack |
| 数字签名 | Authenticode 有效性验证 |
| YARA 扫描 | 内置规则 + 自定义规则文件支持 |
| 风险评分 | 自动: LOW / MEDIUM / HIGH |
| 哈希 | MD5、SHA1、SHA256、ImpHash、SSDeep |
| VirusTotal | 通过 VT API 查询哈希 (可选) |

---

## 后渗透 — Webshell 部署 (v2.2.5)

确认 SQLi 后，bingo 自动执行完整后渗透链:

**链路:** `SQLi 登录绕过 → 文件上传 → Webshell → AntSword 连接`

```bash
# 在 bingo 聊天中 — 只需描述目标
bingo> https://target.com/login 存在 SQLi — 获取管理员权限并部署 Webshell
```

bingo 自动处理每个步骤:

| 步骤 | 内容 |
|------|------|
| 1. SQLi 认证绕过 | 向登录表单注入 `admin'--` / `' OR 1=1--` |
| 2. 会话捕获 | 自动保存认证 Cookie |
| 3. 文件上传 | 通过已认证的上传端点上传 Webshell |
| 4. Webshell 测试 | 执行 `id`、`whoami`、`uname -a` 确认 RCE |
| 5. AntSword 配置 | 输出 AntSword C2 连接字符串 |
| 6. 数据库全量转储 | Shell 确认后自动运行 DbDumper |

**Webshell 类型自动选择:**

| 后端 | Webshell |
|------|----------|
| PHP | `<?php system($_GET['cmd']); ?>` |
| JSP | Runtime.exec() Shell |
| ASPX | ProcessStartInfo Shell |

---

## 数据库转储 (v2.9.6)

确认 SQLi / Webshell / RCE 后自动触发:

- 转储对象: `member` / `user` / `admin` / `g5_member` / `xe_member`
- **无行数限制** — `max_rows_per_table=0`（无限制），全量转储整张表
- 保存凭据 → `CREDENTIALS_{表名}.json`
- 自动识别哈希类型 → 输出 `hashcat -m {模式}` 命令
- 使用提取的凭据重新尝试管理员登录

**保存位置 (自动检测 OS):**

| 操作系统 | 路径 |
|----------|------|
| macOS | `~/Desktop/dump/{目标}_{时间戳}/` |
| Windows | `~/Desktop/dump/{目标}_{时间戳}/` (自动检测 OneDrive 桌面) |
| Linux | `~/Desktop/dump/{目标}_{时间戳}/` (无 Desktop 则使用 `~/dump/`) |

> **v2.9.6 修复:** AI 生成的提取代码将数据保存到 `/tmp/` 并忽略 DbDumper 的问题已修复。
> 现已强制禁止 `/tmp/` 路径，必须使用桌面路径，并新增 FLOOR 注入 `query_fn` 模板。

---

## XSS 扫描 (v2.9.6)

bingo 自动检测反射型和存储型 XSS:

- 扫描所有参数的反射上下文 (HTML / 属性 / JS / URL)
- **反射位置去重** — 即使同一参数在 HTML 响应中出现多次，也只输出唯一上下文
- 循环检测器区分合法扫描输出和真正的无限循环
- 输出格式: `反射位置: {参数}={上下文}` + 唯一位置数量汇总

**v2.9.5 修复原因:** 部分页面中 XSS 探针在单次响应中反射数十次。旧版本在同一行连续出现 5 次时判定为无限循环并强制终止。v2.9.5 将扫描结果行的阈值提高至 25 次，并在 AI 生成代码中强制执行去重逻辑。

---

## Cloudflare 绕过 (发现真实 IP)

```python
import requests, urllib3
urllib3.disable_warnings()
REAL_IP = "x.x.x.x"  # 从 SPF/DNS 记录中获取
s = requests.Session()
s.verify = False
r = s.get(f"https://{REAL_IP}/", headers={"Host": "target.com"})
```

查找真实 IP: `dig TXT target.com` → 查看 SPF 记录中的 IP。

---

## 更新日志

| 版本 | 摘要 |
|------|------|
| v3.0.6 | SQLi提取: 自动检测IP封禁 + 12种X-Forwarded-For头部轮换，耗尽时保存部分数据 |
| v3.0.5 | 修复: 最终报告现在保存到 Desktop/dump/目标名/ (修复 ~/.config/bingo/reports/ 错误路径) |
| v3.0.4 | 凭据获取后: 自动发现管理页面 + IP限制绕过(头部欺骗/SSRF/真实IP直连) + 报告输出 |
| v3.0.3 | DB转储: 优先DbDumper → 失败或遗漏STEP 0表时自动回退至手动分页提取 |
| v3.0.2 | DB转储: 通过实际样本数据验证会员表 (SELECT LIMIT 5)，禁止仅凭列名判断 |
| v3.0.1 | 表识别: 基于列名检测 + 支持混淆表名 |
| v3.0.0 | DbDumper 灵活使用 — AI 按情境选择方法 (无WAF / 有WAF / WebShell) |
| v2.9.8 | 简化保存规则: /tmp/ 允许中间文件，仅最终结果存至桌面 |
| v2.9.7 | 所有最终输出文件强制保存至 Desktop/dump/目标名/ |
| v2.9.6 | DB转储: 禁止/tmp/保存，强制桌面路径，新增FLOOR注入query_fn模板 |
| v2.9.5 | XSS 反射去重修复 — 防止重复反射误触无限循环终止 |
| v2.9.3 | DB转储: 无行数限制 + 自动保存到桌面 (macOS/Windows) |
| v2.9.2 | CMS 偏见修复 — 每个目标全新检测，零假设 |
| v2.9.1 | Bug 修复: 变量替换、警告泛滥、误报 |
| v2.9.0 | 11 个新模块: HTTP 走私、GraphQL、OAuth/JWT、Playwright、告警 |
| v2.8.0 | SQLi 引擎全面升级 — sqlmap 级别精度 |
| v2.7.0 | 渗透成功后自动数据库转储 |
| v2.3.0 | Burp Engine — 纯 Python 实现 Repeater/Intruder/Scanner |
| v2.2.0 | Pentest Precision Engine — WAF 绕过、CAPTCHA OCR |
| v2.1.0 | API 模糊测试、报告后交互式操作 |

---

## 语言设置

```bash
/lang        # 在聊天中切换语言
```

| 语言 | 代码 |
|------|------|
| English | `en` |
| 한국어 | `ko` |
| 中文 | `zh` |

---

## 系统要求

- Python 3.10+
- 至少一个支持模型的 API 密钥
- (可选) VPN — 自动检测并显示

---

## 贡献

```bash
git clone https://github.com/bingook/bingo.git
cd bingo && bash install.sh
```

欢迎提交 PR。重大变更请先开 Issue 讨论。

---

## 许可证

MIT © 2026 bingook

---

<div align="center">

**输入目标，其余交给 bingo。**

</div>
