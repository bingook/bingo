<div align="center">

<img src="assets/logo.png" width="150" alt="bingo logo"/>

# bingo

**AI 驱动的红队终端**

[![Version](https://img.shields.io/badge/version-3.2.45-brightgreen)](https://github.com/bingook/bingo/releases)
[![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux-lightgrey)](https://github.com/bingook/bingo)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

**🌐 语言:** [English](README.md) · [한국어](README_ko.md) · [中文](README_zh.md)

> ⚠️ **不支持 Windows。** bingo 仅支持 **macOS 和 Linux**。
> 自 v3.2.45 起，Windows 支持已永久终止，不会再有任何 Windows 相关更新。

*DeepSeek · Claude · GPT · GLM · Qwen · Ollama · 自定义*

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


---

## 快速开始

```bash
bingo                        # 启动
bingo scan https://target    # 自动全扫描
bingo --version
bingo --reset
```

首次启动: 选择语言 → 输入 API 密钥 → 开始使用.

---

## 使用方法

在聊天窗口输入目标和任务即可，无需记忆命令。

**示例提示词:**
```
目标: https://example.com

任务:
1. 全面侦察 — 检测 WAF、数据库类型、技术栈
2. SQL 注入 — error → union → blind → time-based
3. 管理员凭据 — 转储 admin/user/member 表
4. 管理员登录 — 截图取证
5. 数据库全量转储 — 成功后运行 DbDumper
```

> 只需描述你的目标，AI 会自动决定一切。

---

## 核心功能

| 领域 | bingo 所做的事 |
|------|--------------|
| **侦察** | WAF 检测、技术指纹识别、爬取所有页面/JS/API 端点 |
| **SQLi** | Error-based → Union → Boolean blind → Time-based (所有数据库类型) |
| **WAF 绕过** | Cloudflare / AWS WAF / ModSecurity — 自动选择绕过方式 |
| **XSS** | Stored / Reflected / DOM — 成功后劫持会话 |
| **SSRF** | 云元数据(AWS/GCP/Azure)端点测试 |
| **文件上传** | 扩展名绕过、Webshell 上传 |
| **认证攻击** | 登录爆破、SQLi 认证绕过、CAPTCHA 自动解决 |
| **IDOR/BOLA** | 对象 ID 枚举、水平权限提升 |
| **JWT/OAuth** | alg:none、弱密钥、redirect_uri 滥用 |
| **GraphQL** | 内省攻击、批量攻击、字段注入 |
| **HTTP 走私** | CL.TE / TE.CL 去同步 |
| **凭据转储** | 提取哈希 → 自动建议 hashcat 命令 |
| **数据库转储** | 确认 SQLi 后全量转储 (DbDumper v2.7) |
| **截图** | 通过 Playwright 自动截取管理后台 |
| **报告** | 自动保存含 CVSS 评分的 Markdown 报告 |

---

## 🌐 代理池轮换 (v3.2.18) — 新功能

自动轮换 IP 地址，绕过 WAF 封锁、速率限制和 IP 封禁。

### 支持的代理类型

| 类型 | 格式 | 说明 |
|------|------|------|
| HTTP | `http://ip:port` | 基础代理 |
| HTTP + 认证 | `http://user:pass@ip:port` | 带账号密码 |
| HTTPS | `https://ip:port` | SSL 隧道 |
| SOCKS5 | `socks5://ip:port` | 需要 PySocks |
| SOCKS5h | `socks5h://ip:port` | DNS 也通过代理解析（更匿名） |
| Tor | `socks5h://127.0.0.1:9050` | 需要 Tor 守护进程 |
| API 自动获取 | URL | ProxyScrape、Webshare、自定义 |

### 快速开始

```bash
# 手动添加单个代理
/proxy add socks5://1.2.3.4:1080

# 启用 Tor 模式（需先运行 Tor: brew install tor && tor）
/proxy tor

# 从 API 自动获取免费代理
/proxy api

# 从文件批量加载（每行一个）
/proxy file ~/proxies.txt

# 查看代理池状态
/proxy list
```

### 所有 `/proxy` 子命令

| 命令 | 说明 |
|------|------|
| `/proxy list` | 显示代理池状态及全部代理列表 |
| `/proxy add <url>` | 手动添加单个代理 |
| `/proxy file <路径>` | 从文本文件批量加载（每行一个） |
| `/proxy api [url]` | 从 API URL 自动获取，或选择内置预设 |
| `/proxy tor [密码]` | 启用 Tor 模式（可选: 控制端口密码） |
| `/proxy rotate` | 立即强制切换到下一个代理 |
| `/proxy test` | 测试当前代理连接（延迟检测） |
| `/proxy unban` | 解封所有被标记封禁的代理 |
| `/proxy clear` | 清空整个代理池 |
| `/proxy off` | 禁用代理（直接请求） |

### 自动轮换工作原理

当 bingo 检测到封禁（HTTP 429、403、IP 封锁、连接重置）时:

```
1. 将当前代理标记为 BANNED（已封禁）
2. 自动切换到下一个可用代理
3. 若为 Tor 模式：发送 NEWNYM 信号 → 新 Tor 线路（新 IP）
4. 将新代理 URL 注入到 AI 提示中 → 后续脚本自动使用
5. 等待时间从 15 秒缩短至 3 秒后重试
```

AI 生成的脚本中自动插入的代码:
```python
# [PROXY_ROTATED: now using socks5://5.6.7.8:9090]
PROXIES = {'http': 'socks5://5.6.7.8:9090', 'https': 'socks5://5.6.7.8:9090'}
session.get(url, proxies=PROXIES, timeout=15, verify=False)
```

### Tor 配置指南

**第一步 — 安装 Tor:**
```bash
# macOS
brew install tor && brew services start tor

# Ubuntu / Debian
sudo apt install tor && sudo systemctl start tor

```

**第二步 — （可选）启用 Tor 控制端口:**

编辑 `/etc/tor/torrc`（Linux）或 `/usr/local/etc/tor/torrc`（macOS）:
```
ControlPort 9051
CookieAuthentication 1
```
重启: `sudo systemctl restart tor`

**第三步 — 在 bingo 中启用 Tor:**
```bash
/proxy tor              # 无密码（Cookie 认证）
/proxy tor mypassword   # 使用 HashedControlPassword 时
```

**第四步 — 安装 stem（用于线路切换）:**
```bash
pip install stem
```
不安装 `stem` Tor 仍可使用，但无法在被封禁时自动切换 IP（Tor 线路替换）。

> **Tor 使用技巧:**  
> - 使用 `socks5h://` 时 DNS 也通过 Tor 解析 → 更强的匿名性  
> - 验证 Tor 是否运行: `curl --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip`  
> - 线路切换间隔: 建议最少 10 秒（Tor 策略限制）

### 从 API 预设自动获取

```bash
/proxy api
```
将出现选择菜单:
```
1. ProxyScrape (SOCKS5) — 免费，5000+ 代理
2. ProxyScrape (HTTP)   — 免费，HTTP 代理
3. ProxyScrape (SOCKS4) — 免费，SOCKS4 代理
4. GeoNode Free         — 已过滤，在线率 90%+
0. 手动输入            — 自定义 API URL
```

或直接指定 URL:
```bash
/proxy api https://api.proxyscrape.com/v3/...
/proxy api https://你的代理服务器.com/list.txt
```

支持的 API 响应格式:
- 纯文本（每行一个: `ip:port` 或 `scheme://ip:port`）
- JSON 数组: `["socks5://1.2.3.4:1080", ...]`

### 代理文件格式

```bash
# proxies.txt（# 开头为注释行）
# HTTP 代理
http://1.2.3.4:3128
http://user:pass@5.6.7.8:3128

# SOCKS5 代理
socks5://9.10.11.12:1080
socks5h://13.14.15.16:1080

# Tor（本地）
socks5h://127.0.0.1:9050
```

```bash
/proxy file ~/proxies.txt
```

### AI 脚本中的代理使用

当 `/proxy` 激活时，AI 生成的所有 Python 脚本将自动包含:

```python
import requests

# [bingo v3.2.18: PROXY ACTIVE — 以下 PROXIES 为必填项]
PROXIES = {'http': 'socks5://1.2.3.4:1080', 'https': 'socks5://1.2.3.4:1080'}

s = requests.Session()
s.proxies.update(PROXIES)
s.verify = False   # Tor / 自签名证书必须关闭验证

r = s.get("https://target.com/api/...", timeout=15)
print(f"[GET {r.url} → {r.status_code}/{len(r.content)}B]")
```

### 实战场景

**场景 1: 基础代理池 → 绕过 WAF**
```bash
/proxy api              # 自动获取 100+ 免费代理
bingo> https://target.com 执行 SQL 注入测试
# → 检测到封禁时自动切换到下一个代理
```

**场景 2: Tor + 线路切换**
```bash
brew services start tor  # 启动 Tor
pip install stem         # 支持线路切换
/proxy tor               # 在 bingo 中启用 Tor
bingo> https://target.com 认证绕过测试
# → 每次被封禁时自动获取新 IP（Tor 新线路）
```

**场景 3: 付费代理服务对接**
```bash
# 使用 Webshare、ProxyEmpire 等服务的 API URL
/proxy api https://proxy.webshare.io/api/v2/proxy/list/?format=txt
# 或加载下载好的文件
/proxy file ~/Downloads/webshare_proxies.txt
```

### 依赖要求

```bash
pip install PySocks  # SOCKS5 代理支持（自动安装）
pip install stem     # Tor 线路切换（可选）
```

两个包均已包含在 `pyproject.toml` 中，随 bingo 自动安装。

### 常见问题排查

| 症状 | 解决方案 |
|------|----------|
| `SOCKS5 not supported` | `pip install PySocks` |
| Tor 连接失败 | `brew services start tor` 或 `sudo systemctl start tor` |
| 线路切换不生效 | `pip install stem` + torrc 中添加 `ControlPort 9051` |
| 代理池耗尽 | `/proxy unban` 或 `/proxy api` 重新获取 |
| 删除特定代理 | `/proxy clear` 后重新添加所需代理 |

---

## 支持的 AI 模型

| 提供商 | 示例模型 |
|--------|---------|
| OpenAI | `gpt-4o`, `gpt-4-turbo`, `o1` |
| Anthropic | `claude-3-5-sonnet`, `claude-opus-4` |
| DeepSeek | `deepseek-chat`, `deepseek-reasoner` |
| GLM | `glm-4`, `glm-5` |
| Qwen | `qwen-max`, `qwen-plus` |
| Ollama | 任何本地模型 |
| Custom | 任何 OpenAI 兼容端点 |

---

## WAF 绕过 — 自动选择

| WAF | 使用的绕过技术 |
|-----|--------------|
| Cloudflare | 双重 URL 编码 → Unicode → UA 伪造 |
| AWS WAF | 编码 → SLEEP→子查询 → XFF 头 |
| ModSecurity | 空格/**/ → IF→CASE WHEN → 大小写混合 |
| Nginx/OpenResty | `%0a` 换行 → 注释 → 混淆 |
| 国内 WAF | 空字节 → 超长 UTF-8 → 函数替换 |

---

## Burp Engine — 自动触发 (v3.2.51)

URL 与漏洞关键词同时出现时，**Burp 引擎自动触发**，无需手动命令。

```
bingo> https://target.com sqli渗透
bingo> https://target.com xss测试
bingo> https://target.com rce利用
```

自动触发关键词：`sqli` `xss` `rce` `ssrf` `xxe` `inject` `payload` `fuzz` `scan` `exploit` `oob`

> **没有 URL 则不触发。** URL 与关键词缺一不可。

---

## 防幻觉 — 4 层防护

每个 AI 响应必须通过全部 4 项检查才能输出:

1. **代码块防护** — 拒绝空存根、JSON 计划
2. **文本拦截** — 拒绝 AI 自我坦白
3. **假凭据封锁** — 没有 HTTP 证据的凭据一律拒绝
4. **未验证结论封锁** — 没有代码执行的"SQLi 已确认"一律拒绝

报告证据标签:

| 标签 | 含义 |
|------|------|
| `✅ VERIFIED` | 真实 HTTP 响应已确认 |
| `🟡 LIKELY` | 部分证据 |
| `🔍 INFERRED` | 仅为推断 — 需手动验证 |

---

## `bingo scan` — 全自动流水线

```bash
bingo scan https://target.com
```

自动运行 5 个阶段，无需交互:

| 阶段 | 执行内容 |
|------|---------|
| 1. 侦察 | 技术指纹、WAF 检测、端点映射 |
| 2. 收集 | 管理后台、敏感文件、参数发现 |
| 3. 测试 | SQLi / LFI / XSS / SSRF / IDOR 探测 |
| 4. 利用 | WAF 绕过、数据提取、凭据转储 |
| 5. 报告 | 含 CVSS 评分 + 证据的 Markdown 报告 |

报告保存路径: `~/.config/bingo/reports/report_<domain>.md`

---

## 命令列表

在聊天窗口输入 `/` 打开命令菜单（方向键浏览）。

| 命令 | 功能 |
|------|------|
| `/scan <url>` | 完整红队流水线 |
| `/waf <url>` | 仅 WAF 检测 + 绕过 |
| `/crack [hash]` | 哈希破解 — 在线查询 → 离线爆破 |
| `/proxy [子命令]` | **代理池轮换**（v3.2.18 新增）|
| `/stop` | 停止正在执行的任务 |
| `/tools` | 显示所有工具 + 安装状态 |
| `/tools install <name>` | 安装指定工具 |
| `/tools install all` | 一键安装所有缺失工具 |
| `/model` | 添加或切换 AI 模型 |
| `/skill <关键词>` | 搜索技能知识库 |
| `/history` | 查看对话历史 |
| `/export` | 保存对话为 `.md` 文件 |
| `/config` | 查看当前配置 |
| `/lang` | 切换语言（ko / zh / en）|
| `/clear` | 清屏 |
| `/quit` | 退出 |

---

## 移动端 — APK / IPA 分析 (v2.2.8)

可直接在聊天窗口分析 Android APK 和 iOS IPA 文件。

### Android APK

```bash
bingo> analyze target.apk
bingo> target.apk secret scan
bingo> pentest com.example.app
```

| 方法 | 速度 | 命令 |
|------|------|------|
| TruffleHog native | ⚡ 快 9 倍 | `bingo> target.apk trufflehog` |
| jadx 全量反编译 | 更全面 | `bingo> target.apk jadx full scan` |

### iOS IPA

```bash
bingo> analyze target.ipa
bingo> ios swift decompile target.ipa
```

**需要:** Java 17+ 及 Malimite.jar
```bash
brew install openjdk@17
# Malimite.jar: https://github.com/LaurieWired/Malimite/releases
java -jar ~/tools/Malimite.jar target.ipa --output ./decompiled/
```

### 提取内容

| 提取项目 | 详情 |
|---------|------|
| 硬编码密钥 | AWS Key、Google API、Firebase、Stripe、JWT、GitHub Token |
| 权限声明 | 所有声明权限 + 危险权限 |
| 导出组件 | Activities、Services、Receivers、Providers |
| 深度链接 / URL Scheme | Intent Filter、自定义 Scheme 处理器 |
| 网络端点 | 从代码+资源中提取的 API URL |
| SSL 固定 | 检测 → 自动生成绕过指南 |
| 第三方 SDK | Firebase、Sentry、Analytics 等 |

---

## 数据库转储 (v2.9.6)

确认 SQLi / Webshell / RCE 后自动触发:

- 转储对象: `member` / `user` / `admin` / `g5_member` / `xe_member`
- **无行数限制** — `max_rows_per_table=0`（全量转储）
- 保存凭据 → `CREDENTIALS_{table}.json`
- 检测哈希类型 → 输出 `hashcat -m {mode}` 命令
- 使用提取的凭据重试管理员登录

**保存路径:**

| 操作系统 | 路径 |
|----------|------|
| macOS | `~/Desktop/dump/{target}_{timestamp}/` |
| Windows | `~/Desktop/dump/{target}_{timestamp}/` |
| Linux | `~/Desktop/dump/{target}_{timestamp}/` |

---

## Cloudflare 绕过（真实 IP 发现）

```python
import requests, urllib3
urllib3.disable_warnings()
REAL_IP = "x.x.x.x"  # 从 SPF/DNS 记录获取的真实 IP
s = requests.Session()
s.verify = False
r = s.get(f"https://{REAL_IP}/", headers={"Host": "target.com"})
```

查找真实 IP: `dig TXT target.com` → 找 SPF 记录中的 IP。

---

## 配置与数据存储

| 路径 | 内容 |
|------|------|
| `~/.config/bingo/config.json` | API 密钥、模型、语言 |
| `~/.config/bingo/reports/` | 自动保存的扫描报告 |
| `~/.config/bingo/sessions/` | 聊天会话历史 |
| `~/.bingo/tools/` | 自动下载的 Go 工具 |
| `BINGO_REPORTS_DIR` | 覆盖报告路径（环境变量）|

---

## 系统要求

- Python 3.10+
- 至少一个受支持模型的 API 密钥
- （可选）VPN 或代理 — 自动检测并显示

---

## 版本历史

| 版本 | 摘要 |
|------|------|
| v3.2.45 | **仅支持 macOS/Linux** — 永久终止 Windows 支持 |
| v3.2.28 | 核心引擎复原 — 回滚至最稳定基础版本 |
| v3.2.18 | **代理池轮换** — HTTP/HTTPS/SOCKS5/Tor/API，封禁后自动切换，RULE 26-T |
| v3.2.17 | 误报修复: `Body: <!DOCTYPE html>` 循环检测器，RULE 26-S |
| v3.2.16 | CAPTCHA 误报修复 — 排除 script 标签 |
| v3.2.15 | `NameError` 预防: RULE 26-Q — 使用前必须初始化变量 |
| v3.2.14 | 登录效率优化: 3 次 HTTP 500 后切换 JS 分析（RULE 26-P）|
| v3.0.6 | SQLi 提取: 自动 IP 封禁检测 + XFF 轮换（12个请求头）|
| v3.0.5 | 修复: 最终报告保存到 Desktop/dump/target/ |
| v2.9.6 | 数据库转储: 禁止 /tmp/ 保存，强制 Desktop 路径，添加 FLOOR 注入模板 |
| v2.9.5 | XSS 反射去重修复 — 防止重复反射触发误报循环终止 |
| v2.9.0 | 11 个新模块: HTTP 走私、GraphQL、OAuth/JWT、Playwright |
| v2.8.0 | SQLi 引擎全面重构 |
| v2.7.0 | 成功入侵后自动数据库转储 |
| v2.2.0 | Pentest Precision Engine — WAF 绕过、CAPTCHA OCR |

---

## 开源许可

MIT © 2026 bingook

---

<div align="center">

**输入目标，bingo 完成其余一切。**

</div>
