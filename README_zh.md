<div align="center">

<img src="assets/logo.png" width="180" alt="bingo logo"/>

# bingo

**AI 驱动的红队终端**

[![Version](https://img.shields.io/badge/version-2.3.28-brightgreen?logo=github)](https://github.com/bingook/bingo/releases)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue?logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey)](https://github.com/bingook/bingo)

*DeepSeek · Claude · GPT · GLM · Qwen · Ollama · Custom*

**🌐 Language / 언어 / 语言:**
[English](README.md) · [한국어](README_ko.md) · [中文](README_zh.md)

> **v2.3.30 — 正式发布版**  
> v2.3.30 是最新稳定版本。

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
