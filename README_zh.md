<div align="center">

<img src="assets/logo.png" width="180" alt="bingo logo"/>

# bingo

**AI 驱动的红队终端**

[![Version](https://img.shields.io/badge/version-2.3.23-brightgreen?logo=github)](https://github.com/bingook/bingo/releases)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue?logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey)](https://github.com/bingook/bingo)

*DeepSeek · Claude · GPT · GLM · Qwen · Ollama · Custom*

**🌐 Language / 언어 / 语言:**
[English](README.md) · [한국어](README_ko.md) · [中文](README_zh.md)

> **v2.3.23 — 正式发布版**  
> v2.3.23 是最新稳定版本。

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
- **v2.3.23 新增**: 无限循环防护 —— 重复结果 5 次 → 立即终止进程

### WAF 绕过
- 支持 Cloudflare · Safe3 · D盾 · 云锁
- 自动应用编码变形 / 注释插入 / HPP / chunked 编码

### 中国 WAF 专项
- Safe3 WAF → null byte unicode → overlong UTF-8 → 函数替换
- D盾 → 关键字混淆
- 云锁 → HTTP 参数污染

---

## v2.3.23 新功能 —— 无限循环终止器

旧版本中，表枚举循环曾连续运行 28 分钟，将同一张表输出 383 次。  
v2.3.23 新增三层防护：

| 层级 | 机制 | 触发条件 |
|------|------|---------|
| 执行前拦截 | 静态分析 | `for`+`range`+`TOP 1`+无`seen=set()` → 直接阻止执行 |
| 实时 KILL | 流式输出监控 | 同一行重复 5 次 → 立即终止进程 |
| 超时限制 | 硬性限制 | 脚本超过 300 秒 → 强制终止 |

**正确枚举模式（v2.3.23 强制要求）**：
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
