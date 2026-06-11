<div align="center">

<img src="assets/logo.png" width="180" alt="bingo logo"/>

**Hacker-style AI Terminal — Multi-Model · Multi-Language**

[![Python](https://img.shields.io/badge/python-3.10%2B-green?logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-green)](https://github.com/bingook/bingo)

*DeepSeek · Claude · GPT · GLM · Qwen · Ollama · Custom*

</div>

---

## 설치

### macOS / Linux

```bash
curl -fsSL https://raw.githubusercontent.com/bingook/bingo/main/install.sh | bash
```

또는 git clone 후:

```bash
git clone https://github.com/bingook/bingo.git
cd bingo
bash install.sh
```

### Windows (PowerShell)

```powershell
irm https://raw.githubusercontent.com/bingook/bingo/main/install.ps1 | iex
```

또는 git clone 후:

```powershell
git clone https://github.com/bingook/bingo.git
cd bingo
.\install.ps1
```

### pip 직접 설치

```bash
pip install bingo-ai
```

> **요구사항:** Python 3.10+

---

## 실행

```bash
bingo
```

첫 실행 시 **언어 선택 → AI 모델 API 키 입력 → 채팅 시작**.  
설정은 자동 저장됩니다.

```bash
bingo --reset    # 설정 초기화 (온보딩 재실행)
bingo --version  # 버전 확인
bingo --help     # 도움말
```

---

## 지원 모델

| 프로바이더 | 기본 모델 | API |
|-----------|----------|-----|
| **DeepSeek** | `deepseek-chat` | [platform.deepseek.com](https://platform.deepseek.com) |
| **Anthropic Claude** | `claude-opus-4-5` | [console.anthropic.com](https://console.anthropic.com) |
| **OpenAI GPT** | `gpt-4o` | [platform.openai.com](https://platform.openai.com) |
| **Zhipu GLM** | `glm-4` | [open.bigmodel.cn](https://open.bigmodel.cn) |
| **Alibaba Qwen** | `qwen-turbo` | [dashscope.aliyuncs.com](https://dashscope.aliyuncs.com) |
| **Ollama** (로컬) | `llama3` | [ollama.com](https://ollama.com) |
| **Custom** | — | 직접 Base URL 입력 |

모델은 언제든지 `/model` 명령어로 추가하거나 전환할 수 있습니다.

---

## 명령어

채팅 중 `/` 로 시작하는 명령어:

| 명령어 | 설명 |
|--------|------|
| `/help` | 명령어 목록 표시 |
| `/model` | 모델 추가 또는 전환 |
| `/clear` | 화면 지우기 |
| `/config` | 현재 설정 보기 |
| `/history` | 대화 목록 보기 |
| `/export` | 대화를 `.md` 파일로 저장 |
| `/lang` | 언어 변경 |
| `/quit` | 종료 |

---

## 다국어

| 언어 | 코드 |
|------|------|
| 한국어 | `ko` |
| 中文 | `zh` |
| English | `en` |

첫 실행 시 선택하거나 `/lang` 으로 언제든 변경 가능.

---

## 설정 파일

설정은 OS별 표준 경로에 자동 저장됩니다:

| OS | 경로 |
|----|------|
| macOS | `~/Library/Application Support/bingo/config.json` |
| Linux | `~/.config/bingo/config.json` |
| Windows | `%APPDATA%\bingo\config.json` |

```json
{
  "lang": "ko",
  "active_model": "deepseek/deepseek-chat",
  "models": [
    {
      "provider": "deepseek",
      "model": "deepseek-chat",
      "api_key": "sk-...",
      "base_url": "https://api.deepseek.com/v1",
      "alias": "ds"
    }
  ]
}
```

---

## 구조

```
bingo/
├── bingo/
│   ├── cli.py          # 진입점 + 온보딩
│   ├── config.py       # 설정 저장/로드 (크로스 플랫폼)
│   ├── models/
│   │   ├── base.py     # 스트리밍 HTTP (OpenAI 호환 + Claude 전용)
│   │   └── registry.py # 프로바이더 등록
│   ├── ui/
│   │   └── terminal.py # 해커 그린 터미널 UI
│   └── lang/
│       └── strings.py  # 다국어 문자열
├── install.sh          # macOS/Linux 설치
├── install.ps1         # Windows 설치
└── pyproject.toml
```

---

## 기여

```bash
git clone https://github.com/bingook/bingo.git
cd bingo
pip install -e ".[dev]"
```

PR 환영합니다.

---

## 라이선스

MIT © 2026
