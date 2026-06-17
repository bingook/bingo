<div align="center">

<img src="assets/logo.png" width="180" alt="bingo logo"/>

# bingo

**AI 기반 레드팀 터미널**

[![Version](https://img.shields.io/badge/version-2.3.23-brightgreen?logo=github)](https://github.com/bingook/bingo/releases)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue?logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey)](https://github.com/bingook/bingo)

*DeepSeek · Claude · GPT · GLM · Qwen · Ollama · Custom*

**🌐 Language / 언어 / 语言:**
[English](README.md) · [한국어](README_ko.md) · [中文](README_zh.md)

> **v2.3.23 — 공식 릴리스**  
> v2.3.23이 최신 안정 버전입니다.

</div>

---

## bingo란?

bingo는 실제 침투 테스트 워크플로우를 자동화하는 해커 스타일 AI 터미널입니다.  
타겟 URL을 입력하면 bingo가 전체 레드팀 파이프라인을 실행합니다 — WAF 감지, 취약점 스캔, SQL 인젝션, 파일 업로드 익스플로잇, IDOR 열거, 해시 크래킹, 자동 리포트 생성 — 선택한 AI 모델로 전부 구동됩니다.

**제로 환각 엔진** (v2.3.13 — 4계층 검증): 모든 AI 응답은 4개의 독립적인 계층에서 검증된 후에만 채택됩니다.
1. 코드 블록: JSON 딕셔너리, 스텁, 시뮬레이션 코드는 거부
2. 텍스트 레벨: JSON 계획서, AI 자백문 차단
3. 가짜 자격증명: HTTP 증거 없는 비밀번호/해시 클레임 차단
4. 미증명 결론: "SQLi 발견", "WAF 우회 성공" 등을 코드 블록 없이 주장하면 자동 차단 → Python requests 코드 강제 생성

**Burp 엔진** (v2.3): 순수 Python으로 구현된 Burp Suite 기능 세트. Burp Suite 설치 불필요.

| Burp 기능 | bingo 등가 | 설명 |
|---|---|---|
| Repeater | `burp_engine.repeater()` | 커스텀 헤더/바디/파라미터로 HTTP 재전송 |
| Intruder | `burp_engine.intruder()` | `§payload§` 마커에 페이로드 퍼징 |
| Scanner (Active) | `burp_engine.scanner_active()` | SQLi / XSS / SSTI 자동 탐지 |
| Collaborator | `burp_engine.CollaboratorClient()` | interactsh 기반 OOB 탐지 |
| Comparer | `burp_engine.comparer()` | Boolean SQLi 확인용 응답 비교 |

---

## 설치

### 방법 A — pip (권장)

```bash
pip install bingo-ai
bingo
```

업데이트:
```bash
bingo --update
```

### 방법 B — git clone (macOS / Linux)

```bash
curl -fsSL https://raw.githubusercontent.com/bingook/bingo/main/install.sh | bash
```

### 방법 C — Windows

```powershell
pip install bingo-ai
bingo
```

---

## 빠른 시작

```
bingo
> 언어 선택: ko
> API 키 입력: sk-...
> 타겟 입력: https://target.com
```

그 다음은 bingo가 자동으로 처리합니다.

---

## 주요 명령어

| 명령어 | 설명 |
|--------|------|
| `/lang ko` | 언어 변경 (ko / zh / en) |
| `/model deepseek` | AI 모델 변경 |
| `/report` | 침투 테스트 리포트 생성 |
| `/history` | 세션 기록 보기 |
| `/clear` | 화면 지우기 |

---

## 지원 AI 모델

| 모델 | 환경 변수 |
|------|----------|
| DeepSeek | `DEEPSEEK_API_KEY` |
| Claude | `ANTHROPIC_API_KEY` |
| GPT-4o | `OPENAI_API_KEY` |
| GLM-4 | `ZHIPU_API_KEY` |
| Qwen | `DASHSCOPE_API_KEY` |
| Ollama | 로컬 설치 필요 없음 (자동 감지) |

---

## 핵심 기능

### 제로 환각 엔진
- 4계층 검증으로 AI 거짓 보고 완전 차단
- 모든 취약점은 실제 HTTP 응답 증거 필수

### 정밀 SQLi 엔진
- MSSQL / MySQL / PostgreSQL / Oracle 지원
- Boolean blind, Time-based, Error-based, UNION 자동 선택
- WAF 우회 페이로드 자동 생성
- **v2.3.23 신규**: 무한 루프 방지 — 중복 결과 5회 → 즉시 프로세스 종료

### WAF 우회
- Cloudflare · Safe3 · D盾 · 云锁 지원
- 인코딩 변형 / 주석 삽입 / HPP / chunked 인코딩 자동 적용

### 한국형 CMS 특화
- GnuBoard, XpressEngine, Rhymix 자동 감지
- 한국어 자격증명 사전 내장
- CAPTCHA (kcaptcha) 자동 OCR 해결

---

## v2.3.23 신규 기능 — 무한 루프 킬러

이전 버전에서 테이블 열거 루프가 28분 동안 동일한 테이블을 383번 출력하는 버그 발생.  
v2.3.23에서 3단계 방어막 추가:

| 단계 | 메커니즘 | 트리거 |
|------|---------|--------|
| 실행 전 차단 | 정적 분석 | `for`+`range`+`TOP 1`+`seen=set()` 없음 → 실행 자체 차단 |
| 실시간 KILL | 스트리밍 모니터 | 동일 줄 5회 반복 → 즉시 프로세스 종료 |
| 타임아웃 | 하드 제한 | 스크립트 300초 초과 → 강제 종료 |

**올바른 열거 패턴 (v2.3.23 필수)**:
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
# 결과: 중복 없는 고유 테이블 목록
```

---

## SQL 인젝션 오라클 규칙 (v2.3.21+)

```
✅ 유효한 오라클: TRUE/FALSE 페이로드가 예측 가능한 방식으로 다른 응답
❌ 무효: WAF 403/503 = 불리언 조건 아님
❌ 무효: 응답 크기만으로 판단 (내용 비교 필수)

✅ 로그인 성공: 응답 본문에 로그아웃 링크 또는 사용자 ID 포함
❌ 로그인 아님: Set-Cookie 헤더만으로는 불충분

✅ DB명 출처: SQL 에러 메시지 (ORA-*, MySQL syntax error 등)
❌ DB명 아님: URL 경로, 도메인 이름에서 추출 금지

⚠ VBScript 에러 = SQLi 아님:
   800a01a8, 800a0d5d, 8002000a, 800a000d → 파라미터화된 쿼리, 테스트 중단
   
⚡ ADODB 800a0cc1 = 스택 쿼리 실행 가능 신호 → EXEC/INSERT 시도
```

---

## 라이선스

MIT License — 자세한 내용은 [LICENSE](LICENSE) 참조

---

<div align="center">

**[English](README.md) · [한국어](README_ko.md) · [中文](README_zh.md)**

</div>
