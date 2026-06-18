<div align="center">

<img src="assets/logo.png" width="180" alt="bingo logo"/>

# bingo

**AI 기반 레드팀 터미널**

[![Version](https://img.shields.io/badge/version-2.3.32-brightgreen?logo=github)](https://github.com/bingook/bingo/releases)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue?logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey)](https://github.com/bingook/bingo)

*DeepSeek · Claude · GPT · GLM · Qwen · Ollama · Custom*

**🌐 Language / 언어 / 语言:**
[English](README.md) · [한국어](README_ko.md) · [中文](README_zh.md)

> **v2.4.0 — 공식 릴리스**  
> v2.4.0이 최신 안정 버전입니다.

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
- **v2.3.26 신규**: 무한 루프 방지 — 중복 결과 5회 → 즉시 프로세스 종료

### WAF 우회
- Cloudflare · Safe3 · D盾 · 云锁 지원
- 인코딩 변형 / 주석 삽입 / HPP / chunked 인코딩 자동 적용

### 한국형 CMS 특화
- GnuBoard, XpressEngine, Rhymix 자동 감지
- 한국어 자격증명 사전 내장
- CAPTCHA (kcaptcha) 자동 OCR 해결

---

## v2.4.0 — AI 자동 SQLi 단계 전환 + DB 권한 상승 + 쉘 드로퍼 + WAF++ *(2026-06)*

**신규 모듈:**
- `sqli_auto.py` — SQLi 자동 단계 전환 엔진 (에러→유니온→불린→타임→스택 자동 선택, DB별 전용 페이로드)
- `db_privesc.py` — DB 권한 상승 자동화 (xp_cmdshell 활성화, EXECUTE AS, INTO OUTFILE, COPY TO PROGRAM)
- `shell_dropper.py` — 웹쉘 배포 + 리버스 쉘 자동 생성 (certutil, PowerShell, bash/python/nc)

**신규 WAF 시그니처:** dotDefender, Imperva, Wallarm, 360wzws, anquanbao, Nginx WAF — 전용 우회 전략

**다국어:** 14개 신규 i18n 키 (ko/zh/en)

**시스템 프롬프트:** `=== v2.4.0 AUTO-ENGINE DECISION RULES ===` 섹션 추가

## v2.3.33 — 보고서 환각 수정: 세션 state 격리 *(2026-06)*

- **🔴 버그 수정: 보고서 환각 — 이전 세션 carry-over 완전 차단** — 사용자가 `n` (재개 안 함)을 선택해도 이전 세션의 자격증명·테이블·DB명이 `_agent_state`에 잔류해 새 세션 최종 보고서에 포함되는 "보고서 환각" 버그 수정. `_offer_resume()` "n" 분기에서 즉시 `_reset_agent_state()`를 호출하여 이전 세션 state를 완전히 리셋한다.
- **🟢 현재 세션 추적 목록 신설: `_session_tables` / `_session_credentials`** — 현재 세션에서 실제 발견된 항목만 누적하는 in-memory 목록 2개 신설. `_parse_agent_state()`에서 테이블/자격증명 파싱 시 이 목록도 동시에 업데이트.
- **🟢 보고서 프롬프트 강화** — `_auto_generate_report()`가 이제 "현재 세션 확인 항목"과 "이전 세션 항목"을 AI에게 별도 전달. AI에게 명시적으로 지시: *"자격증명은 반드시 현재 세션 항목만 보고. 이전 세션 항목은 ⚠️ 이전 세션 (재확인 불가)으로 표시."*
- **🟡 다국어: 3개 신규 키** — `session_state_cleared`, `session_prev_data_warning`, `session_current_confirmed` (ko/zh/en).

## v2.3.32 — UTF-16LE 해시 오탐 필터 *(2026-06)*

- **🔴 해시 감지: UTF-16LE 오탐 필터 추가** — `extract_hashes_from_text`가 이제 UTF-16LE 인코딩된 문자열(예: `25004D0065006D006200650072002500` = `%Member%`)을 NTLM 해시로 오탐하는 문제 해결. 2바이트 쌍마다 `00`이 고/하위 바이트에 규칙적으로 등장하면 UTF-16LE로 판단하여 크랙 건너뜀. MSSQL/ASP Unicode 컬럼에서 발생하는 오탐 토큰 낭비 방지.
- **🟡 다국어: 1개 신규 키** — `hash_utf16le_skipped` (ko/zh/en).

## v2.3.31 — urllib.parse 자동 import 주입 *(2026-06)*

- **🔴 Precheck: `urllib.parse` 자동 주입** — AI가 `urllib.parse.quote/urlencode/urlparse` 등을 사용하면서 `import urllib.parse`를 누락하는 경우, `_precheck_python_code`가 실행 전 자동으로 주입. `NameError: name 'urllib' is not defined` 완전 해결 (`urllib3`를 `urllib.parse`로 혼용하는 오류 방지).
- **🔴 Rule 21: urllib.parse vs urllib3 명시** — `import urllib3`는 표준 라이브러리 `urllib.parse`를 활성화하지 않음. 반드시 `import urllib.parse` 또는 `from urllib.parse import quote`로 별도 임포트.
- **🟡 다국어: 1개 신규 키** — `urllib_parse_injected` (ko/zh/en).

## v2.3.30 신규 기능 — 응답 인코딩 자동 감지, 배너 버전 수정, Syntax Precheck 오탐 제거 *(2026-06)*

- **🔴 Rule 21: 응답 인코딩 자동 감지** — AI가 `r.text`를 직접 사용하지 않음. EUC-KR/EUC-JP/GB2312 등 구형 한국어·일본어·중국어 사이트에서 깨진 문자(`Է` 등) 완전 해결. Content-Type 헤더 → HTML meta charset → apparent_encoding → UTF-8 순으로 자동 감지.
- **🔴 Precheck: `r.text` → `smart_decode()` 자동 주입** — `_precheck_python_code`가 `requests.get/post` + `.text` 패턴 감지 시 자동으로 `_smart_decode()` 헬퍼 삽입 및 `.text` 호출 교체.
- **🟠 배너 버전 수정** — 터미널 배너가 하드코딩 `v2.3.4` 대신 `__version__`을 동적으로 읽어 표시.
- **🟠 Syntax Precheck 오탐 수정** — `None` 반환 값이 "정상"과 "오류"를 동시에 의미해서 매번 경고가 뜨던 문제 해결. `None`(정상) vs `__SYNTAX_ERR__`(실제 오류) 분리.
- **🟡 다국어: 2개 신규 키** — `encoding_auto_detected`, `encoding_inject_notice` (ko/zh/en).

## v2.3.29 — WAF ReadTimeout 가드, URL 연소 버그 수정, f-string 자동 수정 *(2026-06)*

AI 생성 코드의 반복 오류를 차단하는 3가지 방어 레이어:

- **🔴 Rule 19: ReadTimeout = WAF silent drop** — SQL 인젝션 페이로드에서 `ReadTimeout` 발생 시 WAF 차단으로 인식하고 즉시 피벗.
- **🔴 Rule 20: URL 구성 가드** — `base_url + "https://..."` 패턴 금지.
- **🟡 다국어: 2개 신규 키** — `waf_timeout_detected`, `url_concat_fixed` (ko/zh/en).

## v2.3.26 신규 기능 — 하드 워치독 타임아웃, pymssql VPN 가드, Oracle 검증 *(2026-06)*

### 버그 수정

- **🔴 블로킹 소켓 무한 대기 수정 (pymssql 무한 루프)** — stdout 출력이 없는 경우에도 300초 후 `p.kill()`을 호출하는 전용 워치독 스레드 추가. 이전 타임아웃은 `for raw_line in p.stdout:` 루프 내에서만 작동해, pymssql 처럼 TCP 연결 중 아무 출력도 없으면 루프 자체가 진행되지 않아 타임아웃 체크가 실행되지 않았음.
- **🔴 Rule 13: pymssql/pyodbc 필수 타임아웃** — AI는 반드시 `timeout=10, login_timeout=10` 설정 후 데몬 스레드(`join(timeout=15)`)로 실행해야 함. VPN NAT IP(`198.18.x.x`, `192.168.x.x` 등)를 SQL Server 타겟으로 절대 사용 금지.
- **🟠 Rule 14: Boolean oracle 사전 검증** — 추출 루프 실행 전 TRUE/FALSE 응답 크기 차이 ≥ 10B 확인 필수. 동일하면 oracle 무효 → 다른 기법으로 전환.
- **🟠 Rule 15: WAITFOR 엄격한 임계값** — `WAITFOR 5s`는 응답 시간 ≥ 4.0s일 때만 유효. 1.36s 응답은 오탐.
- **🟡 Rule 16: 자격증명 우선 공격 순서** — DB 크리덴셜이 이미 추출된 경우, 복잡한 blind SQLi보다 로그인 폼 시도를 먼저 수행. `<input type="password">` 없는 페이지는 건너뜀.
- **i18n: 신규 다국어 키 6개** — `script_watchdog_killed`, `pymssql_vpn_ip_warn`, `bool_oracle_invalid`, `waitfor_false_positive`, `cred_first_login_try`, `login_page_no_form` (ko/zh/en).

## v2.3.25 신규 기능 — SQLi 오라클 정밀도 개선 & UnboundLocalError 수정

### 버그 수정

- **🔴 `UnboundLocalError: cannot access local variable 't'` 수정** — `_run_code_blocks` 내 `for t in threads:` 루프 변수가 전역 `t()` 번역 함수를 덮어쓰던 문제. 3곳 모두 `for _th in threads:`로 변경.
- **🟠 VBScript 800a01a8 경고 오발 수정** — 같은 결과 배치에 OLE DB SQL 에러(`80040e14`, `80040e07`)가 함께 있으면 VBScript "인젝션 불가" 경고를 억제. 혼합 결과 정확히 판별.
- **🟠 800a01a8을 WAF 우회 성공으로 오분석하는 문제 수정** — Rule 11 추가: `800a01a8 = VBScript 런타임 에러 ≠ WAF 우회`. AI가 더 이상 800a01a8을 인젝션 성공으로 판정하지 않음.
- **🟡 타입 지정 정수 파라미터에서의 불필요한 ORDER BY/UNION 열거 수정** — Rule 12 추가: 타입 에러 감지 시 ORDER BY 및 UNION SELECT 열거 즉시 중단.
- **i18n: 신규 다국어 키 3개** — `mixed_sqli_result_title`, `mixed_sqli_result_detail`, `typed_param_skip` (ko/zh/en).

---

## v2.3.26 이전 — 무한 루프 킬러

이전 버전에서 테이블 열거 루프가 28분 동안 동일한 테이블을 383번 출력하는 버그 발생.  
v2.3.26에서 3단계 방어막 추가:

| 단계 | 메커니즘 | 트리거 |
|------|---------|--------|
| 실행 전 차단 | 정적 분석 | `for`+`range`+`TOP 1`+`seen=set()` 없음 → 실행 자체 차단 |
| 실시간 KILL | 스트리밍 모니터 | 동일 줄 5회 반복 → 즉시 프로세스 종료 |
| 타임아웃 | 하드 제한 | 스크립트 300초 초과 → 강제 종료 |

**올바른 열거 패턴 (v2.3.26 필수)**:
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
