<div align="center">

<img src="assets/logo.png" width="150" alt="bingo logo"/>

# bingo

**AI 기반 레드팀 터미널**

[![Version](https://img.shields.io/badge/version-3.0.4-brightgreen)](https://github.com/bingook/bingo/releases)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

**🌐 언어:** [English](README.md) · [한국어](README_ko.md) · [中文](README_zh.md)

*DeepSeek · Claude · GPT · GLM · Qwen · Ollama · Custom*

</div>

---

## 설치

```bash
pip install bingo-ai
bingo
```

**업데이트:**
```bash
bingo --update
```

**Git 클론:**
```bash
git clone https://github.com/bingook/bingo.git
cd bingo && bash install.sh
```

**Windows (PowerShell 관리자 실행):**
```powershell
irm https://raw.githubusercontent.com/bingook/bingo/main/install.ps1 | iex
```

---

## 빠른 시작

```bash
bingo                        # 실행
bingo scan https://target    # 자동 전체 스캔
bingo --version
bingo --reset
```

첫 실행: 언어 선택 → API 키 입력 → 시작.

---

## 사용 방법

채팅창에 타겟과 작업 내용을 입력하면 됩니다. 별도 명령어 불필요.

**예시 프롬프트 (bingo에 붙여넣기):**
```
타겟: https://example.com

작업 우선순위:
1. 전체 정보 수집 — WAF, DB 종류, 기술 스택 탐지
2. SQLi — 에러 기반 → 유니온 → 블라인드 → 타임 기반
3. 관리자 계정 탈취 — admin/user/member 테이블 덤프
4. 관리자 패널 로그인 — 스크린샷 증거
5. DB 전체 덤프 — SQLi 성공 후 DbDumper 자동 실행
```

> 원하는 내용을 설명하면 AI가 자동으로 판단하여 실행합니다.

---

## 핵심 기능

| 영역 | bingo가 하는 일 |
|------|----------------|
| **정보 수집** | WAF 탐지, 기술 스택 핑거프린팅, 전체 페이지/JS/API 크롤링 |
| **SQLi** | 에러 기반 → 유니온 → 불리언 블라인드 → 타임 기반 (모든 DB) |
| **WAF 우회** | Cloudflare / AWS WAF / ModSecurity — 자동 선택 우회 |
| **XSS** | Stored / Reflected / DOM — 성공 시 세션 하이재킹 |
| **SSRF** | 클라우드 메타데이터 (AWS/GCP/Azure) 엔드포인트 테스트 |
| **파일 업로드** | 확장자 우회, 웹쉘 업로드 |
| **인증 공격** | 로그인 브루트포스, SQLi 인증 우회, CAPTCHA 자동 풀기 |
| **IDOR/BOLA** | 오브젝트 ID 열거, 수평 권한 상승 |
| **JWT/OAuth** | alg:none, 약한 시크릿, redirect_uri 남용 |
| **GraphQL** | 인트로스펙션, 배치 공격, 필드 인젝션 |
| **HTTP 스머글링** | CL.TE / TE.CL 디싱크 |
| **크레덴셜 덤프** | 해시 추출 → hashcat 명령어 자동 제안 |
| **DB 덤프** | SQLi 확인 후 전체 테이블 덤프 (DbDumper v2.7) |
| **스크린샷** | Playwright로 관리자 패널 자동 스크린샷 |
| **리포트** | CVSS 점수 포함 마크다운 리포트 자동 저장 |

---

## 지원 AI 모델

| 제공사 | 예시 모델 |
|--------|----------|
| OpenAI | `gpt-4o`, `gpt-4-turbo`, `o1` |
| Anthropic | `claude-3-5-sonnet`, `claude-opus-4` |
| DeepSeek | `deepseek-chat`, `deepseek-reasoner` |
| GLM | `glm-4`, `glm-5` |
| Qwen | `qwen-max`, `qwen-plus` |
| Ollama | 로컬 모델 전부 |
| Custom | OpenAI 호환 엔드포인트 전부 |

---

## WAF 우회 — 자동 선택

| WAF | 적용 우회 기법 |
|-----|--------------|
| Cloudflare | 이중 URL 인코딩 → 유니코드 → UA 스푸핑 |
| AWS WAF | 인코딩 → SLEEP→서브쿼리 → XFF 헤더 |
| ModSecurity | 공백/**/ → IF→CASE WHEN → 대소문자 혼합 |
| Nginx/OpenResty | `%0a` 개행 → 주석 → 난독화 |
| 중국 WAF | 널바이트 → 오버롱 UTF-8 → 함수 치환 |

---

## 환각 방지 — 4단계 검증

AI 응답은 4가지 검사를 모두 통과해야 출력됩니다:

1. **코드 블록 가드** — 빈 스텁, JSON 플랜 차단
2. **텍스트 인터셉트** — AI 자기고백 차단
3. **가짜 크레덴셜 차단** — HTTP 증거 없이 계정/비번 출력 차단
4. **미검증 결론 차단** — 코드 실행 없이 "SQLi 확인" 출력 차단

리포트 증거 레이블:

| 레이블 | 의미 |
|--------|------|
| `✅ VERIFIED` | 실제 HTTP 응답으로 확인됨 |
| `🟡 LIKELY` | 부분적 증거 있음 |
| `🔍 INFERRED` | 추론만 — 수동 검증 필요 |

---

## `bingo scan` — 전체 자동 파이프라인

```bash
bingo scan https://target.com
```

5단계를 자동으로 실행합니다. 조작 불필요:

| 단계 | 내용 |
|------|------|
| 1. 정보 수집 | 기술 핑거프린트, WAF 탐지, 엔드포인트 맵핑 |
| 2. 수집 | 관리자 패널, 민감 파일, 파라미터 발견 |
| 3. 테스트 | SQLi / LFI / XSS / SSRF / IDOR 프로빙 |
| 4. 익스플로잇 | WAF 우회, 데이터 추출, 크레덴셜 덤프 |
| 5. 리포트 | CVSS 점수 + 증거 포함 마크다운 리포트 |

리포트 저장 위치: `~/.config/bingo/reports/report_<domain>.md`

---

## 명령어

채팅창에서 `/` 입력 시 명령어 메뉴가 열립니다 (방향키로 탐색).

| 명령어 | 기능 |
|--------|------|
| `/scan <url>` | 전체 레드팀 파이프라인 |
| `/waf <url>` | WAF 탐지 + 우회만 |
| `/crack [hash]` | 해시 크랙 — 온라인 → 오프라인 |
| `/stop` | 실행 중인 작업 중지 |
| `/tools` | 전체 도구 목록 + 설치 현황 |
| `/tools install <이름>` | 특정 도구 설치 |
| `/tools install all` | 누락된 도구 전부 설치 |
| `/model` | AI 모델 추가/변경 |
| `/skill <키워드>` | 스킬 지식베이스 검색 |
| `/history` | 대화 기록 보기 |
| `/export` | 대화 내용 `.md`로 저장 |
| `/config` | 현재 설정 보기 |
| `/lang` | 언어 변경 (ko / zh / en) |
| `/clear` | 화면 지우기 |
| `/quit` | 종료 |

**도구 설치 예시:**
```bash
/tools                        # 전체 도구 보기
/tools install nmap           # nmap 자동 설치
/tools install nuclei ffuf    # 여러 도구 설치
/tools install all            # 모두 설치
```

**해시 크랙 예시:**
```bash
/crack                              # 마지막 응답에서 자동 추출
/crack $2y$10$Eix...               # 특정 해시 크랙
/crack -w ~/rockyou.txt             # 커스텀 워드리스트
```

---

## 설정 및 데이터 저장

| 경로 | 내용 |
|------|------|
| `~/.config/bingo/config.json` | API 키, 모델, 언어 |
| `~/.config/bingo/reports/` | 자동 저장 스캔 리포트 |
| `~/.config/bingo/sessions/` | 채팅 세션 기록 |
| `~/.bingo/tools/` | 자동 다운로드된 Go 도구 |
| `BINGO_REPORTS_DIR` | 리포트 경로 변경 (환경 변수) |

**OS별 설정 파일 위치:**

| OS | 경로 |
|----|------|
| macOS | `~/Library/Application Support/bingo/config.json` |
| Linux | `~/.config/bingo/config.json` |
| Windows | `%APPDATA%\bingo\config.json` |

---

## 모바일 — APK / IPA 분석 (v2.2.8)

채팅창에서 Android APK 및 iOS IPA 파일을 직접 분석할 수 있습니다.

### Android APK

```bash
# bingo 채팅창에서
bingo> analyze target.apk
bingo> target.apk secret scan
bingo> pentest com.example.app
```

| 방식 | 속도 | 명령어 |
|------|------|--------|
| TruffleHog 네이티브 | ⚡ 9배 빠름 | `bingo> target.apk trufflehog` |
| jadx 전체 디컴파일 | 정밀 | `bingo> target.apk jadx full scan` |

**CLI / Python:**
```bash
trufflehog filesystem target.apk --json --no-verification
# Docker (설치 불필요):
docker run -v $(pwd):/work trufflesecurity/trufflehog:latest filesystem /work/target.apk --json
```

**TruffleHog 설치:**
```bash
brew install trufflesecurity/trufflehog/trufflehog   # macOS
curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin  # Linux
```

### iOS IPA

```bash
# bingo 채팅창에서
bingo> analyze target.ipa
bingo> ios swift decompile target.ipa
bingo> malimite target.ipa
```

**필요 사항:** Java 17+ 및 Malimite.jar
```bash
brew install openjdk@17
# Malimite.jar 다운로드: https://github.com/LaurieWired/Malimite/releases
mkdir -p ~/tools && mv ~/Downloads/Malimite.jar ~/tools/
java -jar ~/tools/Malimite.jar target.ipa --output ./decompiled/
trufflehog filesystem ./decompiled/ --json --no-verification
```

### 자동 탐지 (APK 또는 IPA)

```bash
bingo> auto scan target.apk    # AI가 적합한 방법 자동 선택
bingo> auto scan target.ipa
```

### bingo가 추출하는 항목

| 항목 | 상세 |
|------|------|
| 하드코딩된 시크릿 | AWS 키, Google API, Firebase, Stripe, JWT, GitHub 토큰 |
| 권한 | 선언된 전체 + 위험 권한 |
| 익스포트된 컴포넌트 | Activities, Services, Receivers, Providers |
| 딥링크 / URL 스킴 | Intent 필터, 커스텀 스킴 핸들러 |
| 네트워크 엔드포인트 | 코드 + 에셋에서 추출된 API URL |
| SSL 피닝 | 탐지 → 우회 가이드 자동 생성 |
| 서드파티 SDK | Firebase, Sentry, Analytics 등 |

---

## Windows EXE — 독립 실행 파일 빌드

Python 없이 실행되는 `.exe` 파일 생성:

```bash
pip install pyinstaller
pyinstaller --onefile --name bingo bingo/__main__.py
# 출력: dist/bingo.exe
```

`dist/bingo.exe`를 아무 Windows PC에 복사 — Python 불필요.  
실행: `bingo.exe` 또는 `bingo.exe scan https://target.com`

---

## EXE Phase 0 — Windows PE 정적 분석 (v2.3.5)

Windows 실행 파일(EXE / DLL / SYS)을 **실행하지 않고** 분석합니다.

```bash
# bingo 채팅창에서
bingo> analyze malware.exe
bingo> pe static analysis sample.dll
bingo> check this exe: payload.exe
```

| 분석 항목 | 상세 |
|-----------|------|
| 아키텍처 | x86 / x64 / ARM, 컴파일 타임스탬프 |
| 섹션 엔트로피 | >7.0 = 패킹/암호화/난독화 |
| 임포트 테이블 | 30+ 공격 기법별 의심 Windows API |
| 문자열 | C2 URL, 하드코딩 IP, API 키, 뮤텍스, Base64 블롭 |
| 패커 탐지 | UPX, Themida, VMProtect, MPRESS, ASPack |
| 디지털 서명 | Authenticode 유효성 확인 |
| YARA 스캔 | 내장 룰 + 커스텀 룰 파일 지원 |
| 위험도 점수 | 자동: LOW / MEDIUM / HIGH |
| 해시 | MD5, SHA1, SHA256, ImpHash, SSDeep |
| VirusTotal | VT API를 통한 해시 조회 (선택) |

---

## 사후 침투 — 웹쉘 배포 (v2.2.5)

SQLi 확인 후 bingo가 전체 사후 침투 체인을 자동 실행합니다:

**체인:** `SQLi 로그인 우회 → 파일 업로드 → 웹쉘 → AntSword 연결`

```bash
# bingo 채팅창에서 — 목표만 설명하면 됩니다
bingo> https://target.com/login 에서 SQLi 있음 — 관리자 접근 후 웹쉘 배포해줘
```

bingo가 각 단계를 처리합니다:

| 단계 | 내용 |
|------|------|
| 1. SQLi 인증 우회 | `admin'--` / `' OR 1=1--` 로그인 폼에 인젝션 |
| 2. 세션 캡처 | 인증 쿠키 자동 저장 |
| 3. 파일 업로드 | 인증된 업로드 엔드포인트로 웹쉘 업로드 |
| 4. 웹쉘 테스트 | `id`, `whoami`, `uname -a` 실행으로 RCE 확인 |
| 5. AntSword 설정 | AntSword C2 연결 문자열 출력 |
| 6. DB 전체 덤프 | 쉘 확인 후 DbDumper 자동 실행 |

**웹쉘 유형 자동 선택:**

| 백엔드 | 웹쉘 |
|--------|------|
| PHP | `<?php system($_GET['cmd']); ?>` |
| JSP | Runtime.exec() 쉘 |
| ASPX | ProcessStartInfo 쉘 |

---

## DB 덤프 (v2.9.6)

SQLi / 웹쉘 / RCE 확인 후 자동 실행:

- 덤프 대상: `member` / `user` / `admin` / `g5_member` / `xe_member`
- **행 수 제한 없음** — `max_rows_per_table=0` (무제한), 전체 테이블 전량 덤프
- 크레덴셜 저장 → `CREDENTIALS_{테이블}.json`
- 해시 유형 자동 탐지 → `hashcat -m {모드}` 명령어 출력
- 추출된 크레덴셜로 관리자 로그인 재시도

**저장 위치 (OS 자동 감지):**

| OS | 경로 |
|----|------|
| macOS | `~/Desktop/dump/{타겟}_{타임스탬프}/` |
| Windows | `~/Desktop/dump/{타겟}_{타임스탬프}/` (OneDrive 바탕화면 자동 감지) |
| Linux | `~/Desktop/dump/{타겟}_{타임스탬프}/` (Desktop 없으면 `~/dump/` 사용) |

> **v2.9.6 수정:** AI가 생성한 추출 코드가 `/tmp/`에 저장하고 DbDumper를 무시하는 버그 수정.
> `/tmp/` 저장 완전 금지, Desktop 경로 강제, FLOOR 인젝션 `query_fn` 템플릿 추가.

---

## XSS 스캔 (v2.9.6)

bingo가 자동으로 반사형/저장형 XSS를 탐지합니다:

- 모든 파라미터의 반사 컨텍스트 스캔 (HTML / 속성 / JS / URL)
- **반사 위치 중복 제거** — 동일 파라미터가 HTML 응답에 여러 번 나타나도 고유 컨텍스트만 출력
- 루프 감지기가 정상 스캔 출력과 실제 무한 루프를 구분
- 출력 형식: `반사 위치: {파라미터}={컨텍스트}` + 고유 위치 수 요약

**v2.9.5 수정 이유:** 일부 페이지는 XSS 프로브가 단일 응답에 수십 번 반사됩니다. 이전 버전은 동일한 줄이 5회 연속되면 무한루프로 판단해 강제 종료했습니다. v2.9.5는 스캔 결과 줄의 임계값을 25회로 높이고 AI 생성 코드에 중복 제거를 강제 적용합니다.

---

## Cloudflare 우회 (실제 IP 발견)

```python
import requests, urllib3
urllib3.disable_warnings()
REAL_IP = "x.x.x.x"  # SPF/DNS 레코드에서 확인
s = requests.Session()
s.verify = False
r = s.get(f"https://{REAL_IP}/", headers={"Host": "target.com"})
```

실제 IP 찾기: `dig TXT target.com` → SPF 레코드의 IP 확인.

---

## 변경 이력

| 버전 | 요약 |
|------|------|
| v3.0.4 | 크리덴셜 확보 후: 관리자 페이지 자동 탐색 + IP 제한 우회 (헤더 스푸핑/SSRF/실IP) + 보고서 포함 |
| v3.0.3 | DB 덤프: DbDumper 우선 시도 → 실패 또는 STEP 0 테이블 누락 시 수동 페이지네이션 자동 폴백 |
| v3.0.2 | DB 덤프: 회원 테이블 판단 시 실제 샘플 데이터 확인 (SELECT LIMIT 5), 컬럼명만으로 판단 금지 |
| v3.0.1 | 테이블 식별: 컬럼명 기반 + 난독화 테이블명 지원 |
| v3.0.0 | DbDumper 유연 사용 — AI가 상황별 방법 선택 (WAF 없음 / WAF 있음 / WebShell) |
| v2.9.8 | 저장 규칙 단순화: /tmp/는 중간 파일 허용, 최종 결과만 Desktop 저장 |
| v2.9.7 | 모든 최종 출력 파일 Desktop/dump/타겟명/ 강제 저장 |
| v2.9.6 | DB 덤프: /tmp/ 저장 금지 강제, Desktop 경로 의무화, FLOOR 인젝션 query_fn 템플릿 추가 |
| v2.9.5 | XSS 반사 중복 제거 수정 — 반복 반사로 인한 오탐 루프 종료 방지 |
| v2.9.3 | DB 덤프: 행 수 제한 없음 + 바탕화면 자동 저장 (macOS/Windows) |
| v2.9.2 | CMS 편향 수정 — 타겟별 신규 탐지, 무추정 |
| v2.9.1 | 버그 수정: 변수 치환, 경고 스팸, 오탐 |
| v2.9.0 | 11개 신규 모듈: HTTP 스머글링, GraphQL, OAuth/JWT, Playwright, 알림 |
| v2.8.0 | SQLi 엔진 전면 개편 — sqlmap 수준 정밀도 |
| v2.7.0 | 침투 성공 후 DB 자동 덤프 |
| v2.3.0 | Burp Engine — 순수 Python으로 Repeater/Intruder/Scanner 구현 |
| v2.2.0 | Pentest Precision Engine — WAF 우회, CAPTCHA OCR |
| v2.1.0 | API 퍼징, 리포트 후 인터랙티브 액션 |

---

## 언어 설정

```bash
/lang        # 채팅에서 언어 변경
```

| 언어 | 코드 |
|------|------|
| English | `en` |
| 한국어 | `ko` |
| 中文 | `zh` |

---

## 요구 사항

- Python 3.10+
- 지원 모델 중 하나의 API 키
- (선택) VPN — 자동 탐지 후 표시됨

---

## 기여하기

```bash
git clone https://github.com/bingook/bingo.git
cd bingo && bash install.sh
```

PR 환영합니다. 큰 변경사항은 먼저 이슈를 열어주세요.

---

## 라이선스

MIT © 2026 bingook

---

<div align="center">

**타겟만 입력하면 bingo가 나머지를 처리합니다.**

</div>
