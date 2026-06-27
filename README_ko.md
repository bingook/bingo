<div align="center">

<img src="assets/logo.png" width="150" alt="bingo logo"/>

# bingo

**AI 기반 레드팀 터미널**

[![Version](https://img.shields.io/badge/version-3.2.65-brightgreen)](https://github.com/bingook/bingo/releases)
[![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux-lightgrey)](https://github.com/bingook/bingo)
[![Python](https://img.shields.io/badge/python-3.12-blue)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

**🌐 언어:** [English](README.md) · [한국어](README_ko.md) · [中文](README_zh.md)

> ⚠️ **Windows는 지원하지 않습니다.** bingo는 **macOS 및 Linux 전용**입니다.
> v3.2.45부터 Windows 지원이 영구적으로 중단되었습니다. Windows 관련 업데이트는 절대 제공하지 않습니다.

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


---

## 빠른 시작

```bash
bingo                        # 실행
bingo scan https://target    # 자동 전체 스캔
bingo --version
bingo --reset
```

최초 실행: 언어 선택 → API 키 입력 → 시작.

---

## 사용법

채팅창에 타겟과 할 일을 입력하면 됩니다. 명령어 불필요.

**예시 프롬프트:**
```
타겟: https://example.com

작업:
1. 전체 레콘 — WAF, DB 종류, 기술 스택 탐지
2. SQL 인젝션 — error → union → blind → time-based
3. 관리자 계정 — admin/user/member 테이블 덤프
4. 관리자 로그인 — 스크린샷 증거
5. DB 전체 덤프 — 성공 후 DbDumper 실행
```

> 원하는 것만 말하면 AI가 모든 것을 자동으로 결정합니다.

---

## 핵심 기능

| 영역 | bingo가 하는 일 |
|------|----------------|
| **레콘** | WAF 탐지, 기술 핑거프린팅, 모든 페이지/JS/API 엔드포인트 크롤링 |
| **SQLi** | Error-based → Union → Boolean blind → Time-based (전 DB 종류) |
| **WAF 우회** | Cloudflare / AWS WAF / ModSecurity — 자동 선택 우회 |
| **XSS** | Stored / Reflected / DOM — 성공 시 세션 하이재킹 |
| **SSRF** | 클라우드 메타데이터(AWS/GCP/Azure) 엔드포인트 테스트 |
| **파일 업로드** | 확장자 우회, 웹쉘 업로드 |
| **인증 공격** | 로그인 브루트포스, SQLi 인증 우회, CAPTCHA 자동 해결 |
| **IDOR/BOLA** | 오브젝트 ID 열거, 수평 권한 상승 |
| **JWT/OAuth** | alg:none, 약한 비밀키, redirect_uri 악용 |
| **GraphQL** | 인트로스펙션, 배치 공격, 필드 인젝션 |
| **HTTP 스머글링** | CL.TE / TE.CL 디싱크 |
| **자격증명 덤프** | 해시 추출 → hashcat 명령 자동 제안 |
| **DB 덤프** | 확인된 SQLi 후 전체 테이블 덤프 (DbDumper v2.7) |
| **스크린샷** | Playwright로 관리자 패널 자동 스크린샷 |
| **보고서** | CVSS 점수 포함 마크다운 보고서 자동 저장 |

---

## 🌐 프록시 풀 로테이션 (v3.2.18) — 신규

WAF 밴, 속도 제한, IP 차단을 자동으로 우회합니다.

### 지원 프록시 타입

| 타입 | 형식 | 비고 |
|------|------|------|
| HTTP | `http://ip:port` | 기본 프록시 |
| HTTP + 인증 | `http://user:pass@ip:port` | 계정 포함 |
| HTTPS | `https://ip:port` | SSL 터널 |
| SOCKS5 | `socks5://ip:port` | PySocks 필요 |
| SOCKS5h | `socks5h://ip:port` | DNS도 프록시 통해 해석 (더 익명) |
| Tor | `socks5h://127.0.0.1:9050` | Tor 데몬 필요 |
| API 자동 수집 | URL | ProxyScrape, Webshare, 커스텀 |

### 빠른 시작

```bash
# 프록시 1개 수동 추가
/proxy add socks5://1.2.3.4:1080

# Tor 모드 활성화 (먼저 Tor 실행 필요: brew install tor && tor)
/proxy tor

# API에서 무료 프록시 자동 수집
/proxy api

# 파일에서 일괄 로드 (한 줄에 1개)
/proxy file ~/proxies.txt

# 풀 상태 확인
/proxy list
```

### 모든 `/proxy` 서브커맨드

| 커맨드 | 설명 |
|--------|------|
| `/proxy list` | 풀 상태 + 전체 프록시 목록 표시 |
| `/proxy add <url>` | 프록시 1개 수동 추가 |
| `/proxy file <경로>` | 텍스트 파일에서 일괄 로드 (한 줄에 1개) |
| `/proxy api [url]` | API URL에서 자동 수집 또는 프리셋 선택 |
| `/proxy tor [비밀번호]` | Tor 모드 활성화 (선택: 제어 포트 비밀번호) |
| `/proxy rotate` | 즉시 다음 프록시로 강제 전환 |
| `/proxy test` | 현재 프록시 연결 확인 (지연 시간 측정) |
| `/proxy unban` | 밴된 프록시 전부 해제 (실패 기록 초기화) |
| `/proxy clear` | 풀 전체 초기화 |
| `/proxy off` | 프록시 비활성화 (직접 요청) |

### 자동 로테이션 동작 원리

bingo가 밴을 감지하면 (HTTP 429, 403, IP 차단, 연결 리셋):

```
1. 현재 프록시를 BANNED로 표시
2. 다음 사용 가능한 프록시로 자동 전환
3. Tor 모드인 경우: NEWNYM 신호 → 새 Tor 회로 (새 IP)
4. AI 힌트에 새 프록시 URL 주입 → 다음 스크립트가 자동으로 사용
5. 대기 시간 15초 → 3초로 단축 후 재시도
```

AI 생성 스크립트에 자동으로 삽입되는 코드:
```python
# [PROXY_ROTATED: now using socks5://5.6.7.8:9090]
PROXIES = {'http': 'socks5://5.6.7.8:9090', 'https': 'socks5://5.6.7.8:9090'}
session.get(url, proxies=PROXIES, timeout=15, verify=False)
```

### Tor 설정 가이드

**1단계 — Tor 설치:**
```bash
# macOS
brew install tor && brew services start tor

# Ubuntu / Debian
sudo apt install tor && sudo systemctl start tor

```

**2단계 — (선택) Tor 제어 포트 활성화:**

`/etc/tor/torrc` (Linux) 또는 `/usr/local/etc/tor/torrc` (macOS) 편집:
```
ControlPort 9051
CookieAuthentication 1
```
재시작: `sudo systemctl restart tor`

**3단계 — bingo에서 Tor 활성화:**
```bash
/proxy tor              # 비밀번호 없음 (쿠키 인증)
/proxy tor mypassword   # HashedControlPassword 사용 시
```

**4단계 — stem 설치 (회로 교체용):**
```bash
pip install stem
```
`stem` 없이도 Tor는 동작하지만, IP 밴 시 회로 자동 교체(새 IP 획득)가 비활성화됩니다.

> **Tor 사용 팁:**  
> - `socks5h://` 사용 시 DNS도 Tor를 통해 해석 → 더 강력한 익명성  
> - Tor가 실행 중인지 확인: `curl --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip`  
> - 회로 교체 간격: 최소 10초 권장 (Tor 정책)

### API 프리셋으로 자동 수집

```bash
/proxy api
```
선택창이 나타납니다:
```
1. ProxyScrape (SOCKS5) — 무료, 5000+ 프록시
2. ProxyScrape (HTTP)   — 무료, HTTP 프록시
3. ProxyScrape (SOCKS4) — 무료, SOCKS4 프록시
4. GeoNode Free         — 필터링됨, 업타임 90%+
0. 직접 입력            — 커스텀 API URL
```

또는 URL 직접 지정:
```bash
/proxy api https://api.proxyscrape.com/v3/...
/proxy api https://나의-프록시-서버.com/list.txt
```

지원 응답 형식:
- 텍스트 (한 줄에 1개: `ip:port` 또는 `scheme://ip:port`)
- JSON 배열: `["socks5://1.2.3.4:1080", ...]`

### 파일로 프록시 관리

```bash
# proxies.txt 형식 (주석은 # 사용)
# HTTP 프록시
http://1.2.3.4:3128
http://user:pass@5.6.7.8:3128

# SOCKS5 프록시
socks5://9.10.11.12:1080
socks5h://13.14.15.16:1080

# Tor (로컬)
socks5h://127.0.0.1:9050
```

```bash
/proxy file ~/proxies.txt
```

### AI 스크립트에서 프록시 사용

`/proxy` 활성화 시, AI가 생성하는 모든 Python 스크립트에 자동으로 포함:

```python
import requests

# [bingo v3.2.18: PROXY ACTIVE — 아래 PROXIES 반드시 포함]
PROXIES = {'http': 'socks5://1.2.3.4:1080', 'https': 'socks5://1.2.3.4:1080'}

s = requests.Session()
s.proxies.update(PROXIES)
s.verify = False   # Tor / 자체 서명 인증서 필수

r = s.get("https://target.com/api/...", timeout=15)
print(f"[GET {r.url} → {r.status_code}/{len(r.content)}B]")
```

### 실전 시나리오

**시나리오 1: 기본 프록시 풀 → WAF 우회**
```bash
/proxy api              # 무료 프록시 100개+ 수집
bingo> https://target.com SQL 인젝션 실행해줘
# → 밴 감지 시 자동으로 다음 프록시 사용
```

**시나리오 2: Tor + 회로 교체**
```bash
brew services start tor  # Tor 시작
pip install stem         # 회로 교체 지원
/proxy tor               # bingo에서 Tor 활성화
bingo> https://target.com 인증 우회 테스트
# → 밴될 때마다 새 IP(Tor 회로) 자동 획득
```

**시나리오 3: 구매한 프록시 서비스 연동**
```bash
# Webshare, ProxyEmpire 등 서비스의 API URL 사용
/proxy api https://proxy.webshare.io/api/v2/proxy/list/?format=txt
# 또는 다운로드한 파일 로드
/proxy file ~/Downloads/webshare_proxies.txt
```

### 요구사항

```bash
pip install PySocks  # SOCKS5 프록시 지원 (자동 설치)
pip install stem     # Tor 회로 교체 (선택 사항)
```

두 패키지 모두 `pyproject.toml`에 포함되어 bingo와 함께 자동 설치됩니다.

### 트러블슈팅

| 증상 | 해결책 |
|------|--------|
| `SOCKS5 not supported` | `pip install PySocks` |
| Tor 연결 실패 | `brew services start tor` 또는 `sudo systemctl start tor` |
| 회로 교체 안 됨 | `pip install stem` + torrc에 `ControlPort 9051` 추가 |
| 프록시 소진 | `/proxy unban` 또는 `/proxy api` 로 새로 수집 |
| 특정 프록시 제거 | `/proxy clear` 후 다시 추가 |

---

## 지원 AI 모델

| 제공사 | 예시 모델 |
|--------|----------|
| OpenAI | `gpt-4o`, `gpt-4-turbo`, `o1` |
| Anthropic | `claude-3-5-sonnet`, `claude-opus-4` |
| DeepSeek | `deepseek-chat`, `deepseek-reasoner` |
| GLM | `glm-4`, `glm-5` |
| Qwen | `qwen-max`, `qwen-plus` |
| Ollama | 모든 로컬 모델 |
| Custom | OpenAI 호환 엔드포인트 |

---

## WAF 우회 — 자동 선택

| WAF | 사용되는 우회 기법 |
|-----|------------------|
| Cloudflare | 이중 URL 인코딩 → 유니코드 → UA 스푸핑 |
| AWS WAF | 인코딩 → SLEEP→서브쿼리 → XFF 헤더 |
| ModSecurity | Space/**/ → IF→CASE WHEN → 대소문자 혼합 |
| Nginx/OpenResty | `%0a` 개행 → 주석 → 난독화 |
| 중국 WAF | 널 바이트 → 과장된 UTF-8 → 함수 치환 |

---

## Burp Engine — 자동 실행 (v3.2.51)

URL + 취약점 키워드가 입력에 함께 있으면 **Burp 엔진이 자동 실행**됩니다. 별도 명령 불필요.

```
bingo> https://target.com sqli 찾아줘
bingo> https://target.com xss 테스트
bingo> https://target.com rce 익스플로잇
```

자동 트리거 키워드: `sqli` `xss` `rce` `ssrf` `xxe` `inject` `payload` `fuzz` `scan` `exploit` `oob`

> **URL이 없으면 실행 안 됨.** URL + 키워드 둘 다 필요.

---

## 환각 방지 — 4단계 가드

모든 AI 응답은 4가지 검사를 통과해야 출력됩니다:

1. **코드 블록 가드** — 빈 스텁, JSON 계획 거부
2. **텍스트 인터셉트** — AI 자기 고백 거부
3. **가짜 자격증명 차단** — HTTP 증거 없는 크레덴셜 차단
4. **미검증 결론 차단** — 코드 실행 없는 "SQLi 확인됨" 차단

보고서 증거 레이블:

| 레이블 | 의미 |
|--------|------|
| `✅ VERIFIED` | 실제 HTTP 응답으로 확인됨 |
| `🟡 LIKELY` | 부분적 증거 |
| `🔍 INFERRED` | 추론만 — 수동 검증 필요 |

---

## `bingo scan` — 완전 자동 파이프라인

```bash
bingo scan https://target.com
```

5단계 자동 실행, 상호작용 불필요:

| 단계 | 수행 내용 |
|------|----------|
| 1. 레콘 | 기술 핑거프린팅, WAF 탐지, 엔드포인트 맵 |
| 2. 수집 | 관리자 패널, 민감한 파일, 파라미터 발견 |
| 3. 테스트 | SQLi / LFI / XSS / SSRF / IDOR 탐지 |
| 4. 익스플로잇 | WAF 우회, 데이터 추출, 자격증명 덤프 |
| 5. 보고서 | CVSS 점수 + 증거 포함 마크다운 보고서 |

보고서 저장 위치: `~/.config/bingo/reports/report_<domain>.md`

---

## 명령어 목록

채팅창에서 `/`를 입력하면 명령어 메뉴가 열립니다 (방향키로 탐색).

| 명령어 | 기능 |
|--------|------|
| `/scan <url>` | 전체 레드팀 파이프라인 |
| `/waf <url>` | WAF 탐지 + 우회만 |
| `/crack [hash]` | 해시 크랙 — 온라인 조회 → 오프라인 |
| `/proxy [서브]` | **프록시 풀 로테이션** (v3.2.18 신규) |
| `/stop` | 실행 중인 작업 중지 |
| `/tools` | 전체 도구 + 설치 상태 |
| `/tools install <name>` | 특정 도구 설치 |
| `/tools install all` | 누락된 모든 도구 한번에 설치 |
| `/model` | AI 모델 추가/변경 |
| `/skill <키워드>` | 스킬 지식베이스 검색 |
| `/history` | 대화 기록 보기 |
| `/export` | 대화를 `.md`로 저장 |
| `/config` | 현재 설정 보기 |
| `/lang` | 언어 변경 (ko / zh / en) |
| `/clear` | 화면 초기화 |
| `/quit` | 종료 |

---

## 모바일 — APK / IPA 분석 (v2.2.8)

채팅창에서 직접 Android APK 및 iOS IPA 파일을 분석할 수 있습니다.

### Android APK

```bash
bingo> analyze target.apk
bingo> target.apk 시크릿 스캔
bingo> pentest com.example.app
```

| 방법 | 속도 | 명령 |
|------|------|------|
| TruffleHog native | ⚡ 9배 빠름 | `bingo> target.apk trufflehog` |
| jadx 전체 디컴파일 | 철저함 | `bingo> target.apk jadx full scan` |

### iOS IPA

```bash
bingo> analyze target.ipa
bingo> ios swift decompile target.ipa
```

**필요사항:** Java 17+ 및 Malimite.jar
```bash
brew install openjdk@17
# Malimite.jar: https://github.com/LaurieWired/Malimite/releases
java -jar ~/tools/Malimite.jar target.ipa --output ./decompiled/
```

### 추출 항목

| 항목 | 상세 |
|------|------|
| 하드코딩된 시크릿 | AWS 키, Google API, Firebase, Stripe, JWT, GitHub 토큰 |
| 권한 | 선언된 모든 권한 + 위험 권한 |
| 익스포트된 컴포넌트 | Activities, Services, Receivers, Providers |
| 딥링크 / URL 스킴 | Intent 필터, 커스텀 스킴 핸들러 |
| 네트워크 엔드포인트 | 코드+에셋에서 추출된 API URL |
| SSL 피닝 | 탐지 → 우회 가이드 자동 생성 |
| 서드파티 SDK | Firebase, Sentry, Analytics 등 |

---

## DB 덤프 (v2.9.6)

SQLi / 웹쉘 / RCE 확인 후 자동 실행:

- 덤프 대상: `member` / `user` / `admin` / `g5_member` / `xe_member`
- **행 제한 없음** — `max_rows_per_table=0` (전체 테이블 덤프)
- 자격증명 저장 → `CREDENTIALS_{table}.json`
- 해시 타입 탐지 → `hashcat -m {mode}` 명령 출력
- 추출된 자격증명으로 관리자 로그인 재시도

**저장 위치:**

| OS | 경로 |
|----|------|
| macOS | `~/Desktop/dump/{target}_{timestamp}/` |
| Windows | `~/Desktop/dump/{target}_{timestamp}/` |
| Linux | `~/Desktop/dump/{target}_{timestamp}/` |

---

## OAuth 오픈 클라이언트 등록 체인 공격 (v3.2.65)

bingo v3.2.65는 **`sec-web-oauth-open-reg`** 스킬을 추가합니다. 미인증 동적 클라이언트 등록을 허용하는 치명적인 OAuth 설정 오류를 이용한 계정 탈취 완전 체인입니다.

### 공격 체인

```
/.well-known/oauth-authorization-server
        ↓
  registration_endpoint (인증 없이 접근 가능)
        ↓
  공격자가 클라이언트 등록 → client_id + client_secret 획득
        ↓
  공격자 redirect_uri로 인가 요청
        ↓
  피해자 클릭 → 인가 코드가 attacker.com으로 전송
        ↓
  토큰 교환 (PKCE 미강제)
        ↓
  와일드카드 CORS → 크로스오리진 토큰 읽기
        ↓
  계정 탈취 완료 ✓
```

### bingo가 자동으로 점검하는 항목

| 점검 항목 | 스킬 커버 |
|-----------|----------|
| `/.well-known/oauth-authorization-server` 메타데이터 탐지 | ✅ |
| `registration_endpoint` 미인증 접근 | ✅ |
| `redirect_uri` 화이트리스트 우회 | ✅ |
| PKCE (`code_challenge`) 강제 여부 | ✅ |
| `Access-Control-Allow-Origin: *` + Credentials 동시 허용 | ✅ |
| 인가 코드 탈취 PoC | ✅ |

### 사용 방법

```
bingo skill show sec-web-oauth-open-reg
bingo skill search oauth
```

---

## DApp / Web3 / 스마트 컨트랙트 감사 (v3.2.62)

bingo에 **DApp/Web3 전용 스킬 28개**가 추가되었습니다. Web3 관련 키워드가 감지되면 **자동으로 스킬이 로드**됩니다.

### 자동 트리거 키워드

아래 키워드가 입력에 포함되면 Web3 스킬 컨텍스트가 자동으로 주입됩니다:

`web3` `dapp` `defi` `nft` `스마트 컨트랙트` `solidity` `블록체인` `이더리움` `abi` `metamask` `walletconnect` `wagmi` `ethers` `viem` `reentrancy` `재진입` `flash loan` `플래시론` `oracle` `erc20` `erc721` `delegatecall` `selfdestruct` `ecrecover` `swc-`

별도 명령 없이 자연어로 입력하면 됩니다.

```bash
bingo> https://app.uniswap.org 스마트 컨트랙트 감사해줘
bingo> https://defi-target.com 재진입 취약점 확인
bingo> 플래시론 공격 가능한지 분석해줘
bingo> https://app.target.com dapp 침투 테스트  # 지갑 자동 생성 + SIWE 로그인
```

### DApp 감사 스킬 (총 28개)

| # | 스킬 ID | 설명 |
|---|---------|------|
| 1 | `web3-dapp-fingerprint` | DApp 기술 스택 핑거프린팅 (ethers/web3.js/wagmi/viem) |
| 2 | `web3-rpc-enum` | Ethereum JSON-RPC 엔드포인트 열거 및 노출 감지 |
| 3 | `web3-abi-extract` | 지갑 없이 컨트랙트 ABI + 함수 시그니처 추출 |
| 4 | `web3-reentrancy` | SWC-107 재진입 공격 취약점 감지 (Slither 패턴) |
| 5 | `web3-integer-overflow` | SWC-101 정수 오버플로우/언더플로우 감지 |
| 6 | `web3-access-control` | SWC-105 미보호 함수 + 소유권 탈취 패턴 |
| 7 | `web3-tx-order-dependency` | SWC-114 프론트런닝 / TX 순서 의존성 |
| 8 | `web3-flash-loan` | Flash Loan 공격 벡터 분석 (가격 오라클 조작) |
| 9 | `web3-oracle-manipulation` | 온체인 오라클 조작 / TWAP 우회 |
| 10 | `web3-signature-replay` | SWC-121 서명 재사용 / EIP-712 미적용 |
| 11 | `web3-delegate-call` | SWC-112 delegatecall 슬롯 충돌 취약점 |
| 12 | `web3-selfdestruct` | SWC-106 selfdestruct 오용 + 강제 이더 전송 |
| 13 | `web3-unchecked-call` | SWC-104 return value 미확인 저수준 call |
| 14 | `web3-timestamp-dependence` | SWC-116 블록 타임스탬프 의존성 |
| 15 | `web3-private-data` | SWC-136 프라이빗 스토리지 데이터 노출 |
| 16 | `web3-wallet-connect-enum` | WalletConnect/MetaMask 없이 DApp API 열거 |
| 17 | `web3-graphql-subgraph` | DApp GraphQL 서브그래프 쿼리 취약점 |
| 18 | `web3-nft-metadata-ssrf` | NFT 메타데이터 SSRF / URI 조작 |
| 19 | `web3-defi-full-pipeline` | DeFi 전체 공격 파이프라인 (자동 선택) |
| 20 | `web3-contract-audit` | 스마트 컨트랙트 종합 감사 리포트 생성 |
| 21 | `web3-blind-signing-audit` | EIP-712/7730 블라인드 서명 감사 (Trail of Bits / Bybit 패턴) |
| 22 | `web3-safe-multisig-optype` | Safe 멀티시그 operation-type 조작 (Bybit 15억 달러 해킹 벡터) |
| 23 | `web3-frontend-injection` | DApp 프론트엔드 JS 인젝션 / 주소 스와핑 (EtherDelta 패턴) |
| 24 | `web3-weak-randomness` | SWC-120 약한 온체인 무작위성 (block.timestamp/blockhash 예측 가능) |
| 25 | `web3-dos-gas-limit` | SWC-128 가스 한도 DoS / 무한 루프 / 외부 의존 DoS |
| 26 | `web3-wallet-gen` | **[v3.2.62 신규]** 테스트용 이더리움 지갑 즉시 생성 (주소 + 프라이빗 키) |
| 27 | `web3-siwe-auth` | **[v3.2.62 신규]** Sign-In with Ethereum (EIP-4361) DApp 자동 로그인 |
| 28 | `web3-dapp-full-auth` | **[v3.2.62 신규]** 지갑 생성 → SIWE 로그인 → 세션 토큰 → 인증 API 전체 침투 파이프라인 |

### 핵심 취약점 커버리지

| 취약점 | SWC | 심각도 | 지원 |
|--------|-----|--------|------|
| 재진입 | SWC-107 | CRITICAL | ✅ |
| 정수 오버플로우 | SWC-101 | HIGH | ✅ |
| 미보호 함수 | SWC-105 | CRITICAL | ✅ |
| Delegatecall 충돌 | SWC-112 | HIGH | ✅ |
| 서명 재사용 | SWC-121 | HIGH | ✅ |
| 타임스탬프 의존성 | SWC-116 | MEDIUM | ✅ |
| 약한 무작위성 | SWC-120 | HIGH | ✅ |
| 가스 한도 DoS | SWC-128 | HIGH | ✅ |
| 블라인드 서명 (EIP-7730) | — | HIGH | ✅ |
| Safe op-type 조작 | — | CRITICAL | ✅ (Bybit 벡터) |
| 프론트엔드 JS 인젝션 | — | CRITICAL | ✅ (EtherDelta 패턴) |
| 플래시론 공격 | — | CRITICAL | ✅ |
| 오라클 조작 | — | CRITICAL | ✅ |
| NFT 메타데이터 SSRF | — | HIGH | ✅ |
| DApp 인증 우회 (SIWE) | — | HIGH | ✅ *신규* |
| IDOR/BOLA (인증 API) | — | HIGH | ✅ *신규* |

### DApp 지갑 인증 — 테스트 지갑 생성 + SIWE 로그인 (v3.2.62)

대부분의 DApp은 지갑 연결 없이는 API에 접근할 수 없습니다 (`401 Unauthorized`). bingo는 이제 이 과정을 자동으로 처리합니다:

```
bingo> https://app.target.com dapp 침투 테스트

# bingo 자동 실행:
# 1. [web3-wallet-gen]      테스트용 이더리움 지갑 생성 (실제 자산 없음)
# 2. [web3-siwe-auth]       EIP-4361 챌린지 서명 → 세션 토큰 획득
# 3. [web3-dapp-full-auth]  인증된 모든 API 엔드포인트 테스트 (IDOR/BOLA/권한 상승)
```

**동작 원리:**

```
모든 DApp API → 401 Unauthorized (지갑 없음)
                    ↓
           bingo가 테스트 지갑 생성
           주소: 0xAbCd... (새로 생성, 자산 없음)
                    ↓
       DApp이 서명 챌린지 전송 (EIP-4361)
                    ↓
       bingo가 테스트 지갑 키로 서명
                    ↓
       세션 토큰 획득 → Bearer eyJ...
                    ↓
       인증된 모든 엔드포인트 퍼징
       → IDOR / BOLA / 권한 상승 테스트
```

> ⚠️ **안전**: bingo는 **새로운 테스트 전용 지갑**을 생성합니다. 실제 자산이 없는 빈 지갑이며, 사용자의 기존 지갑이나 프라이빗 키는 절대 필요하지 않습니다. 생성된 테스트 주소에 실제 ETH/토큰을 절대 입금하지 마세요.

### 블라인드 서명 / EIP-7730 (Bybit 해킹 벡터)

2025년 2월 Bybit 15억 달러 해킹은 Safe 멀티시그의 블라인드 서명 취약점을 이용했습니다:
- 공격자가 `operation` 파라미터를 `0`(call) → `1`(delegatecall)로 변경
- 하드웨어 지갑에서 서명자가 변경 사실을 감지 불가
- EIP-712 구조화 데이터만으로는 이를 방지하기 부족

bingo의 `web3-blind-signing-audit`과 `web3-safe-multisig-optype` 스킬이 이 패턴을 탐지합니다:

```
[CRITICAL] Operation Type UI 미표시
           Safe 트랜잭션 operation type (0=call, 1=delegatecall)이 UI에 표시 안 됨
           수정: 서명 UI에 operation type을 명시적으로 표시

[HIGH] EIP-7730 미구현
       하드웨어 지갑에서 사람이 읽을 수 있는 트랜잭션 상세 표시 불가
       수정: JSON 매니페스트를 https://github.com/LedgerHQ/clear-signing-erc7730-registry 에 제출
```

### 사용 예시 (지갑 인증 포함 전체 침투 테스트)

```bash
# 지갑 로그인이 필요한 DApp
bingo> https://app.defi-protocol.com dapp 침투 테스트

# bingo 자동 실행:
# 1. DApp 기술 스택 핑거프린팅 (ethers/wagmi/web3.js)
# 2. 테스트 지갑 생성: 0xNewAddress... (테스트 전용 — 실제 자산 없음)
# 3. SIWE 로그인 (EIP-4361) → 세션 토큰 획득
# 4. 인증된 모든 엔드포인트 IDOR/BOLA 테스트
# 5. 스마트 컨트랙트 SWC 취약점 스캔
# 6. EIP-7730 블라인드 서명 준수 여부 확인
# 7. 프론트엔드 JS 인젝션 / 주소 스와핑 테스트
# 8. 심각도 등급이 포함된 전체 침투 보고서 생성
```

---

## Cloudflare 우회 (실제 IP 발견)

```python
import requests, urllib3
urllib3.disable_warnings()
REAL_IP = "x.x.x.x"  # SPF/DNS 레코드에서 찾은 실제 IP
s = requests.Session()
s.verify = False
r = s.get(f"https://{REAL_IP}/", headers={"Host": "target.com"})
```

실제 IP 찾기: `dig TXT target.com` → SPF 레코드 IP 확인.

---

## 설정 및 데이터 저장

| 경로 | 내용 |
|------|------|
| `~/.config/bingo/config.json` | API 키, 모델, 언어 |
| `~/.config/bingo/reports/` | 자동 저장 스캔 보고서 |
| `~/.config/bingo/sessions/` | 채팅 세션 기록 |
| `~/.bingo/tools/` | 자동 다운로드 Go 도구 |
| `BINGO_REPORTS_DIR` | 보고서 경로 오버라이드 (환경변수) |

---

## 요구사항

- Python **3.12** (Playwright 호환성 필수)
- 지원 모델 중 하나의 API 키
- (선택) VPN 또는 프록시 — 자동 감지 및 표시

---

## 변경 이력

| 버전 | 요약 |
|------|------|
| v3.2.65 | **OAuth 오픈 클라이언트 등록 체인 공격** — `/.well-known/oauth-authorization-server` 자동 탐지 → 미인증 클라이언트 등록 → redirect_uri 인가 코드 탈취 → PKCE 우회 → 와일드카드 CORS 악용 → 계정 완전 탈취 (`sec-web-oauth-open-reg`); 프록시 데드락 수정(RLock); DApp 스킬 SyntaxWarning 정리 |
| v3.2.64 | 프록시 데드락 수정 (RLock), `skills_data15.py` SyntaxWarning 정리 |
| v3.2.62 | **DApp 지갑 인증** — 테스트 지갑 생성, SIWE 로그인 (EIP-4361), 인증 API 전체 침투 파이프라인 (총 28개 스킬) |
| v3.2.61 | **DApp/Web3 감사** — 스마트 컨트랙트 스킬 25개, EIP-7730 블라인드 서명, Bybit Safe op-type, 프론트엔드 인젝션, SWC-120/128 |
| v3.2.57 | 환각 방지 레이블 (VERIFIED/LIKELY/INFERRED), Playwright JS 감지, 스킬 로딩 수정, Python 3.12 전용 |
| v3.2.45 | **macOS/Linux 전용** — Windows 지원 영구 중단 |
| v3.2.28 | 핵심 엔진 복원 — 가장 안정적인 베이스로 롤백 |
| v3.2.18 | **프록시 풀 로테이션** — HTTP/HTTPS/SOCKS5/Tor/API, 밴 시 자동 교체, RULE 26-T |
| v3.2.17 | 오탐 수정: `Body: <!DOCTYPE html>` 루프 감지기, RULE 26-S |
| v3.2.16 | CAPTCHA 오탐 수정 — 스크립트 태그 제외 |
| v3.2.15 | `NameError` 방지: RULE 26-Q — 변수 사용 전 초기화 의무 |
| v3.2.14 | 로그인 효율성: 3회 HTTP 500 후 JS 분석 피벗 (RULE 26-P) |
| v3.0.6 | SQLi 추출: IP 밴 자동 감지 + XFF 로테이션(12개 헤더) |
| v3.0.5 | 수정: 최종 보고서가 Desktop/dump/target/에 저장되도록 |
| v2.9.6 | DB 덤프: /tmp/ 저장 금지, Desktop 경로 강제, FLOOR 인젝션 템플릿 추가 |
| v2.9.5 | XSS 반사 중복 제거 — 반복 반사로 인한 오탐 루프 킬 방지 |
| v2.9.0 | 11개 신규 모듈: HTTP 스머글링, GraphQL, OAuth/JWT, Playwright |
| v2.8.0 | SQLi 엔진 전면 개편 |
| v2.7.0 | 성공적인 침투 후 DB 자동 덤프 |
| v2.2.0 | Pentest Precision Engine — WAF 우회, CAPTCHA OCR |

---

## 라이선스

MIT © 2026 bingook

---

<div align="center">

**타겟을 입력하세요. bingo가 나머지를 합니다.**

</div>
