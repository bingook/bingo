# BINGO SKILLS INDEX

bingo 에이전트가 자동으로 로드하는 전문 스킬 라이브러리.
AI가 `SKILL_LOAD: <스킬명>` 을 선언하면 즉시 해당 전문 지식이 주입됨.

---

## 📦 내장 스킬 (즉시 사용 가능)

| 카테고리 | 스킬명 (SKILL_LOAD 이름) | 설명 |
|---|---|---|
| SQL Injection | `sqli` | SQLi 전체 방법론 (10가지) |
| WAF Bypass | `waf_bypass` | WAF 우회 기법 |
| Web Vuln | `web_vuln` | XSS/SSRF/LFI/SSTI/RCE 종합 |
| API Security | `api_security` | API 취약점 점검 |
| Auth Attack | `auth_attack` | 인증 우회/세션 공격 |
| Recon | `recon` | 정찰/서브도메인/핑거프린팅 |
| **Korean CMS** | **`gnuboard5-attack`** | **그누보드5 전체 공격 체인 (실전 검증)** |

---

## 🔥 hack-skills 102개 (SKILL_LOAD: 로 동적 로드)

AI가 공격 상황에 맞게 자동 선택. `SKILL_LOAD: <스킬명>` 형식으로 요청.

### Web Injection (웹 인젝션)
| 스킬명 | 설명 |
|---|---|
| `injection-checking` | 인젝션 취약점 초기 탐지 방법론 |
| `sqli-sql-injection` | SQL 인젝션 완전 공략 (489줄) |
| `xss-cross-site-scripting` | XSS 전체 기법 (379줄) |
| `ssti-server-side-template-injection` | SSTI 템플릿 인젝션 공략 (344줄) |
| `cmdi-command-injection` | 명령어 인젝션 (687줄) |
| `nosql-injection` | NoSQL 인젝션 (MongoDB, Redis 등) |
| `xxe-xml-external-entity` | XXE 외부 엔티티 공격 (554줄) |
| `expression-language-injection` | EL/SpEL 인젝션 |
| `jndi-injection` | JNDI/Log4Shell 공격 |
| `crlf-injection` | CRLF 인젝션/헤더 분리 |
| `xslt-injection` | XSLT 프로세서 인젝션 |
| `csv-formula-injection` | CSV 수식 인젝션 |
| `email-header-injection` | 이메일 헤더 인젝션 |
| `http-parameter-pollution` | HTTP 파라미터 오염 |
| `type-juggling` | 타입 저글링 (PHP == 우회) |

### Server-Side Attacks (서버사이드 공격)
| 스킬명 | 설명 |
|---|---|
| `ssrf-server-side-request-forgery` | SSRF 완전 공략 (323줄) |
| `deserialization-insecure` | 역직렬화 취약점 (725줄) |
| `request-smuggling` | HTTP 요청 밀수 (314줄) |
| `http2-specific-attacks` | HTTP/2 특화 공격 |
| `http-host-header-attacks` | Host 헤더 공격 |
| `web-cache-deception` | 웹 캐시 기만 |
| `dns-rebinding-attacks` | DNS 리바인딩 |
| `dangling-markup-injection` | 댕글링 마크업 |
| `arbitrary-write-to-rce` | 임의 쓰기→RCE 연계 |

### Client-Side Attacks (클라이언트사이드)
| 스킬명 | 설명 |
|---|---|
| `csrf-cross-site-request-forgery` | CSRF 공격 (526줄) |
| `cors-cross-origin-misconfiguration` | CORS 설정 오류 (269줄) |
| `clickjacking` | 클릭재킹 공격 |
| `open-redirect` | 오픈 리다이렉트 (380줄) |
| `csp-bypass-advanced` | CSP 우회 고급 기법 |
| `prototype-pollution` | 프로토타입 오염 (190줄) |
| `prototype-pollution-advanced` | 프로토타입 오염 고급 (338줄) |

### Authentication & Authorization (인증/인가)
| 스킬명 | 설명 |
|---|---|
| `authbypass-authentication-flaws` | 인증 우회 종합 (441줄) |
| `auth-sec` | 인증 보안 체크리스트 |
| `idor-broken-object-authorization` | IDOR/BOLA (336줄) |
| `jwt-oauth-token-attacks` | JWT/OAuth 토큰 공격 (301줄) |
| `oauth-oidc-misconfiguration` | OAuth/OIDC 설정 오류 |
| `saml-sso-assertion-attacks` | SAML SSO 어설션 공격 |
| `401-403-bypass-techniques` | 401/403 우회 (348줄) |
| `password-reset-flaws` → `authbypass-authentication-flaws` | 비밀번호 재설정 취약점 |

### File & Upload (파일 공격)
| 스킬명 | 설명 |
|---|---|
| `upload-insecure-files` | 파일 업로드 취약점 (542줄) |
| `path-traversal-lfi` | 경로 탐색/LFI (802줄) |
| `file-access-vuln` | 파일 접근 취약점 |
| `insecure-source-code-management` | 소스코드 관리 취약점 |

### API Security (API 보안)
| 스킬명 | 설명 |
|---|---|
| `api-sec` | API 보안 종합 |
| `api-recon-and-docs` | API 정찰/문서 열거 |
| `api-authorization-and-bola` | API 인가/BOLA |
| `api-auth-and-jwt-abuse` | API 인증/JWT 남용 |
| `graphql-and-hidden-parameters` | GraphQL/숨겨진 파라미터 |

### Business Logic (비즈니스 로직)
| 스킬명 | 설명 |
|---|---|
| `business-logic-vulnerabilities` | 비즈니스 로직 취약점 (711줄) |
| `business-logic-vuln` | 비즈니스 로직 요약 |
| `race-condition` | 레이스 컨디션 (526줄) |

### Recon & Methodology (정찰/방법론)
| 스킬명 | 설명 |
|---|---|
| `hack` | 해킹 마스터 라우터 (162줄) |
| `recon-and-methodology` | 정찰 & 방법론 (389줄) |
| `recon-for-sec` | 보안 정찰 |
| `subdomain-takeover` | 서브도메인 탈취 (247줄) |
| `waf-bypass-techniques` | WAF 우회 기법 (290줄) |

### Privilege Escalation (권한 상승)
| 스킬명 | 설명 |
|---|---|
| `linux-privilege-escalation` | Linux 권한 상승 (346줄) |
| `windows-privilege-escalation` | Windows 권한 상승 (328줄) |
| `linux-security-bypass` | Linux 보안 우회 |
| `linux-lateral-movement` | Linux 횡적 이동 |
| `windows-av-evasion` | Windows AV 우회 |
| `windows-lateral-movement` | Windows 횡적 이동 |

### Network & Infrastructure (네트워크/인프라)
| 스킬명 | 설명 |
|---|---|
| `reverse-shell-techniques` | 역방향 셸 기법 (290줄) |
| `tunneling-and-pivoting` | 터널링/피버팅 (343줄) |
| `container-escape-techniques` | 컨테이너 탈출 (339줄) |
| `kubernetes-pentesting` | 쿠버네티스 침투 (348줄) |
| `network-protocol-attacks` | 네트워크 프로토콜 공격 |
| `ntlm-relay-coercion` | NTLM 릴레이 강제 |
| `unauthorized-access-common-services` | 공통 서비스 무단접근 |

### Active Directory (액티브 디렉토리)
| 스킬명 | 설명 |
|---|---|
| `active-directory-kerberos-attacks` | AD 커버로스 공격 (311줄) |
| `active-directory-acl-abuse` | AD ACL 남용 (295줄) |
| `active-directory-certificate-services` | AD CS 공격 (303줄) |

### Mobile Security (모바일 보안)
| 스킬명 | 설명 |
|---|---|
| `android-pentesting-tricks` | Android 침투 테스트 (369줄) |
| `ios-pentesting-tricks` | iOS 침투 테스트 (418줄) |
| `mobile-ssl-pinning-bypass` | SSL 피닝 우회 (531줄) |

### Cryptography Attacks (암호화 공격)
| 스킬명 | 설명 |
|---|---|
| `hash-attack-techniques` | 해시 공격 기법 (491줄) |
| `rsa-attack-techniques` | RSA 공격 기법 (437줄) |
| `classical-cipher-analysis` | 고전 암호 분석 (663줄) |
| `symmetric-cipher-attacks` | 대칭 암호 공격 (462줄) |
| `lattice-crypto-attacks` | 격자 기반 암호 공격 (497줄) |

### Binary/Exploit (바이너리/익스플로잇)
| 스킬명 | 설명 |
|---|---|
| `binary-protection-bypass` | 바이너리 보호 우회 (295줄) |
| `format-string-exploitation` | 포맷 스트링 공격 (312줄) |
| `stack-overflow-and-rop` | 스택 오버플로/ROP (304줄) |
| `heap-exploitation` | 힙 익스플로잇 (217줄) |
| `kernel-exploitation` | 커널 익스플로잇 (307줄) |
| `browser-exploitation-v8` | V8 브라우저 익스플로잇 (334줄) |
| `sandbox-escape-techniques` | 샌드박스 탈출 (250줄) |
| `arbitrary-write-to-rce` | 임의 쓰기→RCE |
| `anti-debugging-techniques` | 안티 디버깅 기법 (407줄) |
| `code-obfuscation-deobfuscation` | 코드 난독화/역난독화 (391줄) |

### Reverse Engineering (리버스 엔지니어링)
| 스킬명 | 설명 |
|---|---|
| `symbolic-execution-tools` | 심볼릭 실행 도구 (419줄) |
| `vm-and-bytecode-reverse` | VM/바이트코드 리버싱 (450줄) |
| `memory-forensics-volatility` | 메모리 포렌식 (323줄) |
| `traffic-analysis-pcap` | 패킷 캡처 분석 (341줄) |
| `steganography-techniques` | 스테가노그래피 (348줄) |

### Emerging & Special (최신/특수)
| 스킬명 | 설명 |
|---|---|
| `ghost-bits-cast-attack` | Ghost Bits 캐스트 공격 (799줄, Black Hat Asia 2026) |
| `llm-prompt-injection` | LLM 프롬프트 인젝션 (357줄) |
| `ai-ml-security` | AI/ML 보안 공격 (425줄) |
| `defi-attack-patterns` | DeFi/블록체인 공격 패턴 (355줄) |
| `smart-contract-vulnerabilities` | 스마트 컨트랙트 취약점 (314줄) |
| `dependency-confusion` | 의존성 혼동 공격 (178줄) |
| `macos-process-injection` | macOS 프로세스 인젝션 (384줄) |
| `macos-security-bypass` | macOS 보안 우회 (337줄) |

---

## 수동 로드 명령어

```
/skill load <스킬명>
/skill list
```

## AI 자동 사용 방법

AI는 공격 상황을 파악한 후 자동으로:
```
SKILL_LOAD: xss-cross-site-scripting
SKILL_LOAD: waf-bypass-techniques, ssti-server-side-template-injection
```
형식으로 필요한 스킬을 동적으로 로드함.
