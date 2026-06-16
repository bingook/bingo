"""
Skill Engine — CyberSecurity-Skills 195개 + SecSkills 로컬 완전 내장
오프라인 즉시 사용 가능. git clone 시 full 마크다운 추가 확보 가능.
"""
from __future__ import annotations
import json
import os
import subprocess
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# ── 완전 내장 DB 로드 ────────────────────────────────────────────
from .skills_data import SKILLS_DB, MODULE_INDEX, TAG_INDEX
from .skills_data2 import SKILLS_DB_2, MODULE_INDEX_2, TAG_INDEX_2
from .skills_data3 import SKILLS_DB_3, MODULE_INDEX_3, TAG_INDEX_3
from .skills_data4 import SKILLS_DB_4, MODULE_INDEX_4, TAG_INDEX_4
from .skills_data5 import SKILLS_DB_5, MODULE_INDEX_5, TAG_INDEX_5
from .skills_data6 import SKILLS_DB_6, MODULE_INDEX_6, TAG_INDEX_6
from .skills_data7 import SKILLS_DB_7, MODULE_INDEX_7, TAG_INDEX_7

# 통합 (CyberSecurity-Skills + SecSkills + BurpEngine + PostExploit + SecKnowledge — v2.2.6)
ALL_SKILLS: dict[str, dict] = {
    **SKILLS_DB, **SKILLS_DB_2, **SKILLS_DB_3,
    **SKILLS_DB_4, **SKILLS_DB_5, **SKILLS_DB_6,
    **{s["name"]: s for s in SKILLS_DB_7},
}
ALL_MODULE_INDEX: dict[str, list[str]] = {}
ALL_TAG_INDEX: dict[str, list[str]] = {}

for _src_idx in [MODULE_INDEX, MODULE_INDEX_2, MODULE_INDEX_3, MODULE_INDEX_4, MODULE_INDEX_5, MODULE_INDEX_6, MODULE_INDEX_7]:
    for k, v in _src_idx.items():
        if k not in ALL_MODULE_INDEX:
            ALL_MODULE_INDEX[k] = []
        ALL_MODULE_INDEX[k].extend(v)

for _src_idx in [TAG_INDEX, TAG_INDEX_2, TAG_INDEX_3, TAG_INDEX_4, TAG_INDEX_5, TAG_INDEX_6, TAG_INDEX_7]:
    for k, v in _src_idx.items():
        if k not in ALL_TAG_INDEX:
            ALL_TAG_INDEX[k] = []
        ALL_TAG_INDEX[k].extend(v)


SKILLS_REPO = "https://github.com/Hi-FullHouse/CyberSecurity-Skills.git"

# bingo 데이터 디렉토리 (기존 config.py CONFIG_DIR와 동일 위치)
def _skills_dir() -> Path:
    import sys
    if sys.platform == "win32":
        base = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
        return base / "bingo" / "skills"
    elif sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "bingo" / "skills"
    return Path.home() / ".config" / "bingo" / "skills"


SKILLS_DIR = _skills_dir()


# ── 39개 모듈 메타데이터 (오프라인 내장 — clone 없이도 작동) ────
# name=중국어, en=영어, ko=한국어
BUILTIN_MODULES: list[dict] = [
    {"id": "01", "name": "信息搜集",     "en": "Reconnaissance",         "ko": "정보수집",
     "skills": ["OSINT/피동정보수집", "DNS열거", "서브도메인탐색", "기술스택핑거프린팅", "네트워크공간검색", "능동정보수집", "소셜엔지니어링정보"]},
    {"id": "02", "name": "漏洞扫描",     "en": "VulnerabilityScanning",  "ko": "취약점스캐닝",
     "skills": ["Web취약점스캔", "네트워크취약점스캔", "DB보안평가", "설정감사스캔", "취약점스캐너자동화", "AI에이전트취약점스캔"]},
    {"id": "03", "name": "漏洞利用",     "en": "Exploitation",           "ko": "취약점이용",
     "skills": ["Web취약점이용", "SQL인젝션", "XSS", "파일포함/업로드", "명령어인젝션", "SSRF", "인증우회", "Metasploit", "AI에이전트이용"]},
    {"id": "04", "name": "权限提升",     "en": "PrivilegeEscalation",    "ko": "권한상승",
     "skills": ["Linux권한상승", "Windows권한상승", "커널/서비스오설정", "자격증명탈취"]},
    {"id": "05", "name": "后渗透",       "en": "PostExploitation",       "ko": "후속침투",
     "skills": ["정보수집/데이터탈취", "자격증명덤프/해시전달", "원격제어/인터랙티브셸", "키로거/화면캡처"]},
    {"id": "06", "name": "横向移动",     "en": "LateralMovement",        "ko": "횡적이동",
     "skills": ["횡적이동", "내부프록시/터널", "PsExec/WMI원격실행"]},
    {"id": "07", "name": "持久化",       "en": "Persistence",            "ko": "지속성확보",
     "skills": ["장기통제", "부트/로그인자동실행", "계정생성/자격증명지속", "Office지속화", "Bootkit/펌웨어지속화"]},
    {"id": "08", "name": "痕迹清除",     "en": "CoveringTracks",         "ko": "흔적제거",
     "skills": ["흔적제거/포렌식대응", "프로세스인젝션/코드인젝션", "코드난독화/분석방해", "AMSI우회/EDR회피"]},
    {"id": "09", "name": "报告撰写",     "en": "Reporting",              "ko": "보고서작성",
     "skills": ["모의침투보고서작성", "취약점등급/CVSS", "Markdown보고서템플릿", "HTML보고서템플릿", "Word/PDF보고서템플릿"]},
    {"id": "10", "name": "移动安全",     "en": "MobileSecurity",         "ko": "모바일보안",
     "skills": ["Android보안테스트", "iOS보안테스트"]},
    {"id": "11", "name": "无线安全",     "en": "WirelessSecurity",       "ko": "무선보안",
     "skills": ["Wi-Fi보안감사"]},
    {"id": "12", "name": "代码审计",     "en": "CodeAudit",              "ko": "코드감사",
     "skills": ["PHP코드감사", "Java코드감사", "JS/Node.js코드감사", "Python코드감사", "C코드감사", "C++코드감사", "Rust코드감사", "Go코드감사", "AI에이전트코드감사"]},
    {"id": "13", "name": "逆向工程",     "en": "ReverseEngineering",     "ko": "리버스엔지니어링",
     "skills": ["정적역방향분석", "동적디버그분석", "악성코드분석"]},
    {"id": "14", "name": "安全审计",     "en": "SecurityAudit",          "ko": "보안감사",
     "skills": ["등급보호합규감사", "설정보안감사", "보안아키텍처감사", "클라우드보안감사", "컨테이너보안감사", "네트워크합규평가", "AI에이전트보안감사"]},
    {"id": "15", "name": "应急响应",     "en": "IncidentResponse",       "ko": "사고대응",
     "skills": ["사건분류/우선순위평가", "로그수집분석", "네트워크트래픽분석", "사건봉쇄/제거", "클라우드환경응급대응", "사건복기/보고서", "AI보안응급대응"]},
    {"id": "16", "name": "大模型安全",   "en": "LLMSecurity",            "ko": "LLM/AI보안",
     "skills": ["프롬프트인젝션방어", "LLM데이터유출방지", "AI공급망보안", "대형모델레드팀테스트", "AI에이전트권한제어", "모델적대공격방어", "모델출력안전/환각검출", "AI앱보안설정감사", "연합학습보안", "멀티모달AI보안"]},
    {"id": "17", "name": "云安全",       "en": "CloudSecurity",          "ko": "클라우드보안",
     "skills": ["AWS보안평가", "Azure보안평가", "GCP보안평가", "클라우드IAM감사", "클라우드스토리지보안", "클라우드네트워크/WAF", "서버리스보안", "멀티클라우드보안"]},
    {"id": "18", "name": "安全开发运维", "en": "DevSecOps",              "ko": "DevSecOps",
     "skills": ["CI/CD파이프라인보안감사", "IaC보안스캔", "SAST정적테스트", "DAST동적테스트", "소프트웨어공급망보안", "보안요구사항/위협모델링"]},
    {"id": "19", "name": "工控安全",     "en": "ICS-OT-Security",        "ko": "산업제어보안",
     "skills": ["SCADA보안평가", "PLC/RTU보안테스트", "공업네트워크프로토콜보안", "IEC62443합규감사", "공업보안응급계획", "산업방화벽/네트워크분할"]},
    {"id": "20", "name": "区块链安全",   "en": "Blockchain-Web3-Security","ko": "블록체인/Web3보안",
     "skills": ["스마트컨트랙트감사", "DeFi프로토콜평가", "합의메커니즘분석", "Web3프론트엔드/월렛보안", "블록체인노드강화", "MEV/크로스체인브릿지보안"]},
    {"id": "21", "name": "物联网安全",   "en": "IoT-Security",           "ko": "IoT보안",
     "skills": ["펌웨어역방향분석", "BLE/Zigbee/Z-Wave보안테스트", "IoT통신프로토콜보안", "임베디드장치하드웨어보안테스트", "IoT플랫폼/클라우드보안", "스마트홈/커넥티드카보안"]},
    {"id": "22", "name": "数据安全",     "en": "DataSecurityPrivacy",    "ko": "데이터보안/개인정보",
     "skills": ["DLP데이터유출방지", "데이터분류/등급보호", "DB보안/암호화", "데이터마스킹/익명화", "GDPR/개인정보보호법합규", "개인정보영향평가PIA"]},
    {"id": "23", "name": "社会工程学",   "en": "SocialEngineering",      "ko": "소셜엔지니어링",
     "skills": ["피싱이메일시뮬레이션", "보이스피싱/Vishing테스트", "물리침투/소셜엔지니어링", "피싱인프라구축", "직원보안의식평가"]},
    {"id": "24", "name": "红蓝对抗",     "en": "RedBlueTeam",            "ko": "레드/블루팀",
     "skills": ["레드팀평가방법론", "블루팀방어/탐지", "퍼플팀협업평가", "BAS공격시뮬레이션플랫폼", "방어개선사이클"]},
    {"id": "25", "name": "供应链安全",   "en": "SupplyChainSecurity",    "ko": "공급망보안",
     "skills": ["SBOM생성/검증", "소프트웨어의존성/오픈소스합규감사", "코드서명/공급망무결성", "제3자공급업체위험평가", "공급망공격탐지/대응"]},
    {"id": "26", "name": "漏洞管理",     "en": "VulnerabilityManagement","ko": "취약점관리",
     "skills": ["취약점정보/CVE조회", "취약점검증/PoC테스트", "취약점우선순위/위험평가", "취약점수정/패치관리", "취약점생명주기관리", "버그바운티/크라우드소싱테스트"]},
    {"id": "27", "name": "操作系统安全", "en": "OSSecurity",             "ko": "OS보안",
     "skills": ["Windows보안강화/기준선검사", "Windows공격/횡적이동기술", "Linux보안강화/기준선검사", "Linux공격/권한유지기술", "macOS보안평가/강화", "국산OS보안강화"]},
    {"id": "28", "name": "威胁狩猎",     "en": "ThreatHunting",          "ko": "위협헌팅",
     "skills": ["위협탐색방법론/가설주도", "Sigma규칙탐지엔지니어링", "ATT&CK기반위협탐색", "네트워크트래픽/로그이상탐지"]},
    {"id": "29", "name": "威胁情报",     "en": "ThreatIntelligence",     "ko": "위협인텔리전스",
     "skills": ["위협정보피드/TAXII-STIX관리", "MISP플랫폼배포/공유", "APT그룹분석/귀속", "위협정보주도보안운영"]},
    {"id": "30", "name": "数字取证",     "en": "DigitalForensics",       "ko": "디지털포렌식",
     "skills": ["디스크이미징/증거획득", "메모리포렌식분석Volatility", "Windows디지털포렌식", "Linux디지털포렌식", "브라우저/이메일포렌식"]},
    {"id": "31", "name": "SOC运营",      "en": "SOCOperations",          "ko": "SOC운영",
     "skills": ["SIEM알림규칙/연관분석", "SOC사건분류/대응절차", "보안자동화/오케스트레이션SOAR", "SOC지표/운영효과측정"]},
    {"id": "32", "name": "身份访问管理", "en": "IAM",                    "ko": "IAM/접근권한관리",
     "skills": ["기업IAM전략/아키텍처", "PAM특권계정관리", "클라우드IAM/연합인증", "AD도메인보안/공격경로분석"]},
    {"id": "33", "name": "容器安全",     "en": "ContainerSecurity",      "ko": "컨테이너보안",
     "skills": ["컨테이너이미지보안/취약점스캔", "Kubernetes RBAC/보안정책", "컨테이너런타임보안Falco", "컨테이너탈출탐지/방어"]},
    {"id": "34", "name": "API安全",      "en": "APISecurity",            "ko": "API보안",
     "skills": ["OWASP API보안테스트", "API인증/인가보안", "GraphQL/마이크로서비스API보안"]},
    {"id": "35", "name": "密码学与PKI",  "en": "CryptographyPKI",        "ko": "암호학/PKI",
     "skills": ["TLS/SSL보안설정감사", "PKI아키텍처/인증서보안관리", "암호화알고리즘/키관리"]},
    {"id": "36", "name": "零信任架构",   "en": "ZeroTrust",              "ko": "제로트러스트",
     "skills": ["제로트러스트아키텍처설계/구현", "마이크로세그멘테이션/SDP", "ZTNA솔루션/IAM통합"]},
    {"id": "37", "name": "端点安全",     "en": "EndpointSecurity",       "ko": "엔드포인트보안",
     "skills": ["EDR배포/탐지규칙", "파일리스악성코드/LOLBins탐지", "엔드포인트강화/합규기준선", "모바일장치보안/MDM"]},
    {"id": "38", "name": "勒索软件防御", "en": "RansomwareDefense",      "ko": "랜섬웨어방어",
     "skills": ["랜섬웨어공격체인분석/탐지", "랜섬웨어응급대응/복구", "랜섬웨어방어강화/백업전략"]},
    {"id": "39", "name": "安全治理合规", "en": "GovernanceCompliance",   "ko": "보안거버넌스/합규",
     "skills": ["보안프레임워크/합규감사", "위험관리/보안측정", "보안정책체계/보안의식"]},
    {"id": "40", "name": "客户端认证绕过", "en": "ClientSideAuthBypass",  "ko": "클라이언트인증우회(ACPV)",
     "skills": [
         "localStorage/sessionStorage 토큰 조작",
         "JS 인증 플래그 우회",
         "무인증 API 엔드포인트 탐지",
         "Burp Suite 응답 변조 인증 우회",
         "authRequired/isLoggedIn 플래그 분석",
         "JWT 위조 인증 우회 PoC",
     ]},
    {"id": "41", "name": "API发现与智能模糊测试", "en": "ApiDiscoveryFuzzing", "ko": "API탐지/AI퍼징",
     "skills": [
         "Swagger/OpenAPI 문서 자동 탐지",
         "Google Discovery Document 스캔",
         "WordPress REST API 열거",
         "GraphQL 엔드포인트 탐지",
         "무인증 API 엔드포인트 자동 테스트",
         "AI 파라미터 자동 퍼징 (IDOR/SQLi/SSTI)",
         "민감 응답 키워드 자동 분류",
         "500 오류 기반 인젝션 탐지",
     ]},
    {"id": "42", "name": "SQL Server 2025 AI特性利用", "en": "MSSQL2025AIExploit", "ko": "MSSQL2025AI기능악용",
     "skills": [
         "SQL Server 2025 엔진 자동 감지",
         "버전 확인 (@@version 기반)",
         "Stacked Query 실행 가능 여부 (WAITFOR DELAY)",
         "sysadmin/db_owner 권한 확인",
         "sp_invoke_external_rest_endpoint 활성화 확인",
         "외부 서버로 테이블 데이터 전송 PoC",
         "CREATE EXTERNAL MODEL → NTLM 해시 탈취 PoC",
         "AI_GENERATE_EMBEDDINGS C2 채널 PoC",
     ]},
    {"id": "43", "name": "ArubaOS XXE/SSRF预授权漏洞", "en": "ArubaOsXxeSsrf", "ko": "ArubaOS인증없는XXE",
     "skills": [
         "포트 32000/TCP 자동 감지",
         "ArubaOS XML API 배너 확인",
         "Pre-Auth XXE OOB SSRF 콜백 테스트",
         "응답 타이밍 기반 블라인드 XXE 탐지",
         "XXE SSRF로 내부 포트 스캔 자동화",
         "재현 가능한 curl PoC 자동 생성",
         "CVSS 9.3 Critical 수준 증거 문서화",
     ]},
    {"id": "44", "name": "Ivanti Sentry预授权RCE (CVE-2026-10520)", "en": "IvantiSentryRCE", "ko": "이반티센트리사전인증RCE",
     "skills": [
         "Ivanti Sentry 제품 자동 감지 (/mics/login.jsp)",
         "취약 엔드포인트 인증 없이 접근 가능 여부 확인",
         "패치 여부 판단 (302 리다이렉트 체크)",
         "Pre-Auth RCE 명령 실행 확인 (id / uname -a / hostname)",
         "명령 실행 결과 자동 추출 및 증거 문서화",
         "버전 정보 추출 시도",
         "CVSS 10.0 Critical curl PoC 자동 생성",
     ]},
    {"id": "47", "name": "Next.js缓存投毒→0点击SXSS", "en": "NextJsCacheSxss", "ko": "NextJS캐시포이즈닝SXSS",
     "skills": [
         "Next.js App Router 및 버전 자동 탐지",
         "Cloudflare/CDN 캐시 레이어 존재 확인",
         "리퀘스트 헤더 → 리스폰스 헤더 반영 탐지 (미들웨어 설정 오류)",
         "RSC 엔드포인트 동적 페이지 탐지 (x-nextjs-prerender 제외)",
         "Content-Type: text/html 주입 → RSC 컨텍스트 전환 확인",
         "URL 파라미터 → RSC body 반영 확인 → SXSS 가능성 검증",
         "2단계 캐시 포이즈닝 PoC 자동 생성 (Refresh 헤더 활용)",
     ]},
    {"id": "48", "name": "Redis DarkReplica UAF→RCE (CVE-2026-23631)", "en": "RedisDarkReplica", "ko": "Redis_DarkReplica_RCE",
     "skills": [
         "Redis 포트 자동 탐지 (6379/6380/6381/6382)",
         "인증 없는 접근 확인 (NOAUTH 여부)",
         "빈 패스워드 / 자격증명 AUTH 자동 시도",
         "INFO server → redis_version 추출 → 취약 버전 비교",
         "SLAVEOF NO ONE 권한 확인 (복제 제어 가능 여부)",
         "FUNCTION LIST 엔진 확인 (Lua 함수 등록 가능 여부)",
         "CONFIG GET slave-read-only 접근 확인",
         "완전 익스플로잇 가능 시 DarkReplica PoC 자동 생성",
     ]},
    {"id": "49", "name": "HTML Injection + Chrome 자동완성 CSP 우회 비번탈취", "en": "HtmlAutofillSteal", "ko": "HTML_AutoFill_비번탈취",
     "skills": [
         "GET 파라미터 HTML 반사 취약점 자동 탐지",
         "로그인 폼 (email/password) 존재 여부 확인",
         "CSP 분석 — script-src 차단 여부 (XSS 불가 → HTML만으로 공격 가능)",
         "Referrer-Policy 오버라이드 가능 여부 확인",
         "<meta name=referrer content=unsafe-url> + <meta Refresh> 체인 검증",
         "Chrome 자동완성 악용 → GET 폼으로 비번 URL 노출 확인",
         "1-click 익스플로잇 PoC URL 자동 생성",
         "CSS full-page clickjack PoC 자동 생성 (style-src unsafe-inline 허용 시)",
     ]},
    {"id": "50", "name": "Web Cache Deception + SameSite Lax 우회", "en": "WebCacheDeception", "ko": "웹캐시기만_SameSite우회",
     "skills": [
         "캐시 응답 헤더 자동 탐지 (X-Cache, CF-Cache-Status, Age 등)",
         "Cache-Control: private 누락 여부 확인",
         "캐시된 응답에서 JWT/세션토큰/PII 등 민감 데이터 탐지",
         "MISS→HIT 두 번 요청으로 실제 캐싱 동작 확인",
         "SameSite=Lax 쿠키 + meta-refresh top-level navigation 우회 검증",
         "민감 경로 (/profile /settings /dashboard) 별도 캐시 검사",
         "SameSite Lax 우회 PoC HTML 자동 생성",
         "Cache buster(cb=UNIQUE)로 피해자 응답 캐싱 체인 시뮬레이션",
     ]},
    {"id": "51", "name": "Grafana→GCP토큰→비공개저장소 체인 (클라우드토큰정찰)", "en": "CloudTokenRecon", "ko": "클라우드토큰정찰",
     "skills": [
         "오픈 DevTool(Grafana/Prometheus/Kibana/Jenkins) 자동 탐지",
         "TLS 인증서 SAN 와일드카드 추출 → 숨겨진 섀도우 서브도메인 발굴",
         "JS 번들 전체 파싱 — 공식 문서에 없는 내부 도메인/API 경로 추출",
         "비인증 GCP/AWS/Azure 토큰 엔드포인트 자동 퍼징 (/_api/gcp-token 등)",
         "섀도우 도메인에서도 토큰 엔드포인트 자동 퍼징 (JS 피벗)",
         "토큰 타입 자동 식별 (GCP OAuth2 / AWS STS / GitHub PAT / JWT 등)",
         "클라우드 크리덴셜 체인 홉 수 계산 (token→SecretManager→Vercel→GitHub)",
         "AI 판단: DevTool + 클라우드 환경 = 체인 가능성 자동 경보",
     ]},
    {"id": "52", "name": "EXTRACTVALUE 에러 기반 + Second-Order SQLi 고급 익스플로잇", "en": "AdvancedSQLiExploit", "ko": "고급SQLi익스플로잇",
     "skills": [
         "EXTRACTVALUE(1,CONCAT(0x7e,subquery)) 에러 기반 데이터 추출 자동화",
         "CAST()/EXP() overflow 기반 MySQL 에러 익스플로잇 변형",
         "Time-based blind SQLi: SLEEP/pg_sleep/WAITFOR DELAY 멀티 DB 지원",
         "Second-order SQLi 비동기 컨텍스트 탐지 (이메일 알림/예약 작업/리포트 생성)",
         "Second-order 시간 간격 오라클: 예약 시간 vs 실제 실행 시간 측정",
         "OOB DNS 익스필트레이션: LOAD_FILE + DNS 서버로 데이터 반출",
         "한국 CMS(그누보드/영카트) board.php/item.php 파라미터 자동 퍼징",
         "AI 판단: SQLi 확인 환경 → EXTRACTVALUE 고급 모드 자동 전환",
     ]},
    {"id": "53", "name": "CVE-2026-31431 Copy Fail 커널 LPE + 컨테이너 탈출 탐지", "en": "CopyFailLPE", "ko": "CopyFail커널LPE탐지",
     "skills": [
         "HTTP 헤더에서 Linux 커널 버전 leak 탐지 (Server/X-Powered-By 헤더 파싱)",
         "/proc/version 직접 노출 여부 확인 (웹 서버 설정 오류)",
         "웹쉘 실행 시 uname -r / lsmod algif_aead / python3 버전 자동 점검",
         "algif_aead 커널 모듈 로드 확인 → 732바이트 Python PoC 실행 가능성 평가",
         "컨테이너/K8s 환경 감지 → 페이지 캐시 호스트 전역 공유 → 컨테이너 탈출 경로 평가",
         "취약 커널 범위 판정: Linux 4.9+ ~ 2026-04-01 패치 이전 (Ubuntu/RHEL/Amazon/SUSE 버전 매핑)",
         "온디스크 파일 무결성 검사 우회 특성 탐지 (페이지 캐시 수정, SHA256 기반 탐지 불가)",
         "AI 판단: 리눅스 서버 + post-RCE 컨텍스트 → 자동 활성화",
     ]},
    {"id": "54", "name": "Ruby 웹앱 Ruzzy+LibAFL C 확장 파서 퍼징 표면 탐지", "en": "RubyLibAFLFuzz", "ko": "Ruby퍼징표면탐지",
     "skills": [
         "Ruby 프레임워크 자동 감지: HTTP 헤더/쿠키/에러 바디 분석 (Rails/Sinatra/Puma/Unicorn/Passenger/Rack)",
         "C 확장 파서 엔드포인트 탐지: Nokogiri(XML), Oj(JSON), graphql-ruby(GraphQL), Psych(YAML), msgpack-ruby, google-protobuf",
         "GraphQL 엔드포인트 확인 → libgraphqlparser C 확장 → Ruzzy+LibAFL 최우선 퍼징 타겟",
         "파일 업로드 엔드포인트 발견 → RMagick/MiniMagick/ImageMagick C 확장 파이프라인 퍼징 표면 평가",
         "YAML unsafe load 위험 탐지: Psych.load / YAML.load 사용 패턴 → Ruby 객체 역직렬화 위험",
         "Gem/프레임워크 버전 정보 leak 탐지 (HTTP 헤더 / 에러 바디에서 버전 파싱)",
         "Ruzzy+LibAFL 하네스 코드 자동 생성: lld/.preinit_array 패치 적용 LibAFL 0.8.0 호환 harness template",
         "AI 판단: Ruby 헤더 감지 or 파일 업로드 바이너리 처리 or Ruby CMS URL 패턴 → 자동 활성화",
     ]},
    {"id": "55", "name": "AI 생성 코드 보안 표면 탐지 — 시크릿/의존성/비즈니스로직/아티팩트", "en": "AICodeSecSurface", "ko": "AI코드보안표면탐지",
     "skills": [
         "시크릿 노출 탐지: JS 번들/응답 바디에서 OpenAI·AWS·GCP·Stripe·GitHub 토큰·DB 연결문자열·Private Key 자동 추출 (VERIFIED PoC)",
         "AI 플레이스홀더 자격증명 탐지: admin/test/changeme 하드코딩 — AI 코딩 도구 출력물에서 흔한 미제거 패턴",
         "취약 의존성 버전 핑거프린팅: lodash/moment/axios/log4j/Spring/jQuery/Angular/Next.js 버전 → CVE 매핑",
         "AI 코딩 아티팩트 탐지: CORS *(와일드카드), 디버그 라우트, TODO 시크릿, Node.js 스택트레이스, 미인증 admin 엔드포인트",
         "설정/자격증명 파일 노출: .env/.git/config/credentials.json/service-account.json/actuator/env 등 30+ 경로 확인",
         "비즈니스 로직 표면: /api/price·/api/transfer·/api/balance·/api/admin 등 AI 스캐폴드 공통 패턴 15개",
         "Spring Actuator 완전 노출 탐지 (/actuator/env, /actuator/heapdump) → 환경변수·힙덤프 전체 탈취 가능",
         "AI 판단: 모든 웹 타겟에 기본 활성화 — 특히 JS 번들 감지 시, .env 응답 200 시 강화 스캔",
         "ProjectDiscovery 2026 조사 근거: 200명 실무자 중 78%가 AI 코딩으로 시크릿 노출 증가 보고",
         "Zero-Hallucination: 모든 발견 VERIFIED curl PoC 첨부 — 미확인 발견 INFERRED 레벨로 표시",
     ]},
    {"id": "56", "name": "CSPT+CloudflareWAF우회+다중ContentType퍼징 — SPA경로순회·XSS→ATO체인", "en": "CSPTWafBypass", "ko": "CSPT_WAF우회_ContentType퍼징",
     "skills": [
         "CSPT(Client-Side Path Traversal) 탐지: React/Angular/Vue/Next.js JS 번들에서 location.pathname·router.query가 API fetch에 직접 전달되는 패턴 자동 분석",
         "CSPT 엔드포인트 검증: SPA 라우트 기반 ../ 순회 테스트 — /app/user/profile/../../admin 등 21개 인코딩 변형 (VERIFIED PoC)",
         "Cloudflare WAF 우회: oncontentvisibilityautostatechange CSS Containment API 이벤트 핸들러로 Cloudflare 필터 우회 (2026년 4월 @YourFinalSin 발견)",
         "XSS→ATO 체인: CF WAF bypass XSS → OAuth authorization code 탈취 → 토큰 교환 → 완전 계정 탈취 체인 구성",
         "다중 Content-Type 퍼징: application/json·text/xml·application/x-www-form-urlencoded·multipart/form-data·graphql·yaml 등 14가지 Content-Type으로 API 엔드포인트 응답 차이 탐지",
         "XXE 연계: XML Content-Type 수락 엔드포인트 발견 시 XXE 페이로드 자동 생성",
         "OAuth 흐름 탐지: OAuth/SSO 엔드포인트 + Cloudflare WAF 조합 시 ATO 체인 자동 구성",
         "쿠키 주입 DOM XSS: document.cookie → innerHTML/eval 싱크 패턴 탐지 (@RenwaX23, Bug Bytes #235)",
         "Auxclick 클릭재킹: X-Frame-Options 우회하는 중간 마우스 버튼(onauxclick) 이벤트 핸들러 탐지",
         "AI 판단: SPA 프레임워크 감지 시 자동 활성화 / Cloudflare 헤더 감지 시 WAF 우회 페이로드 생성 / OAuth 엔드포인트 발견 시 ATO 체인 구성",
         "연구 근거: Intigriti Bug Bytes #235 (2026년 4월) — @xssdoctor CSPT, @YourFinalSin CF WAF bypass, @RenwaX23 cookie XSS, Auxclick clickjacking",
         "Zero-Hallucination: CSPT 200 응답 VERIFIED / CF 우회 LIKELY / 쿠키·Auxclick INFERRED — evidence_level 자동 설정",
     ]},
    {"id": "57", "name": "DOMPurify Prototype Pollution→XSS 우회 — CVE-2026-41238 CUSTOM_ELEMENT_HANDLING 폴백 상속", "en": "DOMPurifyPPBypass", "ko": "DOMPurify_PP_XSS우회",
     "skills": [
         "DOMPurify 버전 지문 추출: JS 번들(minified/bundled)/package.json/package-lock.json/CDN 경로에서 DOMPurify 버전 자동 감지",
         "취약 범위 판정: DOMPurify 3.0.1–3.3.3 = 취약 (CVE-2026-41238) / 3.4.0+ = 패치됨 / v2.x = 해당 없음 — VERIFIED 증거 수준",
         "Prototype Pollution 가젯 탐지: lodash<4.17.21·jQuery<3.4.0·qs<6.7.3·merge·deepmerge·extend·minimist·hoek 라이브러리 버전 지문 및 PP 취약 여부 분류",
         "CUSTOM_ELEMENT_HANDLING 폴백 분석: DOMPurify.sanitize() 기본 설정({}) 호출 패턴 탐지 — Object.prototype 상속으로 오염된 tagNameCheck/attributeNameCheck가 모든 커스텀 엘리먼트/이벤트 허용",
         "완전 공격 체인 평가: 취약 DOMPurify + PP 가젯 동시 존재 시 CRITICAL — 커스텀 엘리먼트(<x-foo onclick=alert(1)>) 기반 XSS 완전 무력화",
         "타입 보존 PP 벡터 탐지: postMessage + Object.assign/merge 패턴 → RegExp 객체 주입 가능 경로 식별 (string PP는 효과 없음 — 정밀 분류)",
         "package.json 노출 탐지: /package.json·/package-lock.json 공개 접근 가능 여부 확인 및 의존성 정보 추출",
         "브라우저 콘솔 PoC 생성: Object.prototype.tagNameCheck=/.*/; DOMPurify.sanitize('<x-foo onclick=alert(document.domain)>') — Burp 검증용 콘솔 코드 자동 생성",
         "수정 권고: DOMPurify 3.4.0 업그레이드 + lodash/jQuery/merge 패치 + DOMPurify.sanitize(html, {CUSTOM_ELEMENT_HANDLING:{tagNameCheck:/^(b|i|u)$/}}) 명시적 설정",
         "AI 판단: 모든 웹 대상에서 JS 번들 분석 자동 실행 — DOMPurify 라이브러리 감지 시 즉시 버전 취약성 평가, XSS 싱크 근처에서 사용 시 우선순위 상향",
         "연구 근거: trace37 labs (CVE-2026-41238, 2026-04-23) — GHSA-v9jr-rg53-9pgp, CWE-79+CWE-1321",
         "Zero-Hallucination: 버전 JS에서 직접 확인 VERIFIED / PP+DP 조합 LIKELY / postMessage 패턴만 INFERRED — evidence_level 자동 설정",
     ]},
    {"id": "58", "name": "Cloudflare ACME WAF 우회 — ACME 챌린지 경로 Fail-Open 로직 버그 오리진 직접 접근", "en": "CloudflareACMEBypass", "ko": "CF_ACME_WAF우회",
     "skills": [
         "Cloudflare 감지: CF-Ray / server:cloudflare / CF-Cache-Status 헤더 지문으로 Cloudflare 엣지 확인",
         "제어 테스트: 일반 경로에서 WAF 차단(403) 확인 → ACME 경로 비교 기준 확립 — VERIFIED 증거 수준",
         "ACME 경로 WAF 우회 테스트: /.well-known/acme-challenge/{fake_token} 요청 → CF-Ray 부재 + 오리진 직접 응답 확인",
         "오리진 서버 지문 수집: ACME 경로에서 server 헤더 / Server-Timing 등 오리진 고유 정보 추출",
         "헤더 기반 공격 벡터 테스트: X-Forwarded-For(SSRF) / X-Original-URL(인증우회) / X-HTTP-Method-Override / X-Debug-Mode / X-Forwarded-Host(캐시포이즈닝) WAF 우회 시 오리진 도달 확인",
         "LFI 테스트 (PHP 타겟): ACME 경로 접두어로 /../../../etc/passwd 등 파일 시스템 접근 시도 — 오리진 직접 도달 시 실제 LFI 확인",
         "Spring Actuator 노출 확인: ACME 우회 경로로 /actuator/env · /actuator/health · /actuator/beans 접근 → 환경변수/빈 정보 유출 탐지",
         "수정 검증: 패치 적용 여부 확인 (2025년 10월 27일 이후) — CF-Ray 헤더가 ACME 경로에도 존재 시 정상 패치 VERIFIED",
         "수정 권고: Cloudflare IP 범위(cloudflare.com/ips/)만 오리진 허용 + Authenticated Origin Pulls(mTLS) 활성화 + /.well-known/ 경로 WAF 적용 확인",
         "AI 판단: CF 엣지 감지 + WAF 차단 응답 확인 시 자동 활성화 — ACME 우회 가능성 판단 후 LFI·헤더 공격 자동 체인",
         "연구 근거: FearsOff Security (Kirill Firsov, 2025-10-09) — Cloudflare HackerOne Bug Bounty, 2026년 1월 공개",
        "Zero-Hallucination: 오리진 직접 도달 VERIFIED / WAF 우회+헤더 공격 LIKELY / Spring Actuator INFERRED — evidence_level 자동 설정",
    ]},
   {"id": "59", "name": "React2Shell WAF 우회 — 멀티파트 파서 차이로 Vercel WAF 우회 CVE-2025-55182 RCE 공격 표면", "en": "React2ShellWafBypass", "ko": "React2Shell_WAF우회",
    "skills": [
        "React/Next.js 탐지: x-powered-by:Next.js / x-nextjs-* 헤더 / _next/static 자산 / Vercel 배포 헤더 지문 — VERIFIED 증거",
        "React Server Functions 엔드포인트 탐지: Next-Action 헤더를 수락하는 경로 탐색 — CVE-2025-55182 공격 표면 확인",
        "WAF 감지: :constructor 포함 페이로드에 HTTP 403 응답 확인 — 보호 장치 존재 판단",
        "BP1(중복 boundary): Content-Type에 boundary 파라미터 2개 삽입 — WAF는 마지막 boundary 사용(본문 미검사), busboy는 첫 번째로 파싱",
        "BP2(비UTF-8 헤더 바이트): 헤더에 0x88 등 비UTF-8 바이트 삽입 → WAF 파서 오류 → Fail-Open(모든 트래픽 통과)",
        "BP3(UTF-16LE 인코딩): 멀티파트 필드 Content-Type에 charset=utf16le 설정 → WAF: 원시 바이트 스캔(탐지 불가) → busboy: UTF-16 디코딩(:constructor 출현)",
        "BP4(중복 필드 Content-Type): utf16le/utf8 Content-Type 헤더 2개 삽입 → WAF는 마지막(utf8 스캔), busboy는 첫 번째(utf16le 디코딩) 사용",
        "BP5(boundary 종료자 후행 공백): --boundary-- SPACE 삽입 → WAF: 폼 종료로 인식 → busboy: 유효하지 않은 종료자 무시, 이후 부분 정상 파싱",
        "PoC 요청 자동 생성: Burp Suite 검증용 BP1-BP5 완전한 curl 명령어 생성 — 실제 RCE 페이로드 없음(안전한 탐침)",
        "AI 자동 판단: Next.js 감지 + Next-Action 수락 확인 시 자동 활성화 — 5개 우회 기법 순차 테스트",
        "연구 근거: Hacktron AI (ginoah/Mohan, 2026-05-04) — $170,000 Vercel React2Shell Challenge, 5개 우회 × $50,000",
        "Zero-Hallucination: React 탐지 VERIFIED / Next-Action 엔드포인트 VERIFIED / WAF 우회 성공 VERIFIED / 불확실 INFERRED — evidence_level 자동 설정",
    ]},
   {"id": "60", "name": "Apache Druid SSRF — CVE-2025-27888 프록시 URL 파싱 혼동으로 내부망/클라우드 메타데이터 접근", "en": "ApacheDruidSSRF", "ko": "Apache_Druid_SSRF",
    "skills": [
        "Apache Druid 관리 콘솔 탐지: /unified-console.html / /druid/coordinator/v1/isLeader / x-druid-* 헤더 / 포트 8888 서비스 지문 — VERIFIED 증거",
        "버전 감지: HTML/헤더에서 druid-버전 정규식 추출 → 취약 버전 판단 (< 31.0.2 또는 < 32.0.1)",
        "프록시 엔드포인트 탐지: /proxy / /druid/proxy / /druid/coordinator/v1/proxy — 무효 URL 탐침으로 오류 메시지 확인",
        "SSRF 확인 — 클라우드 메타데이터: AWS IMDSv1 169.254.169.254/latest/meta-data/iam/security-credentials 접근 시도",
        "SSRF 확인 — GCP/Azure 메타데이터: metadata.google.internal / 169.254.169.254/metadata/instance 접근 시도",
        "내부 서비스 스캔: 127.0.0.1:80/8080 등 localhost 포트 접근 → 내부망 서비스 노출 확인",
        "Druid 클러스터 노드 노출: coordinator:8081/broker:8082/overlord:8090/historical:8083 내부 API SSRF 접근",
        "AI 자동 판단: /druid/ 경로 감지 또는 포트 8888 Druid 서비스 식별 시 자동 활성화 — 클라우드 배포 타겟 우선 테스트",
        "연구 근거: XBOW Security (Nico Waisman, 2025-09-23) — AI 기반 제로데이 발견, /proxy 엔드포인트 AI 추론으로 식별",
        "Zero-Hallucination: Druid 탐지 VERIFIED / 프록시 발견 VERIFIED / SSRF 확인 VERIFIED / 서비스 추론 LIKELY — evidence_level 자동 설정",
        "PoC 자동 생성: curl 명령어 — 클라우드 메타데이터 탈취 / 내부 Druid 노드 열거 / IMDSv1 IAM 자격증명 추출",
        "CVSS: 9.8(클라우드 메타데이터) / 9.1(SSRF 확인) / 7.5(프록시 발견) — 영향도별 등급화",
    ]},
   {"id": "61", "name": "PAN-OS 인증 우회 — CVE-2025-0108 Nginx/Apache 경로 혼동 이중 디코딩 트래버설로 관리 인터페이스 무인증 접근", "en": "PanOSAuthBypass", "ko": "PanOS_인증우회",
    "skills": [
        "PAN-OS 관리 인터페이스 탐지: /php/login.php / GlobalProtect / x-pan-* 헤더 / 포트 443/4443 지문 — VERIFIED 증거",
        "버전 추출: HTML 본문에서 PAN-OS 버전 정규식 탐지 → 취약 버전 판단 (< 10.2.14 / < 11.0.7 / < 11.2.5)",
        "이중 디코딩 우회 페이로드: /unauth/%252e%252e/php/<target>.php/PAN_help/x.css — Nginx: /unauth/ 인증 off, Apache: 내부 리다이렉트 시 2차 디코딩 → ./../ 트래버설",
        "PHP 실행 확인: HTTP 200 + PHP 응답 본문(비-로그인 페이지) → 인증 우회 VERIFIED",
        "다중 PHP 타깃 테스트: ztp_gate.php / login.php / errors.php / php_session.php — 첫 번째 성공 엔드포인트 기록",
        "RCE 체인 평가: CVE-2025-0108(인증 우회) + CVE-2024-9474(권한 상승) 체인으로 root RCE 가능성 — LIKELY",
        "AI 자동 판단: 포트 443/4443 PAN-OS 응답 감지 시 자동 활성화 — 인터넷 노출 방화벽 우선 테스트",
        "연구 근거: Assetnote/Searchlight Cyber (Adam Kues, 2025-02-12) — CVE-2024-0012 패치 리뷰 중 제로데이 발견",
        "Zero-Hallucination: PAN-OS 탐지 VERIFIED / 버전 취약 판단 VERIFIED / 우회 확인 VERIFIED / RCE 체인 LIKELY",
        "CVSS: 9.9(RCE 체인) / 9.3(인증 우회) / 7.5(취약 버전) — 영향도별 등급화",
    ]},
   {"id": "62", "name": "IngressNightmare — CVE-2025-1974 Kubernetes ingress-nginx 무인증 어드미션 컨트롤러 어노테이션 인젝션 + ssl_engine RCE", "en": "IngressNightmareRCE", "ko": "IngressNightmare_RCE",
    "skills": [
        "Kubernetes API 서버 탐지: /api/v1 / /apis / /version — gitVersion 추출 / K8s 클러스터 공격 표면 확인 — VERIFIED 증거",
        "Ingress NGINX 지문: server 헤더 / ingress-nginx 버전 / 메트릭 엔드포인트 → 취약 버전 판단 (< 1.11.5 또는 < 1.12.1)",
        "어드미션 컨트롤러 노출 탐지: 포트 8443/443에 AdmissionReview 프로브 전송 → 무인증 응답 확인 — VERIFIED",
        "무인증 AdmissionReview 접근 확인: 인증 없이 AdmissionReview 요청 처리 여부 → 클러스터 내 어느 파드에서나 공격 가능",
        "어노테이션 인젝션 표면 매핑: CVE-2025-24514(auth-url) / CVE-2025-1097(auth-tls-match-cn) / CVE-2025-1098(mirror UID) 접근 가능 여부",
        "RCE 체인 평가: 클라이언트 바디 버퍼 .so 업로드 → ProcFS FD 접근 → ssl_engine 인젝션 → nginx -t RCE — LIKELY",
        "클러스터 Secret 탈취 가능성: ingress-nginx ServiceAccount ClusterRole → 전체 네임스페이스 Secret 접근",
        "SSRF 연계: 외부 SSRF 취약점 → 내부 클러스터 파드 네트워크 → 어드미션 컨트롤러 직접 접근",
        "AI 자동 판단: K8s 포트(6443/8443) 감지 또는 SSRF로 내부 클러스터 접근 가능 시 자동 활성화",
        "연구 근거: Wiz Research (Nir Ohfeld 외 3명, 2025-03-24) — 클라우드 환경 43% 취약, Fortune 500 포함 6,500+ 클러스터 노출",
        "Zero-Hallucination: K8s 탐지 VERIFIED / 어드미션 노출 VERIFIED / 버전 취약 VERIFIED / RCE 체인 LIKELY",
        "CVSS: 9.8(어드미션 무인증) / 8.8(어노테이션 인젝션) / 9.8(RCE + 클러스터 탈취) — CVE-2025-1974",
    ]},
   {"id": "46", "name": "CSWSH+EXE노출+로컬WebSocket RCE체인", "en": "CswshRceChain", "ko": "CSWSH_RCE체인탐지",
     "skills": [
         "JS 파일에서 EXE 다운로드 함수 자동 추출",
         "EXE 파일 미인증 다운로드 경로 퍼징",
         "JS에서 localhost WebSocket 서버 패턴 탐지 (ws://127.0.0.1:PORT)",
         "CSWSH — Origin 헤더 검증 없음 탐지",
         "WebSocket 메서드 열거 (GET/VERSION, RUN/DRIVE 등)",
         "RCE 가젯 탐지 — explorer.exe 폴백 패턴",
         "제로클릭 CSWSH→RCE PoC HTML 자동 생성",
     ]},
    {"id": "45", "name": "OAuth链式攻击检测 (开放注册+邮件信任)", "en": "OAuthChainAttack", "ko": "OAuth체인공격탐지",
     "skills": [
         "OAuth 서버 메타데이터 자동 발견 (/.well-known/oauth-authorization-server)",
         "인증 없는 클라이언트 등록 탐지 (Open Registration)",
         "미인증 Authorization 엔드포인트 접근 테스트",
         "CORS wildcard 탐지 (OAuth 응답 크로스오리진 노출)",
         "이메일 미검증 계정 생성 탐지 (Pattern B)",
         "OAuth Provider 동작 여부 확인",
         "이메일 신뢰 체인 완성 — 수백만 계정 탈취 가능성 검증",
         "체인 스코어 계산 (A: 0~5, B: 0~3) + curl PoC 자동 생성",
     ]},
]


@dataclass
class Skill:
    module_id: str
    module_name: str
    skill_name: str
    content: str = ""

    def to_prompt(self) -> str:
        return (
            f"[Skill {self.module_id}: {self.module_name}]\n"
            f"Skill: {self.skill_name}\n"
            f"{self.content}"
        )


class SkillEngine:
    """CyberSecurity-Skills + Cursor Skills 통합 엔진"""

    def __init__(self):
        self._local: bool = SKILLS_DIR.exists() and any(SKILLS_DIR.iterdir())

    # ── 설치 ───────────────────────────────────────────────────
    def install(self, on_progress=None) -> bool:
        """git clone으로 39개 모듈 설치"""
        log = on_progress or print
        if not shutil.which("git"):
            log("git not found — using built-in metadata only")
            return False

        SKILLS_DIR.parent.mkdir(parents=True, exist_ok=True)
        log(f"Cloning CyberSecurity-Skills → {SKILLS_DIR}")
        try:
            subprocess.run(
                ["git", "clone", "--depth=1", SKILLS_REPO, str(SKILLS_DIR)],
                check=True, capture_output=True, timeout=120,
            )
            self._local = True
            log("Skills installed!")
            return True
        except Exception as e:
            log(f"Clone failed: {e} — using built-in metadata")
            return False

    def update(self) -> bool:
        if not self._local:
            return self.install()
        try:
            subprocess.run(["git", "-C", str(SKILLS_DIR), "pull"],
                           check=True, capture_output=True, timeout=60)
            return True
        except Exception:
            return False

    # ── 검색 ───────────────────────────────────────────────────
    def search(self, keyword: str) -> list[dict]:
        """키워드로 스킬 검색 — 내장 DB 전체 195개 대상"""
        results = []
        kw = keyword.lower()

        # 내장 DB에서 검색
        for skill_id, skill in ALL_SKILLS.items():
            score = 0
            if kw in skill["name"].lower():
                score += 3
            if any(kw in t for t in skill.get("tags", [])):
                score += 2
            if kw in skill.get("desc", "").lower():
                score += 1
            if kw in " ".join(skill.get("commands", [])).lower():
                score += 1
            if kw in " ".join(skill.get("payloads", [])).lower():
                score += 2

            if score > 0:
                results.append({
                    "id": skill_id,
                    "module": skill["module"],
                    "skill": skill["name"],
                    "tags": skill.get("tags", []),
                    "score": score,
                })

        # 점수 순 정렬
        results.sort(key=lambda x: -x["score"])
        return results

    def get_skill(self, skill_id: str) -> dict | None:
        """스킬 ID로 전체 내용 반환 (내장 DB 우선, 로컬 마크다운 보조)"""
        skill = ALL_SKILLS.get(skill_id)
        if not skill:
            return None

        # 로컬 git clone이 있으면 full 마크다운 추가
        if self._local:
            md_content = self._load_skill_content_by_id(skill_id)
            if md_content:
                skill = dict(skill)
                skill["full_content"] = md_content

        return skill

    def get_skill_prompt(self, skill_id: str) -> str:
        """AI 프롬프트 삽입용 스킬 컨텍스트"""
        skill = self.get_skill(skill_id)
        if not skill:
            return ""

        parts = [
            f"## Skill: {skill['name']} [{skill_id}]",
            f"**Description:** {skill.get('desc', '')}",
            f"**Tags:** {', '.join(skill.get('tags', []))}",
        ]
        if skill.get("tools"):
            parts.append(f"**Tools:** {', '.join(skill['tools'])}")
        if skill.get("commands"):
            parts.append("**Key Commands:**")
            for cmd in skill["commands"][:5]:
                parts.append(f"  ```\n  {cmd}\n  ```")
        if skill.get("payloads"):
            parts.append("**Key Payloads:**")
            for pl in skill["payloads"][:5]:
                parts.append(f"  - `{pl}`")
        if skill.get("notes"):
            parts.append(f"**Notes:** {skill['notes']}")
        if skill.get("full_content"):
            parts.append(f"\n**Full Reference:**\n{skill['full_content'][:2000]}")

        return "\n".join(parts)

    def get_module(self, module_id: str) -> list[Skill]:
        """모듈 ID로 스킬 목록 반환"""
        # 내장 DB에서 해당 모듈 스킬 찾기
        skills = []
        for skill_id, skill in ALL_SKILLS.items():
            if skill_id.startswith(module_id + "-") or \
               skill.get("module", "").lower() == module_id.lower():
                content = self.get_skill_prompt(skill_id)
                skills.append(Skill(
                    module_id=module_id,
                    module_name=skill.get("module", ""),
                    skill_name=skill["name"],
                    content=content,
                ))
        return skills

    def get_phase_prompt(self, phase: str) -> str:
        """Red Team 단계에 해당하는 스킬 프롬프트 생성 — 내장 DB 기반"""
        PHASE_MAP = {
            "recon":   ["01"],
            "scan":    ["02"],
            "exploit": ["03"],
            "privesc": ["04"],
            "post":    ["05"],
            "lateral": ["06"],
            "persist": ["07"],
            "cover":   ["08"],
            "report":  ["09"],
        }
        ids = PHASE_MAP.get(phase, [])
        parts = []

        for mid in ids:
            phase_skills = {
                k: v for k, v in ALL_SKILLS.items()
                if k.startswith(f"{mid}-")
            }
            if not phase_skills:
                continue

            skill_lines = []
            for skill_id, skill in phase_skills.items():
                tools_str = ", ".join(skill.get("tools", [])[:3])
                cmd_preview = skill.get("commands", [""])[0][:60] if skill.get("commands") else ""
                skill_lines.append(
                    f"  • {skill['name']}\n"
                    f"    Tools: {tools_str}\n"
                    f"    {skill.get('desc', '')[:100]}"
                    + (f"\n    Example: `{cmd_preview}`" if cmd_preview else "")
                )

            mod_name = list(phase_skills.values())[0].get("module", "")
            parts.append(
                f"## Phase {mid}: {mod_name}\n" +
                "\n".join(skill_lines)
            )

        return "\n\n".join(parts)

    def list_all(self) -> list[dict]:
        """39개 모듈 목록 반환 (내장 DB 기반)"""
        return BUILTIN_MODULES

    def stats(self) -> dict:
        """내장 스킬 통계"""
        from ..tools.secknowledge_loader import is_available as _secknow_ok, references_status as _secknow_status
        return {
            "total_skills": len(ALL_SKILLS),
            "cybersecurity_skills": len(SKILLS_DB) + len(SKILLS_DB_2),
            "secskills_local": len(SKILLS_DB_3),
            "secknowledge_skills": len(SKILLS_DB_7),
            "secknowledge_refs_available": _secknow_ok(),
            "secknowledge_status": _secknow_status(),
            "total_modules": len(ALL_MODULE_INDEX),
            "total_tags": len(ALL_TAG_INDEX),
            "local_clone": self._local,
        }

    # ── 내부 헬퍼 ─────────────────────────────────────────────
    def _skill_path(self, module_id: str, skill_name: str) -> str:
        if not self._local:
            return "(built-in only — run `bingo skill install` to download full content)"
        for mod in BUILTIN_MODULES:
            if mod["id"] == module_id:
                folder = f"{module_id}-{mod['name']}-{mod['en']}"
                return str(SKILLS_DIR / folder)
        return ""

    def _load_skill_content(self, module_id: str, skill_name: str) -> str:
        if not self._local:
            return ""
        for mod in BUILTIN_MODULES:
            if mod["id"] == module_id:
                folder = SKILLS_DIR / f"{module_id}-{mod['name']}-{mod['en']}"
                if folder.exists():
                    for f in folder.glob("*.md"):
                        if skill_name[:6].lower() in f.name.lower():
                            try:
                                return f.read_text(encoding="utf-8")[:3000]
                            except Exception:
                                pass
        return ""

    def _load_skill_content_by_id(self, skill_id: str) -> str:
        """스킬 ID(예: 01-002)로 로컬 마크다운 파일 검색"""
        if not self._local:
            return ""
        module_id = skill_id.split("-")[0]
        skill = ALL_SKILLS.get(skill_id)
        if not skill:
            return ""
        for mod in BUILTIN_MODULES:
            if mod["id"] == module_id:
                folder = SKILLS_DIR / f"{module_id}-{mod['name']}-{mod['en']}"
                if folder.exists():
                    for f in folder.glob("*.md"):
                        try:
                            return f.read_text(encoding="utf-8")[:3000]
                        except Exception:
                            pass
        return ""

    # ═══════════════════════════════════════════════════════════
    # LocalSkills — SecSkills-main / advsec-plus 등 로컬 스킬
    # ═══════════════════════════════════════════════════════════
    # 패키지 내부 local_skills 디렉토리 경로
    _LOCAL_SKILLS_BASE: Path = Path(__file__).parent / "local_skills"

    # keyword → (skill_dir, reference_file) 라우팅 테이블
    _LOCAL_SKILL_ROUTES: list[tuple[list[str], str, str | None]] = [
        # (keywords, skill_dir_name, reference_file or None)
        (["sqli", "sql", "sqlmap", "injection"], "SecSkills-main", "tools-sqlmap.md"),
        (["sqli", "sql injection", "blind", "union", "payload"], "SecSkills-main", "web-sqli.md"),
        (["waf", "bypass", "tamper", "firewall"], "SecSkills-main", "web-waf-bypass.md"),
        (["nmap", "port scan", "portscan", "network scan"], "SecSkills-main", "info-port-scan.md"),
        (["subdomain", "dns", "sublist3r", "subfinder"], "SecSkills-main", "info-subdomain.md"),
        (["fingerprint", "whatweb", "tech stack", "wappalyzer"], "SecSkills-main", "info-fingerprint.md"),
        (["osint", "shodan", "fofa", "google dork"], "SecSkills-main", "info-osint.md"),
        (["dir", "gobuster", "ffuf", "dirsearch", "directory brute"], "SecSkills-main", "info-dir-brute.md"),
        (["xss", "cross-site", "script inject"], "SecSkills-main", "web-xss.md"),
        (["rce", "command injection", "code execution", "reverse shell"], "SecSkills-main", "web-rce.md"),
        (["ssrf", "server-side request"], "SecSkills-main", "web-ssrf.md"),
        (["upload", "file upload", "webshell", "shell upload"], "SecSkills-main", "web-upload.md"),
        (["lfi", "path traversal", "directory traversal", "local file"], "SecSkills-main", "web-lfi-path.md"),
        (["xxe", "xml external", "xml injection"], "SecSkills-main", "web-xxe.md"),
        (["ssti", "template injection", "jinja", "twig"], "SecSkills-main", "web-ssti.md"),
        (["deserialization", "java deser", "pickle", "ysoserial"], "SecSkills-main", "web-deser.md"),
        (["auth bypass", "login bypass", "authn", "authz", "403 bypass"], "SecSkills-main", "web-auth-logic.md"),
        (["cors", "origin", "access-control"], "SecSkills-main", "web-cors.md"),
        (["race condition", "race", "concurrency"], "SecSkills-main", "web-race-condition.md"),
        (["brute force", "bruteforce", "hydra", "password spray"], "SecSkills-main", "host-brute.md"),
        (["hydra"], "SecSkills-main", "tools-hydra.md"),
        (["metasploit", "msf", "msfvenom"], "SecSkills-main", "tools-msf.md"),
        (["impacket", "smb", "pass-the-hash", "kerberos"], "SecSkills-main", "tools-impacket.md"),
        (["fuzz", "burp intruder", "fuzzing payloads"], "SecSkills-main", "tools-fuzz.md"),
        (["shellcode", "evasion", "antivirus", "av bypass", "amsi"], "SecSkills-main", "evasion-shellcode.md"),
        (["linux privesc", "linux privilege", "sudo", "suid"], "SecSkills-main", "post-linux-privesc.md"),
        (["windows privesc", "windows privilege", "uac bypass"], "SecSkills-main", "post-win-privesc.md"),
        (["active directory", "ad", "domain controller", "bloodhound"], "SecSkills-main", "post-ad.md"),
        (["credentials", "mimikatz", "lsass", "credential dump"], "SecSkills-main", "post-credentials.md"),
        # advsec-plus 라우팅
        (["jwt", "json web token", "oauth", "oidc"], "advsec-plus", "api-security.md"),
        (["graphql", "websocket", "grpc", "api fuzz"], "advsec-plus", "api-security.md"),
        (["android", "apk", "ios", "frida", "objection", "mobile"], "advsec-plus", "mobile-security.md"),
        (["cloud", "aws", "azure", "gcp", "s3", "bucket", "metadata"], "advsec-plus", "cloud-security.md"),
        (["kubernetes", "k8s", "docker escape", "container escape"], "advsec-plus", "cloud-security.md"),
        (["git leak", "dependency confusion", "ci cd", "supply chain"], "advsec-plus", "supply-chain-devsec.md"),
        (["prototype pollution", "2fa bypass", "cache deception"], "advsec-plus", "web-advanced.md"),
        (["edr", "syscall", "direct syscall", "hell gate", "etw"], "advsec-plus", "evasion-advanced.md"),
        # api-unauth-fuzz 라우팅 (전체 스킬)
        (["unauth", "unauthorized", "api fuzz", "js extract", "tech stack detect"], "api-unauth-fuzz", None),
        # secknowledge 라우팅 (런타임 reference 로더)
        (["secknowledge", "wooYun", "gaarm", "l1-l4", "l1 l4", "method", "methodology"], "secknowledge", None),
    ]

    def local_skill_context(self, keyword: str, max_chars: int = 4000) -> str:
        """키워드에 맞는 로컬 스킬 레퍼런스를 AI 프롬프트용으로 반환.

        Returns empty string if no match found.
        """
        kw = keyword.lower()
        matched: list[tuple[str, str | None]] = []

        for keywords, skill_dir, ref_file in self._LOCAL_SKILL_ROUTES:
            if any(k in kw for k in keywords):
                matched.append((skill_dir, ref_file))

        if not matched:
            return ""

        parts: list[str] = []
        seen: set[str] = set()

        for skill_dir, ref_file in matched:
            cache_key = f"{skill_dir}/{ref_file}"
            if cache_key in seen:
                continue
            seen.add(cache_key)

            base = self._LOCAL_SKILLS_BASE / skill_dir

            if ref_file:
                ref_path = base / "references" / ref_file
                if ref_path.exists():
                    content = ref_path.read_text(encoding="utf-8")
                    parts.append(
                        f"=== [引用:references/{ref_file}] ===\n{content[:max_chars]}"
                    )
            else:
                skill_md = base / "SKILL.md"
                if skill_md.exists():
                    content = skill_md.read_text(encoding="utf-8")
                    parts.append(
                        f"=== [Skill:{skill_dir}] ===\n{content[:max_chars]}"
                    )

            if len("\n\n".join(parts)) > max_chars * 2:
                break

        return "\n\n".join(parts)

    def local_skill_search(self, keyword: str) -> list[dict]:
        """로컬 스킬에서 키워드 검색 — 매칭된 스킬 이름과 파일 목록 반환"""
        kw = keyword.lower()
        results = []
        seen: set[str] = set()

        for keywords, skill_dir, ref_file in self._LOCAL_SKILL_ROUTES:
            if any(k in kw for k in keywords):
                key = f"{skill_dir}/{ref_file}"
                if key in seen:
                    continue
                seen.add(key)
                results.append({
                    "skill_dir": skill_dir,
                    "reference": ref_file,
                    "matched_keywords": [k for k in keywords if k in kw],
                    "path": str(self._LOCAL_SKILLS_BASE / skill_dir / "references" / ref_file)
                    if ref_file else str(self._LOCAL_SKILLS_BASE / skill_dir / "SKILL.md"),
                })
        return results

    def list_local_skills(self) -> list[dict]:
        """로컬 스킬 디렉토리 목록"""
        if not self._LOCAL_SKILLS_BASE.exists():
            return []
        result = []
        for d in sorted(self._LOCAL_SKILLS_BASE.iterdir()):
            if d.is_dir():
                skill_md = d / "SKILL.md"
                refs = list((d / "references").glob("*.md")) if (d / "references").exists() else []
                result.append({
                    "name": d.name,
                    "has_skill_md": skill_md.exists(),
                    "references": [r.name for r in sorted(refs)],
                    "ref_count": len(refs),
                })
        return result
