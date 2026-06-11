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

# 통합 (CyberSecurity-Skills 195개 + SecSkills 로컬 스킬 추가)
ALL_SKILLS: dict[str, dict] = {**SKILLS_DB, **SKILLS_DB_2, **SKILLS_DB_3}
ALL_MODULE_INDEX: dict[str, list[str]] = {}
ALL_TAG_INDEX: dict[str, list[str]] = {}

for _src_idx in [MODULE_INDEX, MODULE_INDEX_2, MODULE_INDEX_3]:
    for k, v in _src_idx.items():
        if k not in ALL_MODULE_INDEX:
            ALL_MODULE_INDEX[k] = []
        ALL_MODULE_INDEX[k].extend(v)

for _src_idx in [TAG_INDEX, TAG_INDEX_2, TAG_INDEX_3]:
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
BUILTIN_MODULES: list[dict] = [
    {"id": "01", "name": "信息搜集", "en": "Reconnaissance",
     "skills": ["OSINT/피동정보수집", "DNS열거", "서브도메인탐색", "기술스택핑거프린팅", "네트워크공간검색", "능동정보수집", "소셜엔지니어링정보"]},
    {"id": "02", "name": "漏洞扫描", "en": "VulnerabilityScanning",
     "skills": ["Web취약점스캔", "네트워크취약점스캔", "DB보안평가", "설정감사스캔", "취약점스캐너자동화", "AI에이전트취약점스캔"]},
    {"id": "03", "name": "漏洞利用", "en": "Exploitation",
     "skills": ["Web취약점이용", "SQL인젝션", "XSS", "파일포함/업로드", "명령어인젝션", "SSRF", "인증우회", "Metasploit", "AI에이전트이용"]},
    {"id": "04", "name": "权限提升", "en": "PrivilegeEscalation",
     "skills": ["Linux권한상승", "Windows권한상승", "커널/서비스오설정", "자격증명탈취"]},
    {"id": "05", "name": "后渗透", "en": "PostExploitation",
     "skills": ["정보수집/데이터탈취", "자격증명덤프/해시전달", "원격제어/인터랙티브셸", "키로거/화면캡처"]},
    {"id": "06", "name": "横向移动", "en": "LateralMovement",
     "skills": ["횡적이동", "내부프록시/터널", "PsExec/WMI원격실행"]},
    {"id": "07", "name": "持久化", "en": "Persistence",
     "skills": ["장기통제", "부트/로그인자동실행", "계정생성/자격증명지속", "Office지속화", "Bootkit/펌웨어지속화"]},
    {"id": "08", "name": "痕迹清除", "en": "CoveringTracks",
     "skills": ["흔적제거/포렌식대응", "프로세스인젝션/코드인젝션", "코드난독화/분석방해", "AMSI우회/EDR회피"]},
    {"id": "09", "name": "报告撰写", "en": "Reporting",
     "skills": ["모의침투보고서작성", "취약점등급/CVSS", "Markdown보고서템플릿", "HTML보고서템플릿", "Word/PDF보고서템플릿"]},
    {"id": "10", "name": "移动安全", "en": "MobileSecurity",
     "skills": ["Android보안테스트", "iOS보안테스트"]},
    {"id": "11", "name": "无线安全", "en": "WirelessSecurity",
     "skills": ["Wi-Fi보안감사"]},
    {"id": "12", "name": "代码审计", "en": "CodeAudit",
     "skills": ["PHP코드감사", "Java코드감사", "JS/Node.js코드감사", "Python코드감사", "C코드감사", "C++코드감사", "Rust코드감사", "Go코드감사", "AI에이전트코드감사"]},
    {"id": "13", "name": "逆向工程", "en": "ReverseEngineering",
     "skills": ["정적역방향분석", "동적디버그분석", "악성코드분석"]},
    {"id": "14", "name": "安全审计", "en": "SecurityAudit",
     "skills": ["등급보호합규감사", "설정보안감사", "보안아키텍처감사", "클라우드보안감사", "컨테이너보안감사", "네트워크합규평가", "AI에이전트보안감사"]},
    {"id": "15", "name": "应急响应", "en": "IncidentResponse",
     "skills": ["사건분류/우선순위평가", "로그수집분석", "네트워크트래픽분석", "사건봉쇄/제거", "클라우드환경응급대응", "사건복기/보고서", "AI보안응급대응"]},
    {"id": "16", "name": "大模型安全", "en": "LLMSecurity",
     "skills": ["프롬프트인젝션방어", "LLM데이터유출방지", "AI공급망보안", "대형모델레드팀테스트", "AI에이전트권한제어", "모델적대공격방어", "모델출력안전/환각검출", "AI앱보안설정감사", "연합학습보안", "멀티모달AI보안"]},
    {"id": "17", "name": "云安全", "en": "CloudSecurity",
     "skills": ["AWS보안평가", "Azure보안평가", "GCP보안평가", "클라우드IAM감사", "클라우드스토리지보안", "클라우드네트워크/WAF", "서버리스보안", "멀티클라우드보안"]},
    {"id": "18", "name": "安全开发运维", "en": "DevSecOps",
     "skills": ["CI/CD파이프라인보안감사", "IaC보안스캔", "SAST정적테스트", "DAST동적테스트", "소프트웨어공급망보안", "보안요구사항/위협모델링"]},
    {"id": "19", "name": "工控安全", "en": "ICS-OT-Security",
     "skills": ["SCADA보안평가", "PLC/RTU보안테스트", "공업네트워크프로토콜보안", "IEC62443합규감사", "공업보안응급계획", "산업방화벽/네트워크분할"]},
    {"id": "20", "name": "区块链安全", "en": "Blockchain-Web3-Security",
     "skills": ["스마트컨트랙트감사", "DeFi프로토콜평가", "합의메커니즘분석", "Web3프론트엔드/월렛보안", "블록체인노드강화", "MEV/크로스체인브릿지보안"]},
    {"id": "21", "name": "物联网安全", "en": "IoT-Security",
     "skills": ["펌웨어역방향분석", "BLE/Zigbee/Z-Wave보안테스트", "IoT통신프로토콜보안", "임베디드장치하드웨어보안테스트", "IoT플랫폼/클라우드보안", "스마트홈/커넥티드카보안"]},
    {"id": "22", "name": "数据安全", "en": "DataSecurityPrivacy",
     "skills": ["DLP데이터유출방지", "데이터분류/등급보호", "DB보안/암호화", "데이터마스킹/익명화", "GDPR/개인정보보호법합규", "개인정보영향평가PIA"]},
    {"id": "23", "name": "社会工程学", "en": "SocialEngineering",
     "skills": ["피싱이메일시뮬레이션", "보이스피싱/Vishing테스트", "물리침투/소셜엔지니어링", "피싱인프라구축", "직원보안의식평가"]},
    {"id": "24", "name": "红蓝对抗", "en": "RedBlueTeam",
     "skills": ["레드팀평가방법론", "블루팀방어/탐지", "퍼플팀협업평가", "BAS공격시뮬레이션플랫폼", "방어개선사이클"]},
    {"id": "25", "name": "供应链安全", "en": "SupplyChainSecurity",
     "skills": ["SBOM생성/검증", "소프트웨어의존성/오픈소스합규감사", "코드서명/공급망무결성", "제3자공급업체위험평가", "공급망공격탐지/대응"]},
    {"id": "26", "name": "漏洞管理", "en": "VulnerabilityManagement",
     "skills": ["취약점정보/CVE조회", "취약점검증/PoC테스트", "취약점우선순위/위험평가", "취약점수정/패치관리", "취약점생명주기관리", "버그바운티/크라우드소싱테스트"]},
    {"id": "27", "name": "操作系统安全", "en": "OSSecurity",
     "skills": ["Windows보안강화/기준선검사", "Windows공격/횡적이동기술", "Linux보안강화/기준선검사", "Linux공격/권한유지기술", "macOS보안평가/강화", "국산OS보안강화"]},
    {"id": "28", "name": "威胁狩猎", "en": "ThreatHunting",
     "skills": ["위협탐색방법론/가설주도", "Sigma규칙탐지엔지니어링", "ATT&CK기반위협탐색", "네트워크트래픽/로그이상탐지"]},
    {"id": "29", "name": "威胁情报", "en": "ThreatIntelligence",
     "skills": ["위협정보피드/TAXII-STIX관리", "MISP플랫폼배포/공유", "APT그룹분석/귀속", "위협정보주도보안운영"]},
    {"id": "30", "name": "数字取证", "en": "DigitalForensics",
     "skills": ["디스크이미징/증거획득", "메모리포렌식분석Volatility", "Windows디지털포렌식", "Linux디지털포렌식", "브라우저/이메일포렌식"]},
    {"id": "31", "name": "SOC运营", "en": "SOCOperations",
     "skills": ["SIEM알림규칙/연관분석", "SOC사건분류/대응절차", "보안자동화/오케스트레이션SOAR", "SOC지표/운영효과측정"]},
    {"id": "32", "name": "身份访问管理", "en": "IAM",
     "skills": ["기업IAM전략/아키텍처", "PAM특권계정관리", "클라우드IAM/연합인증", "AD도메인보안/공격경로분석"]},
    {"id": "33", "name": "容器安全", "en": "ContainerSecurity",
     "skills": ["컨테이너이미지보안/취약점스캔", "Kubernetes RBAC/보안정책", "컨테이너런타임보안Falco", "컨테이너탈출탐지/방어"]},
    {"id": "34", "name": "API安全", "en": "APISecurity",
     "skills": ["OWASP API보안테스트", "API인증/인가보안", "GraphQL/마이크로서비스API보안"]},
    {"id": "35", "name": "密码学与PKI", "en": "CryptographyPKI",
     "skills": ["TLS/SSL보안설정감사", "PKI아키텍처/인증서보안관리", "암호화알고리즘/키관리"]},
    {"id": "36", "name": "零信任架构", "en": "ZeroTrust",
     "skills": ["제로트러스트아키텍처설계/구현", "마이크로세그멘테이션/SDP", "ZTNA솔루션/IAM통합"]},
    {"id": "37", "name": "端点安全", "en": "EndpointSecurity",
     "skills": ["EDR배포/탐지규칙", "파일리스악성코드/LOLBins탐지", "엔드포인트강화/합규기준선", "모바일장치보안/MDM"]},
    {"id": "38", "name": "勒索软件防御", "en": "RansomwareDefense",
     "skills": ["랜섬웨어공격체인분석/탐지", "랜섬웨어응급대응/복구", "랜섬웨어방어강화/백업전략"]},
    {"id": "39", "name": "安全治理合规", "en": "GovernanceCompliance",
     "skills": ["보안프레임워크/합규감사", "위험관리/보안측정", "보안정책체계/보안의식"]},
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
        return {
            "total_skills": len(ALL_SKILLS),
            "cybersecurity_skills": len(SKILLS_DB) + len(SKILLS_DB_2),
            "secskills_local": len(SKILLS_DB_3),
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
