"""
bingo/core/recon/asset_db.py — 자산 DB & 우선순위 분류 v1.0 (v3.5.22)

수집된 패시브/액티브 결과를 통합하고:
  • P0-P3 우선순위 자동 분류
  • 공격 표면 요약 리포트 생성
  • JSON 파일로 저장/불러오기
  • Nuclei 자동 실행 명령 생성
"""
from __future__ import annotations

import json
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

from .passive import PassiveResult
from .active import ActiveResult, LiveHost, PortResult, P0_PORTS, P1_PORTS


# ── 데이터 구조 ──────────────────────────────────────────────────────────────

@dataclass
class PriorityAsset:
    url: str
    ip: str = ""
    priority: str = "P2"   # P0 / P1 / P2 / P3
    reasons: list[str] = field(default_factory=list)
    open_ports: list[int] = field(default_factory=list)
    technologies: list[str] = field(default_factory=list)
    status: int = 0
    title: str = ""
    waf: str = ""
    attack_hints: list[str] = field(default_factory=list)


# 경로 패턴 → 우선순위 규칙
_P0_PATH_PATTERNS: list[tuple[str, str]] = [
    ("/.env",         "⚡ .env 파일 노출 → 자격증명 즉각 확인"),
    ("/.git",         "⚡ .git 디렉터리 노출 → 소스코드 덤프 가능"),
    ("/phpmyadmin",   "⚡ phpMyAdmin 노출"),
    ("/adminer",      "⚡ Adminer DB 관리툴 노출"),
    ("/swagger",      "🔍 Swagger UI → API 명세 공개"),
    ("/actuator",     "⚡ Spring Boot Actuator 노출"),
    ("/graphql",      "🔍 GraphQL 엔드포인트 발견"),
    ("/api-docs",     "🔍 API 문서 노출"),
    ("/v2/api-docs",  "🔍 Swagger v2 API 문서"),
    ("/console",      "⚡ 개발 콘솔 노출"),
]

_P1_PATH_PATTERNS: list[tuple[str, str]] = [
    ("/admin",   "🎯 관리자 패널"),
    ("/manager", "🎯 관리자 패널"),
    ("/login",   "🔑 로그인 페이지 → 자격증명 공격"),
    ("/upload",  "📁 업로드 기능"),
    ("/api",     "🔌 API 엔드포인트"),
]

# 공격 힌트 — 기술스택 기반
_TECH_ATTACK_HINTS: dict[str, list[str]] = {
    "PHP":          ["SQLi 시도: ' OR 1=1--", "LFI: ?page=../etc/passwd"],
    "ASP.NET":      ["MSSQL time-based SQLi", "ViewState 역직렬화"],
    "Spring":       ["Spring4Shell CVE-2022-22965", "Actuator 데이터 탈취"],
    "Laravel":      ["Laravel debug mode → .env 노출", "Deserialization RCE"],
    "WordPress":    ["xmlrpc.php bruteforce", "wp-admin 자격증명 공격"],
    "Django":       ["Debug 모드 확인: ?debug=1", "CSRF bypass"],
    "GnuBoard":     ["SQLi: /bbs/login.php", "File upload: /bbs/write_update.php"],
    "XpressEngine": ["SQLi: /xe/index.php?mid=", "LFI bypass"],
    "Express":      ["Prototype pollution", "Path traversal"],
    "Nginx":        ["off-by-slash: /api../", "HTTP Splitting"],
}


class AssetDB:
    """자산 데이터베이스 — 수집 결과 통합 & 우선순위 분류"""

    def __init__(self, target: str, save_dir: Path | None = None):
        self.target = target
        self.save_dir = save_dir or (Path.cwd() / "recon_output" / target.replace(".", "_"))
        self.passive: PassiveResult | None = None
        self.active: ActiveResult | None = None
        self.priority_assets: list[PriorityAsset] = []
        self.collected_at: str = time.strftime("%Y-%m-%dT%H:%M:%S")

    def load(
        self,
        passive: PassiveResult | None = None,
        active: ActiveResult | None = None,
    ) -> None:
        self.passive = passive
        self.active = active
        self._classify()

    # ── 우선순위 분류 ─────────────────────────────────────────────────────────

    def _classify(self) -> None:
        self.priority_assets.clear()

        if self.active:
            # IP → 포트 맵 만들기
            ip_port_map: dict[str, list[int]] = {}
            for pr in self.active.port_results:
                ip_port_map[pr.host] = pr.open_ports

            for host in self.active.live_hosts:
                pa = PriorityAsset(
                    url=host.url,
                    ip=host.ip,
                    technologies=host.technologies,
                    status=host.status,
                    title=host.title,
                    waf=host.waf,
                    open_ports=ip_port_map.get(host.ip, []),
                )
                priority, reasons = self._score(pa)
                pa.priority = priority
                pa.reasons = reasons
                pa.attack_hints = self._get_hints(pa)
                self.priority_assets.append(pa)

        _order = {"P0": 0, "P1": 1, "P2": 2, "P3": 3}
        self.priority_assets.sort(key=lambda x: _order.get(x.priority, 4))

    def _score(self, pa: PriorityAsset) -> tuple[str, list[str]]:
        reasons: list[str] = []

        # P0 — 즉각 공격 가능
        risky_p0 = set(pa.open_ports) & P0_PORTS
        if risky_p0:
            svc = {6379: "Redis", 9200: "Elasticsearch", 27017: "MongoDB",
                   11211: "Memcached", 2375: "Docker API", 8888: "Jupyter", 2379: "etcd"}
            for p in sorted(risky_p0):
                reasons.append(f"⚡ {svc.get(p, '위험 서비스')} 포트 {p} 노출 → 즉각 RCE/데이터")
            return "P0", reasons

        for path, hint in _P0_PATH_PATTERNS:
            if path in pa.url.lower():
                reasons.append(hint)
                return "P0", reasons

        if pa.status == 403:
            reasons.append("🚧 403 Forbidden → WAF 우회 후 관리자 패널 가능성")
            # 관리자 경로 + 403이면 P0
            if any(p in pa.url for p in ["/admin", "/manager", "/api"]):
                return "P0", reasons
            return "P1", reasons

        # P1 — 오늘 내 테스트
        risky_p1 = set(pa.open_ports) & P1_PORTS
        if risky_p1:
            reasons.append(f"🟠 위험 서비스 포트: {sorted(risky_p1)}")
            return "P1", reasons

        for path, hint in _P1_PATH_PATTERNS:
            if path in pa.url.lower():
                reasons.append(hint)
                return "P1", reasons

        for tech in ["Spring", "Laravel", "Django", "WordPress", "GnuBoard"]:
            if tech in pa.technologies:
                reasons.append(f"🎯 {tech} 탐지 → 알려진 취약점 존재")
                return "P1", reasons

        if pa.status in (200, 301, 302):
            reasons.append("✅ 일반 웹 서비스 (XSS/IDOR/SQLi 탐색)")
            return "P2", reasons

        reasons.append("💤 정적 또는 비활성 서비스")
        return "P3", reasons

    def _get_hints(self, pa: PriorityAsset) -> list[str]:
        hints: list[str] = []
        for tech in pa.technologies:
            for key, h in _TECH_ATTACK_HINTS.items():
                if key.lower() in tech.lower():
                    hints.extend(h)
        return list(dict.fromkeys(hints))[:5]

    # ── 리포트 ───────────────────────────────────────────────────────────────

    def attack_surface_summary(self) -> str:
        lines = [
            "",
            f"{'═'*62}",
            f"  🎯 TARGET   : {self.target}",
            f"  📅 SCANNED  : {self.collected_at}",
            f"{'═'*62}",
        ]

        # 패시브 결과
        if self.passive:
            lines += [
                "",
                "  📊 패시브 수집 (Passive Recon)",
                f"  {'─'*40}",
                f"  🌐 서브도메인   : {len(self.passive.all_subdomains())}",
                f"  📡 IP 주소      : {len(self.passive.ips)}",
                f"  🏢 ASN CIDR     : {len(self.passive.asn_prefixes)}",
            ]
            if self.passive.emails:
                lines.append(f"  📧 이메일       : {len(self.passive.emails)}")
            if self.passive.shodan_results:
                cves = sum(len(r.get("vulns", [])) for r in self.passive.shodan_results)
                lines.append(f"  🔍 Shodan       : {len(self.passive.shodan_results)} 서비스, CVE {cves}개")
            if self.passive.fofa_results:
                lines.append(f"  🔍 FOFA         : {len(self.passive.fofa_results)} 자산")

        # 액티브 결과
        if self.active:
            total_open = sum(len(p.open_ports) for p in self.active.port_results)
            interesting = [h for h in self.active.live_hosts if h.interesting]
            lines += [
                "",
                "  ⚡ 액티브 수집 (Active Recon)",
                f"  {'─'*40}",
                f"  🌐 생존 호스트  : {len(self.active.live_hosts)}",
                f"  ⚠️  즉시 확인    : {len(interesting)}",
                f"  🔌 열린 포트    : {total_open}",
            ]
            if self.active.js_endpoints:
                lines.append(f"  🔗 JS API 엔드포인트: {len(self.active.js_endpoints)}")

        # 우선순위 분류
        p0 = [a for a in self.priority_assets if a.priority == "P0"]
        p1 = [a for a in self.priority_assets if a.priority == "P1"]
        p2 = [a for a in self.priority_assets if a.priority == "P2"]

        if p0:
            lines += [
                "",
                f"  🔴 P0 — 즉시 공격 ({len(p0)}개)",
                f"  {'─'*40}",
            ]
            for a in p0:
                lines.append(f"  ⚡ {a.url}  [{a.status}]")
                for r in a.reasons[:2]:
                    lines.append(f"     → {r}")
                for h in a.attack_hints[:2]:
                    lines.append(f"     💡 {h}")

        if p1:
            lines += [
                "",
                f"  🟠 P1 — 오늘 내 테스트 ({len(p1)}개)",
                f"  {'─'*40}",
            ]
            for a in p1[:6]:
                tech_str = ", ".join(a.technologies[:2]) if a.technologies else ""
                waf_str = f" [WAF: {a.waf}]" if a.waf else ""
                lines.append(f"  •  {a.url}{waf_str}  {tech_str}")

        if p2:
            lines += [
                "",
                f"  🟡 P2 — 이번 주 내 ({len(p2)}개)",
                f"  {'─'*40}",
                f"  (상위 5개만 표시)",
            ]
            for a in p2[:5]:
                lines.append(f"  •  {a.url}  [{a.status}] {a.title[:40]}")

        # JS 엔드포인트
        if self.active and self.active.js_endpoints:
            lines += [
                "",
                "  🔗 JS에서 발견된 API 엔드포인트 (상위 10)",
                f"  {'─'*40}",
            ]
            for ep in self.active.js_endpoints[:10]:
                lines.append(f"  {ep}")

        # Google Dorks
        if self.passive and self.passive.google_dorks:
            lines += [
                "",
                "  🔎 Google Dork 쿼리 (복사해서 사용)",
                f"  {'─'*40}",
            ]
            for d in self.passive.google_dorks[:6]:
                lines.append(f"  {d}")

        # 이메일 목록
        if self.passive and self.passive.emails:
            lines += [
                "",
                "  📧 수집된 이메일 (스피어피싱/자격증명 공격용)",
                f"  {'─'*40}",
            ]
            for e in self.passive.emails[:8]:
                lines.append(f"  {e}")

        # Nuclei 실행 명령 제안
        if self.active and self.active.live_hosts:
            live_count = len(self.active.live_hosts)
            lines += [
                "",
                "  ⚙️  다음 단계 — Nuclei 자동 스캔",
                f"  {'─'*40}",
                f"  # 생존 호스트 {live_count}개에 nuclei 실행:",
                f"  # /recon nuclei {self.target}",
                f"  # 또는:",
                f"  # nuclei -l recon_output/{self.target.replace('.', '_')}/live_hosts.txt \\",
                f"  #   -t cves/ -t exposures/ -t misconfiguration/ -t technologies/ \\",
                f"  #   -severity critical,high,medium -rate-limit 30",
            ]

        lines.append(f"\n{'═'*62}")
        return "\n".join(lines)

    def save(self) -> Path:
        """자산 DB를 JSON + 텍스트 파일로 저장"""
        self.save_dir.mkdir(parents=True, exist_ok=True)

        # live_hosts.txt (nuclei 입력용)
        if self.active and self.active.live_hosts:
            live_txt = self.save_dir / "live_hosts.txt"
            live_txt.write_text("\n".join(h.url for h in self.active.live_hosts))

        # subdomains.txt
        if self.passive and self.passive.all_subdomains():
            subs_txt = self.save_dir / "subdomains.txt"
            subs_txt.write_text("\n".join(self.passive.all_subdomains()))

        # google_dorks.txt
        if self.passive and self.passive.google_dorks:
            dorks_txt = self.save_dir / "google_dorks.txt"
            dorks_txt.write_text("\n".join(self.passive.google_dorks))

        # asset_db.json (통합)
        data = {
            "target": self.target,
            "collected_at": self.collected_at,
            "subdomains": self.passive.all_subdomains() if self.passive else [],
            "ips": self.passive.ips if self.passive else [],
            "asn_prefixes": self.passive.asn_prefixes if self.passive else [],
            "emails": self.passive.emails if self.passive else [],
            "shodan_results": self.passive.shodan_results if self.passive else [],
            "fofa_results": self.passive.fofa_results if self.passive else [],
            "live_hosts": [
                {
                    "url": h.url, "ip": h.ip, "status": h.status,
                    "title": h.title, "tech": h.technologies,
                    "server": h.server, "waf": h.waf, "interesting": h.interesting,
                }
                for h in (self.active.live_hosts if self.active else [])
            ],
            "port_results": [
                {"host": p.host, "open_ports": p.open_ports, "services": p.services}
                for p in (self.active.port_results if self.active else [])
            ],
            "js_endpoints": self.active.js_endpoints if self.active else [],
            "priority_assets": [
                {
                    "url": a.url, "ip": a.ip, "priority": a.priority,
                    "reasons": a.reasons, "open_ports": a.open_ports,
                    "technologies": a.technologies, "waf": a.waf,
                    "attack_hints": a.attack_hints,
                }
                for a in self.priority_assets
            ],
            "google_dorks": self.passive.google_dorks if self.passive else [],
            "github_dorks": self.passive.github_dorks if self.passive else [],
        }

        out_file = self.save_dir / "asset_db.json"
        out_file.write_text(json.dumps(data, ensure_ascii=False, indent=2))
        return out_file

    @classmethod
    def load_from_file(cls, path: Path) -> "AssetDB":
        data = json.loads(path.read_text())
        db = cls(target=data["target"], save_dir=path.parent)
        db.collected_at = data.get("collected_at", "")
        return db

    def run_nuclei(self, severity: str = "critical,high,medium") -> str:
        """Nuclei 스캔 실행 (nuclei 설치된 경우)"""
        if not self.active or not self.active.live_hosts:
            return "⚠️ 생존 호스트가 없습니다. 먼저 /recon active를 실행하세요."

        try:
            subprocess.run(["nuclei", "-version"], capture_output=True, timeout=5)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return "⚠️ nuclei가 설치되지 않았습니다. https://nuclei.projectdiscovery.io 에서 설치하세요."

        self.save()
        live_txt = self.save_dir / "live_hosts.txt"
        nuclei_out = self.save_dir / "nuclei_findings.txt"

        cmd = [
            "nuclei",
            "-l", str(live_txt),
            "-t", "cves/", "-t", "exposures/", "-t", "misconfiguration/", "-t", "technologies/",
            "-severity", severity,
            "-rate-limit", "30",
            "-o", str(nuclei_out),
            "-silent",
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            if nuclei_out.exists():
                findings = nuclei_out.read_text()
                count = findings.count("\n")
                return f"✅ Nuclei 완료: {count} 발견 → {nuclei_out}"
            return "✅ Nuclei 완료 (발견 없음)"
        except subprocess.TimeoutExpired:
            return "⏰ Nuclei 타임아웃 (600초)"
        except Exception as e:
            return f"⚠️ Nuclei 오류: {e}"
