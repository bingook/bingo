"""
bingo/core/recon/passive.py — 패시브 정보수집 모듈 v1.0 (v3.5.22)

외부 의존성 없이 동작하는 패시브 수집:
  • crt.sh  — Certificate Transparency 서브도메인 열거
  • BGPView — ASN / IP CIDR 수집
  • Shodan  — 서비스 탐지 (API 키 필요)
  • FOFA    — 자산 탐지 (이메일+키 필요, 중국 표적에 특히 강력)
  • Hunter.io — 이메일 수집 (API 키 필요)
  • Google / GitHub Dork 생성 (키 불필요)
"""
from __future__ import annotations

import base64
import json
import re
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field


# ── 데이터 구조 ──────────────────────────────────────────────────────────────

@dataclass
class PassiveResult:
    target: str
    subdomains: list[str] = field(default_factory=list)
    ips: list[str] = field(default_factory=list)
    asn_prefixes: list[str] = field(default_factory=list)
    emails: list[str] = field(default_factory=list)
    cert_sans: list[str] = field(default_factory=list)
    shodan_results: list[dict] = field(default_factory=list)
    fofa_results: list[dict] = field(default_factory=list)
    github_dorks: list[str] = field(default_factory=list)
    google_dorks: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def all_subdomains(self) -> list[str]:
        return sorted(set(self.subdomains + self.cert_sans))

    def summary(self) -> str:
        lines = [
            f"  🎯 Target     : {self.target}",
            f"  🌐 Subdomains : {len(self.all_subdomains())}",
            f"  📡 IPs        : {len(self.ips)}",
            f"  🏢 ASN CIDRs  : {len(self.asn_prefixes)}",
            f"  📧 Emails     : {len(self.emails)}",
            f"  🔒 Cert SANs  : {len(self.cert_sans)}",
        ]
        if self.shodan_results:
            lines.append(f"  🔍 Shodan     : {len(self.shodan_results)} results")
        if self.fofa_results:
            lines.append(f"  🔍 FOFA       : {len(self.fofa_results)} results")
        if self.errors:
            lines.append(f"  ⚠️  Errors     : {len(self.errors)}")
        return "\n".join(lines)


# ── 내부 HTTP 헬퍼 ───────────────────────────────────────────────────────────

_UA = "bingo-recon/3.5.22 (github.com/bingo)"


def _get(url: str, timeout: int = 12, extra_headers: dict | None = None) -> str:
    headers = {"User-Agent": _UA}
    if extra_headers:
        headers.update(extra_headers)
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except Exception as e:
        raise RuntimeError(str(e)) from e


# ── 1. Certificate Transparency — crt.sh ─────────────────────────────────────

def crtsh_enum(domain: str) -> list[str]:
    """crt.sh에서 인증서 SAN 기반 서브도메인 열거 (무료, 키 불필요)"""
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    try:
        raw = _get(url, timeout=18)
        data = json.loads(raw)
        subs: set[str] = set()
        for entry in data:
            for name in entry.get("name_value", "").split("\n"):
                name = name.strip().lstrip("*.").lower()
                if name.endswith(f".{domain}") or name == domain:
                    subs.add(name)
        return sorted(subs)
    except Exception as e:
        return []


# ── 2. BGPView — ASN & IP prefix ─────────────────────────────────────────────

def bgpview_asn_lookup(org_name: str) -> list[dict]:
    """조직명 → ASN 목록"""
    url = f"https://api.bgpview.io/search?query_term={urllib.parse.quote(org_name)}"
    try:
        raw = _get(url, timeout=10)
        data = json.loads(raw)
        return data.get("data", {}).get("asns", [])
    except Exception:
        return []


def bgpview_prefixes(asn: int) -> list[str]:
    """ASN → IPv4 CIDR 프리픽스 목록"""
    url = f"https://api.bgpview.io/asn/{asn}/prefixes"
    try:
        raw = _get(url, timeout=10)
        data = json.loads(raw)
        return [p["prefix"] for p in data.get("data", {}).get("ipv4_prefixes", [])]
    except Exception:
        return []


def bgpview_ip_info(ip: str) -> dict:
    """IP → ASN/조직 정보"""
    url = f"https://api.bgpview.io/ip/{ip}"
    try:
        raw = _get(url, timeout=8)
        return json.loads(raw).get("data", {})
    except Exception:
        return {}


def _collect_asn_prefixes(ips: list[str]) -> list[str]:
    """IP 목록으로 ASN CIDR 수집"""
    seen: set[str] = set()
    prefixes: list[str] = []
    for ip in ips[:8]:
        try:
            info = bgpview_ip_info(ip)
            for p in info.get("prefixes", []):
                prefix = p.get("prefix", "")
                if prefix and prefix not in seen:
                    seen.add(prefix)
                    prefixes.append(prefix)
        except Exception:
            continue
        time.sleep(0.2)  # BGPView rate limit 방어
    return prefixes


# ── 3. Shodan API ─────────────────────────────────────────────────────────────

def shodan_search(query: str, api_key: str, max_results: int = 30) -> list[dict]:
    """Shodan 호스트 검색 (API 키 필요)"""
    url = (
        f"https://api.shodan.io/shodan/host/search"
        f"?key={api_key}&query={urllib.parse.quote(query)}&limit={max_results}"
    )
    try:
        raw = _get(url, timeout=15)
        data = json.loads(raw)
        results = []
        for m in data.get("matches", []):
            results.append({
                "ip":       m.get("ip_str"),
                "port":     m.get("port"),
                "hostname": m.get("hostnames", []),
                "org":      m.get("org"),
                "os":       m.get("os"),
                "product":  m.get("product"),
                "version":  m.get("version"),
                "vulns":    list(m.get("vulns", {}).keys()),
            })
        return results
    except Exception:
        return []


def shodan_host(ip: str, api_key: str) -> dict:
    """특정 IP 상세 조회"""
    url = f"https://api.shodan.io/shodan/host/{ip}?key={api_key}"
    try:
        raw = _get(url, timeout=12)
        return json.loads(raw)
    except Exception:
        return {}


# ── 4. FOFA API ───────────────────────────────────────────────────────────────

def fofa_search(
    query: str,
    email: str,
    api_key: str,
    max_results: int = 30,
    fields: str = "ip,port,host,title,server,icp,country,city",
) -> list[dict]:
    """
    FOFA 자산 검색 (API 키 필요)
    
    예시 query:
      domain="example.com"
      host="example.com" && country="KR"
      ip="x.x.x.x"
    """
    qb64 = base64.b64encode(query.encode()).decode()
    url = (
        f"https://fofa.info/api/v1/search/all"
        f"?email={urllib.parse.quote(email)}&key={api_key}"
        f"&qbase64={qb64}&size={max_results}&fields={fields}"
    )
    try:
        raw = _get(url, timeout=15)
        data = json.loads(raw)
        field_names = fields.split(",")
        results = []
        for item in data.get("results", []):
            entry = {}
            for i, fname in enumerate(field_names):
                entry[fname] = item[i] if i < len(item) else ""
            results.append(entry)
        return results
    except Exception:
        return []


# ── 5. Hunter.io 이메일 수집 ──────────────────────────────────────────────────

def hunter_emails(domain: str, api_key: str, limit: int = 15) -> list[dict]:
    """Hunter.io 도메인 이메일 수집 (API 키 필요)"""
    url = (
        f"https://api.hunter.io/v2/domain-search"
        f"?domain={domain}&api_key={api_key}&limit={limit}"
    )
    try:
        raw = _get(url, timeout=12)
        data = json.loads(raw)
        emails = []
        for e in data.get("data", {}).get("emails", []):
            emails.append({
                "email":      e.get("value"),
                "first_name": e.get("first_name"),
                "last_name":  e.get("last_name"),
                "position":   e.get("position"),
                "confidence": e.get("confidence"),
                "source":     e.get("sources", [{}])[0].get("uri", "") if e.get("sources") else "",
            })
        return emails
    except Exception:
        return []


# ── 6. DNS 해석 ───────────────────────────────────────────────────────────────

def dns_resolve(hostname: str) -> list[str]:
    """hostname → IP 목록"""
    try:
        results = socket.getaddrinfo(hostname, None)
        return list({r[4][0] for r in results})
    except Exception:
        return []


def bulk_dns_resolve(subdomains: list[str], max_workers: int = 50) -> dict[str, list[str]]:
    """서브도메인 목록 병렬 DNS 해석"""
    from concurrent.futures import ThreadPoolExecutor, as_completed
    mapping: dict[str, list[str]] = {}
    with ThreadPoolExecutor(max_workers=max_workers) as exe:
        futures = {exe.submit(dns_resolve, s): s for s in subdomains}
        for f in as_completed(futures):
            sub = futures[f]
            ips = f.result()
            if ips:
                mapping[sub] = ips
    return mapping


# ── 7. Dork 생성 ─────────────────────────────────────────────────────────────

def generate_google_dorks(domain: str) -> list[str]:
    return [
        f"site:{domain}",
        f"site:{domain} filetype:sql",
        f"site:{domain} filetype:env",
        f"site:{domain} filetype:xml",
        f"site:{domain} inurl:admin",
        f"site:{domain} inurl:login",
        f"site:{domain} inurl:api",
        f"site:{domain} inurl:swagger",
        f"site:{domain} inurl:actuator",
        f'site:{domain} "Index of"',
        f'site:{domain} intext:"DB_PASSWORD"',
        f'site:{domain} intext:"api_key"',
        f'site:{domain} intext:"Authorization"',
        f"site:{domain} ext:php intext:password",
        # 한국 특화
        f"site:{domain} inurl:bbs",
        f"site:{domain} inurl:xe",
        f"site:{domain} inurl:phpmyadmin",
        f'site:{domain} "오류가 발생"',
    ]


def generate_github_dorks(domain: str, org: str = "") -> list[str]:
    base = "https://github.com/search?type=code&q="
    dorks = [
        f"{base}{urllib.parse.quote(domain + ' password')}",
        f"{base}{urllib.parse.quote(domain + ' secret')}",
        f"{base}{urllib.parse.quote(domain + ' api_key')}",
        f"{base}{urllib.parse.quote(domain + ' DB_PASSWORD')}",
        f"{base}{urllib.parse.quote('filename:.env ' + domain)}",
        f"{base}{urllib.parse.quote('filename:config.php ' + domain)}",
    ]
    if org:
        dorks += [
            f"{base}{urllib.parse.quote('org:' + org + ' password')}",
            f"{base}{urllib.parse.quote('org:' + org + ' filename:.env')}",
            f"{base}{urllib.parse.quote('org:' + org + ' filename:config')}",
        ]
    return dorks


# ── 8. 통합 패시브 수집 ──────────────────────────────────────────────────────

def run_passive(
    domain: str,
    shodan_key: str = "",
    fofa_email: str = "",
    fofa_key: str = "",
    hunter_key: str = "",
    org_name: str = "",
    verbose: bool = True,
) -> PassiveResult:
    """
    단일 함수 — 패시브 수집 전체 파이프라인

    Args:
        domain    : 대상 도메인 (예: example.com)
        shodan_key: Shodan API 키 (선택, https://shodan.io)
        fofa_email: FOFA 계정 이메일 (선택, https://fofa.info)
        fofa_key  : FOFA API 키 (선택)
        hunter_key: Hunter.io API 키 (선택, https://hunter.io)
        org_name  : BGPView ASN 검색용 조직명 (선택, 예: "Samsung Electronics")
        verbose   : 진행 상황 출력
    """
    result = PassiveResult(target=domain)
    _p = print if verbose else (lambda *a, **k: None)

    # 1. crt.sh
    _p(f"  [1/6] 🔒 crt.sh Certificate Transparency...")
    try:
        subs = crtsh_enum(domain)
        result.subdomains = subs
        result.cert_sans = subs[:]
        _p(f"       {len(subs)} 서브도메인 발견")
    except Exception as e:
        result.errors.append(f"crt.sh: {e}")

    # 2. DNS 대량 해석 → IP 수집
    _p(f"  [2/6] 📡 DNS 해석 ({len(result.subdomains)} 서브도메인)...")
    try:
        all_subs = [domain] + result.subdomains[:80]
        dns_map = bulk_dns_resolve(all_subs)
        all_ips: set[str] = set()
        for ips in dns_map.values():
            all_ips.update(ips)
        result.ips = sorted(all_ips)
        _p(f"       {len(result.ips)} 고유 IP 발견")
    except Exception as e:
        result.errors.append(f"DNS: {e}")

    # 3. BGPView ASN / CIDR
    _p(f"  [3/6] 🏢 BGPView ASN 조회...")
    try:
        prefixes = _collect_asn_prefixes(result.ips)
        result.asn_prefixes = prefixes
        if org_name:
            asns = bgpview_asn_lookup(org_name)
            for asn_info in asns[:3]:
                asn_num = asn_info.get("asn")
                if asn_num:
                    more = bgpview_prefixes(asn_num)
                    result.asn_prefixes.extend(more)
            result.asn_prefixes = sorted(set(result.asn_prefixes))
        _p(f"       {len(result.asn_prefixes)} CIDR 블록 수집")
    except Exception as e:
        result.errors.append(f"BGPView: {e}")

    # 4. Shodan
    if shodan_key:
        _p(f"  [4/6] 🔍 Shodan 검색...")
        try:
            results = shodan_search(f"hostname:{domain}", shodan_key)
            result.shodan_results = results
            vulns_total = sum(len(r.get("vulns", [])) for r in results)
            _p(f"       {len(results)} 서비스, CVE {vulns_total}개")
        except Exception as e:
            result.errors.append(f"Shodan: {e}")
    else:
        _p(f"  [4/6] 🔍 Shodan 건너뜀 (키 없음 → config에 shodan_key 추가)")

    # 5. FOFA
    if fofa_email and fofa_key:
        _p(f"  [5/6] 🔍 FOFA 검색...")
        try:
            results = fofa_search(f'domain="{domain}"', fofa_email, fofa_key)
            result.fofa_results = results
            _p(f"       {len(results)} 자산 발견")
        except Exception as e:
            result.errors.append(f"FOFA: {e}")
    else:
        _p(f"  [5/6] 🔍 FOFA 건너뜀 (키 없음 → config에 fofa_email/fofa_key 추가)")

    # 6. Hunter.io
    if hunter_key:
        _p(f"  [6/6] 📧 Hunter.io 이메일 수집...")
        try:
            email_data = hunter_emails(domain, hunter_key)
            result.emails = [e["email"] for e in email_data if e.get("email")]
            _p(f"       {len(result.emails)} 이메일 발견")
        except Exception as e:
            result.errors.append(f"Hunter.io: {e}")
    else:
        _p(f"  [6/6] 📧 Hunter.io 건너뜀 (키 없음)")

    # 7. Dork 생성 (항상)
    result.google_dorks = generate_google_dorks(domain)
    result.github_dorks = generate_github_dorks(domain)

    return result
