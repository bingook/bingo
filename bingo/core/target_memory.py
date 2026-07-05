"""
bingo v3.2.71 — Target Memory (도메인별 영구 취약점 기억)

같은 타겟을 재실행해도 이전 탐색 결과를 불러와 AI에게 주입.
저장 위치: ~/.config/bingo/target_memory/<domain_hash>.json
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from datetime import datetime
from typing import Any


_MEMORY_DIR = Path.home() / ".config" / "bingo" / "target_memory"


def _domain_key(target: str) -> str:
    """URL → 안전한 파일명 키 생성."""
    clean = re.sub(r"https?://", "", target).split("/")[0].lower()
    h = hashlib.md5(clean.encode()).hexdigest()[:8]
    safe = re.sub(r"[^a-z0-9\-\.]", "_", clean)[:40]
    return f"{safe}_{h}"


def load(target: str) -> dict:
    """타겟의 저장된 메모리 로드. 없으면 빈 dict 반환."""
    _MEMORY_DIR.mkdir(parents=True, exist_ok=True)
    key = _domain_key(target)
    path = _MEMORY_DIR / f"{key}.json"
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def save(target: str, data: dict) -> None:
    """타겟 메모리 저장 (기존 데이터에 merge)."""
    _MEMORY_DIR.mkdir(parents=True, exist_ok=True)
    key = _domain_key(target)
    path = _MEMORY_DIR / f"{key}.json"
    existing = load(target)
    # merge: 리스트 항목은 dedup, 단일 값은 덮어쓰기
    for k, v in data.items():
        if isinstance(v, list) and isinstance(existing.get(k), list):
            existing[k] = list(dict.fromkeys(existing[k] + v))
        elif v:
            existing[k] = v
    existing["_updated"] = datetime.now().isoformat()
    path.write_text(json.dumps(existing, ensure_ascii=False, indent=2), encoding="utf-8")


def purge_foreign_domains(target: str) -> int:
    """
    Bug-fix v5.0.9: 저장된 메모리에서 현재 타겟과 다른 도메인의 항목을 제거.
    이전 세션에서 incheon.or.kr 등 다른 도메인이 klia.or.kr 메모리에 섞인 경우 정리.
    Returns: 제거된 항목 수
    """
    domain_m = re.search(r"https?://([^/]+)", target)
    if not domain_m:
        return 0
    _target_domain = domain_m.group(1)
    _root_domain = re.sub(r"^(?:www\d*|m|mobile|admin|cms)\.", "", _target_domain)

    def _ok(url: str) -> bool:
        if not url or url.startswith("/"):
            return True
        m = re.search(r"https?://([^/]+)", url)
        if not m:
            return True
        ud = m.group(1)
        ur = re.sub(r"^(?:www\d*|m|mobile|admin|cms)\.", "", ud)
        return ud == _target_domain or ur == _root_domain or ur.endswith("." + _root_domain)

    mem = load(target)
    if not mem:
        return 0

    removed = 0
    sqli_orig = mem.get("sqli_points", [])
    sqli_clean = [p for p in sqli_orig if _ok(p.get("url", ""))]
    removed += len(sqli_orig) - len(sqli_clean)

    ep_orig = mem.get("endpoints", [])
    ep_clean = [e for e in ep_orig if _ok(e.get("url", ""))]
    removed += len(ep_orig) - len(ep_clean)

    if removed > 0:
        mem["sqli_points"] = sqli_clean
        mem["endpoints"] = ep_clean
        mem["_updated"] = datetime.now().isoformat()
        _MEMORY_DIR.mkdir(parents=True, exist_ok=True)
        key = _domain_key(target)
        path = _MEMORY_DIR / f"{key}.json"
        path.write_text(json.dumps(mem, ensure_ascii=False, indent=2), encoding="utf-8")

    return removed


def record_sqli_point(target: str, url: str, param: str, method: str,
                       size_normal: int | None = None, size_injected: int | None = None,
                       sqli_type: str = "unknown") -> None:
    """SQLi 가능 포인트 기록."""
    mem = load(target)
    points = mem.get("sqli_points", [])
    entry = {
        "url": url,
        "param": param,
        "method": method,
        "sqli_type": sqli_type,
        "size_normal": size_normal,
        "size_injected": size_injected,
        "found_at": datetime.now().isoformat(),
    }
    # 중복 방지 (url+param 기준)
    if not any(p["url"] == url and p["param"] == param for p in points):
        points.append(entry)
    save(target, {"sqli_points": points})


def record_users(target: str, users: list[str]) -> None:
    """존재 확인된 유저명 기록."""
    save(target, {"confirmed_users": users})


def record_endpoint(target: str, url: str, status: int, note: str = "") -> None:
    """주요 엔드포인트 기록."""
    mem = load(target)
    eps = mem.get("endpoints", [])
    entry = {"url": url, "status": status, "note": note}
    if not any(e["url"] == url for e in eps):
        eps.append(entry)
    save(target, {"endpoints": eps})


def build_context_injection(target: str, lang: str = "zh") -> str:
    """
    저장된 메모리를 AI 시스템 프롬프트용 텍스트로 변환.
    새 세션 시작 시 이 텍스트를 history에 주입.
    """
    mem = load(target)
    if not mem:
        return ""

    sqli_points = mem.get("sqli_points", [])
    users = mem.get("confirmed_users", [])
    endpoints = mem.get("endpoints", [])
    notes = mem.get("notes", [])
    updated = mem.get("_updated", "")

    lines: list[str] = []

    if lang == "ko":
        lines.append(f"[🧠 타겟 메모리 — {target}] (마지막 업데이트: {updated})")
        if sqli_points:
            lines.append("\n■ 이전 세션에서 확인된 SQLi 가능 포인트 (최우선 공격 대상):")
            for p in sqli_points:
                diff = ""
                if p.get("size_normal") and p.get("size_injected"):
                    diff = f"  정상={p['size_normal']}B vs 주입={p['size_injected']}B"
                lines.append(
                    f"  • URL: {p['url']}  파라미터: {p['param']}  방식: {p.get('sqli_type','?')}{diff}"
                )
            lines.append("  → 이 파라미터에 즉시 blind SQLi / error-based SQLi 집중할 것!")
        if users:
            lines.append(f"\n■ 확인된 존재 유저: {', '.join(users)}")
        if endpoints:
            lines.append("\n■ 주요 엔드포인트:")
            for e in endpoints[:10]:
                lines.append(f"  • [{e['status']}] {e['url']}  {e.get('note','')}")
        if notes:
            lines.append("\n■ 기타 메모:")
            for n in notes:
                lines.append(f"  • {n}")
        lines.append("\n→ 위 정보를 바탕으로 SQLi 포인트를 최우선 공략할 것. 이미 발견된 포인트는 재탐색 불필요.")

    elif lang == "zh":
        lines.append(f"[🧠 目标记忆 — {target}] (最后更新: {updated})")
        if sqli_points:
            lines.append("\n■ 上次会话确认的SQLi可能注入点 (最高优先攻击目标):")
            for p in sqli_points:
                diff = ""
                if p.get("size_normal") and p.get("size_injected"):
                    diff = f"  正常={p['size_normal']}B vs 注入={p['size_injected']}B"
                lines.append(
                    f"  • URL: {p['url']}  参数: {p['param']}  类型: {p.get('sqli_type','?')}{diff}"
                )
            lines.append("  → 立即对这些参数集中进行blind SQLi / error-based SQLi!")
        if users:
            lines.append(f"\n■ 已确认存在的用户: {', '.join(users)}")
        if endpoints:
            lines.append("\n■ 主要端点:")
            for e in endpoints[:10]:
                lines.append(f"  • [{e['status']}] {e['url']}  {e.get('note','')}")
        if notes:
            lines.append("\n■ 其他备注:")
            for n in notes:
                lines.append(f"  • {n}")
        lines.append("\n→ 基于以上信息，优先攻击SQLi注入点。已发现的点无需重新侦察。")

    else:  # en
        lines.append(f"[🧠 Target Memory — {target}] (Last updated: {updated})")
        if sqli_points:
            lines.append("\n■ SQLi candidates from previous session (TOP PRIORITY):")
            for p in sqli_points:
                diff = ""
                if p.get("size_normal") and p.get("size_injected"):
                    diff = f"  normal={p['size_normal']}B vs injected={p['size_injected']}B"
                lines.append(
                    f"  • URL: {p['url']}  param: {p['param']}  type: {p.get('sqli_type','?')}{diff}"
                )
            lines.append("  → Immediately focus blind/error-based SQLi on these parameters!")
        if users:
            lines.append(f"\n■ Confirmed existing users: {', '.join(users)}")
        if endpoints:
            lines.append("\n■ Key endpoints:")
            for e in endpoints[:10]:
                lines.append(f"  • [{e['status']}] {e['url']}  {e.get('note','')}")
        if notes:
            lines.append("\n■ Notes:")
            for n in notes:
                lines.append(f"  • {n}")
        lines.append("\n→ Prioritize SQLi attack on known points. No need to re-recon.")

    return "\n".join(lines)
