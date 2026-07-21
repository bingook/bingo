from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping
import os
import platform
import re

from ...lang.strings import get_strings


@dataclass(frozen=True)
class EvidenceSnapshot:
    confirmed: int = 0
    probable: int = 0
    potential: int = 0
    blocked: int = 0
    quarantined: int = 0

    def as_dict(self) -> dict[str, int]:
        return {
            "confirmed": int(self.confirmed or 0),
            "probable": int(self.probable or 0),
            "potential": int(self.potential or 0),
            "blocked": int(self.blocked or 0),
            "quarantined": int(self.quarantined or 0),
        }

    @classmethod
    def from_exporter(cls, exporter) -> "EvidenceSnapshot":
        if exporter is None:
            return cls()
        try:
            if hasattr(exporter, "stats"):
                stats = exporter.stats() or {}
                return cls(
                    confirmed=int(stats.get("confirmed", 0) or 0),
                    probable=int(stats.get("probable", 0) or 0),
                    potential=max(
                        int(stats.get("potential", 0) or 0),
                        int(stats.get("potential_critical", 0) or 0)
                        + int(stats.get("potential_high", 0) or 0),
                    ),
                    blocked=int(stats.get("blocked", 0) or 0),
                    quarantined=int(stats.get("quarantined", 0) or 0),
                )
        except Exception:
            pass

        confirmed = 0
        probable = 0
        potential = 0
        blocked = 0
        quarantined = 0
        try:
            for finding in list(getattr(exporter, "findings", []) or []):
                confidence = str(getattr(finding, "confidence", "") or "").lower()
                if bool(getattr(finding, "confirmed", False)) or confidence == "confirmed":
                    confirmed += 1
                elif confidence == "probable":
                    probable += 1
                elif confidence in {"potential", "inconclusive"}:
                    potential += 1
                elif confidence == "blocked":
                    blocked += 1
            quarantined = len(list(getattr(exporter, "quarantined", []) or []))
        except Exception:
            pass
        return cls(
            confirmed=confirmed,
            probable=probable,
            potential=potential,
            blocked=blocked,
            quarantined=quarantined,
        )


@dataclass(frozen=True)
class NextStepPlan:
    summary: str
    options: tuple[str, ...]


@dataclass(frozen=True)
class ReportArtifactPlan:
    report_dir: Path
    report_path: Path
    html_report_path: Path
    safe_target: str
    env_override_used: bool = False


@dataclass(frozen=True)
class FindingsArtifactSnapshot:
    summary: str = ""
    findings_brief: tuple[dict[str, object], ...] = ()

    @classmethod
    def from_exporter(cls, exporter, *, limit: int = 30) -> "FindingsArtifactSnapshot":
        if exporter is None:
            return cls()
        summary = ""
        findings_brief: list[dict[str, object]] = []
        try:
            summary = str(getattr(exporter, "summary", lambda: "")() or "")
        except Exception:
            summary = ""
        try:
            for finding in list(getattr(exporter, "findings", []) or [])[: max(int(limit or 30), 0)]:
                findings_brief.append(
                    {
                        "id": getattr(finding, "id", ""),
                        "severity": getattr(finding, "severity", ""),
                        "vuln_type": getattr(finding, "vuln_type", ""),
                        "title": (getattr(finding, "title", "") or "")[:120],
                        "confirmed": bool(getattr(finding, "confirmed", False)),
                    }
                )
        except Exception:
            findings_brief = []
        return cls(summary=summary, findings_brief=tuple(findings_brief))


@dataclass(frozen=True)
class NextStepSuggestion:
    summary_lines: tuple[str, ...] = ()
    options: tuple[str, ...] = ()
    raw_text: str = ""


@dataclass(frozen=True)
class ReportSessionSnapshot:
    session_tables: tuple[object, ...] = ()
    session_credentials: tuple[object, ...] = ()
    previous_tables: tuple[object, ...] = ()
    previous_credentials: tuple[object, ...] = ()
    session_fresh: bool = True
    origin_note: str = ""

    @classmethod
    def from_state(
        cls,
        state: Mapping[str, object] | dict,
        *,
        session_tables: list | tuple | None = None,
        session_credentials: list | tuple | None = None,
        session_fresh: bool = True,
    ) -> "ReportSessionSnapshot":
        current_tables = tuple(session_tables or ())
        current_credentials = tuple(
            filter_verified_report_credentials(list(session_credentials or []))
        )
        state_tables = tuple(list(state.get("tables", []) or []))
        state_credentials = tuple(list(state.get("credentials", []) or []))
        previous_tables = tuple(item for item in state_tables if item not in current_tables)
        previous_credentials = tuple(
            item for item in state_credentials if item not in current_credentials
        )

        origin_note = ""
        if not bool(session_fresh) and (previous_tables or previous_credentials):
            origin_note = (
                "\n⚠️ SESSION ORIGIN NOTICE (CRITICAL — READ CAREFULLY):\n"
                "This session was RESUMED from a previous run.\n"
                "Items confirmed ONLY IN THIS SESSION:\n"
                f"  Tables    : {list(current_tables) or 'none confirmed yet'}\n"
                f"  Credentials: {list(current_credentials) or 'none confirmed yet'}\n"
                "Items from PREVIOUS SESSION (NOT re-verified this run):\n"
                f"  Tables    : {list(previous_tables)}\n"
                f"  Credentials: {list(previous_credentials)}\n"
                "RULE: In the Credentials Extracted section, list ONLY items from THIS SESSION.\n"
                "For previous-session items, note them as '⚠️ From previous session (not re-verified)'.\n"
            )
        elif bool(session_fresh) and not current_tables and not current_credentials:
            origin_note = (
                "\n⚠️ SESSION ACCURACY NOTICE:\n"
                "This is a FRESH session. No credentials or tables were loaded from previous sessions.\n"
                f"Confirmed in this session — Tables: {list(current_tables)}, Credentials: {list(current_credentials)}.\n"
                "RULE: Only report what was actually discovered in this session's execution history.\n"
                "DO NOT invent or assume any credentials, table names, or database names not present in the recent findings context.\n"
            )

        return cls(
            session_tables=current_tables,
            session_credentials=current_credentials,
            previous_tables=previous_tables,
            previous_credentials=previous_credentials,
            session_fresh=bool(session_fresh),
            origin_note=origin_note,
        )


@dataclass(frozen=True)
class ReportGroundTruthSnapshot:
    evidence: EvidenceSnapshot = EvidenceSnapshot()
    findings: tuple[object, ...] = ()
    raw_block: str = ""
    prompt_block: str = ""
    exporter_present: bool = False

    @property
    def confirmed_count(self) -> int:
        return int(self.evidence.confirmed or 0)

    @property
    def potential_count(self) -> int:
        return int(self.evidence.probable or 0) + int(self.evidence.potential or 0)

    @property
    def should_force_deterministic_report(self) -> bool:
        return bool(self.exporter_present and self.confirmed_count == 0)

    @classmethod
    def from_exporter(cls, exporter) -> "ReportGroundTruthSnapshot":
        if exporter is None:
            return cls()

        try:
            if hasattr(exporter, "revalidate_quarantined"):
                exporter.revalidate_quarantined()
        except Exception:
            pass

        evidence = EvidenceSnapshot.from_exporter(exporter)
        findings = tuple(list(getattr(exporter, "findings", []) or []))

        try:
            if hasattr(exporter, "ground_truth_block"):
                raw_block = str(exporter.ground_truth_block() or "")
                prompt_block = (
                    "\n⚠️ FINDINGS GROUND TRUTH (HARD RULE — DO NOT CONTRADICT):\n"
                    + raw_block
                    + "\nEVIDENCE LADDER RULES:\n"
                    + "1) tier=confirmed ONLY → MAY write 已确认/Confirmed/Critical Confirmed.\n"
                    + "2) tier=probable → list ONLY as an unconfirmed verification item; never in confirmed vulnerabilities.\n"
                    + "3) tier=potential → list ONLY as an unconfirmed verification item; never in confirmed vulnerabilities.\n"
                    + "4) tier=quarantined → unresolved candidate; never claim as vuln, never discard.\n"
                    + "5) tier=blocked → WAF/oracle event only; NOT proven vuln.\n"
                    + "6) Fake hashes / login forms are NEVER credentials.\n"
                    + "7) CONFIRMED requires extraction/RCE/browser proof — 100% evidence bar.\n"
                )
                return cls(
                    evidence=evidence,
                    findings=findings,
                    raw_block=raw_block,
                    prompt_block=prompt_block,
                    exporter_present=True,
                )
        except Exception:
            pass

        raw_lines: list[str] = []
        try:
            for finding in findings:
                confirmed = bool(getattr(finding, "confirmed", False))
                raw_lines.append(
                    f"- id={getattr(finding, 'id', '')} type={getattr(finding, 'vuln_type', '')} "
                    f"sev={getattr(finding, 'severity', '')} confirmed={confirmed}"
                )
        except Exception:
            raw_lines = []

        raw_block = "\n".join(raw_lines) if raw_lines else "- (none)\n"
        return cls(
            evidence=evidence,
            findings=findings,
            raw_block=raw_block,
            prompt_block="\n⚠️ FINDINGS GROUND TRUTH:\n" + raw_block,
            exporter_present=True,
        )


@dataclass(frozen=True)
class ArtifactConvergencePlan:
    index_path: Path
    index_json_path: Path
    markdown: str
    payload: dict[str, object]
    report_appendix: str
    session_pointer: str

    def status_message(self, lang: str) -> str:
        return {
            "ko": f"📎 산출물 자동 수렴: {self.index_path}",
            "zh": f"📎 产物已自动汇总: {self.index_path}",
            "en": f"📎 Artifacts converged: {self.index_path}",
        }.get(lang, f"📎 Artifacts converged: {self.index_path}")


def resolve_report_artifact_plan(
    target: str,
    timestamp: str,
    *,
    env_dir: str = "",
    home_dir: Path | str | None = None,
    platform_system: str | None = None,
    desktop_dir: Path | str | None = None,
    xdg_desktop_dir: str = "",
) -> ReportArtifactPlan:
    clean_target = str(target or "unknown")
    safe_target = clean_target.replace("https://", "").replace("http://", "").replace("/", "_")[:30]
    env_dir = str(env_dir or "").strip()
    home_path = Path(home_dir) if home_dir is not None else Path.home()

    if env_dir:
        report_dir = Path(env_dir)
        return ReportArtifactPlan(
            report_dir=report_dir,
            report_path=report_dir / f"report_{safe_target}_{timestamp}.md",
            html_report_path=(report_dir / f"report_{safe_target}_{timestamp}.md").with_suffix(".html"),
            safe_target=safe_target,
            env_override_used=True,
        )

    if desktop_dir is not None:
        desktop_path = Path(desktop_dir)
    else:
        system_name = str(platform_system or platform.system())
        if system_name == "Darwin":
            desktop_path = home_path / "Desktop"
        elif system_name == "Windows":
            try:
                import winreg as _winreg

                key = _winreg.OpenKey(
                    _winreg.HKEY_CURRENT_USER,
                    r"Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
                )
                desktop_path = Path(_winreg.QueryValueEx(key, "Desktop")[0])
            except Exception:
                desktop_path = home_path / "Desktop"
        else:
            desktop_path = Path(xdg_desktop_dir or os.environ.get("XDG_DESKTOP_DIR", str(home_path / "Desktop")))

    raw_target = clean_target.replace("https://", "").replace("http://", "").rstrip("/")
    target_name = raw_target.replace("/", "_").replace(":", "_")[:50]
    report_dir = desktop_path / "dump" / target_name
    report_path = report_dir / f"report_{safe_target}_{timestamp}.md"
    return ReportArtifactPlan(
        report_dir=report_dir,
        report_path=report_path,
        html_report_path=report_path.with_suffix(".html"),
        safe_target=safe_target,
        env_override_used=False,
    )


def build_artifact_convergence_plan(
    target: str,
    *,
    updated_at: str,
    findings_snapshot: FindingsArtifactSnapshot,
    report_path: Path | str | None = None,
    findings_path: Path | str | None = None,
    html_path: Path | str | None = None,
    session_path: Path | str | None = None,
) -> ArtifactConvergencePlan | None:
    report_obj = Path(report_path) if report_path is not None else None
    findings_obj = Path(findings_path) if findings_path is not None else None
    html_obj = Path(html_path) if html_path is not None else None
    session_obj = Path(session_path) if session_path is not None else None

    index_dir = None
    if report_obj is not None:
        index_dir = report_obj.parent
    elif findings_obj is not None:
        index_dir = findings_obj.parent
    elif session_obj is not None:
        index_dir = session_obj.parent
    if index_dir is None:
        return None

    safe = (target or "unknown").replace("https://", "").replace("http://", "").replace("/", "_")[:40]
    index_path = index_dir / f"INDEX_{safe}.md"
    index_json_path = index_dir / f"INDEX_{safe}.json"

    report_abs = str(report_obj.absolute()) if report_obj is not None else ""
    html_abs = str(html_obj.absolute()) if html_obj is not None else ""
    findings_abs = str(findings_obj.absolute()) if findings_obj is not None else ""
    session_abs = str(session_obj.absolute()) if session_obj is not None else ""
    summary = findings_snapshot.summary or ""
    findings_brief = list(findings_snapshot.findings_brief)

    markdown = (
        f"# Bingo Session Index\n\n"
        f"- target: `{target}`\n"
        f"- updated: `{updated_at}`\n"
        f"- report: `{report_abs or 'N/A'}`\n"
        f"- html_report: `{html_abs or 'N/A'}`\n"
        f"- findings: `{findings_abs or 'N/A'}`\n"
        f"- session: `{session_abs or 'N/A'}`\n"
        f"- summary: {summary or 'no findings'}\n\n"
        f"## Findings Snapshot\n\n"
    )
    if findings_brief:
        for finding in findings_brief:
            confidence = "CONFIRMED" if finding.get("confirmed") else "unconfirmed"
            markdown += (
                f"- [{finding.get('severity','?')}] {finding.get('vuln_type','?')} "
                f"— {finding.get('title','')} ({confidence})\n"
            )
    else:
        markdown += "- (none)\n"

    report_appendix = (
        f"\n\n---\n## Converged Artifacts\n\n"
        f"- INDEX: `{index_path}`\n"
        f"- HTML Report: `{html_abs or 'N/A'}`\n"
        f"- Findings JSON: `{findings_abs or 'N/A'}`\n"
        f"- Session log: `{session_abs or 'N/A'}`\n"
        f"- Summary: {summary or 'no findings'}\n"
    )
    if findings_brief:
        report_appendix += "\n### Findings Snapshot\n\n"
        for finding in findings_brief:
            confidence = "CONFIRMED" if finding.get("confirmed") else "unconfirmed"
            report_appendix += (
                f"- [{finding.get('severity','?')}] {finding.get('vuln_type','?')} "
                f"— {finding.get('title','')} ({confidence})\n"
            )

    session_pointer = (
        "=== CONVERGED ARTIFACTS ===\n"
        f"INDEX: {index_path}\n"
        f"REPORT: {report_abs or 'N/A'}\n"
        f"HTML_REPORT: {html_abs or 'N/A'}\n"
        f"FINDINGS: {findings_abs or 'N/A'}\n"
        f"SUMMARY: {summary or 'no findings'}\n"
        "=== END CONVERGED ==="
    )

    return ArtifactConvergencePlan(
        index_path=index_path,
        index_json_path=index_json_path,
        markdown=markdown,
        payload={
            "target": target,
            "updated_at": updated_at,
            "report": report_abs,
            "html_report": html_abs,
            "findings": findings_abs,
            "session": session_abs,
            "summary": summary,
            "findings_snapshot": findings_brief,
        },
        report_appendix=report_appendix,
        session_pointer=session_pointer,
    )


def filter_verified_report_credentials(session_credentials: list) -> list:
    """Keep only credentials with enough structure for report output."""
    filtered: list = []
    for item in session_credentials or []:
        if isinstance(item, dict):
            lowered = {str(k).lower(): str(v).strip() for k, v in item.items()}
            user = lowered.get("username") or lowered.get("user") or lowered.get("mb_id") or lowered.get("id")
            password = lowered.get("password") or lowered.get("passwd") or lowered.get("pwd") or lowered.get("mb_password")
            verified = str(
                lowered.get("verified")
                or lowered.get("success")
                or lowered.get("status")
                or lowered.get("source")
                or lowered.get("evidence")
                or ""
            ).lower()
            if user and password:
                filtered.append(item)
            elif password and any(tok in verified for tok in ("confirmed", "success", "dump", "extract", "valid")):
                filtered.append(item)
            continue

        text = str(item).strip()
        if not text:
            continue
        low = text.lower()
        has_user = bool(re.search(r"\b(?:user(?:name)?|mb_id|login|account)\b\s*[:=]", low))
        has_pass = bool(re.search(r"\b(?:pass(?:word)?|passwd|pwd|mb_password)\b\s*[:=]", low))
        verified_text = bool(
            re.search(
                r"confirmed|login\s+success|valid\s+credential|credential\s+extracted|"
                r"dumped|extracted|로그인\s*성공|登录成功|凭据提取",
                low,
            )
        )
        if has_user and has_pass and verified_text:
            filtered.append(item)
    return filtered


def validate_report_finding_ids(report: str, findings: list) -> tuple[bool, list[str]]:
    """Reject report claims that are not backed by an active Finding ID."""
    active = [
        finding
        for finding in findings
        if getattr(finding, "confidence", "") not in ("blocked", "quarantined")
    ]
    allowed_ids = {str(getattr(finding, "id", "")) for finding in active}
    findings_by_id = {
        str(getattr(finding, "id", "")): finding
        for finding in active
    }
    allowed_types = {str(getattr(finding, "vuln_type", "")) for finding in active}
    aliases = {
        "sqli": r"sqli|sql\s*(?:injection|注入|인젝션)",
        "xss": r"\bxss\b|cross.?site|跨站脚本|크로스.?사이트",
        "ssrf": r"\bssrf\b|服务端请求伪造|서버.?사이드.?요청",
        "lfi": r"\b(?:lfi|rfi)\b|文件包含|파일.?포함",
        "rce": r"\brce\b|remote.?code.?execution|远程代码执行|원격.?코드.?실행",
        "auth_bypass": r"auth.?bypass|认证绕过|인증.?우회",
        "credential": r"credential|凭据|자격.?증명",
        "info_disclosure": r"information.?disclosure|信息泄露|정보.?노출",
        "open_redirect": r"open.?redirect|开放重定向|오픈.?리다이렉트",
        "idor": r"\bidor\b|水平越权|수평.?권한",
        "cors": r"\bcors\b",
        "csrf": r"\bcsrf\b",
    }
    unsupported: list[str] = []
    item_pattern = re.compile(
        r"(?ms)^\s*\d+[.)]\s*\*\*(.+?)\*\*(.*?)(?=^\s*\d+[.)]\s*\*\*|^##\s|\Z)"
    )
    for match in item_pattern.finditer(report or ""):
        title, body = match.group(1), match.group(2)
        segment = title + "\n" + body
        item_types = {
            vuln_type
            for vuln_type, pattern in aliases.items()
            if re.search(pattern, title, re.I)
        }
        for vuln_type in item_types:
            if vuln_type not in allowed_types:
                unsupported.append(f"unsupported_type:{vuln_type}")
        ids = set(re.findall(r"BINGO-(?:Q)?\d{4}", segment, re.I))
        if not ids:
            unsupported.append(f"missing_finding_id:{title[:40]}")
        elif not ids.issubset(allowed_ids):
            unsupported.append(f"unknown_finding_id:{','.join(sorted(ids - allowed_ids))}")
        else:
            unresolved_ids = {
                finding_id
                for finding_id in ids
                if getattr(findings_by_id[finding_id], "confidence", "") != "confirmed"
            }
            explicitly_unconfirmed = bool(
                re.search(
                    r"\b(?:potential|probable|unconfirmed|candidate)\b"
                    r"|미확정|잠재|추정|待验证|潜在|未确认",
                    segment,
                    re.I,
                )
            )
            if unresolved_ids and not explicitly_unconfirmed:
                unsupported.append(
                    f"unconfirmed_claim:{','.join(sorted(unresolved_ids))}"
                )
    if not allowed_ids and item_pattern.search(report or ""):
        unsupported.append("claims_without_findings")
    return not unsupported, sorted(set(unsupported))


def build_fallback_report(
    target: str,
    lang: str,
    *,
    confirmed_count: int,
    potential_count: int,
    ground_truth: str,
    session_credentials: list,
) -> str:
    labels = {
        "ko": ("요약", "발견된 취약점", "증거 (페이로드)", "추출된 자격증명", "권고 조치"),
        "zh": ("摘要", "发现的漏洞", "证据（载荷）", "提取的凭据", "修复建议"),
        "en": ("Summary", "Vulnerabilities Found", "Evidence (Payloads)", "Credentials Extracted", "Recommended Fix"),
    }
    summary, vulns, evidence, creds, fixes = labels.get(lang, labels["en"])
    no_creds = {
        "ko": "- 이번 세션에서 확인된 자격증명 없음",
        "zh": "- 本次会话未确认凭据",
        "en": "- No credentials confirmed in this session",
    }
    fallback_note = {
        "ko": "모델 보고서 생성 실패로 로컬 증거 기반 fallback 보고서를 생성했습니다.",
        "zh": "报告模型不可用，已根据本地证据生成 fallback 报告。",
        "en": "The report model was unavailable; this fallback was generated from local evidence.",
    }.get(lang, "Fallback report generated from local evidence.")
    metrics = {
        "ko": ("확정", "추정/잠재"),
        "zh": ("已确认", "推定/潜在"),
        "en": ("Confirmed", "Probable/Potential"),
    }.get(lang, ("Confirmed", "Probable/Potential"))
    session_credentials = filter_verified_report_credentials(session_credentials)
    credential_lines = (
        "\n".join(f"- {item}" for item in session_credentials)
        if session_credentials else no_creds.get(lang, no_creds["en"])
    )
    truth_lines = [
        line.strip()
        for line in ground_truth.splitlines()
        if line.strip().startswith("- id=")
    ]
    confirmed_truth = [line for line in truth_lines if "tier=confirmed" in line]
    backlog_truth = [line for line in truth_lines if "tier=confirmed" not in line]
    backlog_blob = "\n".join(backlog_truth).lower()
    lang_strings = get_strings(lang)

    def report_msg(key: str, default: str) -> str:
        value = lang_strings.get(key, default)
        if isinstance(value, dict):
            return value.get(lang, value.get("en", default))
        return str(value)

    def fallback_fix_lines() -> str:
        if not backlog_truth:
            return "- " + report_msg(
                "report_fix_no_verified",
                "No verified vulnerabilities. Maintain defensive baselines.",
            ) + "\n"
        lines: list[str] = []
        if "tier=blocked" in backlog_blob:
            lines.append(report_msg(
                "report_fix_blocked",
                "Re-establish a clean baseline/session for blocked items.",
            ))
        if "xss" in backlog_blob and ("quarantined" in backlog_blob or "potential" in backlog_blob):
            lines.append(report_msg(
                "report_fix_xss_browser",
                "Confirm XSS candidates with browser execution evidence.",
            ))
        if "sqli" in backlog_blob and ("tier=probable" in backlog_blob or "tier=potential" in backlog_blob):
            lines.append(report_msg(
                "report_fix_sqli_crosscheck",
                "Re-test SQLi candidates with stable controls.",
            ))
        if not lines:
            lines.append(report_msg(
                "report_fix_backlog_generic",
                "Re-test backlog items according to their evidence tier.",
            ))
        return "\n".join(f"- {line.lstrip('- ')}" for line in lines) + "\n"

    fix_lines = fallback_fix_lines()
    no_verified = {
        "ko": "- 확인된 취약점 없음",
        "zh": "- 未确认漏洞",
        "en": "- No verified vulnerabilities",
    }.get(lang, "- No verified vulnerabilities")
    backlog_label = {
        "ko": "검증 대기 항목 (취약점 미확정)",
        "zh": "待验证项目（未确认漏洞）",
        "en": "Verification Backlog (Unconfirmed)",
    }.get(lang, "Verification Backlog (Unconfirmed)")
    verified_text = "\n".join(confirmed_truth) or no_verified
    backlog_text = "\n".join(backlog_truth) or "- None"
    evidence_text = {
        "ko": "- 확정되지 않은 관찰은 아래 검증 대기 목록에만 표시했습니다.",
        "zh": "- 未确认的观察仅保留在下面的待验证列表中。",
        "en": "- Unconfirmed observations are kept only in the verification backlog below.",
    }.get(lang, "- Unconfirmed observations are kept only in the verification backlog below.")
    return (
        f"# Target: {target}\n"
        f"## {summary}\n"
        f"{fallback_note}\n"
        f"- {metrics[0]}: {confirmed_count}\n"
        f"- {metrics[1]}: {potential_count}\n\n"
        f"## {vulns}\n{verified_text}\n\n"
        f"## {evidence}\n{evidence_text}\n\n"
        f"## {backlog_label}\n{backlog_text}\n\n"
        f"## {creds}\n{credential_lines}\n\n"
        f"## {fixes}\n{fix_lines}"
    )


def build_html_report(
    md_text: str,
    *,
    target: str,
    confirmed_count: int = 0,
    potential_count: int = 0,
    generated_at: str | None = None,
) -> str:
    """Render the evidence-gated markdown report as a standalone HTML file."""
    import html
    from datetime import datetime as _dt

    generated_at = generated_at or _dt.now().strftime("%Y-%m-%d %H:%M:%S")
    safe_target = html.escape(target or "unknown")

    def inline(text: str) -> str:
        out = html.escape(text)
        out = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", out)
        out = re.sub(r"`([^`]+)`", r"<code>\1</code>", out)
        out = re.sub(
            r"\b(BINGO-(?:Q)?\d{4})\b",
            r'<span class="finding-id">\1</span>',
            out,
        )
        severity_map = {
            "Critical": "critical",
            "CRITICAL": "critical",
            "High": "high",
            "HIGH": "high",
            "Medium": "medium",
            "MEDIUM": "medium",
            "Low": "low",
            "LOW": "low",
            "Confirmed": "confirmed",
            "CONFIRMED": "confirmed",
            "Potential": "potential",
            "POTENTIAL": "potential",
            "Probable": "potential",
            "PROBABLE": "potential",
            "Unconfirmed": "unconfirmed",
            "UNCONFIRMED": "unconfirmed",
        }
        for word, css_class in severity_map.items():
            out = re.sub(
                rf"(?<![>\w-]){re.escape(word)}(?![\w-])",
                f'<span class="badge {css_class}">{word}</span>',
                out,
            )
        return out

    body: list[str] = []
    in_ul = False
    in_code = False
    in_section = False
    code_lines: list[str] = []

    def close_ul() -> None:
        nonlocal in_ul
        if in_ul:
            body.append("</ul>")
            in_ul = False

    def close_section() -> None:
        nonlocal in_section
        close_ul()
        if in_section:
            body.append("</section>")
            in_section = False

    for raw in (md_text or "").splitlines():
        line = raw.rstrip()
        if line.strip().startswith("```"):
            if in_code:
                body.append("<pre><code>" + html.escape("\n".join(code_lines)) + "</code></pre>")
                code_lines = []
                in_code = False
            else:
                close_ul()
                in_code = True
                code_lines = []
            continue
        if in_code:
            code_lines.append(line)
            continue
        if not line.strip():
            close_ul()
            continue

        heading = re.match(r"^(#{1,3})\s+(.+)$", line)
        if heading:
            close_section()
            level = min(len(heading.group(1)), 3)
            title = inline(heading.group(2).strip())
            if level == 1:
                body.append(f'<h1 class="md-title">{title}</h1>')
            else:
                body.append(f'<section class="report-card"><h{level}>{title}</h{level}>')
                in_section = True
            continue

        bullet = re.match(r"^\s*[-*]\s+(.+)$", line)
        if bullet:
            if not in_ul:
                body.append("<ul>")
                in_ul = True
            body.append(f"<li>{inline(bullet.group(1).strip())}</li>")
            continue

        numbered = re.match(r"^\s*(\d+)[.)]\s+(.+)$", line)
        if numbered:
            if not in_ul:
                body.append("<ul>")
                in_ul = True
            body.append(
                f'<li><span class="step-no">{numbered.group(1)}</span> '
                f"{inline(numbered.group(2).strip())}</li>"
            )
            continue

        body.append(f"<p>{inline(line)}</p>")

    if in_code:
        body.append("<pre><code>" + html.escape("\n".join(code_lines)) + "</code></pre>")
    close_section()

    html_body = "\n".join(body)
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Bingo Security Report - {safe_target}</title>
  <style>
    :root {{
      --bg: #071018;
      --card: rgba(13, 22, 35, .86);
      --card2: rgba(8, 15, 26, .92);
      --line: rgba(108, 255, 178, .24);
      --mint: #6cffb2;
      --blue: #35d6ff;
      --violet: #b388ff;
      --yellow: #ffd600;
      --red: #ff4d6d;
      --text: #e8f3ff;
      --muted: #8ea1b7;
      --shadow: 0 24px 80px rgba(0, 0, 0, .45);
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      color: var(--text);
      background:
        radial-gradient(circle at 15% 12%, rgba(53, 214, 255, .18), transparent 30%),
        radial-gradient(circle at 85% 8%, rgba(179, 136, 255, .20), transparent 28%),
        radial-gradient(circle at 50% 95%, rgba(108, 255, 178, .10), transparent 36%),
        var(--bg);
      font: 15px/1.65 -apple-system, BlinkMacSystemFont, "Segoe UI", Inter, Roboto, sans-serif;
      min-height: 100vh;
    }}
    .shell {{ width: min(1120px, calc(100vw - 40px)); margin: 34px auto 56px; }}
    .hero {{
      border: 1px solid var(--line);
      background: linear-gradient(145deg, rgba(13,22,35,.96), rgba(7,16,24,.82));
      border-radius: 28px;
      padding: 30px;
      box-shadow: var(--shadow);
      position: relative;
      overflow: hidden;
    }}
    .hero:before {{
      content: "";
      position: absolute;
      inset: 0;
      background: linear-gradient(90deg, transparent, rgba(108,255,178,.08), transparent);
      transform: translateX(-70%);
      pointer-events: none;
    }}
    .brand {{ color: var(--mint); letter-spacing: .18em; font-size: 12px; font-weight: 800; }}
    .hero h1 {{ margin: 10px 0 8px; font-size: clamp(32px, 5vw, 54px); line-height: 1.05; }}
    .hero .target {{ color: var(--blue); word-break: break-all; }}
    .meta {{ color: var(--muted); display: flex; gap: 14px; flex-wrap: wrap; }}
    .metrics {{ display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 14px; margin: 18px 0 24px; }}
    .metric {{
      border: 1px solid rgba(53, 214, 255, .18);
      background: var(--card);
      border-radius: 18px;
      padding: 16px 18px;
    }}
    .metric .label {{ color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: .12em; }}
    .metric .value {{ font-size: 28px; font-weight: 800; margin-top: 4px; }}
    .metric.confirmed .value {{ color: var(--mint); }}
    .metric.potential .value {{ color: var(--yellow); }}
    .metric.mode .value {{ color: var(--violet); font-size: 20px; }}
    .report-card {{
      border: 1px solid rgba(108, 255, 178, .18);
      background: var(--card2);
      border-radius: 22px;
      padding: 22px 24px;
      margin: 16px 0;
      box-shadow: 0 18px 54px rgba(0,0,0,.26);
    }}
    .report-card h2, .report-card h3 {{ margin: 0 0 14px; color: var(--blue); }}
    .md-title {{ display: none; }}
    p {{ margin: 10px 0; }}
    ul {{ margin: 8px 0 0; padding: 0; list-style: none; }}
    li {{ margin: 9px 0; padding-left: 24px; position: relative; }}
    li:before {{ content: "▸"; position: absolute; left: 0; color: var(--mint); }}
    code {{
      color: #d6faff;
      background: rgba(53, 214, 255, .10);
      border: 1px solid rgba(53, 214, 255, .14);
      border-radius: 7px;
      padding: 1px 6px;
    }}
    pre {{
      overflow: auto;
      border-radius: 16px;
      padding: 16px;
      background: #050b12;
      border: 1px solid rgba(108, 255, 178, .16);
    }}
    pre code {{ background: transparent; border: 0; padding: 0; color: #d9fff0; }}
    strong {{ color: #ffffff; }}
    .finding-id {{
      display: inline-block;
      color: #061018;
      background: linear-gradient(90deg, var(--mint), var(--blue));
      border-radius: 999px;
      padding: 1px 8px;
      font-weight: 800;
      letter-spacing: .03em;
    }}
    .badge {{
      display: inline-block;
      border-radius: 999px;
      padding: 1px 8px;
      font-size: .82em;
      font-weight: 800;
      border: 1px solid currentColor;
    }}
    .badge.critical {{ color: var(--red); }}
    .badge.high {{ color: var(--yellow); }}
    .badge.medium {{ color: #ff9f43; }}
    .badge.low {{ color: var(--blue); }}
    .badge.confirmed {{ color: var(--mint); }}
    .badge.potential, .badge.unconfirmed {{ color: var(--yellow); }}
    .step-no {{ color: var(--violet); font-weight: 800; margin-right: 6px; }}
    footer {{ margin-top: 24px; color: var(--muted); text-align: center; font-size: 12px; }}
    @media (max-width: 780px) {{
      .shell {{ width: min(100vw - 24px, 1120px); margin-top: 16px; }}
      .hero {{ padding: 22px; border-radius: 22px; }}
      .metrics {{ grid-template-columns: 1fr; }}
    }}
    @media print {{
      body {{ background: white; color: #121821; }}
      .hero, .metric, .report-card {{ box-shadow: none; background: white; color: #121821; }}
      .report-card, .metric, .hero {{ border-color: #cfd8e3; }}
    }}
  </style>
</head>
<body>
  <main class="shell">
    <header class="hero">
      <div class="brand">BINGO · SECURITY REPORT</div>
      <h1>Evidence-driven assessment</h1>
      <div class="target">{safe_target}</div>
      <div class="meta">
        <span>Generated: {html.escape(generated_at)}</span>
        <span>Report truth: Finding-ID ledger</span>
      </div>
    </header>
    <section class="metrics">
      <div class="metric confirmed"><div class="label">Confirmed</div><div class="value">{int(confirmed_count)}</div></div>
      <div class="metric potential"><div class="label">Probable / Potential</div><div class="value">{int(potential_count)}</div></div>
      <div class="metric mode"><div class="label">Mode</div><div class="value">Hybrid AI-led</div></div>
    </section>
    {html_body}
    <footer>Generated by bingo · Markdown and HTML reports share the same evidence-gated source.</footer>
  </main>
</body>
</html>
"""


def build_evidence_based_next_steps(
    lang: str,
    flags: Mapping[str, object] | dict,
    *,
    confirmed_count: int = 0,
    potential_count: int = 0,
) -> NextStepPlan:
    blocked = int(flags.get("blocked_count", 0) or 0)
    has_potential_sqli = bool(
        flags.get("has_potential_sqli") or potential_count > 0 or blocked > 0
    )
    has_admin_panel = bool(flags.get("has_admin_panel"))

    if lang == "zh":
        if confirmed_count > 0:
            summary = "已有 confirmed 级别发现；下一步应围绕已确认证据继续扩展验证。"
        elif has_potential_sqli:
            summary = "当前没有 confirmed 级别漏洞；现有 SQLi/WAF 迹象只能作为未确认验证队列处理，不能使用 DB/哈希/shell/高权限控制已完成的表述。"
        else:
            summary = "当前没有 confirmed 级别漏洞；下一步应重新建立 baseline 并寻找新的可验证输入面。"
        options = [
            "重新校准目标页面 baseline 后复测 SQLi/WAF oracle，要求稳定 TRUE/FALSE 或时间差证据",
            "枚举同一域名下的 JS/API 端点，寻找新的参数和未授权接口",
            "对登录后对象 ID、订单号、 게시판 wr_id 等参数做 IDOR 边界验证",
            "切换到 LFI/路径遍历候选复测，但只有出现目标文件内容时才升级为发现",
            "检查公开后台路径可访问性并记录状态，不假设默认凭据或已取得管理员权限",
        ]
    elif lang == "ko":
        if confirmed_count > 0:
            summary = "confirmed 등급 발견이 있으므로, 다음 단계는 확정 증거를 기준으로 확장 검증해야 한다."
        elif has_potential_sqli:
            summary = "현재 confirmed 취약점은 없다. SQLi/WAF 징후는 미확정 검증 대기 항목이며 DB, 해시, shell, 관리자 권한 획득으로 쓰면 안 된다."
        else:
            summary = "현재 confirmed 취약점은 없다. baseline을 다시 잡고 검증 가능한 새 입력면을 찾아야 한다."
        options = [
            "목표 페이지 baseline을 재보정한 뒤 SQLi/WAF oracle을 재검증한다",
            "같은 도메인의 JS/API 엔드포인트를 열거해 새 파라미터와 미인증 인터페이스를 찾는다",
            "로그인 후 객체 ID, 주문번호, 게시판 wr_id 계열 파라미터로 IDOR 경계를 검증한다",
            "LFI/경로순회 후보를 재검증하되 실제 파일 내용이 나올 때만 발견으로 승격한다",
            "공개 관리자 경로 접근성만 확인하고 기본 자격증명이나 관리자 획득은 가정하지 않는다",
        ]
    else:
        if confirmed_count > 0:
            summary = "Confirmed findings exist; continue from the verified evidence only."
        elif has_potential_sqli:
            summary = "No confirmed vulnerability exists yet. SQLi/WAF signals are unconfirmed verification backlog items, not proof of database, hash, shell, or admin access."
        else:
            summary = "No confirmed vulnerability exists yet. Rebuild the baseline and look for new independently verifiable input surfaces."
        options = [
            "Recalibrate the target baseline, then re-test SQLi/WAF oracle with stable TRUE/FALSE or timing evidence",
            "Enumerate same-domain JS/API endpoints for new parameters and unauthenticated interfaces",
            "Verify IDOR boundaries on authenticated object IDs, order IDs, and board record IDs",
            "Re-test LFI/path traversal candidates and promote only when exact target file content appears",
            "Check public admin-path reachability only; do not assume default credentials or admin access",
        ]

    if not has_admin_panel:
        options = [
            option.replace(
                "检查公开后台路径可访问性并记录状态，不假设默认凭据或已取得管理员权限",
                "枚举公开管理路径是否存在；若仅有登录页，只记录为 login_form_only",
            )
            .replace(
                "공개 관리자 경로 접근성만 확인하고 기본 자격증명이나 관리자 획득은 가정하지 않는다",
                "공개 관리자 경로 존재 여부만 확인한다. 로그인 페이지만 있으면 login_form_only로 기록한다",
            )
            .replace(
                "Check public admin-path reachability only; do not assume default credentials or admin access",
                "Enumerate public admin paths; if only a login page exists, record login_form_only",
            )
            for option in options
        ]
    return NextStepPlan(summary=summary, options=tuple(options))


def build_report_generation_prompt(
    *,
    target: str,
    lang: str,
    known_state: object,
    recent_findings_context: str,
    ground_truth_prompt_block: str,
    session_snapshot: ReportSessionSnapshot,
) -> str:
    lang_label = {
        "ko": "Korean",
        "zh": "Chinese (Simplified)",
        "en": "English",
    }.get(lang, "English")
    section_labels = {
        "summary": {"ko": "요약", "zh": "摘要", "en": "Summary"},
        "vulns": {"ko": "발견된 취약점", "zh": "发现的漏洞", "en": "Vulnerabilities Found"},
        "evidence": {"ko": "증거 (페이로드)", "zh": "证据（载荷）", "en": "Evidence (Payloads)"},
        "creds": {"ko": "추출된 자격증명", "zh": "提取的凭据", "en": "Credentials Extracted"},
        "fix": {"ko": "권고 조치", "zh": "修复建议", "en": "Recommended Fix"},
    }

    def section(key: str) -> str:
        mapping = section_labels[key]
        return mapping.get(lang, mapping["en"])

    return (
        "[GENERATE FINAL PENTEST REPORT]\n\n"
        f"Target: {target}\n"
        f"Known state: {known_state}\n"
        f"{session_snapshot.origin_note}\n"
        f"{ground_truth_prompt_block}\n"
        f"Recent findings:\n{recent_findings_context}\n\n"
        f"Write a concise penetration test report in {lang_label}.\n"
        "Use EXACTLY these section headers:\n"
        f"# Target: {target}\n"
        f"## {section('summary')}\n"
        f"## {section('vulns')} (severity: Critical/High/Medium/Low)\n"
        f"## {section('evidence')}\n"
        f"## {section('creds')}\n"
        f"## {section('fix')}\n\n"
        "Every vulnerability item MUST include its exact BINGO finding ID. "
        "Do not add a vulnerability type, URL, parameter, or evidence absent from FINDINGS GROUND TRUTH.\n"
        "The vulnerabilities section may contain tier=confirmed items ONLY. "
        "Put probable/potential items in the evidence section and label each explicitly Unconfirmed/Potential.\n"
        "NO code blocks. Plain markdown only. Be concise."
    )


def next_step_panel_title(lang: str) -> str:
    return {
        "ko": "다음 권장 단계",
        "zh": "建议下一步",
        "en": "Suggested next steps",
    }.get(lang, "Suggested next steps")


def build_next_step_prompt(
    *,
    target: str,
    current_state: object,
    lang: str,
    recent_context: str,
    ground_truth: str,
    evidence_flags: Mapping[str, object] | dict,
    summary_label: str,
    options_label: str,
    option_hint: str,
) -> str:
    lang_label = {
        "ko": "Korean",
        "zh": "Chinese (Simplified)",
        "en": "English",
    }.get(lang, "English")
    safe_hints: list[str] = []
    if evidence_flags.get("has_upload"):
        safe_hints.append("webshell upload (upload form confirmed)")
    if evidence_flags.get("has_real_cred"):
        safe_hints.append("password cracking / credential reuse (real hash/cred confirmed)")
    if evidence_flags.get("has_confirmed_sqli"):
        safe_hints.append("deep SQLi extraction (SQLi CONFIRMED)")
    elif evidence_flags.get("has_potential_sqli") or evidence_flags.get("blocked_count"):
        safe_hints.append(
            "CONTINUE SQLi verification / WAF bypass (potential or blocked — DO NOT abandon)"
        )
    else:
        safe_hints.append("re-validate boolean oracle / WAF bypass (SQLi NOT confirmed)")
    safe_hints.extend(
        [
            "API endpoint fuzzing / unauthenticated API",
            "IDOR privilege escalation",
            "ACPV client-side auth bypass",
        ]
    )
    untested_hint = "; ".join(safe_hints)

    return (
        "[NEXT STEP SUGGESTIONS — PENTEST CONTINUATION]\n\n"
        f"Target: {target}\n"
        f"Current state: {current_state}\n\n"
        f"⚠️ FINDINGS GROUND TRUTH (DO NOT CONTRADICT):\n{ground_truth or '(none)'}\n\n"
        f"Evidence flags: {dict(evidence_flags)}\n"
        "HARD RULES:\n"
        "- If confirmed=0: summary MUST say UNCONFIRMED / 未确认, NEVER 已确认/Confirmed Critical.\n"
        "- Do NOT suggest webshell upload unless has_upload=true.\n"
        "- Do NOT suggest credential stuffing / 撞库 / mb_id 'aaa' unless has_real_cred=true.\n"
        "- Do NOT treat WAF 490B blocks as confirmed SQLi.\n\n"
        f"Recent activity:\n{recent_context}\n\n"
        f"Hint — potentially useful next actions: {untested_hint}\n\n"
        "INSTRUCTIONS (CRITICAL — follow EXACTLY):\n"
        "1. Plain text ONLY. NO code blocks. NO markdown headers (#).\n"
        f"2. Respond ENTIRELY in {lang_label}.\n"
        "3. Output in EXACTLY this format (nothing else):\n\n"
        f"{summary_label}: [1-2 sentences about current status]\n\n"
        f"{options_label}:\n"
        f"1. [{option_hint}]\n"
        f"2. [{option_hint}]\n"
        f"3. [{option_hint}]\n"
        f"4. [{option_hint}]\n"
        f"5. [{option_hint}]"
    )


def parse_next_step_response(
    text: str,
    *,
    option_markers: tuple[str, ...] = (),
) -> NextStepSuggestion:
    if not text:
        return NextStepSuggestion(raw_text=str(text or ""))

    lines = str(text).strip().splitlines()
    options: list[str] = []
    summary_lines: list[str] = []
    in_options = False
    markers = tuple(option_markers or ())

    for line in lines:
        stripped = line.strip()
        if any(stripped.startswith(marker) for marker in markers if marker):
            in_options = True
            continue
        if in_options:
            match = re.match(r"^[①②③④⑤1-5][\.\)]\s*(.+)$", stripped)
            if match:
                options.append(match.group(1).strip())
            elif re.match(r"^[①②③④⑤]", stripped):
                options.append(re.sub(r"^[①②③④⑤]\s*", "", stripped))
        elif stripped:
            summary_lines.append(stripped)

    if not options:
        for line in lines:
            match = re.match(r"^[①②③④⑤1-5][\.\)\s]+(.+)$", line.strip())
            if match:
                options.append(match.group(1).strip())

    return NextStepSuggestion(
        summary_lines=tuple(summary_lines),
        options=tuple(options),
        raw_text=str(text or "").strip(),
    )


def sanitize_next_step_summary(
    summary: str,
    flags: Mapping[str, object] | dict,
    lang: str,
    *,
    confirmed_count: int = 0,
    potential_count: int = 0,
    claim_sanitizer: Callable[[str, int, int], str],
) -> str:
    if not summary:
        return summary

    out = claim_sanitizer(summary, confirmed_count, potential_count)
    if confirmed_count > 0:
        return out

    unsupported_takeover_claim = bool(
        re.search(
            r"(?:已通过|通过|获取|获得|拿到|提取|导出|dump(?:ed)?|extract(?:ed)?|"
            r"obtain(?:ed)?|acquir(?:ed|e)|획득|추출|덤프|확보)"
            r".{0,80}"
            r"(?:数据库|DB\b|database|SinkDB|g5_member|哈希|hash|管理员|admin|"
            r"凭据|credential|shell|webshell|관리자|해시|자격증명)",
            out,
            re.I,
        )
    )
    unsupported_access_claim = bool(
        re.search(
            r"(?:shell|webshell|RCE|命令执行|系统命令|관리자|admin\s+access|"
            r"管理员权限|root\s+shell|os-shell)",
            out,
            re.I,
        )
    )
    if unsupported_takeover_claim or unsupported_access_claim:
        return build_evidence_based_next_steps(
            lang,
            flags,
            confirmed_count=confirmed_count,
            potential_count=potential_count,
        ).summary
    return out


def filter_next_steps_by_evidence(options: list[str], flags: Mapping[str, object] | dict) -> list[str]:
    """Remove post-exploit suggestions that outrun current evidence."""
    if not options:
        return options
    out: list[str] = []
    keep_sqli = bool(
        flags.get("has_confirmed_sqli")
        or flags.get("has_potential_sqli")
        or flags.get("blocked_count")
    )
    has_confirmed_sqli = bool(flags.get("has_confirmed_sqli"))
    has_real_cred = bool(flags.get("has_real_cred"))
    has_upload = bool(flags.get("has_upload"))
    has_admin_panel = bool(flags.get("has_admin_panel"))
    for option in options:
        low = (option or "").lower()
        needs_confirmed_sqli = bool(
            re.search(
                r"os-?shell|--os-shell|xp_cmdshell|whoami|命令执行|系统命令|"
                r"rce\b|remote\s+code|getshell|反弹\s*shell|reverse\s+shell|"
                r"堆叠查询|stacked\s+quer|insert.{0,40}admin|admin\s+account|"
                r"插入.{0,40}管理员|新管理员|관리자.{0,20}생성|관리자.{0,20}삽입|"
                r"into\s+outfile|load_file\s*\(|写入|写文件|파일\s*쓰기",
                low,
                re.I,
            )
        )
        needs_extracted_secret = bool(
            re.search(
                r"获取.{0,30}数据库|提取.{0,30}数据库|导出.{0,30}数据库|"
                r"dump.{0,30}(?:db|database|table)|database\s+dump|"
                r"g5_member|mysql\.user|管理员.{0,20}哈希|admin.{0,20}hash|"
                r"password\s*hash|哈希|해시|hash\s+crack|비밀번호\s*크랙",
                low,
                re.I,
            )
        )
        if needs_confirmed_sqli and not (has_confirmed_sqli or has_upload):
            continue
        if needs_extracted_secret and not (has_confirmed_sqli or has_real_cred):
            continue
        needs_admin_or_cred_surface = bool(
            re.search(
                r"default\s+(?:cred|password)|默认凭据|默认密码|简单密码|弱口令|"
                r"admin/admin|credential\s*stuff|撞库|password\s*spray|brute\s*force|"
                r"기본\s*(?:암호|비밀번호)|약한\s*비밀번호",
                low,
                re.I,
            )
        )
        if needs_admin_or_cred_surface and not (has_admin_panel or has_real_cred):
            continue
        is_sqli_path = bool(
            re.search(
                r"sqli|sql\s*注入|布尔|블라인드|blind|oracle|waf|우회|绕过"
                r"|benchmark|sleep|extractvalue|updatexml|substring|时间\s*맹",
                low,
                re.I,
            )
        )
        if is_sqli_path:
            if not flags.get("has_confirmed_sqli"):
                option = re.sub(
                    r"已确认|confirmed\s+sqli|확인된\s*sqli",
                    "潜在(potential)",
                    option,
                    flags=re.I,
                )
            out.append(option)
            continue
        if re.search(
            r"webshell|웹쉘|web\s*shell|파일\s*업로드|upload\s*(?:shell|webshell|php|phtml)|phtml|getshell",
            low,
            re.I,
        ) and not flags.get("has_upload"):
            continue
        if re.search(
            r"撞库|credential\s*stuff|비밀번호\s*크랙|password\s*crack"
            r"|mb_id\s*[\'\"]?aaa|계정\s*[\'\"]?aaa[\'\"]?|default\s*password"
            r"|기본\s*암호|기본\s*비밀번호",
            low,
            re.I,
        ) and not flags.get("has_real_cred"):
            continue
        out.append(option)
    if not out:
        if keep_sqli:
            out = [
                "Re-test boolean oracle / WAF bypass (potential SQLi — do not drop)",
                "Try time-based or error-based extraction with signature evasion",
                "Enumerate JS/API endpoints for unauthenticated access",
            ]
        else:
            out = [
                "Enumerate JS/API endpoints for unauthenticated access",
                "Map application paths without assuming SQLi confirmed",
                "Recon auth/session surfaces",
            ]
    return out[:5]
