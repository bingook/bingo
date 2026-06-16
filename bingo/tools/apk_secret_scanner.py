"""
apk_secret_scanner.py — TruffleHog APK Scanner + Malimite iOS Decompiler
bingo v2.2.9

References:
  TruffleHog APK : https://trufflesecurity.com/blog/cracking-open-apk-files-at-scale
  Malimite        : https://github.com/LaurieWired/Malimite

Key technical notes (TruffleHog APK native mode):
  - Scans AndroidManifest.xml  → decoded from Android Binary XML via resources.arsc
  - Scans strings.xml          → reconstructed from resources.arsc (ID range 0x7f000000–0x7fffffff)
  - Scans DEX bytecode         → extracts const-string instructions with surrounding context
  - Scans all other files      → *.properties, *.json, sqlite, .git dirs, asset JS, etc.
  - ~9× faster than jadx + trufflehog filesystem (no full decompilation step)

Malimite (iOS/macOS):
  - Ghidra-based decompiler — native IPA / .app bundle support
  - Swift class reconstruction + Objective-C support
  - Built-in LLM method translation
  - Skips library code → faster, less noise
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


# ── Data Classes ──────────────────────────────────────────────────────────────

@dataclass
class SecretFinding:
    detector: str = ""
    raw: str = ""
    redacted: str = ""
    file: str = ""
    line: int = 0
    verified: bool = False
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "detector": self.detector,
            "raw": self.raw[:80],
            "redacted": self.redacted,
            "file": self.file,
            "line": self.line,
            "verified": self.verified,
        }


@dataclass
class APKScanResult:
    apk_path: str = ""
    package: str = ""
    method: str = ""        # "trufflehog" | "jadx+trufflehog" | "manual-regex"
    secrets: list[SecretFinding] = field(default_factory=list)
    raw_output: str = ""
    error: str = ""
    commands_used: list[str] = field(default_factory=list)

    def summary(self) -> str:
        lines = [
            "═" * 60,
            f"  APK Secret Scan — {Path(self.apk_path).name}",
            f"  Method  : {self.method}",
            f"  Secrets : {len(self.secrets)} found",
            "═" * 60,
        ]
        if self.secrets:
            for s in self.secrets:
                v = "✅" if s.verified else "⚠ "
                lines.append(f"  {v} [{s.detector}]  {s.redacted or s.raw[:70]}")
                lines.append(f"       @ {s.file}:{s.line}")
        else:
            lines.append("  No secrets detected.")
        if self.error:
            lines.append(f"\n  ⚠ Error: {self.error}")
        if self.commands_used:
            lines.append("\n  Commands used:")
            for c in self.commands_used:
                lines.append(f"    $ {c}")
        return "\n".join(lines)

    def to_dict(self) -> dict:
        return {
            "apk_path": self.apk_path,
            "method": self.method,
            "secrets_count": len(self.secrets),
            "secrets": [s.to_dict() for s in self.secrets],
            "error": self.error,
            "commands_used": self.commands_used,
        }


@dataclass
class MalimiteResult:
    ipa_path: str = ""
    output_dir: str = ""
    decompiled_files: list[str] = field(default_factory=list)
    swift_classes: list[str] = field(default_factory=list)
    objc_classes: list[str] = field(default_factory=list)
    interesting_methods: list[str] = field(default_factory=list)
    secrets: list[SecretFinding] = field(default_factory=list)
    error: str = ""
    commands_used: list[str] = field(default_factory=list)

    def summary(self) -> str:
        lines = [
            "═" * 60,
            f"  Malimite iOS Decompile — {Path(self.ipa_path).name}",
            f"  Output dir      : {self.output_dir}",
            f"  Decompiled files: {len(self.decompiled_files)}",
            f"  Swift classes   : {len(self.swift_classes)}",
            f"  ObjC classes    : {len(self.objc_classes)}",
            f"  Secrets found   : {len(self.secrets)}",
            "═" * 60,
        ]
        if self.interesting_methods:
            lines.append("  Interesting methods (security-related):")
            for m in self.interesting_methods[:15]:
                lines.append(f"    - {m}")
        if self.secrets:
            lines.append("\n  Secrets:")
            for s in self.secrets[:20]:
                v = "✅" if s.verified else "⚠ "
                lines.append(f"  {v} [{s.detector}]  {s.redacted or s.raw[:70]}")
                lines.append(f"       @ {s.file}:{s.line}")
        if self.error:
            lines.append(f"\n  ⚠ Error: {self.error}")
        if self.commands_used:
            lines.append("\n  Commands used:")
            for c in self.commands_used:
                lines.append(f"    $ {c}")
        return "\n".join(lines)

    def to_dict(self) -> dict:
        return {
            "ipa_path": self.ipa_path,
            "output_dir": self.output_dir,
            "decompiled_files": len(self.decompiled_files),
            "swift_classes": self.swift_classes[:50],
            "objc_classes": self.objc_classes[:50],
            "interesting_methods": self.interesting_methods[:30],
            "secrets_count": len(self.secrets),
            "secrets": [s.to_dict() for s in self.secrets[:50]],
            "error": self.error,
        }


# ── Helpers ───────────────────────────────────────────────────────────────────

def _which(cmd: str) -> str | None:
    return shutil.which(cmd)


def _run(cmd: list[str], timeout: int = 300, cwd: str | None = None) -> tuple[int, str, str]:
    try:
        p = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=timeout, cwd=cwd
        )
        return p.returncode, p.stdout, p.stderr
    except FileNotFoundError:
        return -1, "", f"Command not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return -1, "", f"Timeout after {timeout}s"
    except Exception as e:
        return -1, "", str(e)


def _find_malimite_jar() -> str | None:
    """Locate Malimite.jar in common paths or via MALIMITE_JAR env var."""
    env = os.environ.get("MALIMITE_JAR", "")
    if env and Path(env).exists():
        return env

    candidates = [
        Path.home() / "tools" / "Malimite.jar",
        Path.home() / "Malimite" / "Malimite.jar",
        Path.home() / "Downloads" / "Malimite.jar",
        Path("/opt/Malimite/Malimite.jar"),
        Path("/usr/local/lib/Malimite.jar"),
        Path.home() / ".local" / "lib" / "Malimite.jar",
    ]
    for c in candidates:
        if c.exists():
            return str(c)
    return None


def check_tools() -> dict[str, Any]:
    """Check availability of all required tools."""
    trufflehog = _which("trufflehog")
    jadx = _which("jadx")
    java = _which("java")
    malimite_jar = _find_malimite_jar()

    # Check TruffleHog version
    th_version = ""
    if trufflehog:
        _, out, _ = _run(["trufflehog", "--version"])
        th_version = out.strip()

    return {
        "trufflehog": {
            "available": bool(trufflehog),
            "path": trufflehog or "not found",
            "version": th_version,
        },
        "jadx": {
            "available": bool(jadx),
            "path": jadx or "not found",
        },
        "java": {
            "available": bool(java),
            "path": java or "not found",
        },
        "malimite_jar": {
            "available": bool(malimite_jar),
            "path": malimite_jar or "not found — set MALIMITE_JAR env var",
        },
        "recommended_workflow": {
            "android_apk": "trufflehog filesystem <file.apk> --json (9x faster, no jadx needed)",
            "ios_ipa": "java -jar Malimite.jar <file.ipa> --output ./out/ (Ghidra-based)",
        },
    }


# ── Fallback secret patterns (used when mobile_recon not available) ───────────

_FALLBACK_PATTERNS: dict[str, str] = {
    "AWS_ACCESS_KEY": r"AKIA[0-9A-Z]{16}",
    "AWS_SECRET_KEY": r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]",
    "GOOGLE_API_KEY": r"AIza[0-9A-Za-z\-_]{35}",
    "FIREBASE_URL": r"https://[a-z0-9-]+\.firebaseio\.com",
    "FIREBASE_API": r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}",
    "STRIPE_SK": r"sk_live_[0-9a-zA-Z]{24}",
    "STRIPE_PK": r"pk_live_[0-9a-zA-Z]{24}",
    "GITHUB_TOKEN": r"gh[pousr]_[A-Za-z0-9]{36,255}",
    "JWT": r"eyJ[A-Za-z0-9-_]{10,}\.[A-Za-z0-9-_]{10,}\.[A-Za-z0-9-_]{10,}",
    "PRIVATE_KEY": r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
    "GENERIC_API_KEY": r"(?i)api[_-]?key['\"\s:=]{1,5}['\"][A-Za-z0-9\-_]{16,}['\"]",
    "GENERIC_SECRET": r"(?i)(?:secret|password|passwd|token)['\"\s:=]{1,5}['\"][A-Za-z0-9\-_!@#$%]{8,}['\"]",
    "TWILIO": r"SK[0-9a-fA-F]{32}",
    "SLACK_TOKEN": r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}",
    "HEROKU_API": r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
}


def _get_secret_patterns() -> dict[str, str]:
    try:
        from bingo.tools.mobile_recon import SECRET_PATTERNS  # type: ignore
        return {**_FALLBACK_PATTERNS, **SECRET_PATTERNS}
    except ImportError:
        return _FALLBACK_PATTERNS


# ── TruffleHog JSON parser ────────────────────────────────────────────────────

def _parse_trufflehog_json(output: str) -> list[SecretFinding]:
    """Parse TruffleHog --json newline-delimited output."""
    findings: list[SecretFinding] = []
    for line in output.splitlines():
        line = line.strip()
        if not line or line[0] != "{":
            continue
        try:
            obj = json.loads(line)
            sm = obj.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {})
            f = SecretFinding(
                detector=obj.get("DetectorName", "Unknown"),
                raw=obj.get("Raw", ""),
                redacted=obj.get("Redacted", ""),
                verified=obj.get("Verified", False),
                file=sm.get("file", ""),
                line=sm.get("line", 0),
                extra=obj,
            )
            findings.append(f)
        except (json.JSONDecodeError, KeyError):
            continue
    return findings


# ── TruffleHog APK Scanner ────────────────────────────────────────────────────

def scan_apk_trufflehog(apk_path: str, verify: bool = False) -> APKScanResult:
    """
    Scan APK for secrets using TruffleHog's native APK decoder.

    TruffleHog v3.63+ natively processes APK files without external decompilers:
      ① AndroidManifest.xml — Android Binary XML decoded via resources.arsc ResourceTable
      ② strings.xml         — reconstructed from resources.arsc ID range 0x7f000000–0x7fffffff
      ③ DEX bytecode        — const-string instructions with class/method context
      ④ All other assets    — *.json, *.properties, *.js, sqlite, .git dirs, etc.

    ~9× faster than the jadx + trufflehog method.

    Ref: https://trufflesecurity.com/blog/cracking-open-apk-files-at-scale
    """
    result = APKScanResult(apk_path=apk_path, method="trufflehog")

    if not Path(apk_path).exists():
        result.error = f"File not found: {apk_path}"
        return result

    if not _which("trufflehog"):
        result.error = "trufflehog not found — falling back to manual regex scan"
        return _scan_apk_manual(apk_path, result)

    cmd = ["trufflehog", "filesystem", apk_path, "--json"]
    if not verify:
        cmd.append("--no-verification")
    result.commands_used.append(" ".join(cmd))

    rc, stdout, stderr = _run(cmd, timeout=300)
    result.raw_output = stdout

    if stdout:
        result.secrets = _parse_trufflehog_json(stdout)
    elif rc != 0:
        result.error = stderr.strip() or f"Exit {rc}"
        return _scan_apk_manual(apk_path, result)

    return result


def scan_apk_jadx_trufflehog(apk_path: str, verify: bool = False) -> APKScanResult:
    """
    Old method: full jadx decompile → TruffleHog filesystem scan.

    More thorough than native APK scan (covers obfuscated paths native scan may miss)
    but approximately 9× slower due to full decompilation step.
    Use when native scan misses suspected secrets.
    """
    result = APKScanResult(apk_path=apk_path, method="jadx+trufflehog")

    if not Path(apk_path).exists():
        result.error = f"File not found: {apk_path}"
        return result

    if not _which("jadx"):
        result.error = "jadx not found. Install: brew install jadx"
        return result
    if not _which("trufflehog"):
        result.error = "trufflehog not found."
        return result

    with tempfile.TemporaryDirectory(prefix="bingo_jadx_") as tmpdir:
        # Step 1: decompile
        jadx_cmd = ["jadx", apk_path, "-d", tmpdir]
        result.commands_used.append(" ".join(jadx_cmd))
        _run(jadx_cmd, timeout=300)

        # Step 2: scan decompiled output
        th_flags = ["--json", "--no-verification"] if not verify else ["--json"]
        th_cmd = ["trufflehog", "filesystem", tmpdir] + th_flags
        result.commands_used.append(" ".join(th_cmd))
        _, stdout, _ = _run(th_cmd, timeout=300)

        result.raw_output = stdout
        result.secrets = _parse_trufflehog_json(stdout)

    return result


def _scan_apk_manual(apk_path: str, result: APKScanResult) -> APKScanResult:
    """
    Fallback: unzip APK and apply regex patterns.
    Used when TruffleHog is unavailable.
    Covers: *.xml, *.json, *.properties, *.js, *.html, *.txt
    """
    result.method = "manual-regex"
    patterns = _get_secret_patterns()

    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            for name in zf.namelist():
                # Focus on text-content files
                if not any(name.endswith(ext) for ext in (
                    ".xml", ".json", ".properties", ".txt",
                    ".js", ".html", ".gradle", ".yaml", ".yml",
                )):
                    continue
                try:
                    content = zf.read(name).decode("utf-8", errors="ignore")
                    for det, pat in patterns.items():
                        for m in re.finditer(pat, content):
                            raw = m.group(0)
                            redacted = raw[:6] + "****" + raw[-4:] if len(raw) > 14 else raw
                            result.secrets.append(SecretFinding(
                                detector=det,
                                raw=raw,
                                redacted=redacted,
                                file=name,
                                line=content[: m.start()].count("\n") + 1,
                            ))
                except Exception:
                    continue
    except zipfile.BadZipFile:
        result.error = (result.error + " | Invalid APK (bad zip)").lstrip(" | ")

    return result


# ── Malimite iOS Decompiler ───────────────────────────────────────────────────

_INTERESTING_METHOD_PATTERNS = [
    r"(?i)(password|passwd|secret|token|api[_-]?key|auth)",
    r"(?i)(encrypt|decrypt|hash|hmac|sign|verify)",
    r"(?i)(login|logout|authenticate|authorize)",
    r"(?i)(network|http|https|fetch|download|request)",
    r"(?i)(keychain|keystore|secure|credential|cert)",
    r"(?i)(jailbreak|root|tamper|debug|hook)",
    r"(?i)(pinning|ssl|tls|certificate)",
]


def decompile_ipa_malimite(
    ipa_path: str,
    output_dir: str | None = None,
    malimite_jar: str | None = None,
) -> MalimiteResult:
    """
    Decompile IPA/macOS .app bundle using Malimite.

    Malimite (https://github.com/LaurieWired/Malimite):
      - Ghidra-based decompiler with native IPA / .app bundle support
      - Reconstructs Swift classes (structs, enums, protocols)
      - Objective-C support
      - Built-in LLM method translation for obfuscated names
      - Skips library code → focused analysis of app code only

    After decompilation, bingo automatically:
      - Classifies Swift vs ObjC files
      - Identifies security-sensitive methods
      - Runs secret pattern scan on decompiled output
    """
    result = MalimiteResult(ipa_path=ipa_path)

    if not Path(ipa_path).exists():
        result.error = f"File not found: {ipa_path}"
        return result

    jar = malimite_jar or _find_malimite_jar()
    if not jar:
        result.error = (
            "Malimite JAR not found.\n"
            "  1. Download from https://github.com/LaurieWired/Malimite/releases\n"
            "  2. Place at ~/tools/Malimite.jar\n"
            "  3. OR: export MALIMITE_JAR=/path/to/Malimite.jar"
        )
        return result

    if not _which("java"):
        result.error = "Java not found. Install JDK 17+: brew install openjdk@17"
        return result

    if output_dir is None:
        output_dir = str(
            Path(ipa_path).parent / f"{Path(ipa_path).stem}_malimite_output"
        )
    result.output_dir = output_dir
    Path(output_dir).mkdir(parents=True, exist_ok=True)

    cmd = ["java", "-jar", jar, ipa_path, "--output", output_dir]
    result.commands_used.append(" ".join(cmd))
    rc, stdout, stderr = _run(cmd, timeout=600)

    out_path = Path(output_dir)

    # Check if output was produced even on non-zero exit
    produced = list(out_path.rglob("*.java")) + list(out_path.rglob("*.swift"))
    if rc != 0 and not produced:
        result.error = (stderr or f"Malimite exit code {rc}").strip()
        return result

    # Collect decompiled files
    result.decompiled_files = [
        str(f.relative_to(out_path)) for f in out_path.rglob("*") if f.is_file()
    ]

    # Classify Swift vs ObjC
    for f in out_path.rglob("*.java"):
        try:
            content = f.read_text(errors="ignore")
            if "// Swift" in content or "struct " in content or "protocol " in content:
                result.swift_classes.append(f.name)
            else:
                result.objc_classes.append(f.name)
        except Exception:
            continue

    # Find interesting security-relevant methods
    for f in out_path.rglob("*"):
        if not f.is_file() or f.suffix not in (".java", ".swift", ".m", ".h"):
            continue
        try:
            content = f.read_text(errors="ignore")
            for line in content.splitlines():
                for pat in _INTERESTING_METHOD_PATTERNS:
                    if re.search(pat, line) and any(
                        kw in line for kw in ("func ", "void ", "String ", "-(", "+ (")
                    ):
                        entry = f"{f.name}: {line.strip()[:120]}"
                        if entry not in result.interesting_methods:
                            result.interesting_methods.append(entry)
                        break
        except Exception:
            continue

    # Secret scan on decompiled output
    patterns = _get_secret_patterns()
    for f in out_path.rglob("*"):
        if not f.is_file():
            continue
        try:
            content = f.read_text(errors="ignore")
            for det, pat in patterns.items():
                for m in re.finditer(pat, content):
                    raw = m.group(0)
                    redacted = raw[:6] + "****" + raw[-4:] if len(raw) > 14 else raw
                    result.secrets.append(SecretFinding(
                        detector=det,
                        raw=raw,
                        redacted=redacted,
                        file=str(f.relative_to(out_path)),
                        line=content[: m.start()].count("\n") + 1,
                    ))
        except Exception:
            continue

    return result


def scan_and_decompile_ios(ipa_path: str) -> MalimiteResult:
    """Convenience wrapper: Malimite decompile + secret scan on IPA."""
    return decompile_ipa_malimite(ipa_path)


# ── Unified Auto-Scan Entry Point ─────────────────────────────────────────────

def auto_scan(target: str) -> APKScanResult | MalimiteResult | dict:
    """
    Auto-detect target type and dispatch to the correct scanner.

      *.apk  →  scan_apk_trufflehog()  (TruffleHog native, 9× faster)
      *.ipa  →  decompile_ipa_malimite()  (Malimite Ghidra-based)
      *.app  →  decompile_ipa_malimite()  (macOS bundle)
      other  →  package-name OSINT dict with download commands
    """
    t = target.strip()
    p = Path(t)

    if p.suffix == ".apk" and p.exists():
        return scan_apk_trufflehog(t)
    elif p.suffix in (".ipa", ".app") and p.exists():
        return decompile_ipa_malimite(t)
    else:
        # Treat as package name / URL → return OSINT guide
        pkg = t.split("id=")[-1].strip() if "id=" in t else t
        return {
            "type": "package_name_osint",
            "package": pkg,
            "message": "No local file found. Download the APK/IPA first, then scan.",
            "download_commands": {
                "android": [
                    f"apkeep -a {pkg} .",
                    f"python3 -m gplaycli -d {pkg} -f . -v",
                    f"# Manual: https://apkpure.com/search?q={pkg}",
                ],
                "ios": [
                    f"ipatool download -b {pkg}",
                    "# Manual: download IPA via AltStore or Apple Configurator",
                    "# Jailbroken: frida-ios-dump or Clutch",
                ],
            },
            "scan_after_download": {
                "android": f"trufflehog filesystem {pkg}.apk --json --no-verification",
                "ios": f"java -jar ~/tools/Malimite.jar {pkg}.ipa --output ./{pkg}_out/",
            },
        }


# ── Installation Guide ────────────────────────────────────────────────────────

def install_guide(platform: str = "both") -> str:
    """
    Print installation guide for TruffleHog and Malimite.

    Args:
        platform: "android" | "ios" | "both"
    """
    android_guide = """
── TruffleHog (Android APK secret scanner) ───────────────────────
Install:
  macOS  : brew install trufflesecurity/trufflehog/trufflehog
  Linux  : curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin
  Docker : docker pull trufflesecurity/trufflehog:latest
  pip    : pip install trufflehog  (wrapper only — use brew/curl for full version)

Verify:
  trufflehog --version

Usage:
  # Native APK scan (9× faster — no decompiler needed)
  trufflehog filesystem target.apk --json --no-verification

  # With credential verification (requires network)
  trufflehog filesystem target.apk --json

  # Docker
  docker run -v $(pwd):/work trufflesecurity/trufflehog:latest filesystem /work/target.apk --json
"""

    ios_guide = """
── Malimite (iOS/macOS IPA decompiler) ───────────────────────────
Requirements: Java 17+

Install Java:
  macOS  : brew install openjdk@17
  Ubuntu : sudo apt install default-jdk-17

Download Malimite JAR:
  https://github.com/LaurieWired/Malimite/releases/latest
  → Download Malimite.jar

Place JAR (choose one):
  Option A: mkdir -p ~/tools && mv ~/Downloads/Malimite.jar ~/tools/
  Option B: export MALIMITE_JAR=~/Downloads/Malimite.jar  (add to ~/.zshrc)

Verify:
  java -jar ~/tools/Malimite.jar --help

Usage:
  # Decompile IPA → Swift/ObjC source in output dir
  java -jar ~/tools/Malimite.jar target.ipa --output ./decompiled_output/

  # Then scan for secrets with TruffleHog
  trufflehog filesystem ./decompiled_output/ --json --no-verification

  # OR use bingo all-in-one
  python3 -c "from bingo.tools.apk_secret_scanner import auto_scan; r=auto_scan('target.ipa'); print(r.summary())"
"""

    header = """
╔══════════════════════════════════════════════════════════════╗
║   bingo v2.2.9 — TruffleHog APK + Malimite iOS Install      ║
╚══════════════════════════════════════════════════════════════╝"""

    verify_cmd = """
── Verify bingo integration ──────────────────────────────────────
  python3 -c "from bingo.tools.apk_secret_scanner import check_tools; import json; print(json.dumps(check_tools(), indent=2))"
"""

    if platform == "android":
        return header + android_guide + verify_cmd
    elif platform == "ios":
        return header + ios_guide + verify_cmd
    else:
        return header + android_guide + ios_guide + verify_cmd
