"""
apk_toolkit.py — APK Download + Deep Scan + Manipulation Toolkit
bingo v2.2.9

References:
  apkd    : https://github.com/kiber-io/apkd         — APK downloader (ApkPure/ApkCombo/F-Droid/AppGallery/RuStore)
  apkscan : https://github.com/LucasFaudman/apkscan   — APK secret+endpoint scanner (multi-decompiler)
  apk.sh  : https://github.com/ax/apk.sh              — APK manipulation (Frida gadget injection, decode, rebuild)

Tool capabilities:
  apkd    → Download APK without Google Play account; supports F-Droid, ApkPure, ApkCombo, AppGallery, RuStore
            List available versions; batch download; developer ID download
  apkscan → Decompile APK with JADX/APKTool/CFR/Procyon/Krakatau/Fernflower
            Scan for secrets (API keys, tokens, passwords) + backend endpoints
            Supports .apk, .xapk, .dex, .jar, .class, .smali, .aar, .arsc, .aab
            Custom rules: SecretLocator JSON, secret-patterns-db YAML, gitleaks TOML
  apk.sh  → Pull APK from connected device; decode (apktool); rebuild
            Patch APK to inject Frida gadget (frida-gadget.so) for dynamic analysis without root
            Support for app bundles / split APKs
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


# ── Data Classes ──────────────────────────────────────────────────────────────

@dataclass
class APKVersion:
    package: str = ""
    source: str = ""
    version_name: str = ""
    version_code: str = ""
    update_date: str = ""
    size: str = ""

@dataclass
class APKDownloadResult:
    package: str = ""
    source: str = ""
    version: str = ""
    apk_path: str = ""
    success: bool = False
    error: str = ""
    command: str = ""

    def summary(self) -> str:
        if self.success:
            return f"✅ Downloaded: {self.package} v{self.version} ({self.source})\n   Path: {self.apk_path}"
        return f"❌ Download failed: {self.package}\n   Error: {self.error}\n   Cmd: {self.command}"

@dataclass
class APKScanResult:
    apk_path: str = ""
    decompiler: str = ""
    rules: list[str] = field(default_factory=list)
    secrets: list[dict] = field(default_factory=list)
    endpoints: list[str] = field(default_factory=list)
    ssl_pinning_locations: list[str] = field(default_factory=list)
    root_detection_locations: list[str] = field(default_factory=list)
    raw_output: str = ""
    error: str = ""
    commands: list[str] = field(default_factory=list)

    def summary(self) -> str:
        lines = [
            "═" * 60,
            f"  APKscan — {Path(self.apk_path).name}",
            f"  Decompiler : {self.decompiler}",
            f"  Rules      : {', '.join(self.rules) if self.rules else 'default'}",
            f"  Secrets    : {len(self.secrets)}",
            f"  Endpoints  : {len(self.endpoints)}",
            f"  SSL Pinning locations : {len(self.ssl_pinning_locations)}",
            f"  Root Detection locations : {len(self.root_detection_locations)}",
            "═" * 60,
        ]
        if self.secrets:
            lines.append("  Secrets found:")
            for s in self.secrets[:20]:
                name = s.get("name") or s.get("id", "unknown")
                match = s.get("match") or s.get("secret", "")
                file_ = s.get("file", "")
                lines.append(f"    [{name}] {str(match)[:80]} @ {file_}")
        if self.endpoints[:10]:
            lines.append("\n  Endpoints found:")
            for ep in self.endpoints[:10]:
                lines.append(f"    {ep}")
        if self.error:
            lines.append(f"\n  ⚠ Error: {self.error}")
        return "\n".join(lines)

@dataclass
class APKManipResult:
    operation: str = ""    # "decode" | "patch" | "pull" | "build" | "rename"
    input_path: str = ""
    output_path: str = ""
    arch: str = ""
    success: bool = False
    error: str = ""
    commands: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def summary(self) -> str:
        lines = [
            "═" * 60,
            f"  apk.sh [{self.operation.upper()}]",
            f"  Input  : {self.input_path}",
            f"  Output : {self.output_path}",
        ]
        if self.arch:
            lines.append(f"  Arch   : {self.arch}")
        status = "✅ Success" if self.success else f"❌ Failed: {self.error}"
        lines.append(f"  Status : {status}")
        if self.notes:
            lines.append("\n  Notes:")
            for n in self.notes:
                lines.append(f"    • {n}")
        if self.commands:
            lines.append("\n  Commands:")
            for c in self.commands:
                lines.append(f"    $ {c}")
        return "\n".join(lines)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _which(cmd: str) -> str | None:
    return shutil.which(cmd)

def _run(cmd: list[str], timeout: int = 300, cwd: str | None = None) -> tuple[int, str, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=cwd)
        return p.returncode, p.stdout, p.stderr
    except FileNotFoundError:
        return -1, "", f"Command not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return -1, "", f"Timeout after {timeout}s"
    except Exception as e:
        return -1, "", str(e)

def _find_apksh() -> str | None:
    """Find apk.sh in common locations."""
    import os
    env = os.environ.get("APKSH_PATH", "")
    if env and Path(env).exists():
        return env
    candidates = [
        Path.home() / "tools" / "apk.sh",
        Path.home() / "apk.sh" / "apk.sh",
        Path("/opt/apk.sh/apk.sh"),
        Path("/usr/local/bin/apk.sh"),
    ]
    for c in candidates:
        if c.exists():
            return str(c)
    return None

def check_tools() -> dict[str, Any]:
    """Check availability of all APK toolkit tools."""
    apkd = _which("apkd")
    apkscan = _which("apkscan")
    apktool = _which("apktool")
    jadx = _which("jadx")
    adb = _which("adb")
    apksh = _find_apksh()
    apksigner = _which("apksigner")
    frida = _which("frida")

    # Check apkd version
    apkd_ver = ""
    if apkd:
        _, out, _ = _run(["apkd", "--version"])
        apkd_ver = out.strip()

    # Check apkscan version
    apkscan_ver = ""
    if apkscan:
        _, out, _ = _run(["apkscan", "--version"])
        apkscan_ver = out.strip()

    return {
        "apkd": {
            "available": bool(apkd),
            "path": apkd or "not found",
            "version": apkd_ver,
            "install": "pip install git+https://github.com/kiber-io/apkd",
        },
        "apkscan": {
            "available": bool(apkscan),
            "path": apkscan or "not found",
            "version": apkscan_ver,
            "install": "pip3 install apkscan",
        },
        "apk.sh": {
            "available": bool(apksh),
            "path": apksh or "not found — set APKSH_PATH env var or place at ~/tools/apk.sh",
            "install": "git clone https://github.com/ax/apk.sh ~/tools/apk.sh-repo && cp ~/tools/apk.sh-repo/apk.sh ~/tools/apk.sh && chmod +x ~/tools/apk.sh",
        },
        "apktool": {"available": bool(apktool), "path": apktool or "not found"},
        "jadx": {"available": bool(jadx), "path": jadx or "not found"},
        "adb": {"available": bool(adb), "path": adb or "not found"},
        "apksigner": {"available": bool(apksigner), "path": apksigner or "not found"},
        "frida": {"available": bool(frida), "path": frida or "not found"},
        "recommended_workflow": {
            "step1_download": "apkd -p com.target.app -d -s apkpure",
            "step2_scan": "apkscan target.apk -r all_secret_locators endpoints -o secrets.json -f json",
            "step3_patch": "./apk.sh patch target.apk --arch arm64  # inject Frida gadget",
            "step4_dynamic": "frida -U com.target.app -l hook_ssl_pinning.js",
        },
    }


# ── apkd — APK Downloader ─────────────────────────────────────────────────────

# Supported sources (apkd)
APK_SOURCES = ["apkpure", "apkcombo", "fdroid", "appgallery", "rustore", "rumarket", "nashstore"]

def list_apk_versions(
    package_name: str,
    source: str | None = None,
) -> list[APKVersion]:
    """
    List available APK versions using apkd.

    apkd -p com.twitter.android -lv [-s SOURCE]
    Ref: https://github.com/kiber-io/apkd
    """
    if not _which("apkd"):
        return []

    cmd = ["apkd", "-p", package_name, "-lv"]
    if source:
        cmd += ["-s", source]

    _, stdout, _ = _run(cmd, timeout=60)
    versions: list[APKVersion] = []

    # Parse table output
    for line in stdout.splitlines():
        line = line.strip()
        if "|" not in line or "Package" in line or "---" in line:
            continue
        parts = [p.strip() for p in line.split("|") if p.strip()]
        if len(parts) >= 4:
            versions.append(APKVersion(
                package=parts[0] if len(parts) > 0 else package_name,
                source=parts[1] if len(parts) > 1 else "",
                version_name=parts[2] if len(parts) > 2 else "",
                version_code=parts[3] if len(parts) > 3 else "",
                update_date=parts[4] if len(parts) > 4 else "",
                size=parts[5] if len(parts) > 5 else "",
            ))
    return versions

def download_apk(
    package_name: str,
    source: str = "apkpure",
    version_code: str | None = None,
    output_dir: str = ".",
) -> APKDownloadResult:
    """
    Download APK using apkd.

    Sources: apkpure (default), apkcombo, fdroid, appgallery, rustore, rumarket, nashstore

    apkd -p com.instagram.android -d -s apkpure [-vc <VERSION_CODE>]
    Ref: https://github.com/kiber-io/apkd

    Note: apkd supports multiple store sources without requiring a Google Play account.
    """
    result = APKDownloadResult(package=package_name, source=source)

    if not _which("apkd"):
        result.error = (
            "apkd not found.\n"
            "Install: pip install git+https://github.com/kiber-io/apkd\n"
            "Note: Archived project. For newer version check Go-based successor."
        )
        return result

    cmd = ["apkd", "-p", package_name, "-d", "-s", source]
    if version_code:
        cmd += ["-vc", version_code]
    result.command = " ".join(cmd)

    rc, stdout, stderr = _run(cmd, timeout=300, cwd=output_dir)

    # Try to find downloaded file
    apk_file = None
    for p in Path(output_dir).glob("*.apk"):
        if package_name.split(".")[-1].lower() in p.name.lower() or p.stat().st_size > 1_000:
            apk_file = str(p)
            break

    if rc == 0 or apk_file:
        result.success = True
        result.apk_path = apk_file or ""
        # Extract version from stdout
        ver_match = re.search(r"ver\.\s*([\d.]+)", stdout)
        result.version = ver_match.group(1) if ver_match else "unknown"
    else:
        result.error = (stderr or stdout or f"Exit {rc}").strip()

    return result

def batch_download_apks(
    packages: list[str],
    source: str = "apkpure",
    output_dir: str = ".",
) -> list[APKDownloadResult]:
    """
    Batch download multiple APKs using apkd.

    apkd -l packages.txt -d
    """
    if not _which("apkd"):
        return [APKDownloadResult(package=p, error="apkd not found") for p in packages]

    results = []
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("\n".join(packages))
        tmp_path = f.name

    cmd = ["apkd", "-l", tmp_path, "-d"]
    if source:
        cmd += ["-s", source]

    rc, stdout, stderr = _run(cmd, timeout=600, cwd=output_dir)

    for pkg in packages:
        r = APKDownloadResult(package=pkg, source=source, command=" ".join(cmd))
        apk = next(Path(output_dir).glob(f"*{pkg.split('.')[-1]}*.apk"), None)
        if apk:
            r.success = True
            r.apk_path = str(apk)
        else:
            r.error = "File not found after download"
        results.append(r)

    Path(tmp_path).unlink(missing_ok=True)
    return results

def get_developer_apks(
    any_package: str,
    source: str = "apkpure",
) -> dict:
    """
    Find developer ID and list all apps from that developer.

    apkd -ld -p com.instagram.android -s apkpure
    apkd -lv -did Instagram -s apkpure
    """
    if not _which("apkd"):
        return {"error": "apkd not found"}

    cmd = ["apkd", "-ld", "-p", any_package, "-s", source]
    _, stdout, _ = _run(cmd, timeout=60)

    # Extract developer ID from table
    dev_id = None
    for line in stdout.splitlines():
        if "|" not in line or "Package" in line or "---" in line:
            continue
        parts = [p.strip() for p in line.split("|") if p.strip()]
        if len(parts) >= 3:
            dev_id = parts[2]
            break

    return {
        "package": any_package,
        "source": source,
        "developer_id": dev_id,
        "list_all_cmd": f"apkd -lv -did {dev_id} -s {source}" if dev_id else None,
        "download_all_cmd": f"apkd -d -did {dev_id} -s {source}" if dev_id else None,
        "raw_output": stdout,
    }


# ── apkscan — Secret + Endpoint Scanner ──────────────────────────────────────

# Built-in rule sets supported by apkscan
APKSCAN_RULE_SETS = [
    "all_secret_locators", "aws", "azure", "cloud", "curated",
    "default", "endpoints", "gcp", "generic", "gitleaks",
    "high-confidence", "key_locators", "leakin-regexes",
    "locator_sort", "nuclei-regexes", "secret",
]

def scan_apk_secrets_endpoints(
    apk_path: str,
    rules: list[str] | None = None,
    decompiler: str = "jadx",
    output_format: str = "json",
    output_file: str | None = None,
    deobfuscate: bool = False,
    cleanup: bool = True,
    extra_decompilers: list[str] | None = None,
) -> APKScanResult:
    """
    Scan APK for secrets + endpoints using apkscan (multi-decompiler).

    apkscan file.apk -r aws endpoints -o output.json -f json

    Features:
    - Multiple decompilers: jadx, apktool, cfr, procyon, krakatau, fernflower
    - Multiple rule formats: SecretLocator JSON, secret-patterns-db YAML, gitleaks TOML
    - Finds: API keys, tokens, passwords + backend endpoints + SSL pinning + root detection
    - Supports: .apk, .xapk, .dex, .jar, .class, .smali, .aar, .arsc, .aab

    Ref: https://github.com/LucasFaudman/apkscan
    """
    result = APKScanResult(
        apk_path=apk_path,
        decompiler=decompiler,
        rules=rules or ["default"],
    )

    if not Path(apk_path).exists():
        result.error = f"File not found: {apk_path}"
        return result

    if not _which("apkscan"):
        result.error = (
            "apkscan not found.\n"
            "Install: pip3 install apkscan\n"
            "Requires: jadx or apktool for decompilation"
        )
        # Fallback to manual scan
        return _apkscan_manual_fallback(apk_path, result)

    # Build command
    cmd = ["apkscan", apk_path]
    if rules:
        cmd += ["-r"] + rules
    if deobfuscate:
        cmd.append("--deobfuscate")
    if cleanup:
        cmd.append("--cleanup")

    # Decompiler flags
    decompiler_flag_map = {
        "jadx": "-J", "apktool": "-A", "cfr": "-C",
        "procyon": "-P", "krakatau": "-K", "fernflower": "-F",
    }
    primary_flag = decompiler_flag_map.get(decompiler, "-J")
    cmd.append(primary_flag)
    if extra_decompilers:
        for ed in extra_decompilers:
            flag = decompiler_flag_map.get(ed)
            if flag and flag not in cmd:
                cmd.append(flag)

    # Output
    if output_file:
        cmd += ["-o", output_file, "-f", output_format]
    else:
        cmd += ["-f", "json"]

    result.commands.append(" ".join(cmd))
    rc, stdout, stderr = _run(cmd, timeout=600)
    result.raw_output = stdout

    # Parse JSON output
    try:
        data = json.loads(stdout) if stdout.strip().startswith("{") else {}
        if isinstance(data, dict):
            for file_path, locators in data.items():
                for locator_name, matches in (locators or {}).items():
                    if "endpoint" in locator_name.lower():
                        result.endpoints.extend(
                            m.get("match", "") for m in (matches or []) if m.get("match")
                        )
                    elif "ssl" in locator_name.lower() or "pinning" in locator_name.lower():
                        result.ssl_pinning_locations.append(f"{file_path}:{locator_name}")
                    elif "root" in locator_name.lower():
                        result.root_detection_locations.append(f"{file_path}:{locator_name}")
                    else:
                        for m in (matches or []):
                            result.secrets.append({
                                "name": locator_name,
                                "file": file_path,
                                "match": m.get("match", ""),
                            })
    except (json.JSONDecodeError, AttributeError):
        # Try text parsing
        for line in stdout.splitlines():
            if "http" in line.lower() and ("://" in line):
                result.endpoints.append(line.strip())

    if rc != 0 and not result.secrets and not result.endpoints:
        result.error = (stderr or f"Exit {rc}").strip()

    return result

def scan_apk_endpoints(apk_path: str) -> APKScanResult:
    """Scan APK specifically for backend endpoints and test data."""
    return scan_apk_secrets_endpoints(apk_path, rules=["endpoints"])

def scan_apk_cloud_credentials(apk_path: str) -> APKScanResult:
    """Scan APK for cloud credentials (AWS, GCP, Azure)."""
    return scan_apk_secrets_endpoints(apk_path, rules=["aws", "gcp", "azure"])

def _apkscan_manual_fallback(apk_path: str, result: APKScanResult) -> APKScanResult:
    """Fallback: use apk_secret_scanner when apkscan unavailable."""
    try:
        from bingo.tools.apk_secret_scanner import _scan_apk_manual, APKScanResult as TR
        from bingo.tools.apk_secret_scanner import APKScanResult as _TRResult
        tmp = _TRResult(apk_path=apk_path, method="manual-regex-fallback")
        tmp = _scan_apk_manual(apk_path, tmp)
        result.secrets = [s.to_dict() for s in tmp.secrets]
        result.error = (result.error + " | Fell back to manual regex scan").lstrip(" | ")
    except Exception:
        pass
    return result


# ── apk.sh — APK Manipulation ─────────────────────────────────────────────────

def pull_apk_from_device(package_name: str, output_dir: str = ".") -> APKManipResult:
    """
    Pull APK from connected Android device using apk.sh.
    Supports split APKs / app bundles (combined into single APK).

    ./apk.sh pull com.instagram.android
    Ref: https://github.com/ax/apk.sh
    """
    result = APKManipResult(operation="pull", input_path=package_name)
    apksh = _find_apksh()

    if not apksh:
        result.error = _apksh_install_hint()
        # Fallback to adb
        return _pull_via_adb_fallback(package_name, output_dir, result)

    if not _which("adb"):
        result.error = "adb not found. Install: brew install --cask android-platform-tools"
        return result

    cmd = [apksh, "pull", package_name]
    result.commands.append(" ".join(cmd))
    rc, stdout, stderr = _run(cmd, timeout=120, cwd=output_dir)

    # Find pulled APK
    pulled = next(Path(output_dir).glob(f"*{package_name.split('.')[-1]}*.apk"), None)
    if pulled or rc == 0:
        result.success = True
        result.output_path = str(pulled) if pulled else output_dir
        result.notes.append("APK pulled successfully. Split APKs automatically merged.")
    else:
        result.error = (stderr or stdout or f"Exit {rc}").strip()

    return result

def _pull_via_adb_fallback(package_name: str, output_dir: str, result: APKManipResult) -> APKManipResult:
    """Fallback: pull APK via raw adb commands."""
    if not _which("adb"):
        result.error = "Both apk.sh and adb not found"
        return result

    # Get APK path
    cmd1 = ["adb", "shell", "pm", "path", package_name]
    result.commands.append(" ".join(cmd1))
    _, stdout, _ = _run(cmd1, timeout=30)

    apk_path_device = stdout.strip().replace("package:", "")
    if not apk_path_device:
        result.error = f"Package {package_name} not found on device"
        return result

    # Pull APK
    local_path = str(Path(output_dir) / f"{package_name}.apk")
    cmd2 = ["adb", "pull", apk_path_device, local_path]
    result.commands.append(" ".join(cmd2))
    rc, _, stderr = _run(cmd2, timeout=120)

    if rc == 0 and Path(local_path).exists():
        result.success = True
        result.output_path = local_path
        result.notes.append("Pulled via adb (fallback). Split APKs NOT merged.")
    else:
        result.error = stderr.strip()
    return result

def decode_apk(apk_path: str, no_resources: bool = False, no_src: bool = False) -> APKManipResult:
    """
    Decode APK to smali + resources using apk.sh (wraps apktool).

    ./apk.sh decode target.apk
    Ref: https://github.com/ax/apk.sh
    """
    result = APKManipResult(operation="decode", input_path=apk_path)

    if not Path(apk_path).exists():
        result.error = f"File not found: {apk_path}"
        return result

    apksh = _find_apksh()
    if apksh:
        cmd = [apksh, "decode", apk_path]
        if no_resources:
            cmd.append("-r")
        if no_src:
            cmd.append("-s")
        result.commands.append(" ".join(cmd))
        rc, stdout, stderr = _run(cmd, timeout=300)
        output_dir = apk_path.replace(".apk", "")
        if Path(output_dir).exists() or rc == 0:
            result.success = True
            result.output_path = output_dir
            result.notes.append("Decoded to smali + resources with apk.sh/apktool")
        else:
            result.error = (stderr or stdout).strip()
    elif _which("apktool"):
        # fallback to direct apktool
        output_dir = apk_path.replace(".apk", "")
        cmd = ["apktool", "d", apk_path, "-o", output_dir, "-f"]
        if no_resources:
            cmd.append("-r")
        if no_src:
            cmd.append("-s")
        result.commands.append(" ".join(cmd))
        rc, stdout, stderr = _run(cmd, timeout=300)
        if rc == 0 or Path(output_dir).exists():
            result.success = True
            result.output_path = output_dir
            result.notes.append("Decoded directly with apktool (apk.sh not found)")
        else:
            result.error = (stderr or stdout).strip()
    else:
        result.error = "Neither apk.sh nor apktool found. Install: brew install apktool"

    return result

def rebuild_apk(apk_dir: str) -> APKManipResult:
    """
    Rebuild decoded APK directory back to APK.

    ./apk.sh build target_dir/
    """
    result = APKManipResult(operation="build", input_path=apk_dir)
    apksh = _find_apksh()

    if apksh:
        cmd = [apksh, "build", apk_dir]
        result.commands.append(" ".join(cmd))
        rc, stdout, stderr = _run(cmd, timeout=300)
        # output is <dir>.apk
        output_apk = apk_dir.rstrip("/") + ".apk"
        if Path(output_apk).exists() or rc == 0:
            result.success = True
            result.output_path = output_apk
    elif _which("apktool"):
        cmd = ["apktool", "b", apk_dir, "-o", apk_dir.rstrip("/") + "_rebuilt.apk"]
        result.commands.append(" ".join(cmd))
        rc, stdout, stderr = _run(cmd, timeout=300)
        if rc == 0:
            result.success = True
            result.output_path = cmd[-1]
        else:
            result.error = (stderr or stdout).strip()
    else:
        result.error = "Neither apk.sh nor apktool found"

    return result

def patch_apk_frida_gadget(
    apk_path: str,
    arch: str = "arm64",
    gadget_conf: str | None = None,
    net_config: bool = False,
) -> APKManipResult:
    """
    Patch APK to inject Frida gadget (frida-gadget.so) for dynamic analysis WITHOUT root.

    Frida gadget allows:
    - Dynamic instrumentation of the app (hook methods, bypass SSL pinning, etc.)
    - No rooted device required
    - Works with Objection, Frida scripts, Burp HTTPS interception

    ./apk.sh patch target.apk --arch arm64 [--gadget-conf config.json] [--net]
    Ref: https://github.com/ax/apk.sh

    After patching:
    - Install: adb install target.gadget.apk
    - Connect: frida -U com.target.app -l ssl_bypass.js
    - Objection: objection -g com.target.app explore
    """
    result = APKManipResult(
        operation="patch",
        input_path=apk_path,
        arch=arch,
    )

    if not Path(apk_path).exists():
        result.error = f"File not found: {apk_path}"
        return result

    apksh = _find_apksh()
    if not apksh:
        result.error = _apksh_install_hint()
        result.notes = [
            "Alternative without apk.sh:",
            "  1. Decode with apktool: apktool d target.apk",
            "  2. Download frida-gadget.so from https://github.com/frida/frida/releases",
            "  3. Place in lib/<arch>/libfrida-gadget.so",
            "  4. Add loadLibrary call to smali",
            "  5. Rebuild: apktool b target",
            "  6. Sign: apksigner sign --ks debug.keystore target.apk",
        ]
        return result

    cmd = [apksh, "patch", apk_path, "--arch", arch]
    if gadget_conf:
        cmd += ["--gadget-conf", gadget_conf]
    if net_config:
        cmd.append("--net")
    result.commands.append(" ".join(cmd))

    rc, stdout, stderr = _run(cmd, timeout=300)

    output_apk = apk_path.replace(".apk", ".gadget.apk")
    if Path(output_apk).exists() or rc == 0:
        result.success = True
        result.output_path = output_apk
        result.notes = [
            f"Frida gadget injected for arch: {arch}",
            f"Install: adb install {output_apk}",
            "Connect: frida -U <package_name>",
            "SSL bypass: objection -g <package_name> explore",
            "Burp proxy: adb shell settings put global http_proxy 192.168.x.x:8080",
        ]
    else:
        result.error = (stderr or stdout or f"Exit {rc}").strip()
        result.notes = [
            "Requirements: apktool, apksigner, aapt, zipalign, adb, unxz",
            "Install tools: brew install apktool android-platform-tools",
        ]

    return result

def rename_apk_package(apk_path: str, new_package_name: str) -> APKManipResult:
    """
    Rename APK package name (useful for installing alongside original).

    ./apk.sh rename target.apk com.newpackage.name
    """
    result = APKManipResult(operation="rename", input_path=apk_path)
    apksh = _find_apksh()

    if not apksh:
        result.error = _apksh_install_hint()
        return result

    cmd = [apksh, "rename", apk_path, new_package_name]
    result.commands.append(" ".join(cmd))
    rc, stdout, stderr = _run(cmd, timeout=300)

    if rc == 0:
        result.success = True
        result.output_path = apk_path.replace(".apk", f"_{new_package_name}.apk")
        result.notes.append(f"Package renamed to: {new_package_name}")
    else:
        result.error = (stderr or stdout).strip()

    return result


# ── Full Pipeline ─────────────────────────────────────────────────────────────

def full_apk_analysis_pipeline(
    target: str,
    scan_rules: list[str] | None = None,
    patch_for_frida: bool = True,
    arch: str = "arm64",
) -> dict:
    """
    Full APK analysis pipeline:
      1. Download APK (if package name given)
      2. Scan for secrets + endpoints (apkscan)
      3. Patch with Frida gadget (apk.sh) for dynamic analysis

    Args:
        target: APK file path OR package name (e.g. com.target.app)
        scan_rules: apkscan rule sets (default: ["all_secret_locators", "endpoints"])
        patch_for_frida: whether to inject Frida gadget
        arch: target arch for Frida patch (arm, arm64, x86, x86_64)
    """
    results: dict = {
        "target": target,
        "steps": {},
    }

    # Step 1: Resolve APK path
    apk_path = target
    if not Path(target).exists() or not target.endswith(".apk"):
        # Treat as package name → download
        dl = download_apk(target)
        results["steps"]["download"] = dl.summary()
        if dl.success:
            apk_path = dl.apk_path
        else:
            results["error"] = f"Download failed: {dl.error}"
            results["steps"]["download_commands"] = [
                f"apkd -p {target} -d -s apkpure",
                f"apkd -p {target} -d -s fdroid",
            ]
            return results

    # Step 2: Secret + endpoint scan
    rules = scan_rules or ["all_secret_locators", "endpoints"]
    scan = scan_apk_secrets_endpoints(apk_path, rules=rules)
    results["steps"]["scan"] = scan.summary()
    results["secrets_count"] = len(scan.secrets)
    results["endpoints_count"] = len(scan.endpoints)

    # Step 3: Frida gadget patch
    if patch_for_frida:
        patch = patch_apk_frida_gadget(apk_path, arch=arch)
        results["steps"]["frida_patch"] = patch.summary()
        results["patched_apk"] = patch.output_path if patch.success else None

    # Summary
    results["summary"] = (
        f"Secrets: {len(scan.secrets)} | "
        f"Endpoints: {len(scan.endpoints)} | "
        f"Frida patch: {'✅' if (patch_for_frida and results.get('patched_apk')) else '⚠ skipped'}"
    )
    return results


# ── Install Guide ─────────────────────────────────────────────────────────────

def _apksh_install_hint() -> str:
    return (
        "apk.sh not found.\n"
        "Install:\n"
        "  git clone https://github.com/ax/apk.sh ~/tools/apk.sh-repo\n"
        "  cp ~/tools/apk.sh-repo/apk.sh ~/tools/apk.sh\n"
        "  chmod +x ~/tools/apk.sh\n"
        "  # OR: export APKSH_PATH=/path/to/apk.sh\n"
        "Requirements: apktool, apksigner, aapt, zipalign, adb, unxz"
    )

def install_guide() -> str:
    return """
╔══════════════════════════════════════════════════════════════╗
║   bingo v2.2.9 — APK Toolkit (apkd + apkscan + apk.sh)     ║
╚══════════════════════════════════════════════════════════════╝

── apkd (APK downloader from ApkPure/ApkCombo/F-Droid) ──────
  pip install git+https://github.com/kiber-io/apkd

  Test: apkd --version
  Download: apkd -p com.target.app -d -s apkpure

── apkscan (multi-decompiler secret + endpoint scanner) ──────
  pip3 install apkscan

  Requires: jadx (brew install jadx)
  Test: apkscan --help
  Scan: apkscan target.apk -r all_secret_locators endpoints -o out.json

── apk.sh (APK decode / rebuild / Frida patch) ───────────────
  git clone https://github.com/ax/apk.sh ~/tools/apk.sh-repo
  cp ~/tools/apk.sh-repo/apk.sh ~/tools/apk.sh
  chmod +x ~/tools/apk.sh

  Requirements (install all):
    macOS: brew install apktool android-platform-tools
    Ubuntu: apt install apktool adb apksigner zipalign aapt

  OR set env: export APKSH_PATH=~/tools/apk.sh

── Check all tools ────────────────────────────────────────────
  python3 -c "from bingo.tools.apk_toolkit import check_tools; import json; print(json.dumps(check_tools(), indent=2))"
"""
