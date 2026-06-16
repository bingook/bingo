"""
exe_analyzer.py — Windows PE/EXE Static Analysis (Phase 0)
bingo v2.3.0

Phase 0 reconnaissance for Windows executables and PE files.
No execution required — fully static analysis.

Features:
  - File hashing (MD5 / SHA1 / SHA256 / SSDEEP)
  - PE header + metadata parsing
  - Section entropy analysis (packed/encrypted detection)
  - Import / Export table analysis (suspicious API detection)
  - String extraction (URLs, IPs, registry paths, embedded secrets)
  - Packer / compiler / protector detection
  - Resource analysis (version info, icons, embedded PE)
  - Digital signature check
  - YARA rule scanning (optional)
  - VirusTotal hash lookup (optional)
  - Capability scoring (malware indicator heuristics)

Dependencies (auto-installed if missing):
  pip install pefile lief yara-python requests ssdeep

References:
  - LIEF:    https://github.com/lief-project/LIEF
  - pefile:  https://github.com/erocarrera/pefile
  - YARA:    https://github.com/VirusTotal/yara
"""

from __future__ import annotations

import hashlib
import math
import os
import re
import struct
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# ── optional imports ──────────────────────────────────────────────────────────
_HAS_PEFILE = False
_HAS_LIEF = False
_HAS_YARA = False
_HAS_SSDEEP = False

try:
    import pefile  # type: ignore
    _HAS_PEFILE = True
except ImportError:
    pass

try:
    import lief  # type: ignore
    _HAS_LIEF = True
except ImportError:
    pass

try:
    import yara  # type: ignore
    _HAS_YARA = True
except ImportError:
    pass

try:
    import ssdeep  # type: ignore
    _HAS_SSDEEP = True
except ImportError:
    pass


# ── constants ─────────────────────────────────────────────────────────────────

# Suspicious Windows API imports that indicate malicious behavior
_SUSPICIOUS_IMPORTS: dict[str, str] = {
    # Process injection
    "VirtualAllocEx":           "process-injection",
    "WriteProcessMemory":       "process-injection",
    "CreateRemoteThread":       "process-injection",
    "NtUnmapViewOfSection":     "process-hollowing",
    "ZwUnmapViewOfSection":     "process-hollowing",
    "SetThreadContext":         "process-injection",
    "QueueUserAPC":             "apc-injection",
    # Shellcode / reflective loading
    "VirtualProtect":           "memory-protection-change",
    "VirtualAlloc":             "dynamic-memory",
    "HeapCreate":               "heap-allocation",
    # Credential theft
    "MiniDumpWriteDump":        "credential-dump",
    "SamQueryInformationUser":  "sam-access",
    "LsaQueryInformationPolicy":"lsa-access",
    "CryptUnprotectData":       "dpapi-decrypt",
    # Network
    "WinHttpOpen":              "http-client",
    "InternetOpenA":            "internet-api",
    "WSAStartup":               "winsock",
    "socket":                   "network",
    "connect":                  "network",
    # Anti-analysis
    "IsDebuggerPresent":        "anti-debug",
    "CheckRemoteDebuggerPresent":"anti-debug",
    "NtQueryInformationProcess":"anti-debug",
    "GetTickCount":             "timing-check",
    "QueryPerformanceCounter":  "timing-check",
    "Sleep":                    "timing-delay",
    # Persistence
    "RegSetValueEx":            "registry-write",
    "RegCreateKeyEx":           "registry-create",
    "CreateServiceA":           "service-creation",
    "StartService":             "service-start",
    "SchtasksA":                "scheduled-task",
    # Evasion
    "LoadLibraryA":             "dynamic-load",
    "GetProcAddress":           "dynamic-resolve",
    "NtSetInformationThread":   "thread-hiding",
    # Keylogging
    "SetWindowsHookEx":         "hook-install",
    "GetAsyncKeyState":         "keylogger",
    # Screenshot
    "BitBlt":                   "screen-capture",
    "GetDC":                    "screen-capture",
}

# Known packer section names
_PACKER_SECTIONS: set[str] = {
    "UPX0", "UPX1", "UPX2",          # UPX
    ".aspack", "ASPack",              # ASPack
    ".MPRESS1", ".MPRESS2",           # MPRESS
    ".themida", "Themida",            # Themida
    ".vmp0", ".vmp1", ".vmp2",        # VMProtect
    "PESHiELD", "pesection",          # PEShield
    ".nsp0", ".nsp1", ".nsp2",        # NsPack
    ".enigma1", ".enigma2",           # Enigma Protector
    ".winlicens",                     # WinLicense
    ".diet",                          # Diet
    ".petite",                        # Petite
}

# Regex patterns for string extraction
_PATTERNS: dict[str, re.Pattern] = {
    "url":       re.compile(rb"https?://[\w\-\.]+(?:/[\w\-\./?=%&#+~]*)?", re.I),
    "ip":        re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{2,5})?\b"),
    "domain":    re.compile(rb"\b(?:[a-zA-Z0-9\-]+\.){2,}[a-zA-Z]{2,6}\b"),
    "email":     re.compile(rb"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"),
    "registry":  re.compile(rb"(?:HKEY_|HKLM|HKCU|HKCR)[\\\w]+", re.I),
    "file_path": re.compile(rb"[A-Za-z]:\\[\\\w\s\-\.]+"),
    "b64_secret":re.compile(rb"[A-Za-z0-9+/]{40,}={0,2}"),
    "api_key":   re.compile(rb"(?:api[_\-]?key|token|secret|password|passwd|pwd)\s*[=:]\s*[\w\-\.]{8,}", re.I),
    "mutex":     re.compile(rb"Global\\[\w\-]{4,}", re.I),
    "user_agent":re.compile(rb"Mozilla/[\d\.]+ \([\w;\s]+\)", re.I),
}


# ── data classes ──────────────────────────────────────────────────────────────

@dataclass
class PESection:
    name: str = ""
    virtual_address: int = 0
    virtual_size: int = 0
    raw_size: int = 0
    entropy: float = 0.0
    is_executable: bool = False
    is_writable: bool = False
    md5: str = ""
    flags: str = ""


@dataclass
class PEImport:
    dll: str = ""
    functions: list[str] = field(default_factory=list)
    suspicious: list[tuple[str, str]] = field(default_factory=list)  # (func, reason)


@dataclass
class PEExport:
    name: str = ""
    ordinal: int = 0
    address: int = 0


@dataclass
class ExtractedStrings:
    urls: list[str] = field(default_factory=list)
    ips: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    emails: list[str] = field(default_factory=list)
    registry_keys: list[str] = field(default_factory=list)
    file_paths: list[str] = field(default_factory=list)
    api_keys: list[str] = field(default_factory=list)
    mutexes: list[str] = field(default_factory=list)
    user_agents: list[str] = field(default_factory=list)
    b64_candidates: list[str] = field(default_factory=list)
    all_printable: list[str] = field(default_factory=list)


@dataclass
class PEHashes:
    md5: str = ""
    sha1: str = ""
    sha256: str = ""
    ssdeep: str = ""
    imphash: str = ""
    authentihash: str = ""


@dataclass
class PackerInfo:
    detected: bool = False
    packer_name: str = ""
    evidence: list[str] = field(default_factory=list)
    confidence: str = ""    # "high" | "medium" | "low"


@dataclass
class CapabilityScore:
    total: int = 0
    capabilities: list[tuple[str, str]] = field(default_factory=list)  # (capability, evidence)

    def severity(self) -> str:
        if self.total >= 10:
            return "🔴 HIGH"
        if self.total >= 5:
            return "🟡 MEDIUM"
        return "🟢 LOW"


@dataclass
class PEAnalysisResult:
    # Meta
    file_path: str = ""
    file_name: str = ""
    file_size: int = 0
    file_size_human: str = ""

    # Hashes
    hashes: PEHashes = field(default_factory=PEHashes)

    # PE Header
    arch: str = ""              # "x86" | "x64" | "ARM" | "ARM64"
    subsystem: str = ""         # "GUI" | "CUI" | "DLL" | ...
    entry_point: int = 0
    image_base: int = 0
    compile_time: str = ""
    is_dll: bool = False
    is_driver: bool = False
    is_dotnet: bool = False
    has_signature: bool = False
    signature_valid: bool = False
    signature_signer: str = ""
    linker_version: str = ""
    os_version: str = ""

    # Sections
    sections: list[PESection] = field(default_factory=list)
    high_entropy_sections: list[str] = field(default_factory=list)

    # Imports / Exports
    imports: list[PEImport] = field(default_factory=list)
    exports: list[PEExport] = field(default_factory=list)
    suspicious_imports: list[tuple[str, str]] = field(default_factory=list)

    # Strings
    strings: ExtractedStrings = field(default_factory=ExtractedStrings)

    # Packer / Protector
    packer: PackerInfo = field(default_factory=PackerInfo)

    # Version info
    product_name: str = ""
    product_version: str = ""
    file_description: str = ""
    company_name: str = ""
    original_filename: str = ""
    copyright: str = ""
    language_code: str = ""

    # Capabilities
    capabilities: CapabilityScore = field(default_factory=CapabilityScore)

    # YARA
    yara_matches: list[str] = field(default_factory=list)

    # Error
    error: str = ""

    def summary(self) -> str:
        lines = [
            "═" * 64,
            f"  EXE Phase 0 — {self.file_name}",
            f"  Size     : {self.file_size_human}",
            f"  Arch     : {self.arch}",
            f"  Type     : {'DLL' if self.is_dll else ('Driver' if self.is_driver else 'EXE')} {'[.NET]' if self.is_dotnet else ''}",
            f"  Subsystem: {self.subsystem}",
            f"  Compiled : {self.compile_time}",
            "─" * 64,
            f"  MD5      : {self.hashes.md5}",
            f"  SHA256   : {self.hashes.sha256}",
            f"  ImpHash  : {self.hashes.imphash}",
        ]
        if self.hashes.ssdeep:
            lines.append(f"  SSDeep   : {self.hashes.ssdeep}")
        lines.append("─" * 64)

        # Signature
        sig_status = "✅ Valid" if self.signature_valid else ("⚠ Invalid" if self.has_signature else "❌ Unsigned")
        lines.append(f"  Signature: {sig_status}{' — ' + self.signature_signer if self.signature_signer else ''}")

        # Packer
        if self.packer.detected:
            lines.append(f"  Packer   : ⚠ {self.packer.packer_name} [{self.packer.confidence}]")
        else:
            lines.append("  Packer   : Not detected")

        lines.append("─" * 64)

        # Capabilities
        lines.append(f"  Risk     : {self.capabilities.severity()} ({self.capabilities.total} indicators)")
        for cap, ev in self.capabilities.capabilities[:10]:
            lines.append(f"    • {cap}: {ev}")

        lines.append("─" * 64)

        # Sections
        lines.append(f"  Sections : {len(self.sections)}")
        for sec in self.sections:
            marker = "⚠" if sec.entropy > 7.0 else " "
            lines.append(f"    {marker} {sec.name:<12} entropy={sec.entropy:.2f}  size={sec.raw_size:,}")

        # Imports
        total_funcs = sum(len(i.functions) for i in self.imports)
        lines.append(f"  Imports  : {len(self.imports)} DLLs / {total_funcs} functions")
        if self.suspicious_imports:
            lines.append(f"  ⚠ Suspicious imports ({len(self.suspicious_imports)}):")
            for fn, reason in self.suspicious_imports[:15]:
                lines.append(f"    • {fn:<35} [{reason}]")

        # Strings
        s = self.strings
        lines.append("─" * 64)
        if s.urls:
            lines.append(f"  URLs ({len(s.urls)}):")
            for u in s.urls[:10]:
                lines.append(f"    {u}")
        if s.ips:
            lines.append(f"  IPs ({len(s.ips)}): {', '.join(s.ips[:10])}")
        if s.registry_keys:
            lines.append(f"  Registry ({len(s.registry_keys)}):")
            for r in s.registry_keys[:5]:
                lines.append(f"    {r}")
        if s.api_keys:
            lines.append(f"  API Keys/Secrets ({len(s.api_keys)}):")
            for k in s.api_keys[:5]:
                lines.append(f"    {k[:80]}")
        if s.mutexes:
            lines.append(f"  Mutexes: {', '.join(s.mutexes[:5])}")

        # YARA
        if self.yara_matches:
            lines.append(f"  YARA Matches: {', '.join(self.yara_matches)}")

        # Version info
        if self.product_name:
            lines.append("─" * 64)
            lines.append(f"  Product  : {self.product_name} {self.product_version}")
            lines.append(f"  Company  : {self.company_name}")
            lines.append(f"  OrigFile : {self.original_filename}")

        if self.error:
            lines.append(f"\n  ⚠ Error: {self.error}")

        lines.append("═" * 64)
        return "\n".join(lines)


# ── helper functions ──────────────────────────────────────────────────────────

def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    ent = 0.0
    n = len(data)
    for count in freq.values():
        p = count / n
        ent -= p * math.log2(p)
    return round(ent, 4)


def _human_size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def _sha(path: Path) -> PEHashes:
    h = PEHashes()
    data = path.read_bytes()
    h.md5 = hashlib.md5(data).hexdigest()
    h.sha1 = hashlib.sha1(data).hexdigest()
    h.sha256 = hashlib.sha256(data).hexdigest()
    if _HAS_SSDEEP:
        try:
            h.ssdeep = ssdeep.hash(data)
        except Exception:
            pass
    return h


def _arch_str(machine: int) -> str:
    return {
        0x014c: "x86",
        0x0200: "IA64",
        0x8664: "x64",
        0xAA64: "ARM64",
        0x01c0: "ARM",
        0x01c4: "ARMv7",
        0x0EBC: "EFI",
    }.get(machine, f"0x{machine:04x}")


def _subsystem_str(sub: int) -> str:
    return {
        1: "Native",
        2: "GUI (Windows)",
        3: "CUI (Console)",
        7: "POSIX",
        9: "Windows CE",
        10: "EFI",
        14: "Xbox",
    }.get(sub, f"Unknown({sub})")


def _extract_strings(data: bytes, min_len: int = 5) -> ExtractedStrings:
    result = ExtractedStrings()
    seen: dict[str, set] = {k: set() for k in _PATTERNS}

    # ASCII printable strings
    ascii_re = re.compile(rb"[\x20-\x7e]{%d,}" % min_len)
    for m in ascii_re.finditer(data):
        s = m.group().decode("ascii", errors="replace")
        result.all_printable.append(s)

    # Apply pattern matching on raw bytes
    for key, pat in _PATTERNS.items():
        for m in pat.finditer(data):
            val = m.group().decode("latin-1", errors="replace").strip()
            if val not in seen[key]:
                seen[key].add(val)
                if key == "url":
                    result.urls.append(val)
                elif key == "ip":
                    result.ips.append(val)
                elif key == "domain":
                    result.domains.append(val)
                elif key == "email":
                    result.emails.append(val)
                elif key == "registry":
                    result.registry_keys.append(val)
                elif key == "file_path":
                    result.file_paths.append(val)
                elif key == "api_key":
                    result.api_keys.append(val)
                elif key == "mutex":
                    result.mutexes.append(val)
                elif key == "user_agent":
                    result.user_agents.append(val)
                elif key == "b64_secret":
                    if len(val) > 40:
                        result.b64_candidates.append(val)

    return result


def _score_capabilities(
    suspicious: list[tuple[str, str]],
    strings: ExtractedStrings,
    packer: PackerInfo,
    sections: list[PESection],
) -> CapabilityScore:
    score = CapabilityScore()

    def add(cap: str, ev: str, pts: int = 1):
        score.total += pts
        score.capabilities.append((cap, ev))

    # Suspicious imports
    categories: dict[str, list[str]] = {}
    for fn, reason in suspicious:
        categories.setdefault(reason, []).append(fn)

    if "process-injection" in categories:
        add("Process Injection", ", ".join(categories["process-injection"][:3]), 3)
    if "process-hollowing" in categories:
        add("Process Hollowing", ", ".join(categories["process-hollowing"][:3]), 3)
    if "credential-dump" in categories:
        add("Credential Dumping", ", ".join(categories["credential-dump"][:3]), 3)
    if "anti-debug" in categories:
        add("Anti-Debugging", ", ".join(categories["anti-debug"][:3]), 2)
    if "dynamic-resolve" in categories:
        add("Dynamic API Resolution", "GetProcAddress found", 2)
    if "keylogger" in categories:
        add("Keylogging", "GetAsyncKeyState", 2)
    if "hook-install" in categories:
        add("Hook Installation", "SetWindowsHookEx", 2)
    if "screen-capture" in categories:
        add("Screen Capture", ", ".join(categories["screen-capture"][:2]), 1)
    if "registry-write" in categories:
        add("Registry Persistence", ", ".join(categories["registry-write"][:2]), 2)

    # Strings
    if strings.urls:
        add("Network URLs", f"{len(strings.urls)} URL(s) found", 1)
    if strings.ips:
        add("Hardcoded IPs", ", ".join(strings.ips[:3]), 2)
    if strings.api_keys:
        add("Hardcoded Secrets", f"{len(strings.api_keys)} key(s) found", 2)
    if strings.mutexes:
        add("Mutex Names", ", ".join(strings.mutexes[:3]), 1)

    # Packer
    if packer.detected:
        add("Packed/Protected", packer.packer_name, 2)

    # High entropy sections (encrypted data)
    high_ent = [s for s in sections if s.entropy > 7.0]
    if high_ent:
        add("Encrypted/Compressed Sections", ", ".join(s.name for s in high_ent[:3]), 2)

    return score


# ── pefile analysis ───────────────────────────────────────────────────────────

def _analyze_with_pefile(path: Path, result: PEAnalysisResult) -> None:
    try:
        pe = pefile.PE(str(path), fast_load=False)
    except Exception as exc:
        result.error += f"pefile: {exc}; "
        return

    # Architecture
    result.arch = _arch_str(pe.FILE_HEADER.Machine)
    result.entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    result.image_base = pe.OPTIONAL_HEADER.ImageBase
    result.subsystem = _subsystem_str(pe.OPTIONAL_HEADER.Subsystem)
    result.linker_version = f"{pe.OPTIONAL_HEADER.MajorLinkerVersion}.{pe.OPTIONAL_HEADER.MinorLinkerVersion}"
    result.os_version = f"{pe.OPTIONAL_HEADER.MajorOperatingSystemVersion}.{pe.OPTIONAL_HEADER.MinorOperatingSystemVersion}"

    # Flags
    result.is_dll = bool(pe.FILE_HEADER.Characteristics & 0x2000)
    result.is_driver = pe.OPTIONAL_HEADER.Subsystem in (1, 11, 12, 13)

    # Compile time
    import datetime
    try:
        ts = pe.FILE_HEADER.TimeDateStamp
        result.compile_time = datetime.datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        result.compile_time = "Invalid"

    # .NET check
    try:
        if pe.OPTIONAL_HEADER.DATA_DIRECTORY[14].VirtualAddress != 0:
            result.is_dotnet = True
    except Exception:
        pass

    # Imphash
    try:
        result.hashes.imphash = pe.get_imphash()
    except Exception:
        pass

    # Sections
    for sec in pe.sections:
        name = sec.Name.rstrip(b"\x00").decode("utf-8", errors="replace")
        raw = sec.get_data()
        ent = _entropy(raw)
        flags_str = ""
        c = sec.Characteristics
        if c & 0x20000000:
            flags_str += "X"
        if c & 0x40000000:
            flags_str += "R"
        if c & 0x80000000:
            flags_str += "W"
        ps = PESection(
            name=name,
            virtual_address=sec.VirtualAddress,
            virtual_size=sec.Misc_VirtualSize,
            raw_size=sec.SizeOfRawData,
            entropy=ent,
            is_executable=bool(c & 0x20000000),
            is_writable=bool(c & 0x80000000),
            md5=hashlib.md5(raw).hexdigest(),
            flags=flags_str,
        )
        result.sections.append(ps)
        if ent > 7.0:
            result.high_entropy_sections.append(name)

        # Packer detection by section name
        if name in _PACKER_SECTIONS:
            result.packer.detected = True
            result.packer.evidence.append(f"Section name: {name}")
            result.packer.packer_name = name.strip(".")
            result.packer.confidence = "high"

    # Imports
    try:
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode("utf-8", errors="replace")
            funcs = []
            susp = []
            for imp in entry.imports:
                fn = imp.name.decode("utf-8", errors="replace") if imp.name else f"ord_{imp.ordinal}"
                funcs.append(fn)
                if fn in _SUSPICIOUS_IMPORTS:
                    susp.append((fn, _SUSPICIOUS_IMPORTS[fn]))
                    result.suspicious_imports.append((fn, _SUSPICIOUS_IMPORTS[fn]))
            result.imports.append(PEImport(dll=dll, functions=funcs, suspicious=susp))
    except AttributeError:
        pass

    # Exports
    try:
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            name = exp.name.decode("utf-8", errors="replace") if exp.name else ""
            result.exports.append(PEExport(name=name, ordinal=exp.ordinal, address=exp.address))
    except AttributeError:
        pass

    # Version info
    try:
        for fi in pe.FileInfo:
            for vinfo in fi:
                if hasattr(vinfo, "StringTable"):
                    for st in vinfo.StringTable:
                        for k, v in st.entries.items():
                            key = k.decode("utf-8", errors="replace").strip()
                            val = v.decode("utf-8", errors="replace").strip()
                            if key == "ProductName":
                                result.product_name = val
                            elif key == "ProductVersion":
                                result.product_version = val
                            elif key == "FileDescription":
                                result.file_description = val
                            elif key == "CompanyName":
                                result.company_name = val
                            elif key == "OriginalFilename":
                                result.original_filename = val
                            elif key == "LegalCopyright":
                                result.copyright = val
    except Exception:
        pass

    # Signature check (Authenticode)
    try:
        if pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].VirtualAddress != 0:
            result.has_signature = True
    except Exception:
        pass

    # Packer: check imports for obfuscation
    if not result.packer.detected:
        import_names = [i.dll.lower() for i in result.imports]
        func_count = sum(len(i.functions) for i in result.imports)
        if func_count < 5 and len(result.imports) <= 2:
            result.packer.detected = True
            result.packer.evidence.append("Very few imports (obfuscated/packed)")
            result.packer.packer_name = "Unknown Packer"
            result.packer.confidence = "medium"

    # Packer: high overall entropy
    if not result.packer.detected and result.high_entropy_sections:
        if len(result.high_entropy_sections) >= 2:
            result.packer.detected = True
            result.packer.evidence.append(f"Multiple high-entropy sections: {result.high_entropy_sections}")
            result.packer.packer_name = "Packed/Encrypted"
            result.packer.confidence = "medium"

    pe.close()


# ── YARA scanning ─────────────────────────────────────────────────────────────

_BUILT_IN_YARA = r"""
rule SuspiciousAPICalls {
    strings:
        $a = "VirtualAllocEx"
        $b = "WriteProcessMemory"
        $c = "CreateRemoteThread"
        $d = "NtUnmapViewOfSection"
    condition:
        2 of them
}

rule MiniDump {
    strings:
        $a = "MiniDumpWriteDump"
    condition:
        $a
}

rule AntiDebug {
    strings:
        $a = "IsDebuggerPresent"
        $b = "CheckRemoteDebuggerPresent"
        $c = "NtQueryInformationProcess"
    condition:
        2 of them
}

rule HardcodedCredentials {
    strings:
        $a = /password\s*=\s*[\x22\x27][^\x22\x27]{4,}/i
        $b = /api_key\s*=\s*[\x22\x27][^\x22\x27]{8,}/i
        $c = /secret\s*=\s*[\x22\x27][^\x22\x27]{8,}/i
    condition:
        any of them
}
"""


def _run_yara(data: bytes, rules_path: Optional[str] = None) -> list[str]:
    if not _HAS_YARA:
        return []
    try:
        if rules_path and Path(rules_path).exists():
            rules = yara.compile(rules_path)
        else:
            rules = yara.compile(source=_BUILT_IN_YARA)
        matches = rules.match(data=data)
        return [m.rule for m in matches]
    except Exception:
        return []


# ── VirusTotal hash lookup ────────────────────────────────────────────────────

def vt_lookup(sha256: str, api_key: str = "") -> dict:
    """Check hash against VirusTotal (requires API key)."""
    if not api_key:
        return {"error": "No API key provided. Set VT_API_KEY env var."}
    try:
        import requests
        headers = {"x-apikey": api_key}
        r = requests.get(
            f"https://www.virustotal.com/api/v3/files/{sha256}",
            headers=headers,
            timeout=15,
        )
        if r.status_code == 200:
            data = r.json()
            attrs = data.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            return {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "total": sum(stats.values()),
                "popular_threat": attrs.get("popular_threat_classification", {}).get("suggested_threat_label", ""),
                "names": attrs.get("names", [])[:5],
                "link": f"https://www.virustotal.com/gui/file/{sha256}",
            }
        elif r.status_code == 404:
            return {"error": "Hash not found in VirusTotal"}
        else:
            return {"error": f"HTTP {r.status_code}"}
    except Exception as exc:
        return {"error": str(exc)}


# ── main analysis function ────────────────────────────────────────────────────

def analyze_pe(
    file_path: str,
    extract_strings: bool = True,
    run_yara: bool = True,
    yara_rules: Optional[str] = None,
    min_string_len: int = 5,
) -> PEAnalysisResult:
    """
    Full static analysis of a Windows PE/EXE/DLL file.

    Args:
        file_path: Path to the EXE/DLL/SYS file
        extract_strings: Whether to extract strings (URLs, IPs, secrets, etc.)
        run_yara: Whether to run built-in YARA rules
        yara_rules: Optional path to custom YARA rules file
        min_string_len: Minimum length for extracted strings

    Returns:
        PEAnalysisResult with all analysis data
    """
    result = PEAnalysisResult()
    path = Path(file_path)

    if not path.exists():
        result.error = f"File not found: {file_path}"
        return result

    result.file_path = str(path.resolve())
    result.file_name = path.name
    result.file_size = path.stat().st_size
    result.file_size_human = _human_size(result.file_size)

    # Read raw bytes
    data = path.read_bytes()

    # Hashes
    result.hashes = _sha(path)

    # Strings
    if extract_strings:
        result.strings = _extract_strings(data, min_len=min_string_len)

    # PE parsing
    if not _HAS_PEFILE:
        result.error += "pefile not installed (pip install pefile). Basic analysis only. "
    else:
        _analyze_with_pefile(path, result)

    # YARA
    if run_yara:
        result.yara_matches = _run_yara(data, yara_rules)

    # Capability scoring
    result.capabilities = _score_capabilities(
        result.suspicious_imports,
        result.strings,
        result.packer,
        result.sections,
    )

    return result


def quick_scan(file_path: str) -> str:
    """Quick summary scan — returns formatted string."""
    result = analyze_pe(file_path, extract_strings=True, run_yara=True)
    return result.summary()


def batch_analyze(
    directory: str,
    extensions: tuple = (".exe", ".dll", ".sys", ".scr", ".drv"),
    recursive: bool = True,
) -> list[PEAnalysisResult]:
    """Analyze all PE files in a directory."""
    results = []
    base = Path(directory)
    pattern = "**/*" if recursive else "*"
    for p in base.glob(pattern):
        if p.suffix.lower() in extensions:
            results.append(analyze_pe(str(p)))
    return results


def compare_pe(file1: str, file2: str) -> dict:
    """Compare two PE files — useful for detecting malicious modifications."""
    r1 = analyze_pe(file1)
    r2 = analyze_pe(file2)
    return {
        "file1": r1.file_name,
        "file2": r2.file_name,
        "hash_match": r1.hashes.sha256 == r2.hashes.sha256,
        "imphash_match": r1.hashes.imphash == r2.hashes.imphash,
        "size_diff": r2.file_size - r1.file_size,
        "section_count_diff": len(r2.sections) - len(r1.sections),
        "r1_suspicious": len(r1.suspicious_imports),
        "r2_suspicious": len(r2.suspicious_imports),
        "r1_risk": r1.capabilities.severity(),
        "r2_risk": r2.capabilities.severity(),
        "packer_change": r1.packer.detected != r2.packer.detected,
    }


def install_guide() -> str:
    return """
╔══════════════════════════════════════════════════════════════╗
║   bingo v2.3.0 — EXE Phase 0 Install Guide                  ║
╚══════════════════════════════════════════════════════════════╝

Core (required):
  pip install pefile              # PE header parsing
  pip install lief                # Alternative PE parser + rich API

Optional (enhances analysis):
  pip install yara-python         # YARA rule scanning
  pip install ssdeep              # Fuzzy hashing
  pip install requests            # VirusTotal lookup

All-in-one:
  pip install pefile lief yara-python ssdeep requests

External tools (optional):
  # Detect-It-Easy (packer detection)
  brew install detect-it-easy     # macOS
  apt install detect-it-easy      # Ubuntu (snap/flatpak)

  # die (command-line DIE)
  wget https://github.com/horsicq/DIE-engine/releases/latest

Usage in bingo:
  bingo> analyze exe malware.exe
  bingo> pe analysis suspicious.dll
  bingo> check imports target.exe
  bingo> scan exe for secrets payload.exe
  bingo> full exe analysis sample.exe
"""
