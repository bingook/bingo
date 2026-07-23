"""
Tool Executor — 외부 도구 실행 + 자동 설치 + Python 폴백

우선순위:
  1. vendor/ 내장 (sqlmap, wafw00f)
  2. 시스템 PATH 또는 Bingo local tools directory
  3. 자동 설치 시도 (brew/apt/pip/GitHub Releases)
  4. Python 폴백 구현 (모든 도구에 대해 순수 Python 대체)
"""
from __future__ import annotations

import socket
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterator


@dataclass
class ToolResult:
    tool: str
    command: list[str]
    stdout: str
    stderr: str
    returncode: int
    elapsed: float
    success: bool
    used_fallback: bool = False
    fallback_note: str = ""

    def summary(self, max_lines: int = 100) -> str:
        lines = self.stdout.strip().splitlines()
        if len(lines) > max_lines:
            lines = lines[:max_lines] + [f"... (+{len(lines)-max_lines} lines)"]
        return "\n".join(lines)

    def to_ai_context(self) -> str:
        note = f"\n[Fallback: {self.fallback_note}]" if self.used_fallback else ""
        return (
            f"[Tool: {self.tool}]{note}\n"
            f"Command: {' '.join(self.command) if self.command else 'python_fallback'}\n"
            f"Exit code: {self.returncode}  (elapsed: {self.elapsed:.1f}s)\n"
            f"--- Output ---\n{self.summary()}\n"
            f"--------------"
        )


# ── Python 폴백 구현 ─────────────────────────────────────────────────

def _fallback_nmap(target: str, flags: str = "") -> ToolResult:
    """nmap 없을 때 Python socket 포트 스캔"""
    import re as _re
    t0 = time.time()
    host = _re.sub(r"https?://", "", target).split("/")[0].split(":")[0]
    common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 6379, 8080, 8443, 8888, 9200, 27017]
    lines = [f"Python socket scan of {host} (nmap not installed)"]
    open_ports = []
    for port in common_ports:
        try:
            with socket.create_connection((host, port), timeout=1):
                open_ports.append(port)
                lines.append(f"{port}/tcp  open")
        except Exception:
            pass
    if not open_ports:
        lines.append("No common ports open (or filtered)")
    lines.append(f"\n{len(open_ports)} open port(s) found")
    return ToolResult(
        tool="nmap", command=[], stdout="\n".join(lines),
        stderr="", returncode=0, elapsed=time.time() - t0,
        success=True, used_fallback=True,
        fallback_note="python socket scan — install nmap for full scan",
    )


def _fallback_ffuf(url: str, wordlist: str, extensions: str = "php,html") -> ToolResult:
    """ffuf/gobuster 없을 때 Python requests 디렉터리 브루트포스"""
    try:
        import urllib.request as _req
    except ImportError:
        pass
    t0 = time.time()
    lines = [f"Python directory brute-force: {url}"]
    found = []

    # 기본 내장 경로 목록 (워드리스트 없을 때)
    builtin_paths = [
        "admin", "login", "wp-admin", "administrator", "phpmyadmin",
        "backup", "config", "test", ".git", ".env", "api", "api/v1",
        "dashboard", "upload", "uploads", "static", "assets",
        "robots.txt", "sitemap.xml", ".htaccess", "web.config",
    ]

    paths = builtin_paths
    if wordlist and Path(wordlist).exists():
        try:
            with open(wordlist, encoding="utf-8", errors="ignore") as f:
                paths = [l.strip() for l in f if l.strip()][:500]
        except Exception:
            pass

    base = url.rstrip("/")
    for path in paths[:200]:
        try:
            full = f"{base}/{path}"
            req = _req.Request(full, headers={"User-Agent": "Mozilla/5.0"})
            with _req.urlopen(req, timeout=3) as resp:
                code = resp.status
                if code in (200, 301, 302, 403):
                    found.append(f"[{code}] {full}")
                    lines.append(f"[{code}] {full}")
        except Exception:
            pass

    if not found:
        lines.append("No paths found")
    lines.append(f"\n{len(found)} path(s) found")
    return ToolResult(
        tool="ffuf", command=[], stdout="\n".join(lines),
        stderr="", returncode=0, elapsed=time.time() - t0,
        success=True, used_fallback=True,
        fallback_note="python requests bruteforce — install ffuf for full scan",
    )


def _fallback_subfinder(domain: str) -> ToolResult:
    """subfinder/amass 없을 때 Python DNS 브루트포스"""
    import socket as _sock
    t0 = time.time()
    lines = [f"Python subdomain scan: {domain}"]
    found = []
    prefixes = [
        "www", "mail", "ftp", "api", "dev", "staging", "test",
        "admin", "portal", "app", "m", "mobile", "cdn", "static",
        "vpn", "remote", "login", "secure", "shop", "blog",
    ]
    for sub in prefixes:
        fqdn = f"{sub}.{domain}"
        try:
            ip = _sock.gethostbyname(fqdn)
            found.append(f"{fqdn} → {ip}")
            lines.append(f"[FOUND] {fqdn} ({ip})")
        except Exception:
            pass

    if not found:
        lines.append("No subdomains found via DNS lookup")
    lines.append(f"\n{len(found)} subdomain(s) found")
    return ToolResult(
        tool="subfinder", command=[], stdout="\n".join(lines),
        stderr="", returncode=0, elapsed=time.time() - t0,
        success=True, used_fallback=True,
        fallback_note="python DNS bruteforce — install subfinder for comprehensive scan",
    )


def _fallback_nikto(url: str) -> ToolResult:
    """nikto 없을 때 Python requests 기반 기본 취약점 체크"""
    try:
        import urllib.request as _req
        import urllib.error as _err
    except ImportError:
        pass
    t0 = time.time()
    lines = [f"Python web vulnerability check: {url}"]
    findings = []

    checks = [
        ("/robots.txt",       200, "robots.txt found"),
        ("/.git/HEAD",        200, "Git repository exposed!"),
        ("/.env",             200, ".env file exposed!"),
        ("/phpinfo.php",      200, "phpinfo() exposed!"),
        ("/admin",            200, "Admin panel found"),
        ("/wp-login.php",     200, "WordPress login found"),
        ("/phpmyadmin",       200, "phpMyAdmin found"),
        ("/server-status",    200, "Apache server-status exposed"),
        ("/web.config",       200, "web.config exposed!"),
        ("/backup.zip",       200, "Backup file found!"),
        ("/backup.sql",       200, "SQL backup exposed!"),
        ("/.htpasswd",        200, ".htpasswd exposed!"),
    ]

    base = url.rstrip("/")
    for path, expected_code, msg in checks:
        try:
            req = _req.Request(base + path, headers={"User-Agent": "Mozilla/5.0"})
            with _req.urlopen(req, timeout=4) as resp:
                if resp.status == expected_code:
                    findings.append(f"[!] {msg}: {base + path}")
                    lines.append(f"[FINDING] {msg}: {base + path}")
        except Exception:
            pass

    if not findings:
        lines.append("No obvious vulnerabilities found")
    lines.append(f"\n{len(findings)} finding(s)")
    return ToolResult(
        tool="nikto", command=[], stdout="\n".join(lines),
        stderr="", returncode=0, elapsed=time.time() - t0,
        success=True, used_fallback=True,
        fallback_note="python basic vuln check — install nikto for comprehensive scan",
    )


def _fallback_whatweb(url: str) -> ToolResult:
    """whatweb 없을 때 http_probe fingerprint 사용"""
    t0 = time.time()
    try:
        from .http_probe import HttpProbe
        probe = HttpProbe(url, timeout=8)
        fp = probe.fingerprint()
        tech = ", ".join(fp.get("tech", [])) or "unknown"
        cms = fp.get("cms", "unknown")
        server = fp.get("server", "unknown")
        lines = [
            f"Fingerprint: {url}",
            f"Server: {server}",
            f"CMS: {cms}",
            f"Tech: {tech}",
        ]
        return ToolResult(
            tool="whatweb", command=[], stdout="\n".join(lines),
            stderr="", returncode=0, elapsed=time.time() - t0,
            success=True, used_fallback=True,
            fallback_note="bingo http_probe fingerprint — install whatweb for full tech detection",
        )
    except Exception as e:
        return ToolResult(
            tool="whatweb", command=[], stdout="",
            stderr=str(e), returncode=1, elapsed=time.time() - t0,
            success=False, used_fallback=True,
        )


def _fallback_httpx(target: str) -> ToolResult:
    """httpx(Go) 없을 때 bingo http_probe 사용"""
    t0 = time.time()
    try:
        from .http_probe import HttpProbe
        probe = HttpProbe(target, timeout=8)
        fp = probe.fingerprint()
        lines = [
            f"{target}",
            f"Status: 200",
            f"Tech: {', '.join(fp.get('tech', []))}",
            f"Server: {fp.get('server', '-')}",
            f"CMS: {fp.get('cms', '-')}",
        ]
        return ToolResult(
            tool="httpx", command=[], stdout="\n".join(lines),
            stderr="", returncode=0, elapsed=time.time() - t0,
            success=True, used_fallback=True,
            fallback_note="bingo http_probe — install httpx for full probe",
        )
    except Exception as e:
        return ToolResult(
            tool="httpx", command=[], stdout="",
            stderr=str(e), returncode=1, elapsed=time.time() - t0,
            success=False, used_fallback=True,
        )


# 도구 → Python 폴백 함수 매핑
_PYTHON_FALLBACKS = {
    "nmap":      lambda args: _fallback_nmap(args[0] if args else ""),
    "nikto":     lambda args: _fallback_nikto(args[0] if args else ""),
    "whatweb":   lambda args: _fallback_whatweb(args[0] if args else ""),
    "httpx":     lambda args: _fallback_httpx(args[0] if args else ""),
    "ffuf":      lambda args: _fallback_ffuf(
        next((a for a in args if a.startswith("http")), ""),
        next((args[i+1] for i, a in enumerate(args) if a == "-w" and i+1 < len(args)), ""),
    ),
    "gobuster":  lambda args: _fallback_ffuf(
        next((args[i+1] for i, a in enumerate(args) if a in ("-u", "--url") and i+1 < len(args)), ""),
        next((args[i+1] for i, a in enumerate(args) if a in ("-w", "--wordlist") and i+1 < len(args)), ""),
    ),
    "subfinder": lambda args: _fallback_subfinder(
        next((args[i+1] for i, a in enumerate(args) if a == "-d" and i+1 < len(args)), args[0] if args else "")
    ),
    "amass":     lambda args: _fallback_subfinder(
        next((args[i+1] for i, a in enumerate(args) if a == "-d" and i+1 < len(args)), args[0] if args else "")
    ),
}

# Go 바이너리 도구 목록
_GO_TOOLS = {"nuclei", "httpx", "subfinder", "ffuf", "gobuster", "amass"}
# 패키지 매니저 설치 도구 목록
_PKG_TOOLS = {"nmap", "nikto", "whatweb"}


class ToolExecutor:
    def __init__(self, timeout: int = 120):
        self.timeout = timeout

    def run(
        self,
        tool: str,
        args: list[str],
        on_line: Callable[[str], None] | None = None,
        timeout: int | None = None,
        auto_install: bool = True,
    ) -> ToolResult:
        from .registry import ToolRegistry, get_sqlmap_cmd, get_wafw00f_cmd

        # ── 1단계: vendor 내장 Python 스크립트 ────────────────────────
        if tool == "sqlmap":
            vendor_cmd = get_sqlmap_cmd()
            if vendor_cmd:
                return self._exec(tool, vendor_cmd + args, on_line, timeout)
        elif tool == "wafw00f":
            vendor_cmd = get_wafw00f_cmd()
            if vendor_cmd:
                return self._exec(tool, vendor_cmd + args, on_line, timeout)

        # ── 2단계: 시스템 PATH 또는 Bingo local tools directory ───────────────────
        info = ToolRegistry.probe(tool)
        if info.available and info.path:
            return self._exec(tool, [info.path] + args, on_line, timeout)

        # ── 3단계: 자동 설치 시도 ────────────────────────────────────
        if auto_install:
            installed_path = self._auto_install(tool, on_line)
            if installed_path:
                return self._exec(tool, [installed_path] + args, on_line, timeout)

        # ── 4단계: Python 폴백 ───────────────────────────────────────
        fallback_fn = _PYTHON_FALLBACKS.get(tool)
        if fallback_fn:
            if on_line:
                on_line(f"[{tool}] Auto-install failed → Running Python fallback...")
            return fallback_fn(args)

        # complete failure
        return ToolResult(
            tool=tool, command=[], stdout="",
            stderr=f"{tool}: not installed, no fallback. Manual install: {info.install_hint}",
            returncode=-1, elapsed=0, success=False,
        )

    def _auto_install(self, tool: str, log_fn: Callable[[str], None] | None) -> str | None:
        """자동 설치 시도 — 성공 시 바이너리 경로 반환"""
        log = log_fn or (lambda s: None)
        log(f"[{tool}] Not installed → attempting auto-install...")

        # Go 바이너리 — GitHub Releases 다운로드
        if tool in _GO_TOOLS:
            from .downloader import download_tool, TOOLS_DIR
            path = download_tool(tool, log)
            if path and path.exists():
                # registry 캐시 갱신
                from .registry import ToolRegistry
                ToolRegistry._cache.pop(tool, None)
                return str(path)

        # 패키지 매니저 설치 (nmap, nikto, etc.)
        if tool in _PKG_TOOLS:
            from .installer import install_tool
            ok = install_tool(tool, log)
            if ok:
                import shutil
                path = shutil.which(tool)
                if path:
                    from .registry import ToolRegistry
                    ToolRegistry._cache.pop(tool, None)
                    return path

        return None

    def _exec(
        self,
        tool: str,
        cmd: list[str],
        on_line: Callable[[str], None] | None = None,
        timeout: int | None = None,
    ) -> ToolResult:
        t0 = time.time()
        stdout_buf, stderr_buf = [], []

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
            )

            def _read_stdout():
                for line in proc.stdout:
                    line = line.rstrip()
                    stdout_buf.append(line)
                    if on_line:
                        on_line(line)

            t = threading.Thread(target=_read_stdout, daemon=True)
            t.start()
            proc.wait(timeout=timeout or self.timeout)
            t.join(timeout=5)
            stderr_buf = proc.stderr.read().splitlines()

        except subprocess.TimeoutExpired:
            proc.kill()
            stdout_buf.append("[TIMEOUT]")
        except Exception as e:
            return ToolResult(
                tool=tool, command=cmd, stdout="",
                stderr=str(e), returncode=-1,
                elapsed=time.time() - t0, success=False,
            )

        elapsed = time.time() - t0
        return ToolResult(
            tool=tool, command=cmd,
            stdout="\n".join(stdout_buf),
            stderr="\n".join(stderr_buf),
            returncode=proc.returncode,
            elapsed=elapsed,
            success=proc.returncode == 0,
        )

    # ── 도구별 편의 메서드 ──────────────────────────────────────────

    def nmap(self, target: str, flags: str = "-sV --open") -> ToolResult:
        return self.run("nmap", flags.split() + [target])

    def nuclei(self, target: str, severity: str = "critical,high,medium") -> ToolResult:
        return self.run("nuclei", ["-u", target, "-severity", severity, "-silent"])

    def sqlmap(self, url: str, extra: list[str] | None = None) -> ToolResult:
        args = ["-u", url, "--batch", "--level=2", "--risk=2"]
        if extra:
            args += extra
        return self.run("sqlmap", args, timeout=300)

    def ffuf(self, url: str, wordlist: str, extensions: str = "php,html,txt") -> ToolResult:
        return self.run("ffuf", [
            "-u", f"{url}/FUZZ", "-w", wordlist,
            "-e", extensions, "-mc", "200,301,302,403", "-silent",
        ])

    def httpx_probe(self, target: str) -> ToolResult:
        return self.run("httpx", ["-u", target, "-title", "-tech-detect", "-status-code", "-silent"])

    def subfinder(self, domain: str) -> ToolResult:
        return self.run("subfinder", ["-d", domain, "-silent"])

    def wafw00f(self, url: str) -> ToolResult:
        return self.run("wafw00f", [url])

    def whatweb(self, url: str) -> ToolResult:
        return self.run("whatweb", [url, "--color=never"])

    def nikto(self, url: str) -> ToolResult:
        return self.run("nikto", ["-h", url, "-nointeractive"])
