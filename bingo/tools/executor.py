"""
Tool Executor — 외부 도구를 subprocess로 실행하고 결과를 AI가 읽기 쉬운 형태로 반환
"""
from __future__ import annotations
import subprocess
import threading
import time
from dataclasses import dataclass, field
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

    def summary(self, max_lines: int = 50) -> str:
        lines = self.stdout.strip().splitlines()
        if len(lines) > max_lines:
            lines = lines[:max_lines] + [f"... (+{len(lines)-max_lines} lines)"]
        return "\n".join(lines)

    def to_ai_context(self) -> str:
        """AI 프롬프트에 삽입할 결과 포맷"""
        return (
            f"[Tool: {self.tool}]\n"
            f"Command: {' '.join(self.command)}\n"
            f"Exit code: {self.returncode}  (elapsed: {self.elapsed:.1f}s)\n"
            f"--- Output ---\n{self.summary()}\n"
            f"--------------"
        )


class ToolExecutor:
    def __init__(self, timeout: int = 120):
        self.timeout = timeout

    def run(
        self,
        tool: str,
        args: list[str],
        on_line: Callable[[str], None] | None = None,
        timeout: int | None = None,
    ) -> ToolResult:
        from .registry import ToolRegistry
        info = ToolRegistry.probe(tool)
        if not info.available:
            return ToolResult(
                tool=tool, command=[], stdout="",
                stderr=f"{tool} not installed. Install: {info.install_hint}",
                returncode=-1, elapsed=0, success=False,
            )

        cmd = [info.path] + args
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

            # 실시간 stdout 읽기
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
            tool=tool,
            command=cmd,
            stdout="\n".join(stdout_buf),
            stderr="\n".join(stderr_buf),
            returncode=proc.returncode,
            elapsed=elapsed,
            success=proc.returncode == 0,
        )

    # ── 도구별 편의 메서드 ──────────────────────────────────────────

    def nmap(self, target: str, flags: str = "-sV -sC --open") -> ToolResult:
        args = flags.split() + [target]
        return self.run("nmap", args)

    def nuclei(self, target: str, severity: str = "critical,high,medium") -> ToolResult:
        return self.run("nuclei", ["-u", target, "-severity", severity, "-silent"])

    def sqlmap(self, url: str, extra: list[str] | None = None) -> ToolResult:
        args = ["-u", url, "--batch", "--level=2", "--risk=2"]
        if extra:
            args += extra
        return self.run("sqlmap", args, timeout=300)

    def ffuf(self, url: str, wordlist: str, extensions: str = "php,html,txt") -> ToolResult:
        return self.run("ffuf", [
            "-u", f"{url}/FUZZ",
            "-w", wordlist,
            "-e", extensions,
            "-mc", "200,301,302,403",
            "-silent",
        ])

    def httpx_probe(self, target: str) -> ToolResult:
        return self.run("httpx", [
            "-u", target,
            "-title", "-tech-detect", "-status-code",
            "-content-length", "-follow-redirects", "-silent",
        ])

    def subfinder(self, domain: str) -> ToolResult:
        return self.run("subfinder", ["-d", domain, "-silent"])

    def wafw00f(self, url: str) -> ToolResult:
        return self.run("wafw00f", [url])

    def whatweb(self, url: str) -> ToolResult:
        return self.run("whatweb", [url, "--color=never"])
