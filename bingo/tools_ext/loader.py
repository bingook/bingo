"""
bingo/tools_ext/loader.py — YAML 외부 도구 레시피 로더

tools_ext/builtin/*.yaml + 사용자 정의 디렉토리를 스캔해
외부 CLI 도구(nmap, sqlmap, ffuf, nuclei…)를 bingo 세션에서
명령어로 바로 실행할 수 있도록 정의를 등록.
"""
from __future__ import annotations

import subprocess
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

try:
    import yaml as _yaml
    _HAS_YAML = True
except ImportError:
    _HAS_YAML = False


@dataclass
class ToolParam:
    name: str
    type: str = "string"
    description: str = ""
    required: bool = False
    flag: str = ""          # e.g. "-p", "--port"
    position: int = -1      # positional arg index; -1 = flag-based


@dataclass
class ExternalTool:
    name: str
    command: str
    short_description: str = ""
    description: str = ""
    args: List[str] = field(default_factory=list)
    parameters: List[ToolParam] = field(default_factory=list)
    enabled: bool = True

    def is_available(self) -> bool:
        return shutil.which(self.command) is not None

    def build_cmd(self, **kwargs) -> List[str]:
        """파라미터 dict → 실행 가능한 명령어 리스트."""
        cmd = [self.command] + list(self.args)
        positional: Dict[int, str] = {}
        for p in self.parameters:
            val = kwargs.get(p.name)
            if val is None:
                continue
            if p.position >= 0:
                positional[p.position] = str(val)
            elif p.flag:
                cmd += [p.flag, str(val)]
        for i in sorted(positional):
            cmd.append(positional[i])
        return cmd

    def run(self, timeout: int = 60, **kwargs) -> str:
        """동기 실행 → stdout 문자열 반환."""
        cmd = self.build_cmd(**kwargs)
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=timeout, check=False,
            )
            out = result.stdout or ""
            err = result.stderr or ""
            return (out + ("\n[STDERR]\n" + err if err.strip() else "")).strip()
        except FileNotFoundError:
            return f"[tool-error] '{self.command}' not found in PATH"
        except subprocess.TimeoutExpired:
            return f"[tool-error] '{self.command}' timed out after {timeout}s"
        except Exception as e:
            return f"[tool-error] {e}"


_BUILTIN_DIR = Path(__file__).parent / "builtin"


class ToolExtRegistry:
    """외부 도구 레지스트리 — YAML 파일 기반 로드."""

    _tools: Dict[str, ExternalTool] = {}
    _instance: Optional["ToolExtRegistry"] = None

    def __init__(self, extra_dir: Optional[str] = None) -> None:
        self._tools = {}
        self._load_dir(_BUILTIN_DIR)
        if extra_dir:
            self._load_dir(Path(extra_dir))

    @classmethod
    def instance(cls, extra_dir: Optional[str] = None) -> "ToolExtRegistry":
        if cls._instance is None:
            cls._instance = cls(extra_dir)
        return cls._instance

    def _load_dir(self, path: Path) -> None:
        if not path.is_dir() or not _HAS_YAML:
            return
        for f in sorted(path.glob("*.yaml")):
            self._load_file(f)

    def _load_file(self, path: Path) -> None:
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = _yaml.safe_load(fh)
            if not isinstance(data, dict) or not data.get("enabled", True):
                return
            params = [
                ToolParam(
                    name=p.get("name", ""),
                    type=p.get("type", "string"),
                    description=p.get("description", ""),
                    required=p.get("required", False),
                    flag=p.get("flag", ""),
                    position=p.get("position", -1),
                )
                for p in data.get("parameters", [])
            ]
            t = ExternalTool(
                name=data["name"],
                command=data.get("command", data["name"]),
                short_description=data.get("short_description", ""),
                description=data.get("description", ""),
                args=data.get("args", []),
                parameters=params,
                enabled=True,
            )
            self._tools[t.name.lower()] = t
        except Exception:
            pass

    def get(self, name: str) -> Optional[ExternalTool]:
        return self._tools.get(name.lower())

    def list(self, available_only: bool = False) -> List[ExternalTool]:
        tools = list(self._tools.values())
        if available_only:
            tools = [t for t in tools if t.is_available()]
        return tools

    def run(self, name: str, timeout: int = 60, **kwargs) -> str:
        t = self.get(name)
        if not t:
            return f"[tool-ext] '{name}' not found"
        if not t.is_available():
            return f"[tool-ext] '{t.command}' not installed — install it first"
        return t.run(timeout=timeout, **kwargs)
