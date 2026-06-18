from .registry import ToolRegistry, ToolInfo
from .executor import ToolExecutor, ToolResult
from .http_probe import HttpProbe, ProbeResult
from .sqli import SqliScanner, ScanResult
from .downloader import download_tool, GO_TOOLS
from .installer import install_tool

# v2.4.0 — AI 자동 선택 강화 모듈 (lazy import 로 기존 코드 충돌 방지)
def _get_sqli_auto():
    from .sqli_auto import SqliAutoEngine, detect_db_type
    return SqliAutoEngine, detect_db_type

def _get_db_privesc():
    from .db_privesc import DbPrivescEngine
    return DbPrivescEngine

def _get_shell_dropper():
    from .shell_dropper import ShellDropper, gen_reverse_shell
    return ShellDropper, gen_reverse_shell

__all__ = [
    "ToolRegistry", "ToolInfo",
    "ToolExecutor", "ToolResult",
    "HttpProbe", "ProbeResult",
    "SqliScanner", "ScanResult",
    "download_tool", "GO_TOOLS",
    "install_tool",
    # v2.4.0
    "_get_sqli_auto",
    "_get_db_privesc",
    "_get_shell_dropper",
]
