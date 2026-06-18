from .registry import ToolRegistry, ToolInfo
from .executor import ToolExecutor, ToolResult
from .http_probe import HttpProbe, ProbeResult
from .sqli import SqliScanner, ScanResult
from .downloader import download_tool, GO_TOOLS
from .installer import install_tool

# v2.4.0 — AI 자동 선택 강화 모듈 (lazy import)
def _get_sqli_auto():
    from .sqli_auto import SqliAutoEngine, detect_db_type
    return SqliAutoEngine, detect_db_type

def _get_db_privesc():
    from .db_privesc import DbPrivescEngine
    return DbPrivescEngine

def _get_shell_dropper():
    from .shell_dropper import ShellDropper, gen_reverse_shell
    return ShellDropper, gen_reverse_shell

# v2.5.0 — 신규 자동화 모듈 (lazy import)
def _get_js_analyzer():
    from .js_analyzer import JsAutoAnalyzer, analyze_js_content
    return JsAutoAnalyzer, analyze_js_content

def _get_idor_scanner():
    from .idor_scanner import IdorScanner
    return IdorScanner

def _get_auth_bypass():
    from .auth_bypass import AuthBypassEngine, analyze_jwt, gen_password_reset_payloads, gen_oauth_test_cases
    return AuthBypassEngine, analyze_jwt, gen_password_reset_payloads, gen_oauth_test_cases

def _get_ssrf_scanner():
    from .ssrf_scanner import SsrfScanner
    return SsrfScanner

def _get_xxe_scanner():
    from .xxe_scanner import XxeScanner, gen_xxe_payloads
    return XxeScanner, gen_xxe_payloads

def _get_upload_bypass():
    from .upload_bypass import UploadBypassEngine, gen_upload_payloads, gen_polyglot_payload
    return UploadBypassEngine, gen_upload_payloads, gen_polyglot_payload

def _get_report_builder():
    from .report_builder import ReportBuilder
    return ReportBuilder

def _get_korean_cms():
    from .korean_cms import KoreanCmsScanner, detect_cms
    return KoreanCmsScanner, detect_cms

def _get_post_exploit():
    from .post_exploit import PostExploitEngine
    return PostExploitEngine

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
    # v2.5.0
    "_get_js_analyzer",
    "_get_idor_scanner",
    "_get_auth_bypass",
    "_get_ssrf_scanner",
    "_get_xxe_scanner",
    "_get_upload_bypass",
    "_get_report_builder",
    "_get_korean_cms",
    "_get_post_exploit",
]
