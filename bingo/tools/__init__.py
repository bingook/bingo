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

# v2.6.0 — TIER 1/2/3 신규 15개 모듈 (lazy import)
def _get_ssti_scanner():
    from .ssti_scanner import SstiScanner, SstiFinding, SstiReport, RCE_CHAINS
    return SstiScanner, SstiFinding, SstiReport, RCE_CHAINS

def _get_param_discovery():
    from .param_discovery import ParamDiscovery, ParamFinding, ParamReport, BYPASS_HEADERS
    return ParamDiscovery, ParamFinding, ParamReport, BYPASS_HEADERS

def _get_subdomain_takeover():
    from .subdomain_takeover import SubdomainTakeoverScanner, TakeoverReport, TakeoverFinding
    return SubdomainTakeoverScanner, TakeoverReport, TakeoverFinding

def _get_smuggling_scanner():
    from .smuggling_scanner import SmugglingScanner, SmugglingReport, quick_smuggle_check
    return SmugglingScanner, SmugglingReport, quick_smuggle_check

def _get_race_condition():
    from .race_condition import RaceConditionEngine, RaceReport, RaceFinding
    return RaceConditionEngine, RaceReport, RaceFinding

def _get_graphql_tester():
    from .graphql_tester import GraphQLTester, GraphQLReport, GraphQLFinding
    return GraphQLTester, GraphQLReport, GraphQLFinding

def _get_twofa_bypass():
    from .twofa_bypass import TwofaBypassEngine, TwofaReport, TwofaFinding
    return TwofaBypassEngine, TwofaReport, TwofaFinding

def _get_cache_poison():
    from .cache_poison import CachePoisonTester, CacheReport, CacheFinding
    return CachePoisonTester, CacheReport, CacheFinding

def _get_deserialize_tester():
    from .deserialize_tester import DeserializeTester, DeserializeReport, DeserializeFinding
    return DeserializeTester, DeserializeReport, DeserializeFinding

def _get_recon_engine():
    from .recon_engine import ReconEngine, ReconReport, ReconAsset
    return ReconEngine, ReconReport, ReconAsset

def _get_nuclei_runner():
    from .nuclei_runner import NucleiRunner, NucleiReport, NucleiFinding, BUILTIN_TEMPLATES
    return NucleiRunner, NucleiReport, NucleiFinding, BUILTIN_TEMPLATES

def _get_bizlogic_fuzzer():
    from .bizlogic_fuzzer import BizlogicFuzzer, BizlogicReport, BizlogicFinding
    return BizlogicFuzzer, BizlogicReport, BizlogicFinding

def _get_dom_xss_scanner():
    from .dom_xss_scanner import DomXssScanner, DomXssReport, DomXssFinding
    return DomXssScanner, DomXssReport, DomXssFinding

def _get_api_version_enum():
    from .api_version_enum import ApiVersionEnumerator, ApiVersionReport, ApiVersionFinding
    return ApiVersionEnumerator, ApiVersionReport, ApiVersionFinding

def _get_cloud_bucket_scanner():
    from .cloud_bucket_scanner import CloudBucketScanner, BucketReport, BucketFinding
    return CloudBucketScanner, BucketReport, BucketFinding

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
    # v2.6.0
    "_get_ssti_scanner",
    "_get_param_discovery",
    "_get_subdomain_takeover",
    "_get_smuggling_scanner",
    "_get_race_condition",
    "_get_graphql_tester",
    "_get_twofa_bypass",
    "_get_cache_poison",
    "_get_deserialize_tester",
    "_get_recon_engine",
    "_get_nuclei_runner",
    "_get_bizlogic_fuzzer",
    "_get_dom_xss_scanner",
    "_get_api_version_enum",
    "_get_cloud_bucket_scanner",
]
