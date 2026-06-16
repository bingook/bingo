from __future__ import annotations
import sys
import os

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.text import Text

from .config import BingoConfig
from .lang.strings import get_strings, SUPPORTED_LANGS

def _s(lang: str = "en") -> dict:
    """현재 언어 문자열 딕셔너리 반환 (CLI 스탠드어론용)"""
    return get_strings(lang)

console = Console(highlight=False)

BANNER_SMALL = r"""[#00ff41]
  ██████╗ ██╗███╗   ██╗ ██████╗  ██████╗ 
  ██╔══██╗██║████╗  ██║██╔════╝ ██╔═══██╗
  ██████╔╝██║██╔██╗ ██║██║  ███╗██║   ██║
  ██╔══██╗██║██║╚██╗██║██║   ██║██║   ██║
  ██████╔╝██║██║ ╚████║╚██████╔╝╚██████╔╝
  ╚═════╝ ╚═╝╚═╝  ╚═══╝ ╚═════╝  ╚═════╝[/#00ff41]"""


def _onboarding(cfg: BingoConfig) -> BingoConfig:
    """첫 실행 온보딩: 언어 선택 → 모델 설정"""
    os.system("cls" if os.name == "nt" else "clear")
    console.print(BANNER_SMALL)
    console.print()
    console.print(Panel(
        "[#00d4aa]Bingo[/] — AI Terminal  |  Multi-Model  |  Hacker Style\n"
        "[#4a4a4a]DeepSeek · Claude · GPT · GLM · Qwen · Ollama · Custom[/]",
        border_style="#00ff41",
        padding=(0, 2),
    ))
    console.print()

    # ── 언어 선택 ─────────────────────────────────────────────────
    console.print("[#00ff41]Select language / 언어 선택 / 选择语言[/]\n")
    for i, (code, label) in enumerate(SUPPORTED_LANGS.items(), 1):
        console.print(f"  [#00d4aa]{i}[/] — {label}")
    console.print()

    lang_choice = Prompt.ask(
        "[#00ff41]>[/]",
        choices=["1", "2", "3"],
        default="1",
    )
    lang_map = {str(i+1): k for i, k in enumerate(SUPPORTED_LANGS)}
    cfg.lang = lang_map.get(lang_choice, "ko")
    s = get_strings(cfg.lang)

    console.print(f"  [#00ff41]✔[/]  {s['lang_saved']}\n")

    # ── 첫 모델 설정 여부 확인 ────────────────────────────────────
    console.print(f"[#00ff41]{s['select_model']}[/]")
    s = get_strings(cfg.lang)
    console.print(f"[#4a4a4a]({s['cli_model_later']})[/]\n")

    from .models.registry import BUILTIN_PROVIDERS
    from .models.base import ModelConfig

    providers = list(BUILTIN_PROVIDERS.items())
    for i, (pid, info) in enumerate(providers, 1):
        console.print(f"  [#00d4aa]{i}[/] — {info['label']}")
    console.print(f"  [#4a4a4a]0[/] — {s['cli_skip_model']}")
    console.print()

    choice_raw = Prompt.ask("[#00ff41]>[/]", default="0").strip()
    try:
        choice = int(choice_raw)
    except ValueError:
        choice = 0

    if choice > 0:
        idx = choice - 1
        if 0 <= idx < len(providers):
            pid, info = providers[idx]
            api_key = Prompt.ask(
                f"\n[#00ff41]{info['label']} {s['enter_api_key']}[/]",
                password=True,
            )
            default_url = info["base_url"]
            url_raw = Prompt.ask(
                f"[#00ff41]{s['enter_base_url']}[/] [#4a4a4a]({default_url})[/]",
            ).strip()
            base_url = url_raw or default_url

            default_model = info["default_model"]
            model_raw = Prompt.ask(
                f"[#00ff41]{s['model_name_prompt']}[/] [#4a4a4a]({default_model})[/]",
            ).strip()
            model_name = model_raw or default_model

            model_cfg = ModelConfig(
                provider=pid,
                model=model_name,
                api_key=api_key,
                base_url=base_url,
            )
            cfg.add_model(model_cfg)
            cfg.active_model = model_cfg.display_name()
            console.print(f"\n  [#00ff41]✔[/]  {s['model_saved']}\n")

    cfg.save()
    return cfg


def _run_scan_mode(target: str, cfg: BingoConfig, args: list[str], s: dict | None = None) -> None:
    """bingo scan <url> — 완전 자동 Red Team 모드 (인가 시스템 포함)"""
    from rich.live import Live
    from rich.spinner import Spinner
    from rich.text import Text
    from .core.authorization import create_auth_context
    import os

    if s is None:
        s = get_strings(cfg.lang)

    auth_ctx = create_auth_context(target)

    console.print(BANNER_SMALL)
    console.print()
    console.print(Panel(
        f"[#ff4444]⚔  BINGO RED TEAM — AUTHORIZED ENGAGEMENT[/]\n"
        f"[#00d4aa]Target:[/] [white]{target}[/]\n"
        f"[dim]✅ SQLi(read) · DB Extract · Admin Login · Webshell[/dim]\n"
        f"[dim]❌ INSERT/UPDATE/DELETE — permanently blocked[/dim]",
        border_style="#ff4444",
        padding=(0, 2),
    ))
    console.print()

    # 출력 디렉토리
    output_dir = "."
    if "--output" in args:
        idx = args.index("--output")
        output_dir = args[idx + 1] if idx + 1 < len(args) else "."

    # 단계 선택 (기본: 전체)
    phases = None
    if "--phase" in args:
        idx = args.index("--phase")
        phases = args[idx + 1].split(",") if idx + 1 < len(args) else None

    from .redteam.pipeline import RedTeamPipeline
    model_cfg = cfg.get_active_model_config() if cfg.models else None

    def _log(msg: str):
        if "[!]" in msg or "SQLi" in msg or "critical" in msg.lower():
            console.print(f"[#ff4444]{msg}[/]")
        elif "✓" in msg or "✅" in msg or "success" in msg.lower() or "found" in msg.lower():
            console.print(f"[#00ff41]{msg}[/]")
        elif "▶" in msg or "Phase" in msg or "───" in msg:
            console.print(f"\n[#00d4aa]{msg}[/]")
        elif "WAF" in msg or "bypass" in msg.lower():
            console.print(f"[#ffaa00]{msg}[/]")
        elif "❌" in msg or "FORBIDDEN" in msg:
            console.print(f"[#ff4444]{msg}[/]")
        else:
            console.print(f"[#c9d1d9]{msg}[/]")

    pipeline = RedTeamPipeline(
        target=target,
        model_config=model_cfg,
        output_dir=output_dir,
        on_progress=_log,
        auth_ctx=auth_ctx,    # 인가 컨텍스트 전달
    )

    try:
        report_path = pipeline.run(phases=phases)
        console.print(f"\n[#00ff41]{s['cli_scan_done']}: {report_path}[/]")
    except KeyboardInterrupt:
        console.print(f"\n[#ffaa00]{s['cli_scan_abort']}[/]")


def _run_waf_test(target: str, s: dict | None = None) -> None:
    """bingo waf <url> — WAF 탐지 + 우회 테스트"""
    from .tools.http_probe import HttpProbe
    from .tools.waf_bypass import WafDetector, WafBypassEngine

    if s is None:
        cfg = BingoConfig.load()
        s = get_strings(cfg.lang)

    console.print(f"\n[#ffaa00]{s['cli_waf_title']}: {target}[/]\n")
    probe = HttpProbe(target)
    detector = WafDetector(probe)

    with console.status(f"[#ffaa00]{s['waf_detecting']}[/]"):
        result = detector.detect(target)

    if result.detected:
        console.print(f"[#ff4444]{s['cli_waf_detected']}: {result.waf_type}[/]")
        console.print(f"[#ffaa00]{s['cli_waf_confidence']}: {result.confidence}[/]")
        console.print(f"[#4a4a4a]{s['cli_waf_evidence']}: {result.evidence}[/]")
        console.print(f"\n[#00d4aa]{s['cli_waf_strategy']}:[/]")
        for i, strategy in enumerate(result.bypass_priority, 1):
            console.print(f"  {i}. {strategy}")

        console.print(f"\n[#ffaa00]{s['cli_waf_bypass_try']}[/]")
        engine = WafBypassEngine(probe, on_progress=lambda m: console.print(f"[#c9d1d9]{m}[/]"))
        test_payload = "' OR 1=1--"
        success, attempt = engine.auto_bypass(target + "?id=1", test_payload)
        if success and attempt:
            console.print(f"\n[#00ff41]{s['cli_waf_bypass_ok']}[/]")
            console.print(f"[#00ff41]{s['cli_waf_tech']}: {attempt.technique}[/]")
            console.print(f"[#00ff41]{s['cli_waf_payload']}: {attempt.payload_modified}[/]")
        elif success:
            console.print(f"\n[#00ff41]{s['waf_none']}[/]")
        else:
            console.print(f"\n[#ff4444]{s['cli_waf_bypass_fail']}[/]")
    else:
        console.print(f"[#00ff41]{s['cli_waf_none']}[/]")


CURRENT_VERSION = "2.3.9"
PYPI_PACKAGE    = "bingo-ai"
PYPI_JSON_URL   = f"https://pypi.org/pypi/{PYPI_PACKAGE}/json"


def _detect_install_method() -> tuple[str, "Path | None"]:
    """
    설치 방법 자동 감지.
    반환값: ('git' | 'pip', git_root_or_None)
    - 패키지 파일 기준으로 .git 폴더가 있으면 git clone 설치로 판단
    """
    from pathlib import Path
    pkg_dir = Path(__file__).resolve().parent          # bingo/bingo/
    # 최대 3단계 위까지 .git 탐색 (bingo/bingo → bingo/ → 상위)
    for candidate in [pkg_dir, pkg_dir.parent, pkg_dir.parent.parent]:
        if (candidate / ".git").exists():
            return ("git", candidate)
    return ("pip", None)


def _run_update(sl: dict, lang: str = "en") -> None:
    """
    bingo --update
    설치 방법 자동 감지:
      - git clone  → git pull origin main
      - pip install → pip install --upgrade bingo-ai
    macOS / Windows / Linux 공통 동작
    """
    import sys, subprocess, json as _json

    _labels = {
        "ko": {
            "checking":      "📡 최신 버전 확인 중...",
            "method_git":    "📂 설치 방식: git clone — git pull 로 업데이트합니다",
            "method_pip":    "📦 설치 방식: pip — PyPI 에서 업데이트합니다",
            "latest":        "✅ 이미 최신 버전입니다",
            "found":         "🆕 새 버전 발견",
            "upgrading_git": "⬆  git pull 실행 중...",
            "upgrading_pip": "⬆  pip 업그레이드 중...",
            "done":          "✅ 업데이트 완료! 변경 사항을 적용하려면 bingo 를 재시작하세요.",
            "fail_git":      "❌ git pull 실패 — 아래 명령어를 직접 실행하세요:",
            "fail_pip":      "❌ pip 업그레이드 실패 — 아래 명령어를 직접 실행하세요:",
            "fail_pypi":     "⚠  PyPI 버전 확인 실패 — 수동으로 업그레이드하세요:",
        },
        "zh": {
            "checking":      "📡 正在检查最新版本...",
            "method_git":    "📂 安装方式: git clone — 将使用 git pull 更新",
            "method_pip":    "📦 安装方式: pip — 将从 PyPI 更新",
            "latest":        "✅ 已是最新版本",
            "found":         "🆕 发现新版本",
            "upgrading_git": "⬆  正在执行 git pull...",
            "upgrading_pip": "⬆  正在 pip 升级...",
            "done":          "✅ 更新完成！请重新启动 bingo 以应用更改。",
            "fail_git":      "❌ git pull 失败 — 请手动运行:",
            "fail_pip":      "❌ pip 升级失败 — 请手动运行:",
            "fail_pypi":     "⚠  无法检查 PyPI 版本 — 请手动升级:",
        },
        "en": {
            "checking":      "📡 Checking for latest version...",
            "method_git":    "📂 Installed via git clone — updating with git pull",
            "method_pip":    "📦 Installed via pip — updating from PyPI",
            "latest":        "✅ Already up to date",
            "found":         "🆕 New version available",
            "upgrading_git": "⬆  Running git pull...",
            "upgrading_pip": "⬆  Running pip upgrade...",
            "done":          "✅ Update complete! Restart bingo to apply changes.",
            "fail_git":      "❌ git pull failed — run manually:",
            "fail_pip":      "❌ pip upgrade failed — run manually:",
            "fail_pypi":     "⚠  Could not reach PyPI — upgrade manually:",
        },
    }
    lb = _labels.get(lang, _labels["en"])

    def _ver_tuple(v: str):
        try:
            return tuple(int(x) for x in v.split("."))
        except ValueError:
            return (0, 0, 0)

    # ── 설치 방법 감지 ──────────────────────────────────────────────
    method, git_root = _detect_install_method()

    # ────────────────────────────────────────────────────────────────
    # GIT CLONE 경로
    # ────────────────────────────────────────────────────────────────
    if method == "git" and git_root is not None:
        console.print(f"[#00d4aa]{lb['method_git']}[/]")
        console.print(f"[#00d4aa]{lb['upgrading_git']}[/]\n")
        try:
            subprocess.run(
                ["git", "pull", "origin", "main"],
                cwd=str(git_root),
                check=True,
            )
            console.print(f"\n[#00ff41]{lb['done']}[/]")
        except subprocess.CalledProcessError:
            console.print(f"\n[#ff4444]{lb['fail_git']}[/]")
            console.print(f"[#4a4a4a]  cd {git_root} && git pull origin main[/]")
        return

    # ────────────────────────────────────────────────────────────────
    # PIP 경로
    # ────────────────────────────────────────────────────────────────
    console.print(f"[#00d4aa]{lb['method_pip']}[/]")
    console.print(f"[#00d4aa]{lb['checking']}[/]")

    # 1) PyPI 최신 버전 조회
    try:
        import urllib.request
        req = urllib.request.Request(
            PYPI_JSON_URL,
            headers={"User-Agent": f"bingo-updater/{CURRENT_VERSION}"},
        )
        with urllib.request.urlopen(req, timeout=8) as resp:
            data = _json.loads(resp.read())
        latest_ver = data["info"]["version"]
    except Exception:
        console.print(f"[#ff4444]{lb['fail_pypi']}[/]")
        console.print(f"[#4a4a4a]  pip install --upgrade {PYPI_PACKAGE}[/]")
        return

    # 2) 버전 비교
    if _ver_tuple(latest_ver) <= _ver_tuple(CURRENT_VERSION):
        console.print(
            f"[#00ff41]{lb['latest']}[/] [#4a4a4a](v{CURRENT_VERSION})[/]"
        )
        return

    console.print(
        f"[#ffaa00]{lb['found']}:[/] "
        f"[#4a4a4a]v{CURRENT_VERSION}[/] → [#00ff41]v{latest_ver}[/]"
    )
    console.print(f"[#00d4aa]{lb['upgrading_pip']}[/]\n")

    # 3) pip upgrade 실행
    pip_cmd = [sys.executable, "-m", "pip", "install", "--upgrade", PYPI_PACKAGE]
    try:
        subprocess.run(pip_cmd, check=True)
        console.print(f"\n[#00ff41]{lb['done']}[/]")
    except subprocess.CalledProcessError:
        console.print(f"\n[#ff4444]{lb['fail_pip']}[/]")
        console.print(f"[#4a4a4a]  {' '.join(pip_cmd)}[/]")


def main() -> None:
    """bingo 명령어 진입점"""
    args = sys.argv[1:]

    # 언어 먼저 로드
    _cfg_for_lang = BingoConfig.load()
    sl = get_strings(_cfg_for_lang.lang)

    # ── bingo scan <url> ─────────────────────────────────────────
    if args and args[0] == "scan":
        if len(args) < 2:
            console.print("[#ff4444]Usage: bingo scan <url> [--output ./reports] [--phase recon,scan,exploit][/]")
            return
        target = args[1]
        _run_scan_mode(target, _cfg_for_lang, args[2:], sl)
        return

    # ── bingo waf <url> ──────────────────────────────────────────
    if args and args[0] == "waf":
        if len(args) < 2:
            console.print("[#ff4444]Usage: bingo waf <url>[/]")
            return
        _run_waf_test(args[1], sl)
        return

    # ── bingo install exe-deps ───────────────────────────────────
    # Playwright-style: "bingo install exe-deps"
    if args and args[0] == "install" and len(args) > 1 and args[1] in (
        "exe-deps", "exe", "exe-analyzer", "pe-deps",
    ):
        from .tools.exe_analyzer import ensure_exe_deps, _load_optional_deps, _DEPS_CHECKED  # noqa: PLC0415
        import bingo.tools.exe_analyzer as _exe_mod
        _exe_mod._DEPS_CHECKED = False   # force re-check so output always shown
        ensure_exe_deps(silent=False)
        _load_optional_deps()
        return

    # ── bingo tools ──────────────────────────────────────────────
    if args and args[0] == "tools":
        from .tools.registry import ToolRegistry
        console.print(f"\n[#00d4aa]{sl['cli_tools_title']}[/]\n")
        all_tools = ToolRegistry.scan_all()
        for name, info in all_tools.items():
            status = "[#00ff41]✓[/]" if info.available else "[#ff4444]✗[/]"
            ver = f"[#4a4a4a]({info.version[:30]})[/]" if info.available else f"[#4a4a4a]Install: {info.install_hint[:50]}[/]"
            console.print(f"  {status} [white]{name:15s}[/] {ver}")
        console.print()
        return

    # ── bingo skill ───────────────────────────────────────────────
    if args and args[0] == "skill":
        from .skills.engine import SkillEngine
        engine = SkillEngine()
        if len(args) > 1 and args[1] == "install":
            engine.install(on_progress=lambda m: console.print(f"[#00d4aa]{m}[/]"))
        elif len(args) > 1 and args[1] == "search":
            kw = " ".join(args[2:]) if len(args) > 2 else ""
            results = engine.search(kw)
            for r in results[:20]:
                console.print(f"  [#00d4aa]{r['module']}[/] → [white]{r['skill']}[/]")
        elif len(args) > 1 and args[1] == "stats":
            st = engine.stats()
            need = sl['cli_skill_need_install']
            console.print(f"\n[#00d4aa]{sl['cli_skill_stats']}[/]")
            console.print(f"  {sl['cli_skill_total']}: [white]{st['total_skills']}[/]")
            console.print(f"  CyberSecurity-Skills: [white]{st['cybersecurity_skills']}[/]")
            console.print(f"  SecSkills: [white]{st['secskills_local']}[/]")
            console.print(f"  {sl['cli_skill_modules']}: [white]{st['total_modules']}[/] | {sl['cli_skill_tags']}: [white]{st['total_tags']}[/]")
            console.print(f"  {sl['cli_skill_local']}: [white]{'✅' if st['local_clone'] else f'❌ ({need})'}[/]")
        else:
            st = engine.stats()
            console.print(f"\n[#00d4aa]{sl['cli_skill_integrated']}[/]")
            console.print(f"[#4a4a4a]{st['total_skills']} skills (CyberSec {st['cybersecurity_skills']} + SecSkills {st['secskills_local']})[/]\n")
            for mod in engine.list_all():
                console.print(f"  [#00d4aa]{mod['id']}[/] {mod['en']:35s} [#4a4a4a]({len(mod['skills'])} skills)[/]")
        return

    # ── 도움말 ───────────────────────────────────────────────────
    if args and args[0] in ("-h", "--help", "help"):
        console.print(BANNER_SMALL)
        console.print()
        console.print("  [#00d4aa]Usage:[/]")
        console.print(f"    [white]bingo[/]                      {sl['cli_help_chat']}")
        console.print(f"    [white]bingo scan <url>[/]           {sl['cli_help_scan']}")
        console.print(f"    [white]bingo waf <url>[/]            {sl['cli_help_waf']}")
        console.print(f"    [white]bingo tools[/]                {sl['cli_help_tools']}")
        console.print(f"    [white]bingo skill[/]                {sl['cli_help_skill']}")
        console.print(f"    [white]bingo skill install[/]        {sl['cli_help_skill_install']}")
        console.print(f"    [white]bingo skill search <keyword>[/] {sl['cli_help_skill_search']}")
        console.print(f"    [white]bingo install exe-deps[/]      Install EXE Phase 0 libs (pefile, lief, yara, ssdeep, requests)")
        console.print()
        console.print("  [#4a4a4a]Options:[/]")
        console.print(f"    [#00d4aa]--reset[/]    {sl['cli_help_reset']}")
        console.print(f"    [#00d4aa]--version[/]  {sl['cli_help_version']}")
        console.print(f"    [#00d4aa]--update[/]   {sl.get('cli_help_update', 'Check for updates and upgrade to latest version')}")
        console.print()
        console.print("  [#4a4a4a]scan:[/]")
        console.print(f"    [#00d4aa]--output ./reports[/]       {sl['cli_help_output']}")
        console.print(f"    [#00d4aa]--phase recon,scan,exploit[/] {sl['cli_help_phase']}")
        return

    if args and args[0] == "--version":
        console.print("[#00ff41]bingo[/] v2.1.9 — Official Release")
        return

    if args and args[0] == "--update":
        _run_update(get_strings(_cfg_for_lang.lang), _cfg_for_lang.lang)
        return

    # ── 설정 로드 / 첫 실행 온보딩 ───────────────────────────────
    cfg = BingoConfig.load()
    reset = bool(args) and args[0] == "--reset"

    if cfg.is_first_run() or reset:
        if reset:
            from .config import CONFIG_FILE
            if CONFIG_FILE.exists():
                CONFIG_FILE.unlink()
            cfg = BingoConfig()
        cfg = _onboarding(cfg)

    # ── 터미널 실행 ───────────────────────────────────────────────
    s = get_strings(cfg.lang)
    from .ui.terminal import BingoTerminal
    app = BingoTerminal(cfg, s)
    app.run()


if __name__ == "__main__":
    main()
