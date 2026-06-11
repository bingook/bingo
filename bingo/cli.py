from __future__ import annotations
import sys
import os

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.text import Text

from .config import BingoConfig
from .lang.strings import get_strings, SUPPORTED_LANGS

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
    console.print(f"[#4a4a4a](나중에 /model 명령어로 추가할 수 있습니다)[/]\n")

    from .models.registry import BUILTIN_PROVIDERS
    from .models.base import ModelConfig

    providers = list(BUILTIN_PROVIDERS.items())
    for i, (pid, info) in enumerate(providers, 1):
        console.print(f"  [#00d4aa]{i}[/] — {info['label']}")
    console.print(f"  [#4a4a4a]0[/] — 나중에 설정")
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


def _run_scan_mode(target: str, cfg: BingoConfig, args: list[str]) -> None:
    """bingo scan <url> — 완전 자동 Red Team 모드 (인가 시스템 포함)"""
    from rich.live import Live
    from rich.spinner import Spinner
    from rich.text import Text
    from .core.authorization import create_auth_context
    import os

    # 타겟 인가 컨텍스트 생성 (도메인 무관 전체 체인)
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
        elif "✓" in msg or "✅" in msg or "성공" in msg or "발견" in msg:
            console.print(f"[#00ff41]{msg}[/]")
        elif "▶" in msg or "Phase" in msg or "───" in msg:
            console.print(f"\n[#00d4aa]{msg}[/]")
        elif "WAF" in msg or "우회" in msg:
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
        console.print(f"\n[#00ff41]✓ 완료! 보고서: {report_path}[/]")
    except KeyboardInterrupt:
        console.print("\n[#ffaa00]중단됨 — 세션이 저장됐습니다[/]")


def _run_waf_test(target: str) -> None:
    """bingo waf <url> — WAF 탐지 + 우회 테스트"""
    from .tools.http_probe import HttpProbe
    from .tools.waf_bypass import WafDetector, WafBypassEngine

    console.print(f"\n[#ffaa00]🛡 WAF 분석: {target}[/]\n")
    probe = HttpProbe(target)
    detector = WafDetector(probe)

    with console.status("[#ffaa00]WAF 탐지 중...[/]"):
        result = detector.detect(target)

    if result.detected:
        console.print(f"[#ff4444]WAF 탐지됨: {result.waf_type}[/]")
        console.print(f"[#ffaa00]신뢰도: {result.confidence}[/]")
        console.print(f"[#4a4a4a]증거: {result.evidence}[/]")
        console.print(f"\n[#00d4aa]권장 우회 전략:[/]")
        for i, strategy in enumerate(result.bypass_priority, 1):
            console.print(f"  {i}. {strategy}")

        # 자동 우회 시도
        console.print(f"\n[#ffaa00]자동 우회 시도 중...[/]")
        engine = WafBypassEngine(probe, on_progress=lambda s: console.print(f"[#c9d1d9]{s}[/]"))
        test_payload = "' OR 1=1--"
        success, attempt = engine.auto_bypass(target + "?id=1", test_payload)
        if success and attempt:
            console.print(f"\n[#00ff41]✓ 우회 성공![/]")
            console.print(f"[#00ff41]기법: {attempt.technique}[/]")
            console.print(f"[#00ff41]페이로드: {attempt.payload_modified}[/]")
        elif success:
            console.print(f"\n[#00ff41]WAF 없음 — 직접 공격 가능[/]")
        else:
            console.print(f"\n[#ff4444]현재 기법으로 우회 실패 — AI 분석 필요[/]")
    else:
        console.print(f"[#00ff41]WAF 탐지 안됨 — 정상 접근 가능[/]")


def main() -> None:
    """bingo 명령어 진입점"""
    args = sys.argv[1:]

    # ── bingo scan <url> ─────────────────────────────────────────
    if args and args[0] == "scan":
        if len(args) < 2:
            console.print("[#ff4444]Usage: bingo scan <url> [--output ./reports] [--phase recon,scan,exploit][/]")
            return
        target = args[1]
        cfg = BingoConfig.load()
        _run_scan_mode(target, cfg, args[2:])
        return

    # ── bingo waf <url> ──────────────────────────────────────────
    if args and args[0] == "waf":
        if len(args) < 2:
            console.print("[#ff4444]Usage: bingo waf <url>[/]")
            return
        _run_waf_test(args[1])
        return

    # ── bingo tools ──────────────────────────────────────────────
    if args and args[0] == "tools":
        from .tools.registry import ToolRegistry
        console.print("\n[#00d4aa]설치된 도구 현황[/]\n")
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
            engine.install(on_progress=lambda s: console.print(f"[#00d4aa]{s}[/]"))
        elif len(args) > 1 and args[1] == "search":
            kw = " ".join(args[2:]) if len(args) > 2 else ""
            results = engine.search(kw)
            for r in results[:20]:
                console.print(f"  [#00d4aa]{r['module']}[/] → [white]{r['skill']}[/]")
        elif len(args) > 1 and args[1] == "stats":
            s = engine.stats()
            console.print(f"\n[#00d4aa]📚 내장 스킬 통계[/]")
            console.print(f"  전체 스킬: [white]{s['total_skills']}개[/]")
            console.print(f"  CyberSecurity-Skills: [white]{s['cybersecurity_skills']}개[/]")
            console.print(f"  SecSkills 로컬 (Downloads/skills): [white]{s['secskills_local']}개[/]")
            console.print(f"  모듈: [white]{s['total_modules']}개[/] | 태그: [white]{s['total_tags']}개[/]")
            console.print(f"  로컬 Clone: [white]{'✅' if s['local_clone'] else '❌ (bingo skill install 필요)'}[/]")
        else:
            s = engine.stats()
            console.print(f"\n[#00d4aa]CyberSecurity-Skills 39 모듈 + SecSkills 로컬 통합[/]")
            console.print(f"[#4a4a4a]총 {s['total_skills']}개 스킬 내장 (CyberSec {s['cybersecurity_skills']} + SecSkills {s['secskills_local']})[/]\n")
            for mod in engine.list_all():
                console.print(f"  [#00d4aa]{mod['id']}[/] {mod['en']:35s} [#4a4a4a]({len(mod['skills'])} skills)[/]")
        return

    # ── 도움말 ───────────────────────────────────────────────────
    if args and args[0] in ("-h", "--help"):
        console.print(BANNER_SMALL)
        console.print()
        console.print("  [#00d4aa]Usage:[/]")
        console.print("    [white]bingo[/]                      AI 채팅 터미널")
        console.print("    [white]bingo scan <url>[/]           🎯 자동 Red Team 스캔")
        console.print("    [white]bingo waf <url>[/]            🛡 WAF 탐지 + 우회 테스트")
        console.print("    [white]bingo tools[/]                🔧 설치된 도구 목록")
        console.print("    [white]bingo skill[/]                📚 CyberSecurity-Skills 목록")
        console.print("    [white]bingo skill install[/]        스킬 DB 다운로드")
        console.print("    [white]bingo skill search <keyword>[/] 스킬 검색")
        console.print()
        console.print("  [#4a4a4a]Options:[/]")
        console.print("    [#00d4aa]--reset[/]   설정 초기화  |  [#00d4aa]--version[/]  버전 표시")
        console.print()
        console.print("  [#4a4a4a]scan 옵션:[/]")
        console.print("    [#00d4aa]--output ./reports[/]       보고서 저장 위치")
        console.print("    [#00d4aa]--phase recon,scan,exploit[/] 실행할 단계 선택")
        return

    if args and args[0] == "--version":
        console.print("[#00ff41]bingo[/] v2.0.0 — Red Team Edition")
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
