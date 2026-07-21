from bingo.lang.strings import get_slash_commands, get_strings
from bingo.ui.commands import Command, CommandRegistry
from bingo.ui.presenter import ActivityPresenter
from bingo.ui.view_models import ActivityEvent, ActivityKind


def test_activity_presenter_renders_all_supported_languages_without_diagnostics():
    event = ActivityEvent(
        kind=ActivityKind.ACTION_STARTED,
        message_key="chat_action_started",
        values={"activity": "application entry point"},
        diagnostics={"capability": "http_get"},
    )

    rendered = []
    for language in ("ko", "zh", "en"):
        strings = get_strings(language)
        line = ActivityPresenter(lambda key, s=strings: s[key]).present(event)
        rendered.append(line.text)
        assert "http_get" not in line.text

    assert rendered[0] == "application entry point 확인 중"
    assert rendered[1] == "正在检查application entry point"
    assert rendered[2] == "Checking application entry point"


def test_command_registry_is_single_dispatch_and_help_authority():
    seen = []
    registry = CommandRegistry(
        [
            Command("help", "help", lambda args: seen.append(("help", args))),
            Command("quit", "quit", lambda args: seen.append(("quit", args))),
        ]
    )

    registry.dispatch("/help topic")

    assert seen == [("help", "topic")]
    assert registry.visible_names() == ("/help", "/quit")
    assert registry.help_entries() == (("/help", "help"), ("/quit", "quit"))
    assert registry.dispatch("/tools") is None


def test_chat_command_surface_hides_internal_capability_commands():
    forbidden = {"/waf", "/tools", "/skill", "/recon", "/agent", "/login", "/cred"}

    for language in ("ko", "zh", "en"):
        commands = {name for name, _description in get_slash_commands(language)}
        help_text = get_strings(language)["help_text"]
        assert commands.isdisjoint(forbidden)
        assert all(command not in help_text for command in forbidden)
