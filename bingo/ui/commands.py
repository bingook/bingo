from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Iterable


@dataclass(frozen=True)
class Command:
    name: str
    description_key: str
    handler: Callable[[str], object]
    aliases: tuple[str, ...] = ()
    visible: bool = True


class CommandRegistry:
    """Single authority for command completion, help, and dispatch."""

    def __init__(self, commands: Iterable[Command]):
        self._commands: dict[str, Command] = {}
        for command in commands:
            for name in (command.name, *command.aliases):
                normalized = self._normalize(name)
                if normalized in self._commands:
                    raise ValueError(f"duplicate command: {normalized}")
                self._commands[normalized] = command

    @staticmethod
    def _normalize(name: str) -> str:
        return name.strip().lower().lstrip("/")

    def visible_names(self) -> tuple[str, ...]:
        return tuple(
            f"/{command.name}"
            for command in dict.fromkeys(self._commands.values())
            if command.visible
        )

    def dispatch(self, text: str) -> object | None:
        command_text = text.strip()
        if not command_text.startswith("/"):
            return None
        name, _, arguments = command_text[1:].partition(" ")
        command = self._commands.get(self._normalize(name))
        if command is None:
            return None
        return command.handler(arguments.strip())

    def help_entries(self) -> tuple[tuple[str, str], ...]:
        return tuple(
            (f"/{command.name}", command.description_key)
            for command in dict.fromkeys(self._commands.values())
            if command.visible
        )
