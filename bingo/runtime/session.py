from __future__ import annotations

from dataclasses import dataclass, field

from .contracts import Completion, ConversationTurn, RuntimeEvent, RuntimeEventKind


@dataclass
class RuntimeSession:
    """Lossless provider conversation state independent from terminal history."""

    turns: list[ConversationTurn] = field(default_factory=list)
    last_completion: Completion | None = None

    def append(self, turn: ConversationTurn) -> None:
        self.turns.append(turn)

    def observe(self, event: RuntimeEvent) -> None:
        if event.kind is RuntimeEventKind.RESPONSE_COMPLETED:
            self.last_completion = event.completion
