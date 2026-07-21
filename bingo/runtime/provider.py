from __future__ import annotations

from typing import Iterator, Protocol

from .contracts import ModelRequest, ProviderCapabilities, RuntimeEvent


class ProviderAdapter(Protocol):
    """Normalize one model provider into Bingo runtime events.

    Adapters decode provider output only. They never execute requested tools.
    """

    def capabilities(self) -> ProviderCapabilities:
        ...

    def stream(self, request: ModelRequest) -> Iterator[RuntimeEvent]:
        ...
