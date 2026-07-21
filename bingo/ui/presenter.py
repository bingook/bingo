from __future__ import annotations

from typing import Callable

from .view_models import ActivityEvent, ActivityLine


class ActivityPresenter:
    """Render semantic activity without exposing executor identifiers."""

    def __init__(self, translate: Callable[[str], str]):
        self._translate = translate

    def present(self, event: ActivityEvent) -> ActivityLine:
        template = self._translate(event.message_key)
        try:
            text = template.format(**event.values)
        except (KeyError, ValueError):
            text = template
        return ActivityLine(text=text)
