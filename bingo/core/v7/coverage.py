from __future__ import annotations

from dataclasses import dataclass, field

from .contracts import ActionEnvelope, CoveragePoint


@dataclass
class CoverageLedger:
    points: dict[str, CoveragePoint] = field(default_factory=dict)
    action_counts: dict[str, int] = field(default_factory=dict)

    def mark(self, surface: str, key: str, status: str = "seen") -> CoveragePoint:
        point = CoveragePoint(surface=surface, key=key, status=status)
        self.points[f"{surface}:{key}"] = point
        return point

    def record_action(self, envelope: ActionEnvelope) -> int:
        identity = envelope.identity_key()
        self.action_counts[identity] = self.action_counts.get(identity, 0) + 1
        return self.action_counts[identity]

    def repeated_action(self, envelope: ActionEnvelope, threshold: int = 2) -> bool:
        return self.action_counts.get(envelope.identity_key(), 0) >= threshold

    def has(self, surface: str, key: str) -> bool:
        return f"{surface}:{key}" in self.points

    def keys(self, surface: str) -> tuple[str, ...]:
        return tuple(
            sorted(point.key for point in self.points.values() if point.surface == surface)
        )

    def route_keys(self, *, exclude_root: bool = False, limit: int | None = None) -> tuple[str, ...]:
        routes = [
            key
            for key in self.keys("route")
            if not (exclude_root and key == "/")
        ]
        if limit is not None:
            routes = routes[:limit]
        return tuple(routes)

    def uncovered(self, expected: list[tuple[str, str]]) -> list[tuple[str, str]]:
        missing: list[tuple[str, str]] = []
        for surface, key in expected:
            if f"{surface}:{key}" not in self.points:
                missing.append((surface, key))
        return missing

    def summary(self) -> dict[str, int]:
        by_surface: dict[str, int] = {}
        for point in self.points.values():
            by_surface[point.surface] = by_surface.get(point.surface, 0) + 1
        return by_surface
