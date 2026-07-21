from __future__ import annotations

from dataclasses import dataclass, field

from .contracts import EvidenceItem, EvidenceTier


_RANK = {
    EvidenceTier.OBSERVATION: 1,
    EvidenceTier.CANDIDATE: 2,
    EvidenceTier.CONFIRMED: 3,
}


@dataclass
class EvidenceGraph:
    items: dict[str, EvidenceItem] = field(default_factory=dict)

    def add(self, item: EvidenceItem) -> EvidenceItem:
        existing = self.items.get(item.key)
        if existing is None:
            self.items[item.key] = item
            return item
        if _RANK[item.tier] > _RANK[existing.tier]:
            self.items[item.key] = item
            return item
        return existing

    def counts(self) -> dict[str, int]:
        summary = {"observation": 0, "candidate": 0, "confirmed": 0}
        for item in self.items.values():
            summary[item.tier.value] += 1
        return summary

    def confirmed(self) -> list[EvidenceItem]:
        return [item for item in self.items.values() if item.tier == EvidenceTier.CONFIRMED]

    def kind_counts(self, *, tier: EvidenceTier | None = None) -> dict[str, int]:
        counts: dict[str, int] = {}
        for item in self.items.values():
            if tier is not None and item.tier != tier:
                continue
            counts[item.kind] = counts.get(item.kind, 0) + 1
        return counts

    def strongest_kinds(
        self,
        *,
        tier: EvidenceTier | None = None,
        limit: int = 3,
    ) -> tuple[str, ...]:
        counts = self.kind_counts(tier=tier)
        ordered = sorted(counts.items(), key=lambda pair: (-pair[1], pair[0]))
        return tuple(kind for kind, _count in ordered[:limit])

    def plateau_keyset(self) -> frozenset[str]:
        return frozenset(
            f"{item.kind}:{item.key}:{item.tier.value}"
            for item in self.items.values()
        )
