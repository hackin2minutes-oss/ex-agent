"""Evidence records for one investigation.

Every claim in a conclusion cites evidence by id. Each record says which tool collected it, so the report can show how
each fact was obtained.
"""

from dataclasses import asdict, dataclass

# Kinds that describe the code or its metadata. Static evidence cannot show that an attack works.
STATIC_KINDS = ("finding", "source", "advisory", "configuration")
# Kinds that come from running the application. Only these can support CONFIRMED_EXPLOITABLE.
DEMONSTRATED_KINDS = ("dynamic", "runtime")
KINDS = STATIC_KINDS + DEMONSTRATED_KINDS


@dataclass(frozen=True)
class Evidence:
    id: str
    kind: str
    tool: str
    summary: str
    path: str | None = None
    line: int | None = None
    excerpt: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


class EvidenceStore:
    def __init__(self):
        self._items: list[Evidence] = []

    def add(self, *, kind: str, tool: str, summary: str, path: str | None = None, line: int | None = None,
            excerpt: str | None = None) -> Evidence:
        if kind not in KINDS:
            raise ValueError(f"unknown evidence kind: {kind}")
        item = Evidence(id=f"E{len(self._items) + 1}", kind=kind, tool=tool, summary=summary, path=path, line=line,
                        excerpt=excerpt)
        self._items.append(item)
        return item

    def get(self, evidence_id: str) -> Evidence | None:
        return next((item for item in self._items if item.id == evidence_id), None)

    def all(self) -> list[Evidence]:
        return list(self._items)
