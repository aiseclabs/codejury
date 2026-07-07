"""SourceMeta: optional, display-only provenance for a fetched source tree.

It records where a local source tree came from, such as a chain and a contract
address, so a review can show that context. It never feeds finding decisions,
invariants 2 and 3.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from typing import Any


class SourceError(Exception):
    """A source fetch or parse failed, raised to fail loud rather than return a
    partial or empty tree, invariant 4."""


@dataclass(frozen=True, kw_only=True)
class SourceMeta:
    source: str = ""
    chain: str = ""
    chain_id: int | None = None
    address: str = ""
    source_url: str = ""
    contract_name: str = ""
    compiler_version: str = ""
    optimization_used: bool | None = None
    runs: int | None = None
    constructor_arguments: str = ""
    evm_version: str = ""
    license_type: str = ""
    proxy: bool | None = None
    implementation_address: str = ""
    fetched_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=False)

    def is_empty(self) -> bool:
        """No provenance was recorded, so a report shows no Target section."""
        return all(value in ("", None) for value in asdict(self).values())


def _to_int(value: object) -> int | None:
    # bool is an int subclass, so reject it or True would read as 1
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _to_bool(value: object) -> bool | None:
    # explorers report flags as the strings "1" and "0", not JSON booleans
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        token = value.strip().lower()
        if token in ("1", "true"):
            return True
        if token in ("0", "false"):
            return False
    return None


def _to_str(value: object) -> str:
    return value.strip() if isinstance(value, str) else ""


def source_meta_from_dict(data: object) -> SourceMeta:
    """Read a codejury-source.json back into a SourceMeta, or fail loud when the
    file is not a JSON object, invariant 4. A missing field stays empty, never guessed."""
    if not isinstance(data, dict):
        raise SourceError("source metadata is not a JSON object")
    return SourceMeta(
        source=_to_str(data.get("source")),
        chain=_to_str(data.get("chain")),
        chain_id=_to_int(data.get("chain_id")),
        address=_to_str(data.get("address")),
        source_url=_to_str(data.get("source_url")),
        contract_name=_to_str(data.get("contract_name")),
        compiler_version=_to_str(data.get("compiler_version")),
        optimization_used=_to_bool(data.get("optimization_used")),
        runs=_to_int(data.get("runs")),
        constructor_arguments=_to_str(data.get("constructor_arguments")),
        evm_version=_to_str(data.get("evm_version")),
        license_type=_to_str(data.get("license_type")),
        proxy=_to_bool(data.get("proxy")),
        implementation_address=_to_str(data.get("implementation_address")),
        fetched_at=_to_str(data.get("fetched_at")),
    )
