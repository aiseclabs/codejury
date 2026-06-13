"""Domain selection: resolve a name to a `Domain`, or detect one from a file list.

The registry is the one place that knows which domains exist. `get_domain` fails loud on
an unknown or not-yet-available name rather than silently falling back, so a target the
tool cannot review is an error, not an empty clean result. `detect_domain` is a pure
extension heuristic returning a name, kept independent of registration so it can name a
domain that exists as a heuristic before its knowledge set ships.
"""

from __future__ import annotations

from pathlib import Path

from codejury.domains.base import Domain
from codejury.domains.evm import EVM
from codejury.domains.web import WEB

_DOMAINS: dict[str, Domain] = {WEB.name: WEB, EVM.name: EVM}

# the single source of the default domain, so the engine and loaders resolve a missing
# domain here instead of each naming one in its own defaults.
DEFAULT_DOMAIN = WEB


def default_domain() -> Domain:
    return DEFAULT_DOMAIN


def available_domains() -> tuple[str, ...]:
    return tuple(_DOMAINS)


def get_domain(name: str) -> Domain:
    try:
        return _DOMAINS[name]
    except KeyError:
        raise ValueError(
            f"unknown or unavailable review domain {name!r}, available: "
            f"{', '.join(available_domains())}"
        ) from None


def detect_domain(files) -> str:
    """Name the domain a file list most looks like, by extension. Solidity sources name
    the evm domain, everything else names web. A pure heuristic, it does not require the
    named domain to be registered, the caller resolves and fails loud if it is not."""
    paths = list(files)
    sol = sum(1 for f in paths if Path(f).suffix.lower() == ".sol")
    return "evm" if sol > 0 and sol >= (len(paths) - sol) else "web"


def resolve_domain(name: str, files=()) -> Domain:
    """Resolve a `--domain` choice. `auto` detects from the files, anything else is a
    direct lookup. The single entry the CLI uses so detection and lookup cannot drift."""
    chosen = detect_domain(files) if name == "auto" else name
    return get_domain(chosen)
