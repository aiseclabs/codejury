"""AI code security review tool.

Two paths matched to their nature: a coded diff-audit engine, a standard single
call or an adversarial Finder/Challenger/Judge pass, and a whole-repo review run
as a methodology by an interactive agent. Security knowledge lives in rich
markdown vulnerability classes under knowledge/vulnerabilities, injected into the
audit prompt, not in a rendered schema.
"""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("codejury")
except PackageNotFoundError:  # running from a source tree without an install
    __version__ = "0.0.0"
