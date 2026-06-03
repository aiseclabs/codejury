"""AI code security review tool.

Two paths matched to their nature: a coded diff-audit engine (standard single
call or adversarial Finder/Challenger/Judge), and a whole-repo review run as a
methodology by an interactive agent. Security knowledge lives in rich markdown
rules (data/rules) injected into the audit prompt, not in a rendered schema.
"""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("codejury")
except PackageNotFoundError:  # running from a source tree without an install
    __version__ = "0.0.0"
