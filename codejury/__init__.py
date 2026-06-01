"""codejury -- a general-purpose Application Security AI audit framework.

Five layers: Task / (Capability + Orchestrator + Source + Agent) / Provider / Infrastructure.
Domain knowledge lives in YAML capability files as a first-class citizen,
aligned with OWASP ASVS.
"""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("codejury")
except PackageNotFoundError:  # running from a source tree without an install
    __version__ = "0.0.0"
