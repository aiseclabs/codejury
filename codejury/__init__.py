"""codejury: a general-purpose Application Security AI audit framework.

Layers: Task, then Skill plus Selector plus Orchestrator plus Source plus Agent,
then Provider, then Infrastructure. Domain knowledge lives in skill directories
(a manifest plus a prose playbook) as a first-class citizen, aligned with OWASP
ASVS and the OWASP LLM Top 10.
"""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("codejury")
except PackageNotFoundError:  # running from a source tree without an install
    __version__ = "0.0.0"
