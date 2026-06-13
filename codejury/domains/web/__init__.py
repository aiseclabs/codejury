"""The web domain: application security knowledge for web code, the default domain.

Its content root is this package directory, holding the `knowledge/`, `playbook/`, and
`detection.yaml` that codejury has always shipped.
"""

from pathlib import Path

from codejury.domains.base import Domain

WEB = Domain(name="web", content_root=Path(__file__).resolve().parent)
