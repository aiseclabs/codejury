"""The domain layer: the web domain resolves its content, detection names a domain, and
an unavailable domain fails loud rather than silently falling back."""

import pytest

from codejury.domains.base import Domain, content_paths
from codejury.domains.registry import detect_domain, get_domain, resolve_domain
from codejury.domains.web import WEB


def test_web_domain_resolves_shipped_content():
    paths = WEB.paths
    assert paths.vulnerabilities_dir.is_dir()
    assert paths.detection_file.is_file()
    assert paths.methodology_file.is_file()
    assert paths.severity_rubric_file.is_file()
    # the knowledge index and vulnerabilities share a parent, the relocation kept them together
    assert paths.knowledge_index.parent == paths.vulnerabilities_dir.parent


def test_content_paths_layout_follows_the_root():
    paths = content_paths("/srv/x")
    assert str(paths.vulnerabilities_dir) == "/srv/x/knowledge/vulnerabilities"
    assert str(paths.detection_file) == "/srv/x/detection.yaml"
    assert str(paths.unit_review_file) == "/srv/x/playbook/unit-review.md"


def test_get_domain_returns_web_and_fails_loud_on_unknown():
    assert get_domain("web") is WEB
    with pytest.raises(ValueError):
        get_domain("evm")
    with pytest.raises(ValueError):
        get_domain("nonsense")


def test_detect_domain_names_evm_for_solidity_web_otherwise():
    assert detect_domain(["app.py", "views.py", "go.mod"]) == "web"
    assert detect_domain(["Vault.sol", "Token.sol"]) == "evm"
    assert detect_domain(["Vault.sol", "deploy.py"]) == "evm"
    assert detect_domain([]) == "web"


def test_resolve_domain_auto_detects_then_looks_up():
    assert resolve_domain("auto", ["a.py"]) is WEB
    assert resolve_domain("web", []) is WEB
    # auto can name a domain whose knowledge set does not ship yet, then the lookup fails loud
    with pytest.raises(ValueError):
        resolve_domain("auto", ["Vault.sol", "Token.sol"])
