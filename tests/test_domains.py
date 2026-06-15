"""The domain layer: the web domain resolves its content, detection names a domain, and
an unavailable domain fails loud rather than silently falling back."""

import pytest

from codejury.domains.base import Domain, content_paths
from codejury.domains.evm import EVM
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


def test_get_domain_returns_registered_and_fails_loud_on_unknown():
    assert get_domain("web") is WEB
    assert get_domain("evm") is EVM
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
    assert resolve_domain("auto", ["Vault.sol", "Token.sol"]) is EVM
    assert resolve_domain("evm", []) is EVM


def test_evm_domain_resolves_shipped_content_and_strategy():
    paths = EVM.paths
    assert (paths.languages_dir / "solidity.md").is_file()
    assert (paths.vulnerabilities_dir / "reentrancy.md").is_file()
    assert paths.detection_file.is_file()
    assert paths.methodology_file.is_file()
    # the evm review strategy is data on the domain, distinct from web
    assert "reentrancy" in EVM.lenses
    assert EVM.severity_floors and EVM.lenses != WEB.lenses
    assert "reentrancy" in EVM.diff_focus.lower()


def test_evm_facts_backend_fails_loud_without_slither():
    from codejury.domains.base import BackendUnavailable, FactsBackend
    from codejury.domains.evm.facts.slither import SlitherFacts

    backend = SlitherFacts()
    assert isinstance(backend, FactsBackend)
    if backend.available():
        pytest.skip("slither is installed, the missing-tool path does not apply")
    # a missing toolchain is a loud failure, never empty facts that read as a clean review
    with pytest.raises(BackendUnavailable):
        backend.extract(".")


def test_evm_poc_verifier_fails_loud_without_forge():
    from codejury.domains.base import BackendUnavailable
    from codejury.domains.evm.poc import ForgePoC
    from codejury.review.repo.union import Candidate
    from codejury.review.repo.verifier import Verifier

    poc = ForgePoC()
    assert isinstance(poc, Verifier)
    if poc.available():
        pytest.skip("forge is installed, the missing-tool path does not apply")
    with pytest.raises(BackendUnavailable):
        poc.verify(Candidate(title="x"), ".")


def test_importing_the_evm_domain_does_not_pull_the_tool_backends():
    import subprocess
    import sys

    # the domain package must stay a leaf, the heavy seams load only when explicitly used,
    # so registering or selecting the domain never needs the optional dependency
    code = (
        "import codejury.domains.evm, sys\n"
        "assert 'codejury.domains.evm.poc' not in sys.modules\n"
        "assert 'codejury.domains.evm.facts.slither' not in sys.modules\n"
    )
    subprocess.run([sys.executable, "-c", code], check=True)
