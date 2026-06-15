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
    # the evm endpoint is a function sharing helpers, so it dedups by file, web by endpoint
    assert EVM.dedup_by_file is True
    assert WEB.dedup_by_file is False


def test_evm_facts_backend_fails_loud_without_slither(monkeypatch):
    from codejury.domains.base import BackendUnavailable, FactsBackend
    from codejury.domains.evm.facts.slither import SlitherFacts

    backend = SlitherFacts()
    assert isinstance(backend, FactsBackend)
    # force the missing-tool path so it runs whether or not slither is installed: a missing
    # toolchain is a loud failure, never empty facts that read as a clean review
    monkeypatch.setattr(backend, "available", lambda: False)
    with pytest.raises(BackendUnavailable):
        backend.extract(".")


def test_evm_poc_verifier_fails_loud_without_forge(monkeypatch):
    from codejury.domains.base import BackendUnavailable
    from codejury.domains.evm.poc import ForgePoC
    from codejury.review.repo.union import Candidate
    from codejury.review.repo.verifier import Verifier

    poc = ForgePoC()
    assert isinstance(poc, Verifier)
    monkeypatch.setattr(poc, "available", lambda: False)
    with pytest.raises(BackendUnavailable):
        poc.verify(Candidate(title="x"), ".")


_REENTRANT_VAULT = """\
// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;
contract Vault {
    mapping(address => uint256) public balances;
    function deposit() external payable { balances[msg.sender] += msg.value; }
    function _check(uint256 a) internal view returns (bool) { return balances[msg.sender] >= a; }
    function withdraw(uint256 amount) external {
        require(_check(amount), "insufficient");
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
        balances[msg.sender] -= amount;
    }
}
"""


def test_slither_facts_extract_grounds_a_real_contract(tmp_path):
    from shutil import which

    from codejury.domains.evm.facts.slither import SlitherFacts

    backend = SlitherFacts()
    if not backend.available() or which("solc") is None:
        pytest.skip("slither or solc not installed, the extraction path needs both")
    sol = tmp_path / "Vault.sol"
    sol.write_text(_REENTRANT_VAULT, encoding="utf-8")

    facts = backend.extract(sol)
    assert not facts.empty
    vault = facts.data["contracts"]["Vault"]
    assert "balances" in {v["name"] for v in vault["state"]}
    withdraw = vault["functions"]["withdraw(uint256)"]
    assert withdraw["visibility"] == "external"
    assert "balances" in withdraw["writes"]
    # the external call and the internal callee are the facts that ground a reentrancy read
    assert withdraw["external_call"] and withdraw["sends_eth"]
    assert "_check(uint256)" in withdraw["calls"]
    assert "ext-call" in facts.summary


def test_importing_the_evm_domain_does_not_pull_the_heavy_tools():
    import subprocess
    import sys

    # loading the domain binds the facts backend, a light module, but must never pull the
    # optional slither dependency, the forge PoC module, or the repo engine, so registering
    # or selecting the domain stays free of the optional dependency
    code = (
        "import codejury.domains.evm, sys\n"
        "assert 'slither' not in sys.modules\n"
        "assert 'codejury.domains.evm.poc' not in sys.modules\n"
        "assert 'codejury.review' not in sys.modules\n"
    )
    subprocess.run([sys.executable, "-c", code], check=True)


def test_evm_domain_binds_a_facts_backend_web_binds_none():
    from codejury.domains.base import FactsBackend

    assert isinstance(EVM.facts_backend, FactsBackend)
    assert WEB.facts_backend is None
