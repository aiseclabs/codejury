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
    assert EVM.lenses != WEB.lenses
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
    # the per-file map keys this contract's facts on its source path, so the engine grounds a
    # unit owning that file with the call graph the slice may not show
    key = next(k for k in facts.data["by_file"] if k.endswith("Vault.sol"))
    assert "contract Vault" in facts.data["by_file"][key]
    assert "reenter" in facts.data["by_file"][key]
    # withdraw is risk-flagged, so it anchors a focused call-path unit packed with its callee
    # _check, and the fragments slice the real function bodies from source
    text = sol.read_text()
    withdraw_unit = next(u for u in facts.data["units"] if "withdraw" in u["name"])
    body = "".join(text[s:e] for _f, s, e in withdraw_unit["fragments"])
    assert "function withdraw" in body and "_check" in body


def test_by_file_groups_contract_facts_by_source_path():
    # a pure unit test of the grouping, so the by_file logic is covered without the toolchain
    from codejury.domains.evm.facts.slither import _by_file

    def fn(**kw):
        base = {"visibility": "external", "modifiers": [], "reads": [], "writes": [],
                "calls": [], "external_call": False, "sends_eth": False, "can_reenter": False}
        return {**base, **kw}

    contracts = {
        "Vault": {"file": "src/Vault.sol", "state": [],
                  "functions": {"withdraw()": fn(external_call=True, can_reenter=True)}},
        "Token": {"file": "src/Token.sol", "state": [], "functions": {}},
        "Lib": {"file": "", "state": [], "functions": {}},
    }
    by = _by_file(contracts)
    assert set(by) == {"src/Vault.sol", "src/Token.sol"}  # the contract with no path is dropped
    assert "contract Vault" in by["src/Vault.sol"] and "reenter" in by["src/Vault.sol"]
    assert "contract Token" in by["src/Token.sol"]


def _fn(rng, **flags):
    base = {"visibility": "internal", "modifiers": [], "reads": [], "writes": [],
            "calls": [], "external_call": False, "sends_eth": False, "can_reenter": False,
            "range": rng}
    return {**base, **flags}


def test_call_path_units_anchor_on_risk_functions_with_neighborhood():
    from codejury.domains.evm.facts.call_path import call_path_units

    contracts = {
        "Vault": {"file": "src/Vault.sol", "state": [], "functions": {
            "getBalance()": _fn([0, 100]),                                  # pure, no anchor
            "liquidate()": _fn([100, 300], external_call=True, can_reenter=True, calls=["_cleanupLoan()"]),
            "_cleanupLoan()": _fn([300, 420], external_call=True, can_reenter=True, calls=["_update()"]),
            "_update()": _fn([420, 480]),                                   # callee, not an anchor itself
        }}}
    units = call_path_units(contracts)
    # liquidate's set {liquidate,_cleanupLoan} is a subset of _cleanupLoan's
    # {_cleanupLoan,_update,liquidate}, so only the larger neighborhood survives
    assert len(units) == 1
    u = units[0]
    assert "_cleanupLoan" in u["name"] and u["files"] == ["src/Vault.sol"]
    starts = [f[1] for f in u["fragments"]]
    assert starts == sorted(starts) == [100, 300, 420]   # liquidate, _cleanupLoan, _update
    assert all(f[0] == "src/Vault.sol" for f in u["fragments"])
    # the pure getter is on no risk path, the file unit covers it, not a call-path unit
    assert not any(f[1] == 0 for f in u["fragments"])


def test_call_path_units_skip_no_range_and_respect_the_char_cap():
    from codejury.domains.evm.facts.call_path import _UNIT_CHAR_CAP, call_path_units

    contracts = {
        "C": {"file": "a.sol", "state": [], "functions": {
            "f()": _fn([0, 50], external_call=True, calls=["big()", "noRange()"]),
            "big()": _fn([50, 50 + _UNIT_CHAR_CAP + 100]),   # too large to co-locate, dropped
            "noRange()": _fn(None),                          # backend recorded none, skipped
        }}}
    units = call_path_units(contracts)
    assert len(units) == 1
    frags = units[0]["fragments"]
    # the anchor stays, the oversized callee and the callee with no range do not
    assert [f[1] for f in frags] == [0]


def test_rel_file_relativizes_to_root_and_falls_back(tmp_path):
    from codejury.domains.evm.facts.slither import _rel_file

    class _Name:
        def __init__(self, absolute="", short=""):
            self.absolute = absolute
            self.short = short
            self.used = ""

    def contract(name):
        return type("C", (), {"source_mapping": type("M", (), {"filename": name})()})()

    root = tmp_path.resolve()
    assert _rel_file(contract(_Name(absolute=str(root / "src" / "Vault.sol"))), root) == "src/Vault.sol"
    # a file outside the root, such as a dependency, falls back to its basename
    assert _rel_file(contract(_Name(absolute="/elsewhere/Ownable.sol")), root) == "Ownable.sol"
    # the root is the file itself, a review of a single file, the name relative to the repo is the basename
    assert _rel_file(contract(_Name(absolute=str(root / "Vault.sol"))), root / "Vault.sol") == "Vault.sol"
    assert _rel_file(type("C2", (), {"source_mapping": None})(), root) == ""


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
