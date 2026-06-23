"""The agentic reviewer: follow calls with tools, then report. Driven by a scripted mock
provider so the tool loop is tested with no real model."""

import pytest

from codejury.domains.evm import EVM
from codejury.providers.mock import MockProvider
from codejury.review.repo.agentic import AgenticReviewer
from codejury.review.repo.reviewer import RepoReviewError
from codejury.review.repo.shapes import Unit


def _unit(tmp_path):
    (tmp_path / "V.sol").write_text(
        "contract V {\n"
        "  function withdraw() external {\n"
        "    msg.sender.call{value: bal}('');\n"
        "    bal = 0;\n"
        "  }\n"
        "}\n"
    )
    return Unit(name="v-sol", root=str(tmp_path), files=("V.sol",))


def test_agentic_reviewer_uses_a_tool_then_reports(tmp_path):
    unit = _unit(tmp_path)
    prov = MockProvider(responses=[
        '{"tool": "read_file", "args": {"path": "V.sol"}}',
        '{"findings": [{"title": "reentrancy in withdraw", "category": "reentrancy", '
        '"symbol": "withdraw", "file": "V.sol", "line": 3, "severity": "HIGH", '
        '"evidence": "external call before state write at V.sol:3"}]}',
    ])
    cands = AgenticReviewer(provider=prov, model="mock", content=EVM.paths).review(unit, "reentrancy")
    assert [c.category for c in cands] == ["reentrancy"]
    # the tool turn actually ran: two model calls, and the second prompt carried the tool result
    assert len(prov.calls) == 2
    assert any("TOOL RESULT" in m.content for m in prov.calls[1]["messages"])


def test_agentic_reviewer_reports_empty_clean(tmp_path):
    unit = _unit(tmp_path)
    prov = MockProvider(responses=['{"findings": []}'])
    cands = AgenticReviewer(provider=prov, model="mock", content=EVM.paths).review(unit, "")
    assert cands == []


def test_agentic_reviewer_fails_loud_when_budget_spent_without_findings(tmp_path):
    # the model keeps calling tools and never reports: a failed review, not a clean unit
    unit = _unit(tmp_path)
    prov = MockProvider(default='{"tool": "grep", "args": {"pattern": "call"}}')
    rev = AgenticReviewer(provider=prov, model="mock", content=EVM.paths, max_steps=3)
    with pytest.raises(RepoReviewError):
        rev.review(unit, "")


def test_agentic_reviewer_label_is_the_model(tmp_path):
    prov = MockProvider(default='{"findings": []}')
    assert AgenticReviewer(provider=prov, model="gpt-5.5", content=EVM.paths).label == "gpt-5.5"
