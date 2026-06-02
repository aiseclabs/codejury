"""R4: skill selection. Deterministic applies_to pre-filter, optional temp-0
model router that only narrows (and falls back to all candidates when it cannot
decide), and a cacheable selection key."""

import json

from codejury.domain.artifact import CodeArtifact
from codejury.domain.skill import Skill
from codejury.providers.mock import MockProvider
from codejury.selection import (
    SelectionCache,
    Selector,
    SkillRouter,
    selection_key,
)

ANY1 = Skill(id="authn", name="Authn", instructions="check auth")
ANY2 = Skill(id="crypto", name="Crypto", instructions="check crypto")
API = Skill(id="api_design", name="API Design", applies_to=("api_endpoint",), instructions="x")
DIFFONLY = Skill(id="diffonly", name="Diff Only", applies_to=("diff",), instructions="x")

ALL = (ANY1, ANY2, API, DIFFONLY)


def _artifact(kind, content="code"):
    return CodeArtifact(kind=kind, path="p", content=content)


# --- deterministic applies_to filter ---

def test_candidates_filter_by_artifact_kind():
    sel = Selector(ALL)
    file_ids = [s.id for s in sel.candidates(_artifact("file"))]
    assert file_ids == ["authn", "crypto"]  # api/diff-only excluded, sorted by id


def test_candidates_include_kind_specific_skill_only_for_that_kind():
    sel = Selector(ALL)
    assert [s.id for s in sel.candidates(_artifact("api_endpoint"))] == ["api_design", "authn", "crypto"]
    assert [s.id for s in sel.candidates(_artifact("diff"))] == ["authn", "crypto", "diffonly"]


def test_select_without_router_returns_all_candidates():
    sel = Selector(ALL)
    assert [s.id for s in sel.select(_artifact("file"))] == ["authn", "crypto"]


# --- model router (temp 0, narrows only) ---

def _router(response):
    return SkillRouter(provider=MockProvider(default=response), model="m")


def test_router_narrows_to_chosen_candidates():
    sel = Selector(ALL)
    router = _router(json.dumps({"skills": ["authn"]}))
    assert [s.id for s in sel.select(_artifact("file"), router=router)] == ["authn"]


def test_router_ids_outside_candidates_are_ignored():
    sel = Selector(ALL)
    router = _router(json.dumps({"skills": ["authn", "ghost", "api_design"]}))
    # ghost is not a skill; api_design is not a candidate for a file artifact
    assert [s.id for s in sel.select(_artifact("file"), router=router)] == ["authn"]


def test_unparseable_router_reply_falls_back_to_all_candidates():
    sel = Selector(ALL)
    router = _router("not json")
    assert [s.id for s in sel.select(_artifact("file"), router=router)] == ["authn", "crypto"]


def test_router_empty_list_is_respected_not_fallback():
    sel = Selector(ALL)
    router = _router(json.dumps({"skills": []}))
    assert sel.select(_artifact("file"), router=router) == []  # model said none apply


def test_router_only_sees_candidates_in_prompt():
    provider = MockProvider(default=json.dumps({"skills": ["authn"]}))
    Selector(ALL).select(_artifact("file"), router=SkillRouter(provider=provider, model="m"))
    prompt = provider.calls[0]["messages"][0].content
    assert "authn" in prompt and "crypto" in prompt
    assert "api_design" not in prompt  # not a candidate for a file artifact


# --- cacheable selection key ---

def test_selection_key_is_stable_and_sensitive():
    a = _artifact("file", "x = 1")
    cands = [ANY1, ANY2]
    k = selection_key(a, cands, router_model="m")
    assert k == selection_key(a, cands, router_model="m")
    assert k != selection_key(_artifact("file", "x = 2"), cands, router_model="m")  # code
    assert k != selection_key(a, cands, router_model="other")                       # model
    bumped = Skill(id="authn", name="Authn", version="2", instructions="check auth")
    assert k != selection_key(a, [bumped, ANY2], router_model="m")                  # skill content


def test_selection_cache_roundtrip(tmp_path):
    cache = SelectionCache(tmp_path)
    assert cache.get("k") is None
    cache.put("k", ["authn", "crypto"])
    assert cache.get("k") == ["authn", "crypto"]


def test_selection_cache_corrupt_entry_is_a_miss(tmp_path):
    (tmp_path / "k.json").write_text("{ not json")
    assert SelectionCache(tmp_path).get("k") is None
