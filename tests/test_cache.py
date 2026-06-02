import json

from codejury.cli import audit
from codejury.domain.artifact import CodeArtifact
from codejury.domain.observation import Concession, Evidence, Finding, Verdict
from codejury.domain.result import AnalysisResult
from codejury.domain.skill import Skill
from codejury.infrastructure.cache import VerdictCache, verdict_key
from codejury.providers.mock import MockProvider

# SkillRunner drops a VULNERABLE verdict with no location, so the mock carries one.
_VULN = json.dumps(
    {"verdicts": [{"dimension": "x", "status": "VULNERABLE", "evidence": [{"file": "auth.py", "line": 1, "code": "c"}]}]}
)
_SECURE = json.dumps({"verdicts": [{"dimension": "x", "status": "SECURE"}]})

# A minimal one-file diff; DiffSource takes the path from the +++ line.
_DIFF = "+++ b/auth.py\n@@ -0,0 +1 @@\n+password = sha256(p)\n"
_SKILLS = [Skill(id="authn", name="Authentication", instructions="check auth")]


def _statuses(results):
    return [o.status for _, r in results for o in r.observations if o.kind == "verdict"]


# --- acceptance (1): two consecutive audits give the same verdicts ------------

def test_repeated_audit_reuses_cached_verdicts(tmp_path):
    cache = VerdictCache(tmp_path)
    # the provider would answer VULNERABLE first, SECURE second, but the second
    # audit must be served from cache, so it never reaches that second answer.
    provider = MockProvider(responses=[_VULN, _SECURE])
    kw = dict(provider=provider, model="m", max_tokens=8, strategy="single", cache=cache)

    first = audit(_DIFF, _SKILLS, **kw)
    second = audit(_DIFF, _SKILLS, **kw)

    assert len(provider.calls) == 1               # model queried once, not twice
    assert _statuses(first) == _statuses(second) == ["VULNERABLE"]


def test_no_cache_reruns_the_model(tmp_path):
    provider = MockProvider(responses=[_VULN, _SECURE])
    kw = dict(provider=provider, model="m", max_tokens=8, strategy="single")

    first = audit(_DIFF, _SKILLS, cache=None, **kw)
    second = audit(_DIFF, _SKILLS, cache=None, **kw)

    assert len(provider.calls) == 2               # no cache: queried both times
    assert _statuses(first) == ["VULNERABLE"]
    assert _statuses(second) == ["SECURE"]


# --- acceptance (2): editing a capability invalidates the cache ---------------

def test_skill_version_bump_invalidates_cache(tmp_path):
    cache = VerdictCache(tmp_path)
    provider = MockProvider(responses=[_VULN, _SECURE])
    skills_v1 = [Skill(id="authn", name="Authentication", version="1", instructions="check")]
    skills_v2 = [Skill(id="authn", name="Authentication", version="2", instructions="check")]

    first = audit(_DIFF, skills_v1, provider=provider, model="m", max_tokens=8, cache=cache)
    second = audit(_DIFF, skills_v2, provider=provider, model="m", max_tokens=8, cache=cache)

    assert len(provider.calls) == 2               # bumped version is a cache miss
    assert _statuses(first) == ["VULNERABLE"]
    assert _statuses(second) == ["SECURE"]


def test_skill_content_change_invalidates_cache():
    art = CodeArtifact(kind="file", path="x.py", content="a = 1")
    s1 = [Skill(id="authn", name="Authentication", instructions="old wording")]
    s2 = [Skill(id="authn", name="Authentication", instructions="new wording")]
    # no manual bump: a content edit alone changes the fingerprint, hence the key.
    assert verdict_key(art, s1, orchestration="s") != verdict_key(art, s2, orchestration="s")


# --- key composition ----------------------------------------------------------

def test_verdict_key_ignores_cosmetic_whitespace():
    a = CodeArtifact(kind="file", path="x.py", content="a = 1\nb = 2")
    b = CodeArtifact(kind="file", path="x.py", content="a = 1  \r\nb = 2\n\n")
    assert verdict_key(a, _SKILLS, orchestration="s") == verdict_key(b, _SKILLS, orchestration="s")


def test_verdict_key_changes_with_orchestration():
    art = CodeArtifact(kind="file", path="x.py", content="a = 1")
    assert verdict_key(art, _SKILLS, orchestration="single|m|8") != verdict_key(
        art, _SKILLS, orchestration="debate|m|8"
    )


# --- cache store + result round-trip ------------------------------------------

def test_cache_round_trips_through_disk(tmp_path):
    cache = VerdictCache(tmp_path)
    result = AnalysisResult(
        observations=[
            Verdict(
                capability="authn.x",
                status="VULNERABLE",
                evidence=[Evidence(file="a.py", line=3, code="x")],
                matched_anti=["a1"],
            ),
            Finding(capability="authn", title="weak", severity="HIGH", cwe="CWE-327"),
            Concession(capability="authn", target="weak", reason="dup"),
        ]
    )
    cache.put("k", result)
    assert cache.get("k") == result


def test_cache_does_not_store_failed_runs(tmp_path):
    cache = VerdictCache(tmp_path)
    cache.put("k", AnalysisResult(error="provider boom"))
    assert cache.get("k") is None


def test_cache_get_returns_none_on_miss(tmp_path):
    assert VerdictCache(tmp_path).get("absent") is None
