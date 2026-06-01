import json

from codejury.agents.verifier import VerifierAgent
from codejury.domain.artifact import CodeArtifact
from codejury.domain.capability import Capability
from codejury.domain.context import AnalysisContext
from codejury.orchestrators.taint_gate import TaintGateOrchestrator
from codejury.providers.mock import MockProvider

# The verifier always returns VULNERABLE here, so the gate is the only thing that
# can clear a finding -- exactly what we want to test.
_VULN = json.dumps({"verdicts": [{"sub_capability": "x", "status": "VULNERABLE",
                                  "evidence": [{"file": "m.py", "line": 2}]}]})


def _run(content, *, capability="input_validation", context=""):
    agents = {"verifier": VerifierAgent(provider=MockProvider(default=_VULN), model="m")}
    ctx = AnalysisContext(
        artifact=CodeArtifact(kind="file", path="m.py", content=content, context=context),
        capabilities=[Capability(id=capability, name=capability)],
    )
    return TaintGateOrchestrator().run(agents, ctx)


def _statuses(result):
    return [v.status for v in result.observations if v.kind == "verdict"]


def _dismissed(result):
    return [c.capability for c in result.observations if c.kind == "concession"]


# --- single-file: clears the safe-but-scary, keeps the real ones ------------

def test_constant_sink_is_downgraded():
    src = "def q():\n    cursor.execute('SELECT * FROM users WHERE active = 1')\n"
    result = _run(src)
    assert _statuses(result) == []                 # VULNERABLE dismissed
    assert "input_validation.x" in _dismissed(result)


def test_external_sink_is_kept():
    src = "def f(request):\n    return requests.get(request.args['url'])\n"
    assert _statuses(_run(src)) == ["VULNERABLE"]  # real SSRF survives the gate


def test_safe_sink_parser_is_downgraded():
    # ast.literal_eval is a safe sink even though its input is external.
    src = "def f(request):\n    return ast.literal_eval(request.data)\n"
    assert _statuses(_run(src)) == []


def test_pickle_loads_is_kept():
    # pickle.loads is NOT a safe sink -- recall must be preserved here.
    src = "def f(request):\n    return pickle.loads(request.data)\n"
    assert _statuses(_run(src)) == ["VULNERABLE"]


# --- cross-file: the identical-sink pair, end to end -----------------------

_SINK = "def serve(name):\n    return open(os.path.join(STATIC_DIR, name)).read()\n"


def test_cross_file_tainted_caller_keeps_finding():
    caller = "def download(request):\n    return serve(request.args['name'])\n"
    assert _statuses(_run(_SINK, context=caller)) == ["VULNERABLE"]


def test_cross_file_sanitized_caller_clears_finding():
    caller = "def download(request):\n    return serve(os.path.basename(request.args['name']))\n"
    assert _statuses(_run(_SINK, context=caller)) == []


# --- scoping & robustness ---------------------------------------------------

def test_non_taint_capability_is_not_gated():
    # an authn verdict must never be touched by the taint gate, even on clean code.
    src = "def login():\n    return hashlib.md5(b'const').hexdigest()\n"
    assert _statuses(_run(src, capability="authn")) == ["VULNERABLE"]


def test_unparseable_code_keeps_verdicts():
    assert _statuses(_run("def (((bad python")) == ["VULNERABLE"]


def test_unknown_call_is_not_cleared():
    # a value from an unknown function is not provably safe -> keep the finding.
    src = "def f(request):\n    return run_query(helper(request.args['q']))\n"
    assert _statuses(_run(src)) == ["VULNERABLE"]
