import json

from codejury.domain.capability import Capability
from codejury.providers.mock import MockProvider
from codejury.sources.mock import MockSource
from codejury.tasks.base import Task, run_task
from codejury.tasks.registry import load_tasks

from codejury.resources import TASKS_DIR


def test_from_dict_parses_and_defaults():
    task = Task.from_dict({"name": "t", "orchestrator": "debate", "capabilities": ["authn", "crypto"]})
    assert task.name == "t"
    assert task.orchestrator == "debate"
    assert task.capabilities == ("authn", "crypto")
    assert task.provider == "anthropic"  # default
    assert task.max_tokens == 2048  # default


def test_select_filters_by_id_and_none_means_all():
    caps = [Capability(id="authn", name="A"), Capability(id="crypto", name="C")]
    assert [c.id for c in Task(name="t", capabilities=("authn",)).select(caps)] == ["authn"]
    assert [c.id for c in Task(name="t").select(caps)] == ["authn", "crypto"]  # None = all


def test_shipped_tasks_load():
    tasks = load_tasks(TASKS_DIR)
    assert {"quick_scan_single", "audit_diff_debate"} <= set(tasks)
    assert tasks["audit_diff_debate"].orchestrator == "debate"
    assert tasks["audit_diff_debate"].capabilities is None  # all capabilities


def test_run_task_executes_selected_capabilities(monkeypatch):
    reply = json.dumps(
        {"verdicts": [{"sub_capability": "password_storage", "status": "VULNERABLE", "matched_anti": ["PWD-BAD-1"]}]}
    )
    monkeypatch.setattr("codejury.tasks.base.make_provider", lambda name, **kw: MockProvider(default=reply))

    task = Task(name="t", orchestrator="single", capabilities=("authn",))
    caps = [Capability(id="authn", name="Authentication"), Capability(id="crypto", name="Cryptography")]
    results = run_task(task, MockSource(), caps)

    _, result = results[0]
    # only the selected capability was checked
    assert all(v.capability.startswith("authn") for v in result.observations)
    assert result.observations[0].status == "VULNERABLE"
