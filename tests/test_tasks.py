import json

from codejury.domain.skill import Skill
from codejury.providers.mock import MockProvider
from codejury.sources.mock import MockSource
from codejury.tasks.base import Task, run_task
from codejury.tasks.registry import load_tasks

from codejury.resources import TASKS_DIR


def test_from_dict_parses_and_defaults():
    task = Task.from_dict({"name": "t", "orchestrator": "single", "skills": ["authn", "crypto"]})
    assert task.name == "t"
    assert task.orchestrator == "single"
    assert task.skills == ("authn", "crypto")
    assert task.provider == "anthropic"  # default
    assert task.max_tokens == 2048  # default
    assert task.api_base is None  # default


def test_from_dict_reads_api_base():
    task = Task.from_dict({"name": "t", "provider": "litellm", "api_base": "https://proxy.example"})
    assert task.api_base == "https://proxy.example"


def test_run_task_forwards_proxy_config_with_key_from_env(monkeypatch):
    captured = {}

    def fake_make_provider(name, **kwargs):
        captured["name"] = name
        captured.update(kwargs)
        return MockProvider(default='{"verdicts": []}')

    monkeypatch.setattr("codejury.tasks.base.make_provider", fake_make_provider)
    monkeypatch.setattr("codejury.tasks.base.DEFAULT_API_KEY", "sk-from-env")

    task = Task(name="t", provider="litellm", api_base="https://proxy.example")
    run_task(task, MockSource(), [Skill(id="authn", name="A", instructions="x")])

    assert captured["name"] == "litellm"
    assert captured["api_base"] == "https://proxy.example"  # from the task
    assert captured["api_key"] == "sk-from-env"  # from the environment, not the task


def test_select_filters_by_id_and_none_means_all():
    skills = [Skill(id="authn", name="A"), Skill(id="crypto", name="C")]
    assert [s.id for s in Task(name="t", skills=("authn",)).select(skills)] == ["authn"]
    assert [s.id for s in Task(name="t").select(skills)] == ["authn", "crypto"]  # None = all


def test_shipped_tasks_load():
    tasks = load_tasks(TASKS_DIR)
    assert {"quick_scan_single", "audit_diff_debate"} <= set(tasks)
    # debate over skills is not wired yet (R5b); the preset uses taint until then.
    assert tasks["audit_diff_debate"].orchestrator == "taint"
    assert tasks["audit_diff_debate"].skills is None  # all skills


def test_run_task_executes_selected_skills(monkeypatch):
    reply = json.dumps(
        {"verdicts": [{"dimension": "password_storage", "status": "VULNERABLE",
                       "evidence": [{"file": "f", "line": 1, "code": "c"}]}]}
    )
    monkeypatch.setattr("codejury.tasks.base.make_provider", lambda name, **kw: MockProvider(default=reply))

    task = Task(name="t", orchestrator="single", skills=("authn",))
    skills = [Skill(id="authn", name="Authentication", instructions="x"),
              Skill(id="crypto", name="Cryptography", instructions="y")]
    results = run_task(task, MockSource(), skills)

    _, result = results[0]
    # only the selected skill was checked
    assert all(v.capability.startswith("authn") for v in result.observations)
    assert result.observations[0].status == "VULNERABLE"
