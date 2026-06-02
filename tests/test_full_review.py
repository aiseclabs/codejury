"""R7: the full-review three-stage pipeline (design, API, per-API security).

Driven end to end with a MockProvider so it needs no key. Asserts each stage
runs over the right artifacts and that the stages compose into one report."""

import json

from codejury.cli import full_review, scan
from codejury.domain.skill import Skill, load_skills
from codejury.providers.mock import MockProvider
from codejury.resources import SKILLS_DIR

APP = '''
from flask import Flask, request, jsonify
app = Flask(__name__)


@app.route("/users", methods=["GET"])
def list_users():
    return jsonify(load())


@app.route("/users/<uid>", methods=["DELETE"])
def delete_user(uid):
    drop(uid)
    return "", 204


def helper():
    return 1
'''


def _repo(tmp_path):
    (tmp_path / "app.py").write_text(APP)
    (tmp_path / "util.py").write_text("def f():\n    return 1\n")
    return str(tmp_path)


def _reply(dimension="x"):
    return json.dumps({"verdicts": [{"dimension": dimension, "status": "SECURE"}]})


def _skill(sid, **kw):
    return Skill(id=sid, name=sid, instructions="check", **kw)


def _provider():
    return MockProvider(default=_reply())


def test_three_stages_each_run_over_their_artifacts(tmp_path):
    repo = _repo(tmp_path)
    skills = [
        _skill("architecture", applies_to=("repo_design",)),
        _skill("api_design", applies_to=("api_endpoint",)),
        _skill("authn"),  # generic security skill
    ]
    provider = _provider()
    results = full_review(repo, skills, provider=provider, model="m")

    paths = [p for p, _ in results]
    # stage 1 ran once over the design summary (the directory path)
    assert repo in paths
    # stages 2 and 3 ran over each HTTP handler
    assert "app.py::list_users" in paths and "app.py::delete_user" in paths
    # the design summary handed the architecture skill the route inventory
    design_prompt = provider.calls[0]["messages"][0].content
    assert "/users" in design_prompt and "DELETE" in design_prompt


def test_stage_partition_by_applies_to(tmp_path):
    # architecture only sees the design summary; api_design and authn only see handlers
    repo = _repo(tmp_path)
    skills = [
        _skill("architecture", applies_to=("repo_design",)),
        _skill("api_design", applies_to=("api_endpoint",)),
        _skill("authn"),
    ]
    results = full_review(repo, skills, provider=_provider(), model="m")
    by_skill = {}
    for path, res in results:
        for o in res.observations:
            by_skill.setdefault(o.capability.split(".")[0], set()).add(path)

    repo_path = repo
    assert by_skill["architecture"] == {repo_path}                       # design summary only
    assert "app.py::list_users" in by_skill["api_design"]                # handlers only
    assert repo_path not in by_skill["authn"]                            # never on the summary


def test_stages_can_be_skipped(tmp_path):
    repo = _repo(tmp_path)
    skills = [_skill("architecture", applies_to=("repo_design",)), _skill("authn")]
    results = full_review(repo, skills, provider=_provider(), model="m", stages=("design",))
    paths = {p for p, _ in results}
    assert paths == {repo}  # only the design stage ran


def test_no_http_handlers_still_runs_design(tmp_path):
    (tmp_path / "plain.py").write_text("def f():\n    return 1\n")
    skills = [_skill("architecture", applies_to=("repo_design",)), _skill("authn")]
    results = full_review(str(tmp_path), skills, provider=_provider(), model="m")
    assert [p for p, _ in results] == [str(tmp_path)]  # design only; no endpoints to review


def test_coexists_with_scan_no_regression(tmp_path):
    # scan still works on the same tree with the shipped skills, unaffected by full-review
    repo = _repo(tmp_path)
    results = scan(repo, load_skills(SKILLS_DIR), provider=_provider(), model="m", strategy="single")
    assert [p for p, _ in results] == ["app.py", "util.py"]
