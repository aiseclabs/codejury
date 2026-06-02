"""P6-01: the RepoModel entrypoint detection is deterministic and data-driven."""

from codejury.repo.model import (
    Entrypoint,
    build_repo_model,
    build_repo_model_from_dir,
    load_entrypoint_signatures,
)

FLASK = '''
from flask import Flask, request

app = Flask(__name__)
bp = Flask("bp")


@app.route("/users")
def list_users():
    return "ok"


@bp.route("/login", methods=["POST", "PUT"])
def login():
    return request.form["user"]
'''

FASTAPI = '''
from fastapi import APIRouter

router = APIRouter()


@router.get("/items")
async def items():
    return []


@router.post("/items")
async def create_item():
    return {}
'''

CLICK = '''
import click


@click.command()
def run():
    pass
'''

DJANGO = '''
from django.urls import path
from . import views

urlpatterns = [
    path("home/", views.home),
    path("about/", about_view),
]
'''

# include() mounts and class-based views resolve to no handler function: noise
DJANGO_NOISE = '''
from django.urls import path, include
from .views import DashboardView

urlpatterns = [
    path("", include("app.urls")),
    path("accounts/", include("allauth.urls")),
    path("profile/", views.profile),
    path("dash/", DashboardView.as_view()),
]
'''

PLAIN = '''
def helper(x):
    return x + 1
'''


def _model(files):
    return build_repo_model("/repo", files)


def _routes(model):
    return {(e.kind, e.framework, e.function, e.route, e.method) for e in model.entrypoints}


def test_flask_routes_and_methods():
    model = _model({"app.py": FLASK})
    assert _routes(model) == {
        ("http", "flask", "list_users", "/users", "GET"),
        ("http", "flask", "login", "/login", "POST,PUT"),
    }


def test_fastapi_verbs_become_methods():
    model = _model({"api.py": FASTAPI})
    assert _routes(model) == {
        ("http", "fastapi", "items", "/items", "GET"),
        ("http", "fastapi", "create_item", "/items", "POST"),
    }


def test_click_command_is_cli_without_method():
    model = _model({"cli.py": CLICK})
    assert _routes(model) == {("cli", "click", "run", "", "")}


def test_django_path_calls_capture_view_and_route():
    model = _model({"urls.py": DJANGO})
    assert _routes(model) == {
        ("http", "django", "home", "home/", ""),
        ("http", "django", "about_view", "about/", ""),
    }


DJANGO_ROOT = '''
from django.urls import path, include
urlpatterns = [
    path("", include("introduction.urls")),
    path("api/", include("api.urls")),
    path("health/", views.health),
]
'''
DJANGO_INTRO = '''
from django.urls import path
from . import views
urlpatterns = [
    path("home/", views.home),
    path("xss", views.xss),
]
'''
DJANGO_API = '''
from django.urls import path, include
urlpatterns = [
    path("v1/", include("api.v1.urls")),
]
'''
DJANGO_API_V1 = '''
from django.urls import path
urlpatterns = [
    path("users", views.users),
]
'''


def test_django_include_mounts_subroutes_under_prefix():
    model = _model({
        "urls.py": DJANGO_ROOT,
        "introduction/urls.py": DJANGO_INTRO,
        "api/urls.py": DJANGO_API,
        "api/v1/urls.py": DJANGO_API_V1,
    })
    routes = {(e.function, e.route) for e in model.entrypoints}
    assert routes == {
        ("health", "health/"),     # direct route on the root urlconf
        ("home", "home/"),         # included at "" prefix
        ("xss", "xss"),
        ("users", "api/v1/users"),  # nested include: "api/" + "v1/" + "users"
    }
    # the included sub-urlconfs are not also emitted standalone (no bare "users")
    assert all(e.route != "users" for e in model.entrypoints)


def test_django_include_and_cbv_with_no_resolvable_function_are_dropped():
    # include() mounts and an unresolved .as_view() carry no handler function;
    # only the plain function-based view survives, no empty `- -` noise entries
    model = _model({"urls.py": DJANGO_NOISE})
    assert _routes(model) == {("http", "django", "profile", "profile/", "")}
    assert all(e.function for e in model.entrypoints)


def test_plain_module_has_no_entrypoints():
    model = _model({"util.py": PLAIN})
    assert model.entrypoints == ()


def test_files_are_sorted_and_recorded():
    model = _model({"b.py": PLAIN, "a.py": PLAIN})
    assert model.files == ("a.py", "b.py")
    assert model.root == "/repo"


def test_unparseable_file_is_skipped_not_fatal():
    model = _model({"broken.py": "def (:", "ok.py": FLASK})
    assert any(e.function == "list_users" for e in model.entrypoints)


def test_build_is_deterministic():
    files = {"app.py": FLASK, "api.py": FASTAPI, "cli.py": CLICK}
    first = _model(files)
    second = _model(files)
    assert first == second
    assert first.entrypoints == second.entrypoints


def test_signatures_load_from_bundled_data():
    sigs = load_entrypoint_signatures()
    names = {n for s in sigs.decorators for n in s["names"]}
    assert {"route", "get", "post", "command"} <= names
    assert any("path" in s["names"] for s in sigs.calls)


def test_build_from_dir_walks_the_tree(tmp_path):
    (tmp_path / "app.py").write_text(FLASK)
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "api.py").write_text(FASTAPI)
    (tmp_path / "__pycache__").mkdir()
    (tmp_path / "__pycache__" / "junk.py").write_text(CLICK)  # skipped directory

    model = build_repo_model_from_dir(tmp_path)

    functions = {e.function for e in model.entrypoints}
    assert {"list_users", "login", "items", "create_item"} == functions
    assert "run" not in functions  # the __pycache__ file is not walked


def test_entrypoint_is_hashable_and_frozen():
    ep = Entrypoint(file="a.py", line=1, function="f", kind="http", framework="flask")
    assert ep in {ep}
