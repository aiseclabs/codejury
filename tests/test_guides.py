"""Language/framework review guides load and are selected by detection signals
(file globs + dependency-manifest substrings), so adding one is a drop-in file."""

from codejury.guides import Guide, guides_for_diff, load_guides, select_guides


def test_shipped_guides_load():
    by_id = {g.id: g for g in load_guides()}
    assert {"python", "django"} <= set(by_id)
    assert by_id["python"].kind == "language"
    assert by_id["django"].kind == "framework"
    assert "IDOR" in by_id["django"].body or "idor" in by_id["django"].body.lower()


def test_select_by_file_glob():
    matched = {g.id for g in select_guides(["app/urls.py", "app/views.py", "manage.py"])}
    assert "python" in matched      # *.py
    assert "django" in matched      # *urls.py / manage.py


def test_select_by_manifest_substring():
    matched = {g.id for g in select_guides(["main.py"], text="Django==4.2\nrequests\n")}
    assert "django" in matched and "python" in matched


def test_no_signal_no_match():
    assert select_guides(["index.html", "style.css"]) == []   # no .py, no django manifest


def test_select_respects_injected_pool():
    only = [Guide(id="x", kind="framework", title="X", detect_files=("*.xyz",),
                  detect_manifest=(), detect_imports=(), entrypoint_files=(), body="b")]
    assert [g.id for g in select_guides(["a.xyz"], guides=only)] == ["x"]
    assert select_guides(["a.py"], guides=only) == []


def test_guides_for_diff_by_path_and_content():
    diff = ("diff --git a/app/urls.py b/app/urls.py\n"
            "+from django.urls import path\n+urlpatterns = []\n")
    notes = guides_for_diff(diff)
    assert "Django" in notes and "Python" in notes   # urls.py + .py + the django import


def test_guides_for_diff_empty_when_irrelevant():
    assert guides_for_diff("+++ b/README.md\n+hello\n") == ""
