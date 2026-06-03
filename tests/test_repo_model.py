"""RepoModel is a language-agnostic file map. Candidate entrypoint files are
flagged by guide-declared globs, not by parsing code."""

from codejury.review.model import (
    build_repo_model,
    build_repo_model_from_dir,
    candidate_entrypoint_files,
)


def test_build_lists_files_sorted():
    m = build_repo_model("/repo", ["b/x.py", "a.py", "a/y.js"])
    assert m.root == "/repo"
    assert m.files == ("a.py", "a/y.js", "b/x.py")


def test_candidate_entrypoint_files_by_glob():
    files = ["app/urls.py", "app/views.py", "manage.py", "README.md"]
    assert candidate_entrypoint_files(files, globs=["*urls.py"]) == ["app/urls.py"]
    assert candidate_entrypoint_files(files, globs=["*urls.py", "manage.py"]) == ["app/urls.py", "manage.py"]
    assert candidate_entrypoint_files(files, globs=[]) == []


def test_candidate_entrypoint_files_by_content_markers(tmp_path):
    # a DRF viewset in an oddly named file no glob would catch, flagged by marker
    (tmp_path / "handlers.py").write_text("class TokenViewSet(ViewSet):\n    pass\n")
    (tmp_path / "notes.md").write_text("ViewSet mentioned in prose, not code\n")
    (tmp_path / "util.py").write_text("def helper():\n    return 1\n")
    got = candidate_entrypoint_files(
        ["handlers.py", "notes.md", "util.py"], root=tmp_path, markers=["ViewSet"]
    )
    assert got == ["handlers.py"]   # .md is not scanned, util has no marker


def test_build_from_dir_walks_tree_and_skips_noise(tmp_path):
    (tmp_path / "app.py").write_text("x = 1")
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "urls.py").write_text("x = 1")
    (tmp_path / "go.mod").write_text("module x")          # non-.py files are listed too
    (tmp_path / "__pycache__").mkdir()
    (tmp_path / "__pycache__" / "junk.py").write_text("x = 1")
    (tmp_path / "build" / "lib" / "pkg").mkdir(parents=True)
    (tmp_path / "build" / "lib" / "pkg" / "urls.py").write_text("x = 1")  # build artifact, a duplicate of source

    m = build_repo_model_from_dir(tmp_path)
    assert {"app.py", "pkg/urls.py", "go.mod"} <= set(m.files)
    assert all("__pycache__" not in f for f in m.files)   # noise dir skipped
    assert all(not f.startswith("build/") for f in m.files)   # build output skipped, no duplicate source


def test_build_is_deterministic():
    assert build_repo_model("/r", ["b.py", "a.py"]) == build_repo_model("/r", ["a.py", "b.py"])
