"""The path boundary that keeps a tampered or hallucinated location from reading a file
outside the reviewed repo. is_unsafe_rel drops it before it becomes a finding, safe_repo_path
refuses it before a workspace-to-source read."""

from pathlib import Path

from codejury.review.repo.paths import is_unsafe_rel, safe_repo_path


def test_is_unsafe_rel_flags_empty_absolute_and_traversal():
    assert is_unsafe_rel("")
    assert is_unsafe_rel("/etc/passwd")
    assert is_unsafe_rel("../secrets")
    assert is_unsafe_rel("a/../../b")


def test_is_unsafe_rel_allows_a_plain_relative_path():
    assert not is_unsafe_rel("app/api/routes.py")
    assert not is_unsafe_rel("main.go")


def test_safe_repo_path_resolves_a_relative_path_under_root(tmp_path):
    target = tmp_path / "app" / "routes.py"
    target.parent.mkdir(parents=True)
    target.write_text("x", encoding="utf-8")
    resolved = safe_repo_path(tmp_path, "app/routes.py")
    assert resolved == target.resolve()


def test_safe_repo_path_refuses_empty_absolute_and_traversal(tmp_path):
    assert safe_repo_path(tmp_path, "") is None
    assert safe_repo_path(tmp_path, "/etc/passwd") is None
    assert safe_repo_path(tmp_path, "../outside") is None


def test_safe_repo_path_refuses_a_symlink_escaping_root(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("secret", encoding="utf-8")
    (root / "link").symlink_to(outside)
    assert safe_repo_path(root, "link") is None
