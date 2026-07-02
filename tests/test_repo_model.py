"""RepoModel is a language-agnostic file map. Candidate entrypoint files are
flagged by guide-declared globs, not by parsing code."""

from codejury.review.repo.model import (
    build_repo_model,
    build_repo_model_from_dir,
    candidate_entrypoint_files,
    promoted_logic_units,
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
    (tmp_path / "handlers.py").write_text("class TokenViewSet(ViewSet):\n    pass\n")
    (tmp_path / "notes.md").write_text("ViewSet mentioned in prose, not code\n")
    (tmp_path / "util.py").write_text("def helper():\n    return 1\n")
    got = candidate_entrypoint_files(
        ["handlers.py", "notes.md", "util.py"], root=tmp_path, markers=["ViewSet"]
    )
    assert got == ["handlers.py"]


def test_candidate_entrypoint_files_sorted_and_deduped(tmp_path):
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    (tmp_path / "a" / "urls.py").write_text("class ViewSet:\n    pass\n")
    (tmp_path / "b" / "urls.py").write_text("x = 1\n")
    files = ["b/urls.py", "a/urls.py", "a/urls.py"]
    got = candidate_entrypoint_files(files, root=tmp_path, globs=["*urls.py"], markers=["ViewSet"])
    assert got == ["a/urls.py", "b/urls.py"]


CLUSTER = [") Create(", ") ReadOne(", ") ReadAll(", ") Update(", ") Delete(", ") CanRead("]


def test_promoted_logic_units_promotes_resource_interface(tmp_path):
    # a type implementing a cluster of CRUD methods is a REST resource a generic
    # handler dispatches to, so its model file is a real entrypoint
    (tmp_path / "pkg" / "models").mkdir(parents=True)
    (tmp_path / "pkg" / "models" / "share.go").write_text(
        "func (s *Share) ReadAll(a web.Auth) {}\n"
        "func (s *Share) Create(a web.Auth) {}\n"
        "func (s *Share) Delete(a web.Auth) {}\n"
    )
    (tmp_path / "pkg" / "models" / "helper.go").write_text("func plain() int { return 1 }\n")
    files = ["pkg/models/share.go", "pkg/models/helper.go"]
    got = promoted_logic_units(files, root=tmp_path, layer_globs=["*/models/*.go"], markers=CLUSTER)
    assert got == ["pkg/models/share.go"]


def test_promoted_logic_units_single_method_does_not_promote(tmp_path):
    # a lone common method such as ReadAll is not a resource interface, so it must
    # not over-promote a file that merely happens to define it
    (tmp_path / "pkg" / "models").mkdir(parents=True)
    (tmp_path / "pkg" / "models" / "buffer.go").write_text("func (b *Buffer) ReadAll() []byte { return nil }\n")
    got = promoted_logic_units(
        ["pkg/models/buffer.go"], root=tmp_path, layer_globs=["*/models/*.go"], markers=CLUSTER
    )
    assert got == []


def test_promoted_logic_units_empty_cluster_promotes_nothing(tmp_path):
    (tmp_path / "pkg" / "models").mkdir(parents=True)
    (tmp_path / "pkg" / "models" / "share.go").write_text("func (s *Share) Create() {}\nfunc (s *Share) Delete() {}\n")
    got = promoted_logic_units(["pkg/models/share.go"], root=tmp_path, layer_globs=["*/models/*.go"], markers=[])
    assert got == []


def test_promoted_logic_units_only_within_logic_layer(tmp_path):
    (tmp_path / "routes").mkdir()
    (tmp_path / "routes" / "api.go").write_text("func (h *H) Create() {}\nfunc (h *H) Delete() {}\n")
    got = promoted_logic_units(
        ["routes/api.go"], root=tmp_path, layer_globs=["*/models/*.go"], markers=CLUSTER
    )
    assert got == []


def test_build_from_dir_walks_tree_and_skips_noise(tmp_path):
    (tmp_path / "app.py").write_text("x = 1")
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "urls.py").write_text("x = 1")
    (tmp_path / "go.mod").write_text("module x")
    (tmp_path / "__pycache__").mkdir()
    (tmp_path / "__pycache__" / "junk.py").write_text("x = 1")
    (tmp_path / "build" / "lib" / "pkg").mkdir(parents=True)
    (tmp_path / "build" / "lib" / "pkg" / "urls.py").write_text("x = 1")

    m = build_repo_model_from_dir(tmp_path)
    assert {"app.py", "pkg/urls.py", "go.mod"} <= set(m.files)
    assert all("__pycache__" not in f for f in m.files)
    assert all(not f.startswith("build/") for f in m.files)


def test_build_is_deterministic():
    assert build_repo_model("/r", ["b.py", "a.py"]) == build_repo_model("/r", ["a.py", "b.py"])
