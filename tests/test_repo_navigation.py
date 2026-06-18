"""The agentic reviewer's code-navigation tools: read a file, grep the repo, resolve a
definition, all scoped to the repo root so a reviewer can follow a call like a human without
escaping the tree."""

from codejury.review.repo.navigation import find_definition, grep, read_file


def _repo(tmp_path):
    (tmp_path / "app.py").write_text(
        "from lib.util import sanitize\n\n"
        "def handler(req):\n"
        "    q = req.params['id']\n"
        "    return run(sanitize(q))\n"
    )
    lib = tmp_path / "node_modules" / "lib"
    lib.mkdir(parents=True)
    (lib / "util.js").write_text(
        "// vendored dependency on the call path\n"
        "function sanitize(x) {\n"
        "  return x.replace(/'/g, '');  // incomplete, still injectable\n"
        "}\n"
    )
    return str(tmp_path)


def test_read_file_returns_numbered_lines(tmp_path):
    root = _repo(tmp_path)
    out = read_file(root, "app.py", start=3, end=5)
    assert "3\tdef handler(req):" in out
    assert "5\t" in out and "1\tfrom lib.util" not in out


def test_read_file_refuses_path_outside_repo(tmp_path):
    root = _repo(tmp_path)
    assert read_file(root, "../secret.txt").startswith("[not found or outside repo")
    assert read_file(root, "/etc/passwd").startswith("[not found or outside repo")


def test_grep_skips_vendored_deps_by_default(tmp_path):
    root = _repo(tmp_path)
    hits = grep(root, "sanitize")
    files = {h["file"] for h in hits}
    assert "app.py" in files
    assert not any("node_modules" in f for f in files)


def test_find_definition_follows_into_a_vendored_lib(tmp_path):
    # the called method's implementation lives in a vendored dep on the call path, so
    # go-to-definition must reach it, the visibility a single-call reviewer lacks
    root = _repo(tmp_path)
    defs = find_definition(root, "sanitize")
    assert any("node_modules" in d["file"] and d["line"] == 2 for d in defs)


def test_find_definition_matches_python_def(tmp_path):
    root = _repo(tmp_path)
    defs = find_definition(root, "handler")
    assert any(d["file"] == "app.py" and d["line"] == 3 for d in defs)
