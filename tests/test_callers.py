from codejury.sources.callers import caller_context, defined_names
from codejury.sources.chunker import Chunker
from codejury.sources.repo import RepoSource


def test_defined_names_top_level_only():
    code = "def a():\n    def inner(): pass\nclass B: pass\nx = 1\n"
    assert defined_names(code) == {"a", "B"}


def test_defined_names_tolerates_syntax_error():
    assert defined_names("def broken(:\n") == set()


def test_caller_context_finds_cross_file_call_sites():
    files = {
        "lib.py": "def load_capability(path):\n    return open(path)\n",
        "cli.py": "from lib import load_capability\nload_capability(args.cap_dir)\n",
        "other.py": "y = 2\n",
    }
    ctx = caller_context("lib.py", files)
    assert "cli.py:2: load_capability(args.cap_dir)" in ctx
    assert "other.py" not in ctx


def test_caller_context_word_boundary_avoids_prefix_matches():
    # load_capability must NOT match load_capabilities(
    files = {
        "lib.py": "def load_capability(path): ...\n",
        "caller.py": "load_capabilities(dirpath)\n",
    }
    assert caller_context("lib.py", files) == ""


def test_repo_source_attaches_caller_context_when_enabled(tmp_path):
    (tmp_path / "lib.py").write_text("def helper(p):\n    return open(p)\n", encoding="utf-8")
    (tmp_path / "cli.py").write_text("from lib import helper\nhelper(args.path)\n", encoding="utf-8")

    arts = {a.path: a for a in RepoSource(tmp_path, with_callers=True, chunker=Chunker()).list_artifacts()}
    assert "cli.py:2: helper(args.path)" in arts["lib.py"].context
    # without the flag, no context
    arts_off = {a.path: a for a in RepoSource(tmp_path).list_artifacts()}
    assert arts_off["lib.py"].context == ""
