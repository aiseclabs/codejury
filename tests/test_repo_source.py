from codejury.sources.chunker import Chunker
from codejury.sources.repo import RepoSource


def test_chunker_keeps_small_content_as_one_chunk():
    assert Chunker(max_chars=100).split("a.py", "short") == [("a.py", "short")]


def test_chunker_splits_large_content_on_line_boundaries():
    content = "".join(f"line {i}\n" for i in range(100))  # ~ many lines
    chunks = Chunker(max_chars=50).split("a.py", content)
    assert len(chunks) > 1
    assert [p for p, _ in chunks] == [f"a.py#{i}" for i in range(1, len(chunks) + 1)]
    assert "".join(body for _, body in chunks) == content  # lossless
    assert all(len(body) <= 50 or body.count("\n") <= 1 for _, body in chunks)


def test_repo_source_walks_selected_files_and_skips_noise(tmp_path):
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "a.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "b.py").write_text("y = 2\n", encoding="utf-8")
    (tmp_path / "readme.md").write_text("# doc\n", encoding="utf-8")  # wrong extension
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "c.py").write_text("ignored = 1\n", encoding="utf-8")  # skipped dir

    arts = RepoSource(tmp_path).list_artifacts()
    assert [a.path for a in arts] == ["b.py", "pkg/a.py"]  # sorted, relative, posix
    assert all(a.kind == "repo" for a in arts)
    assert arts[0].content == "y = 2\n"


def test_repo_source_chunks_large_files(tmp_path):
    big = "".join(f"row {i}\n" for i in range(500))
    (tmp_path / "big.py").write_text(big, encoding="utf-8")
    arts = RepoSource(tmp_path, chunker=Chunker(max_chars=100)).list_artifacts()
    assert len(arts) > 1
    assert all(a.path.startswith("big.py#") for a in arts)
    assert "".join(a.content for a in arts) == big
