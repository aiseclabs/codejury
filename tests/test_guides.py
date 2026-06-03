"""Language/framework review guides load and are selected by detection signals
(file globs + dependency-manifest substrings), so adding one is a drop-in file."""

from codejury.guides import Guide, load_guides, select_guides


def test_shipped_guides_load():
    by_id = {g.id: g for g in load_guides()}
    assert {"python", "django", "oauth"} <= set(by_id)
    assert by_id["python"].kind == "language"
    assert by_id["django"].kind == "framework"
    assert by_id["oauth"].kind == "protocol"
    assert "IDOR" in by_id["django"].body or "idor" in by_id["django"].body.lower()


def test_every_guide_declares_a_kind_in_frontmatter():
    # kind is sourced from frontmatter, the single source of truth, so a drop-in
    # that forgets it must fail loudly rather than be silently miscategorised
    for g in load_guides():
        assert g.kind in {"language", "framework", "protocol"}, f"{g.id} has kind {g.kind!r}"


def test_protocol_guide_selected_by_protocol_token():
    # language-neutral detection: an OAuth wire field, no ecosystem library name
    matched = {g.id for g in select_guides(["main.py"], text="grant_type=authorization_code\nredirect_uri\n")}
    assert "oauth" in matched


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
                  detect_manifest=(), detect_imports=(), detect_content=(), entrypoint_files=(),
                  entrypoint_markers=(), body="b")]
    assert [g.id for g in select_guides(["a.xyz"], guides=only)] == ["x"]
    assert select_guides(["a.py"], guides=only) == []
