"""The working-directory .env loader the CLI runs at startup."""

import os

from codejury.envfile import load_env_file, parse_env


def test_parse_skips_blanks_and_comments_and_strips_quotes_and_export():
    parsed = parse_env(
        "\n"
        "# a comment\n"
        "CODEJURY_MODEL=claude-opus-4-8\n"
        "export CODEJURY_PROVIDER=anthropic\n"
        'CODEJURY_API_KEY="sk-quoted"\n'
        "CODEJURY_API_BASE='https://example.test'\n"
        "a stray note with no equals\n"
    )
    assert parsed == {
        "CODEJURY_MODEL": "claude-opus-4-8",
        "CODEJURY_PROVIDER": "anthropic",
        "CODEJURY_API_KEY": "sk-quoted",
        "CODEJURY_API_BASE": "https://example.test",
    }


def test_load_missing_file_is_not_an_error(tmp_path):
    assert load_env_file(tmp_path / "absent.env") == []


def test_load_sets_unset_keys_and_reports_them(tmp_path, monkeypatch):
    monkeypatch.delenv("CODEJURY_MODEL", raising=False)
    p = tmp_path / ".env"
    p.write_text("CODEJURY_MODEL=from-file\n")
    loaded = load_env_file(p)
    assert loaded == ["CODEJURY_MODEL"]
    assert os.environ["CODEJURY_MODEL"] == "from-file"


def test_an_exported_value_wins_over_the_file(tmp_path, monkeypatch):
    monkeypatch.setenv("CODEJURY_MODEL", "from-shell")
    p = tmp_path / ".env"
    p.write_text("CODEJURY_MODEL=from-file\n")
    loaded = load_env_file(p)
    assert loaded == []
    assert os.environ["CODEJURY_MODEL"] == "from-shell"


def test_override_replaces_an_existing_value(tmp_path, monkeypatch):
    monkeypatch.setenv("CODEJURY_MODEL", "from-shell")
    p = tmp_path / ".env"
    p.write_text("CODEJURY_MODEL=from-file\n")
    loaded = load_env_file(p, override=True)
    assert loaded == ["CODEJURY_MODEL"]
    assert os.environ["CODEJURY_MODEL"] == "from-file"
