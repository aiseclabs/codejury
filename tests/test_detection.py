"""The file and path classification config loads from data and drives what the
engine treats as a source file, a manifest, a noise dir, or test code, so the
implementation enumerates no language itself."""

from codejury.detection import load_detection


def test_detection_config_loads_with_content():
    d = load_detection()
    assert ".py" in d.source_extensions and ".go" in d.source_extensions   # many ecosystems
    assert ".yaml" in d.config_extensions
    assert ".py" in d.detection_extensions and ".yaml" in d.detection_extensions  # source plus config
    assert "requirements.txt" in d.manifests and "package.json" in d.manifests
    assert ".venv" in d.skip_dirs and "node_modules" in d.skip_dirs


def test_is_test_path_by_directory_segment():
    d = load_detection()
    assert d.is_test_path("app/tests/views.py")
    assert d.is_test_path("spec/billing.rb")
    assert not d.is_test_path("app/views.py")


def test_is_test_path_by_naming_convention_across_ecosystems():
    d = load_detection()
    assert d.is_test_path("app/test_views.py")      # python prefix
    assert d.is_test_path("app/views_test.go")      # go suffix
    assert d.is_test_path("app/billing.spec.js")    # js spec
    assert d.is_test_path("app/api.test.ts")        # js test


def test_is_test_path_keeps_production_sampleish_names():
    d = load_detection()
    for f in ("app/sample_rate.py", "app/mock_billing.py", "app/example_config.py", "app/latest.py"):
        assert not d.is_test_path(f), f
