from codejury.sources.diff import DiffSource

_TWO_FILE = """\
diff --git a/auth.py b/auth.py
index 1111111..2222222 100644
--- a/auth.py
+++ b/auth.py
@@ -1,2 +1,2 @@
-old
+import hashlib
diff --git a/utils.py b/utils.py
index 3333333..4444444 100644
--- a/utils.py
+++ b/utils.py
@@ -5,1 +5,1 @@
+helper()
"""

_NEW_FILE = """\
diff --git a/new.py b/new.py
new file mode 100644
index 0000000..5555555
--- /dev/null
+++ b/new.py
@@ -0,0 +1,1 @@
+print("hi")
"""

_DELETED_FILE = """\
diff --git a/gone.py b/gone.py
deleted file mode 100644
index 6666666..0000000
--- a/gone.py
+++ /dev/null
@@ -1,1 +0,0 @@
-print("bye")
"""


def _paths(diff):
    return [a.path for a in DiffSource(diff).list_artifacts()]


def test_splits_per_file_with_paths_and_bodies():
    arts = DiffSource(_TWO_FILE).list_artifacts()
    assert [a.path for a in arts] == ["auth.py", "utils.py"]
    assert all(a.kind == "diff" for a in arts)
    assert "import hashlib" in arts[0].content
    assert "helper()" in arts[1].content
    assert "utils.py" not in arts[0].content  # second file's hunk did not bleed into the first


def test_added_file_uses_plus_path_not_dev_null():
    assert _paths(_NEW_FILE) == ["new.py"]


def test_deleted_file_uses_minus_path_not_dev_null():
    assert _paths(_DELETED_FILE) == ["gone.py"]


def test_empty_diff_yields_nothing():
    assert DiffSource("").list_artifacts() == []
    assert DiffSource("   \n").list_artifacts() == []
