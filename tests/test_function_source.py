import pytest

from codejury.sources.function import FunctionSource

_CODE = '''\
import hashlib


def store(pwd):
    return hashlib.sha256(pwd).hexdigest()


async def fetch(url):
    return await client.get(url)


class Service:
    def handle(self, req):
        return req.ok
'''


def test_emits_one_artifact_per_function_in_source_order():
    arts = FunctionSource(_CODE, path="auth.py").list_artifacts()
    assert [a.path for a in arts] == ["auth.py::store", "auth.py::fetch", "auth.py::handle"]
    assert all(a.kind == "function" for a in arts)


def test_artifact_content_is_just_that_function():
    arts = FunctionSource(_CODE, path="auth.py").list_artifacts()
    store = arts[0]
    assert store.content.startswith("def store(pwd):")
    assert "hashlib.sha256" in store.content
    assert "fetch" not in store.content  # other functions do not bleed in


def test_async_and_methods_are_included():
    names = [a.path.split("::")[1] for a in FunctionSource(_CODE).list_artifacts()]
    assert "fetch" in names      # async def
    assert "handle" in names     # method inside a class


def test_no_functions_yields_nothing():
    assert FunctionSource("x = 1\nprint(x)\n").list_artifacts() == []


def test_invalid_python_raises():
    with pytest.raises(SyntaxError):
        FunctionSource("def broken(:\n").list_artifacts()
