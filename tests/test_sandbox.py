"""P2-a-1: the PoC verification sandbox. A pass proves the payload marker reached
a dangerous sink; the real sink never runs. Recall-safe: timeout/error/no-reach
never proves."""

import pytest

from codejury.resources import POC_DIR
from codejury.sandbox import (
    PocTemplate,
    load_poc_templates,
    prove,
    template_for_cwe,
)

_T = {t.id: t for t in load_poc_templates()}
CMDI = _T["cmdi"]
PATH = _T["path"]


# --- command injection ---

def test_cmdi_shell_concat_is_proven():
    code = "def run(host):\n    import os\n    os.system('ping ' + host)\n"
    r = prove(code, CMDI)
    assert r.proven is True
    assert any("os.system" in h for h in r.hits)


def test_cmdi_argv_subprocess_is_not_proven():
    # shell=False argv form: the payload reaches subprocess as a list element, not
    # a shell string, so it is not a command injection and must not be proven.
    code = "def run(host):\n    import subprocess\n    subprocess.run(['ping', '-c', '1', host], shell=False)\n"
    assert prove(code, CMDI).proven is False


def test_cmdi_request_handler_is_proven():
    code = (
        "def handler(request):\n"
        "    import os\n"
        "    os.system('ping ' + request.args['host'])\n"
    )
    assert prove(code, CMDI).proven is True


# --- path traversal ---

def test_path_unsanitized_open_is_proven():
    code = "def serve(name):\n    import os\n    return open(os.path.join(STATIC_DIR, name))\n"
    assert prove(code, PATH).proven is True


def test_path_basename_sanitized_is_not_proven():
    # basename strips the traversal and the marker with it -> never reaches open
    code = (
        "def serve(name):\n"
        "    import os\n"
        "    safe = os.path.basename(name)\n"
        "    return open(os.path.join(STATIC_DIR, safe))\n"
    )
    assert prove(code, PATH).proven is False


# --- the real sink never runs ---

def test_sink_is_stubbed_not_executed(tmp_path):
    # if os.system actually ran, this would create the file; it must not.
    sentinel = tmp_path / "pwned"
    code = f"def run(x):\n    import os\n    os.system('touch {sentinel} #' + x)\n"
    prove(code, CMDI)
    assert not sentinel.exists()  # the real shell never executed


# --- recall-safe ---

def test_no_target_function_is_not_proven_with_error():
    r = prove("x = 1\n", CMDI)
    assert r.proven is False and r.error


def test_unparseable_code_is_not_proven():
    assert prove("def (:bad", CMDI).proven is False


def test_target_selected_by_line():
    code = (
        "def safe(x):\n"
        "    return x\n"
        "def vuln(host):\n"
        "    import os\n"
        "    os.system('ping ' + host)\n"
    )
    # line 5 is inside vuln(); the prover should drive that one
    assert prove(code, CMDI, line=5).proven is True


# --- templates / lookup ---

def test_templates_load_from_data():
    assert {"cmdi", "path"} <= {t.id for t in load_poc_templates()}
    assert POC_DIR.is_dir()


def test_template_for_cwe():
    assert template_for_cwe("CWE-78", [CMDI, PATH]) is CMDI
    assert template_for_cwe("CWE-22", [CMDI, PATH]) is PATH
    assert template_for_cwe("CWE-999", [CMDI, PATH]) is None
