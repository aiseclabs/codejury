"""P2-a-1: the PoC verification sandbox. A pass proves the payload marker reached
a dangerous sink; the real sink never runs. Recall-safe: timeout/error/no-reach
never proves."""

import pytest

from codejury.domain.observation import Evidence, Finding, Verdict
from codejury.domain.result import AnalysisResult
from codejury.resources import POC_DIR
from codejury.sandbox import (
    PocTemplate,
    load_poc_templates,
    prove,
    template_for_cwe,
    verify_result,
)

_T = {t.id: t for t in load_poc_templates()}
CMDI = _T["cmdi"]
PATH = _T["path"]
SQLI = _T["sqli"]
SSRF = _T["ssrf"]


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


# --- sql injection (method sink on a free receiver) ---

def test_sqli_concat_query_is_proven():
    code = "def get(name):\n    cursor.execute(\"SELECT * FROM u WHERE n='\" + name + \"'\")\n"
    r = prove(code, SQLI)
    assert r.proven is True
    assert ".execute" in r.hits


def test_sqli_parameterized_is_not_proven():
    # the marker lands in the params tuple, not the query string -> first_str_arg misses it
    code = "def get(name):\n    cursor.execute('SELECT * FROM u WHERE n=%s', (name,))\n"
    assert prove(code, SQLI).proven is False


# --- ssrf ---

def test_ssrf_user_url_is_proven():
    code = "def fetch(request):\n    import requests\n    return requests.get(request.args['url'])\n"
    assert prove(code, SSRF).proven is True


def test_ssrf_host_allowlist_is_not_proven():
    code = (
        "def fetch(request):\n"
        "    import requests\n"
        "    from urllib.parse import urlparse\n"
        "    url = request.args['url']\n"
        "    if urlparse(url).hostname not in ALLOWED_HOSTS:\n"
        "        raise ValueError('host not allowed')\n"
        "    return requests.get(url)\n"
    )
    assert prove(code, SSRF).proven is False


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


# --- verify_result: upgrade a finding to proven ---

_TEMPLATES = load_poc_templates()
_CMDI_CODE = "def run(host):\n    import os\n    os.system('ping ' + host)\n"


def test_verify_result_proves_high_severity_finding():
    result = AnalysisResult(observations=[
        Finding(capability="input_validation.command_injection", title="cmdi", severity="CRITICAL",
                cwe="CWE-78", evidence=[Evidence(file="m.py", line=3, code="os.system(...)")]),
    ])
    out = verify_result(result, _CMDI_CODE, _TEMPLATES)
    o = out.observations[0]
    assert o.attack_path_proven is True
    assert any("PoC proven" in e.code for e in o.evidence)


def test_verify_result_recall_safe_when_not_provable():
    # a safe argv subprocess is not proven; the finding is kept, just not upgraded
    safe = "def run(host):\n    import subprocess\n    subprocess.run(['ping', host], shell=False)\n"
    result = AnalysisResult(observations=[
        Finding(capability="iv.cmdi", title="cmdi", severity="HIGH", cwe="CWE-78",
                evidence=[Evidence(file="m.py", line=3)]),
    ])
    out = verify_result(result, safe, _TEMPLATES)
    assert out.observations[0].attack_path_proven is False
    assert out is result  # unchanged -> same object


def test_verify_result_skips_low_severity_and_unmapped_cwe():
    result = AnalysisResult(observations=[
        Finding(capability="x", title="low", severity="LOW", cwe="CWE-78",
                evidence=[Evidence(file="m.py", line=3)]),                       # below threshold
        Finding(capability="y", title="other", severity="CRITICAL", cwe="CWE-1",
                evidence=[Evidence(file="m.py", line=3)]),                       # no template
    ])
    out = verify_result(result, _CMDI_CODE, _TEMPLATES)
    assert all(o.attack_path_proven is False for o in out.observations)


def test_verify_result_proves_vulnerable_verdict():
    result = AnalysisResult(observations=[
        Verdict(capability="input_validation.command_injection", status="VULNERABLE", cwe="CWE-78",
                evidence=[Evidence(file="m.py", line=3)]),
    ])
    out = verify_result(result, _CMDI_CODE, _TEMPLATES)
    assert out.observations[0].attack_path_proven is True
