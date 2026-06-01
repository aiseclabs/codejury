import ast

from codejury.analysis.provenance import find_calls, parse_function
from codejury.analysis.taint import SAFE, Taint, is_safe_sink, load_vocab, taint_of, worst_sink_taint

VOCAB = load_vocab()  # the shipped codejury/data/taint.yaml


def _taint(source, func_name, callee, arg_index=0):
    func = parse_function(source, func_name)
    call = find_calls(func, callee)[0]
    return taint_of(func, call.args[arg_index], VOCAB)


# --- vocabulary loads -------------------------------------------------------

def test_vocab_loads_expected_entries():
    assert "request.args" in VOCAB.sources
    assert "os.environ" in VOCAB.trusted
    assert "os.path.basename" in VOCAB.sanitizers
    assert "json.loads" in VOCAB.safe_sinks
    assert "join" in VOCAB.propagators


# --- intra-procedural classification ----------------------------------------

def test_constant_concat_is_constant():
    src = ("def q():\n"
           "    table = 'users'\n"
           "    cursor.execute('SELECT * FROM ' + table + ' WHERE active = 1')\n")
    assert _taint(src, "q", "execute") is Taint.CONSTANT


def test_request_field_is_external():
    src = "def f(request):\n    return requests.get(request.args['url'])\n"
    assert _taint(src, "f", "get") is Taint.EXTERNAL


def test_env_is_trusted():
    src = "def g():\n    return open(os.environ['CONFIG_PATH'])\n"
    assert _taint(src, "g", "open") is Taint.TRUSTED


def test_input_call_is_external():
    src = "def g():\n    return open(input())\n"
    assert _taint(src, "g", "open") is Taint.EXTERNAL


def test_sanitizer_neutralizes_external():
    # os.path.basename(request.args[...]) -> sanitized, not external
    src = "def f(request):\n    return open(os.path.basename(request.args['name']))\n"
    assert _taint(src, "f", "open") is Taint.SANITIZED


def test_propagator_carries_taint():
    src = "def f(request):\n    return open(os.path.join(BASE, request.args['name']))\n"
    assert _taint(src, "f", "open") is Taint.EXTERNAL  # join propagates the external arg


def test_propagator_with_sanitized_arg_is_sanitized():
    src = "def f(request):\n    return open(os.path.join(BASE, os.path.basename(request.args['name'])))\n"
    assert _taint(src, "f", "open") is Taint.SANITIZED  # base is trusted-global, name sanitized


def test_parameter_is_param_pending_caller():
    # serve(name): the joined path depends on a parameter -- needs the cross-file hop
    src = "def serve(name):\n    return open(os.path.join(STATIC_DIR, name))\n"
    assert _taint(src, "serve", "open") is Taint.PARAM


def test_unknown_call_is_unknown():
    src = "def f(x):\n    return open(helper(x))\n"
    assert _taint(src, "f", "open") is Taint.UNKNOWN


def test_free_global_is_trusted():
    src = "def f():\n    return open(STATIC_PATH)\n"
    assert _taint(src, "f", "open") is Taint.TRUSTED


# --- safe-sink detection (dotted, so pickle is never confused with json) ----

def test_is_safe_sink_matches_json_and_literal_eval_not_pickle():
    src = ("def a(r):\n    return json.loads(r.data)\n"
           "def b(r):\n    return pickle.loads(r.data)\n"
           "def c(r):\n    return ast.literal_eval(r.data)\n")
    json_call = find_calls(parse_function(src, "a"), "loads")[0]
    pickle_call = find_calls(parse_function(src, "b"), "loads")[0]
    literal_call = find_calls(parse_function(src, "c"), "literal_eval")[0]
    assert is_safe_sink(json_call, VOCAB) is True
    assert is_safe_sink(pickle_call, VOCAB) is False   # the collision that must not happen
    assert is_safe_sink(literal_call, VOCAB) is True


def test_safe_set_membership():
    assert Taint.CONSTANT in SAFE and Taint.SANITIZED in SAFE and Taint.TRUSTED in SAFE
    assert Taint.EXTERNAL not in SAFE and Taint.UNKNOWN not in SAFE and Taint.PARAM not in SAFE


def test_source_method_call_is_external():
    # request.args.get("id") -- a method ON a source object -- must be EXTERNAL, not UNKNOWN
    src = "def f(request):\n    return request.args.get('id')\n"
    func = parse_function(src, "f")
    call = find_calls(func, "get")[0]
    assert taint_of(func, call, VOCAB) is Taint.EXTERNAL


def test_trusted_method_call_is_trusted():
    src = "def f():\n    return os.environ.get('X')\n"
    func = parse_function(src, "f")
    assert taint_of(func, find_calls(func, "get")[0], VOCAB) is Taint.TRUSTED


def test_worst_sink_taint_unknown_when_no_sink_call():
    # tainted data escapes via return with no call sink -> NOT provably safe (UNKNOWN)
    code = "def q(request):\n    sql = 'SELECT ' + request.args['id']\n    return sql\n"
    assert worst_sink_taint(code, {"m.py": code}, VOCAB) is Taint.UNKNOWN


def test_worst_sink_taint_safe_sink_only_is_sanitized():
    # a safe parser consuming external data is provably safe
    code = "def f(request):\n    return ast.literal_eval(request.data)\n"
    assert worst_sink_taint(code, {"m.py": code}, VOCAB) is Taint.SANITIZED
