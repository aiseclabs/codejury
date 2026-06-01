import ast

from codejury.analysis.provenance import (
    Origin,
    find_calls,
    parse_function,
    trace_value,
)


def _arg(source, func_name, callee, arg_index=0):
    """Trace the arg_index-th argument of the call to `callee` inside `func_name`."""
    func = parse_function(source, func_name)
    call = find_calls(func, callee)[0]
    return trace_value(func, call.args[arg_index])


def test_constant_concat_is_constant():
    # sql_constant_concat_safe: SQL built only from constants -> no external source.
    src = (
        "def all_active():\n"
        "    table = 'users'\n"
        "    cursor.execute('SELECT * FROM ' + table + ' WHERE active = 1')\n"
    )
    o = _arg(src, "all_active", "execute")
    assert o.is_constant
    assert o.has_literal and not o.params and not o.attrs


def test_parameter_flows_into_sink():
    # serve(name): the path joined onto STATIC_DIR derives from a parameter.
    src = (
        "def serve(name):\n"
        "    return open(os.path.join(STATIC_DIR, name)).read()\n"
    )
    func = parse_function(src, "serve")
    join = find_calls(func, "join")[0]
    name_arg = join.args[1]               # os.path.join(STATIC_DIR, name) -> `name`
    o = trace_value(func, name_arg)
    assert o.params == frozenset({"name"})
    assert not o.is_constant
    # the trusted base dir is a free module global, not a parameter
    assert trace_value(func, join.args[0]).globals_ == frozenset({"STATIC_DIR"})


def test_request_attribute_is_external_root():
    # ssrf: requests.get(request.args["url"]) -> value rooted at the request param.
    src = (
        "def fetch(request):\n"
        "    return requests.get(request.args['url']).text\n"
    )
    o = _arg(src, "fetch", "get")
    assert "request.args" in o.attrs
    assert o.params == frozenset({"request"})
    assert not o.is_constant


def test_assignment_chain_is_followed():
    # sqli_indirect_var_vuln: name -> clause -> query -> execute(query).
    src = (
        "def find(name):\n"
        "    clause = \"name = '\" + name + \"'\"\n"
        "    query = 'SELECT * FROM users WHERE ' + clause\n"
        "    cursor.execute(query)\n"
    )
    o = _arg(src, "find", "execute")
    assert o.params == frozenset({"name"})   # traced two assignments back
    assert o.has_literal                      # the SQL fragments are literals
    assert not o.is_constant


def test_os_environ_subscript_root():
    src = "def conf():\n    return os.environ['SECRET']\n"
    func = parse_function(src, "conf")
    ret = func.body[0].value                  # os.environ['SECRET']
    assert "os.environ" in trace_value(func, ret).attrs


def test_call_records_callee_not_args():
    # a value from a call is named by the callee; arg analysis is P1-03's job.
    src = "def f(x):\n    return helper(x)\n"
    func = parse_function(src, "f")
    o = trace_value(func, func.body[0].value)
    assert o.calls == frozenset({"helper"})
    assert not o.is_constant


def test_assignment_cycle_terminates():
    src = "def h():\n    x = y\n    y = x\n    return x\n"
    func = parse_function(src, "h")
    trace_value(func, func.body[-1].value)    # must not recurse forever


def test_merge_unions_and_constant_rule():
    a = Origin(params=frozenset({"p"}), has_literal=True)
    b = Origin(attrs=frozenset({"request.args"}))
    m = a.merge(b)
    assert m.params == frozenset({"p"}) and m.attrs == frozenset({"request.args"})
    assert m.has_literal and not m.is_constant
    assert Origin(has_literal=True).is_constant   # pure literal


def test_parse_function_missing_returns_none():
    assert parse_function("def a(): pass", "b") is None
    assert parse_function("def (((", "a") is None   # syntax error -> None, no raise
