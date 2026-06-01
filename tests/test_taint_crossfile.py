from codejury.analysis.provenance import find_calls, parse_function
from codejury.analysis.taint import Taint, load_vocab, taint_in_repo

VOCAB = load_vocab()

# The reviewed file: a sink whose taint depends entirely on the caller.
SINK = (
    "def serve(name):\n"
    "    return open(os.path.join(STATIC_DIR, name)).read()\n"
)

CALLER_TAINTED = (
    "@app.route('/download')\n"
    "def download():\n"
    "    return serve(request.args['name'])\n"
)

CALLER_SANITIZED = (
    "@app.route('/download')\n"
    "def download():\n"
    "    name = os.path.basename(request.args['name'])\n"
    "    return serve(name)\n"
)


def _sink_arg_taint(caller_src):
    files = {"mod.py": SINK, "handlers.py": caller_src}
    func = parse_function(SINK, "serve")
    open_call = find_calls(func, "open")[0]            # open(os.path.join(STATIC_DIR, name))
    return taint_in_repo(func, open_call.args[0], VOCAB, files)


def test_identical_sink_flips_on_caller():
    # The reviewed code is byte-for-byte the same; only the caller differs.
    assert _sink_arg_taint(CALLER_TAINTED) is Taint.EXTERNAL    # raw request param -> vulnerable
    assert _sink_arg_taint(CALLER_SANITIZED) is Taint.SANITIZED  # caller basename'd it -> safe


def test_no_caller_found_is_unknown():
    # serve is never called in the given files -> cannot prove anything, not "safe".
    files = {"mod.py": SINK}
    func = parse_function(SINK, "serve")
    open_call = find_calls(func, "open")[0]
    assert taint_in_repo(func, open_call.args[0], VOCAB, files) is Taint.UNKNOWN


def test_keyword_argument_call_site_resolves():
    caller = (
        "def handler(request):\n"
        "    return serve(name=request.args['x'])\n"
    )
    assert _sink_arg_taint(caller) is Taint.EXTERNAL


def test_module_level_caller_resolves():
    caller = "RESULT = serve(input())\n"   # called at module scope with stdin
    assert _sink_arg_taint(caller) is Taint.EXTERNAL


def test_multiple_callers_combine_to_worst():
    caller = (
        "def a(request):\n"
        "    return serve(request.args['x'])\n"   # external
        "def b():\n"
        "    return serve('static.txt')\n"         # constant
    )
    # any attacker-controlled caller makes the parameter external
    assert _sink_arg_taint(caller) is Taint.EXTERNAL
