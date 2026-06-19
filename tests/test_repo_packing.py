"""Focused packing: extract a definition block, find referenced symbols, and co-locate the
called or inherited code a single-shot reviewer cannot otherwise see, bounded to stay focused."""

from codejury.review.repo.packing import (
    extract_block,
    pack_context,
    pack_fragments,
    referenced_symbols,
)


def test_extract_block_brace_language():
    lines = [
        "contract V {",          # 1
        "  function f() {",      # 2
        "    a();",              # 3
        "    if (x) { b(); }",   # 4
        "  }",                   # 5
        "  function g() {}",     # 6
        "}",                     # 7
    ]
    assert extract_block(lines, 2) == (2, 5)


def test_extract_block_indentation_language():
    lines = [
        "def handler(req):",     # 1
        "    q = req['id']",     # 2
        "    return run(q)",     # 3
        "",                      # 4
        "def other():",         # 5
        "    pass",              # 6
    ]
    assert extract_block(lines, 1) == (1, 3)


def test_referenced_symbols_calls_and_inheritance():
    code = "contract Token is ERC20Base, Ownable {\n  function t() { transferSanity(); pay(x); }\n}"
    syms = referenced_symbols(code)
    assert "transferSanity" in syms and "pay" in syms
    assert "ERC20Base" in syms and "Ownable" in syms
    assert "is" not in syms and "function" not in syms


def _repo(tmp_path):
    (tmp_path / "token.sol").write_text(
        "contract Token {\n"
        "  function transferFrom(address s, uint a) public {\n"
        "    chargeFee(s, a);\n"
        "  }\n"
        "}\n"
    )
    (tmp_path / "fees.sol").write_text(
        "contract Fees {\n"
        "  function chargeFee(address s, uint a) internal {\n"
        "    _balances[s] -= a + fee;  // charges more than approved\n"
        "  }\n"
        "}\n"
    )
    return str(tmp_path)


def test_pack_fragments_pulls_a_called_def_from_another_file(tmp_path):
    root = _repo(tmp_path)
    frags = pack_fragments(root, ("token.sol",))
    assert any(f[0] == "fees.sol" for f in frags)


def test_pack_context_co_locates_the_called_implementation(tmp_path):
    # token.sol calls chargeFee defined in fees.sol; the packed context must carry that body so
    # a single-shot reviewer sees the over-charge a unit-only view would miss
    root = _repo(tmp_path)
    ctx = pack_context(root, ("token.sol",))
    assert "pulled definition from fees.sol" in ctx
    assert "charges more than approved" in ctx


def test_pack_context_skips_locally_defined_symbols(tmp_path):
    # a symbol defined in the unit's own file is already visible, not pulled
    (tmp_path / "a.py").write_text("def helper():\n    pass\n\ndef main():\n    helper()\n")
    ctx = pack_context(str(tmp_path), ("a.py",))
    assert ctx == ""
