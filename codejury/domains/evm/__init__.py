"""The evm domain: smart contract security knowledge for Solidity and the EVM.

Its content root is this package directory, holding the Solidity `knowledge/`, the
repo-review `playbook/`, and `detection.yaml`. The review strategy is data here too:
the pass lenses, a fund-loss-anchored severity floor table, and the diff prompt's focus
and do-not-report blocks. This package imports only `codejury.domains.base` and its own
light facts backend module, both free of the optional EVM dependency, so loading the
domain never needs slither or foundry.
"""

from pathlib import Path

from codejury.domains.base import Domain
from codejury.domains.evm.facts.slither import SlitherFacts

# the repo-review pass lenses for contracts: each pass leads with one, the empty lens
# reviews every class
EVM_LENSES = (
    "access-control",
    "reentrancy",
    "oracle-manipulation",
    "accounting-precision",
    "signature-replay",
    "denial-of-service",
    "",
)

# the firm-rule severity floor table, regex and level pairs, anchored on fund loss
EVM_SEVERITY_FLOORS = (
    (r"reentran|drain|steal.{0,15}fund|unprotected.{0,20}(withdraw|transfer)", "HIGH"),
    (r"access control|missing.{0,15}(modifier|onlyowner|auth)|unprotected.{0,15}initial|"
     r"tx\.origin|public.{0,12}(mint|burn|withdraw|upgrade)", "HIGH"),
    (r"oracle|price manipulation|spot.?price|flash.?loan", "HIGH"),
    (r"\breplay\b|missing nonce|signature.{0,15}(replay|malleab)|missing.{0,12}(chainid|domain)", "HIGH"),
    (r"delegatecall|storage collision|uninitialized.{0,12}proxy|self.?destruct", "HIGH"),
)

EVM_DIFF_FOCUS = """\
Hunt especially for high-impact, fund-affecting problems:
- Reentrancy: an external call or token transfer before the state update, cross-function
  and read-only reentrancy, missing checks-effects-interactions ordering or nonReentrant guard.
- Access control: a missing or wrong modifier on a privileged function, an unprotected
  or re-callable initializer, tx.origin used for authorization, a public mint, burn,
  withdraw, or upgrade, owner-only logic reachable by anyone.
- Oracle and price manipulation: a spot price or raw balance read as a price, flash-loan
  assisted manipulation, a missing TWAP, bound, or staleness check.
- Accounting and precision: rounding that favors the attacker, ERC-4626 first-depositor
  share inflation, division before multiplication, arithmetic in an unchecked block.
- Upgradeability: delegatecall to attacker-influenced code, proxy storage collision, an
  unprotected initializer, a reachable selfdestruct.
- Signatures: a signed message replayable with no nonce, chainid, or domain separator,
  ecrecover malleability, a signer recovered without checking it is nonzero.
"""

EVM_DIFF_DO_NOT_REPORT = """\
Do NOT report, regardless of severity:
- Gas-optimization or code-style notes with no security impact.
- Compiler-version, floating-pragma, or dependency advisories, this tool does not do
  dependency scanning.
- Missing-event or missing-NatSpec notes that do not change exploitability.
- Speculative issues you cannot tie to a concrete exploit in the code shown.
- Overflow or underflow under Solidity 0.8 checked arithmetic, unless the code is in an
  unchecked block or uses a pre-0.8 pragma.
- A missing nonReentrant guard when the shown code already updates state before the
  external call. Correct checks-effects-interactions ordering is itself the defense.
Report only what the shown code proves. Do not infer a flaw from a function, modifier,
caller, or guard that is not in the diff, and do not assume a check is absent merely
because the diff does not show it.
For input-driven issues, flag only when an external caller can actually reach the sink
with attacker-chosen values. A constant, an immutable set at construction, or an
owner-only path is not attacker-controlled. An owner-only, admin-only, or admin-signed
path is trusted: do not assume the owner or admin is compromised or careless to
manufacture an exploit, flag it only when the shown code itself exposes the flaw.
"""

EVM = Domain(
    name="evm",
    content_root=Path(__file__).resolve().parent,
    lenses=EVM_LENSES,
    severity_floors=EVM_SEVERITY_FLOORS,
    diff_focus=EVM_DIFF_FOCUS,
    diff_do_not_report=EVM_DIFF_DO_NOT_REPORT,
    facts_backend=SlitherFacts(),
)
