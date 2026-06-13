# Severity Rubric

Every real finding is reported at a calibrated severity. There is no "refuted for low
impact": a real, evidenced defect is graded and surfaced, never talked out of existence.
Only an unreal finding, one whose controlling fact holds when you read the code, is
dropped, and that is a refutation on the facts, not on the impact.

Severity is anchored on funds. Grade by impact times exploitability, on the code you read:

- **CRITICAL**: direct theft, unauthorized minting, or permanent loss or lock of funds
  with little or no precondition. Drain a pool or vault via reentrancy, mint unlimited
  supply through a missing access check, seize ownership of an unguarded initializer or
  proxy, arbitrary `delegatecall`, a reachable `selfdestruct` that bricks held funds.
- **HIGH**: funds can be taken or locked, but with a precondition that is a line in the
  attack path, not a reason to drop the finding: a flash loan is available, a particular
  market state, winning a race, holding one signed message. Flash-loan oracle
  manipulation, a replayable privileged signature, griefing that locks user funds, a
  rounding or first-depositor attack that captures deposits.
- **MEDIUM**: real but bounded. A precision leak of dust, a DoS that recovers or only
  delays, a manipulation needing capital out of proportion to the gain, an issue gated by
  a trusted role misbehaving. A real defect that looks limited lands here, reported, not
  refuted.
- **LOW**: hardening and defense in depth. A missing zero-address or zero-amount check
  with no concrete exploit, a missing event, a weakened but not broken control, a best
  practice with no exploit path today.

Firm rules, these override a cautious instinct to downgrade to nothing:

- An external call or token transfer before the state update on a value-moving path is a
  reentrancy finding, at least HIGH, even with a guard elsewhere, until you have read the
  cross-function and read-only paths and shown they are safe.
- A privileged function that mints, burns, moves funds, upgrades, or destroys the
  contract and is reachable without the access control its siblings require is at least
  HIGH, CRITICAL when it directly moves or mints funds.
- An unguarded or re-callable `initialize`, or a logic contract left initializable behind
  a proxy, is at least HIGH, since it hands over ownership or the implementation.
- A price or value read from an in-transaction-movable source, a spot AMM price, reserves,
  or a raw balance, used in a value decision is at least HIGH.
- When unsure between two levels, report at the higher and say why. Unsure how to grade is
  not a reason to drop, only an unreal finding is dropped.

## Out of Scope vs LOW

Recall comes first, so almost nothing is dropped. Out of scope and not reported: dependency
or compiler-version advisories, gas-optimization and style notes with no security impact,
and a candidate the facts refute. Everything else real is reported, graded. A weak signal
is LOW, not dropped. Noise is managed by sorting on severity, never by suppressing a
finding. A missed real finding is worse than a LOW the reader skips.
