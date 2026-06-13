# Unit Review Mandate

You own only the files listed in this unit. Going deep on them is your whole job, do not
review anything else.

Read every `external`, `public`, `fallback`, and `receive` function these files expose and
trace each one into the internal functions, libraries, base contracts it inherits, and
external contracts it calls, down to where value moves or state changes. The flaw often
lives in an inherited modifier, a library, or a called protocol, not the entrypoint. Read
the shared `_stack.md` and `inventory/_auth_model.md` for the role and ownership model,
`_vulnerabilities.md` for the class definitions with vulnerable and secure examples, and
`_false_positive_traps.md` for the recurring ways a static read misjudges them.

Hunt the high-impact classes: reentrancy, missing or broken access control, oracle and
price manipulation, accounting and precision errors, proxy, delegatecall, and initializer
flaws, signature replay, unchecked low-level calls, and denial of service. Money is the
asset, grade every finding by funds moved, locked, or stolen.

For every control on the path, decide on the code you actually read, never on the presence
of a named guard:

- **Reentrancy**: is state written before every external call or token transfer on this
  path? A `nonReentrant` modifier guards one function, not the cross-function path that
  shares the same state, nor a read-only reentrancy where another protocol reads this
  contract's view mid-update. Trace the full effects-then-interactions ordering.
- **Access control**: is the privileged function gated to the exact role, by a modifier
  that may live in an inherited base, and on `msg.sender` not `tx.origin`? Compare
  siblings: where most privileged functions carry a modifier and one does not, that one is
  the likely hole. Check the initializer is guarded and the proxy cannot be re-initialized.
- **Oracle and value source**: is a price or value read from a manipulation-resistant
  source with a staleness and bounds check, or from an in-transaction-movable spot price,
  reserves, or raw balance a flash loan can move for free?
- **Accounting**: does share, fee, or balance math round against the user and multiply
  before dividing, and is the first deposit seeded or capped against share-price inflation?
- **Signatures**: is a signed privileged message bound to a nonce, a chainid, and a domain
  separator, the signer checked nonzero? A signature alone is replayable.
- **Trusted-source**: a value is not safe because a caller you treat as trusted set it, if
  that caller is an arbitrary external account or contract.

Refute in place: name the one controlling fact that would make the code safe, read that
exact code, including inherited modifiers and the called contract, and settle it. Confirmed
if the control is absent or bypassable, refuted if it holds, blocked if it turns on a
deploy-time or runtime fact you cannot read, for example which oracle address is wired in.

Recall comes first: when in doubt, surface it. Never drop a real finding to keep the report
clean. The only things you do not report are dependency or compiler advisories, gas and
style notes with no security impact, and a candidate the facts refute. A weaker signal is a
lower severity, not a dropped finding.

Write a runnable proof when you can, a Foundry test that reproduces the exploit strengthens
a finding. When you cannot run one, still report it, marking `Status: blocked` with the
exact `Needs:`, for example a deployed address to fork, or citing the traced controlling
fact in Analysis. Lack of a proof lowers confidence, it does not drop a real finding. Never
broadcast a transaction, never hold a private key, run a proof only against a local fork or
a fresh local deploy.

Grade every real finding by the severity rubric in `inventory/_severity.md` and report all
of them, CRITICAL through LOW. There is no refuting a finding for low impact. Do not talk a
real finding down with a plausible word: "the guard is on another function", "the array is
usually small", "the owner would not do that" lower the severity per the rubric, they do
not make the finding disappear.

Write each confirmed or blocked finding to `candidates/<name>.md`: Risk, Type, Source as the
contract and function, Status, Analysis citing `file:line`, Attack Path, and Fix. Save a
runnable proof to `pocs/<name>.<ext>` under the same `<name>`, so finalize can match it.
Record any cleared control with the controlling fact that cleared it. Then set this unit's
Status to `reviewed`.
