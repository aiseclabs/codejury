"""Command line interface: thin argument parsing and dispatch.

Two paths matched to their nature:

- ``review diff`` runs the coded diff engine over a unified diff: a single
  balanced call in standard mode or the adversarial Finder/Challenger/Judge pass.
- ``review repo <dir>`` scaffolds a workspace and prints the methodology for an
  interactive agent to run a whole-repo review. It does not run an LLM pipeline,
  which a single call cannot do for a whole codebase.

``review diff --dry-run`` exercises the engine with a mock provider and no key.
The audit orchestration itself lives in ``codejury.review.diff.engine``.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

import re

from codejury import __version__
from codejury.domains.registry import available_domains, get_domain, resolve_domain
from codejury.report import gate, render
from codejury.review.diff.engine import audit_diff
from codejury.providers.factory import (
    DEFAULT_API_BASE,
    DEFAULT_API_KEY,
    DEFAULT_MODEL,
    DEFAULT_PROVIDER,
    DEFAULT_RETRIES,
    DEFAULT_ROLE_BACKENDS,
    DEFAULT_TIMEOUT,
    PROVIDERS,
    ROLES,
    make_provider,
)
from codejury.providers.mock import MockProvider
from codejury.review.repo.scaffold import scaffold

_FORMATS = ("text", "markdown", "json", "sarif")
_FAIL_ON = ("critical", "high", "medium", "low")

_DOMAIN_HELP = (
    "review domain to use: 'auto' detects from the target's files, or name one of: "
    + ", ".join(available_domains())
)
_DOMAIN_PRUNE = {".git", ".venv", "venv", "node_modules", "__pycache__", "build", "dist", "target", "out"}


def _add_domain_arg(p) -> None:
    p.add_argument("--domain", default="auto", metavar="DOMAIN", help=_DOMAIN_HELP)


def _repo_file_names(directory: str) -> list[str]:
    """File names under the target, for domain detection only. Names carry the
    extensions the heuristic counts, so the walk reads no file content and prunes the
    usual heavy directories to stay fast on a large repo."""
    names: list[str] = []
    for _root, dirs, files in os.walk(directory):
        dirs[:] = [d for d in dirs if d not in _DOMAIN_PRUNE]
        names.extend(files)
    return names


def _diff_paths(diff: str) -> list[str]:
    """The changed file paths named in a unified diff, for domain detection."""
    return re.findall(r"(?:\+\+\+ b/|diff --git a/\S+ b/)(\S+)", diff)


def _default_workspace() -> str:
    """A user-private default, since the workspace holds the auth model, exploit paths, and PoCs."""
    base = os.environ.get("XDG_STATE_HOME") or str(Path.home() / ".local" / "state")
    return str(Path(base) / "codejury" / "reviews")


def _read_diff(args) -> str:
    if args.file:
        with open(args.file, encoding="utf-8") as f:
            return f.read()
    if args.git_range:
        return subprocess.run(
            ["git", "-C", args.repo or ".", "diff", args.git_range],
            capture_output=True, text=True, check=True,
        ).stdout
    return sys.stdin.read()


def _dry_run_diff() -> str:
    return "+++ b/app.py\n@@ -0,0 +1 @@\n+cursor.execute('SELECT * FROM u WHERE n=' + name)\n"


_MOCK_REPLY = (
    '{"findings": [{"file": "app.py", "line": 1, "severity": "HIGH", '
    '"category": "sql_injection", "description": "[mock] no backend called", '
    '"confidence": 0.9}]}'
)

_REPO_MOCK_REPLY = (
    '{"findings": [{"title": "[mock] no backend called", "category": "other", '
    '"endpoint": "GET /mock", "file": "mock.py", "line": 1, "severity": "MEDIUM", '
    '"evidence": "mock.py:1", "status": "confirmed"}]}'
)


def _base_spec(args):
    """The base backend each role inherits from when its own field is unset."""
    return {"provider": args.provider, "model": args.model,
            "api_key": args.api_key, "api_base": args.api_base, "wire_api": "chat"}


def _role_spec(args, role, base):
    """Resolve one role's backend, each field inheriting the base when its own is unset. A role
    that overrides the provider to a different vendor does not inherit the base key or endpoint,
    which belong to the base vendor, it falls back to its own field or the SDK env."""
    provider = getattr(args, f"{role}_provider") or base["provider"]
    same_vendor = provider == base["provider"]
    return {
        "provider": provider,
        "model": getattr(args, f"{role}_model") or base["model"],
        "api_key": getattr(args, f"{role}_api_key") or (base["api_key"] if same_vendor else None),
        "api_base": getattr(args, f"{role}_api_base") or (base["api_base"] if same_vendor else None),
        "wire_api": getattr(args, f"{role}_wire_api") or "chat",
    }


def _role_provider(args, spec):
    """Build a provider for a resolved role spec. Construction is lazy, so a per-role provider
    object is cheap, no SDK or key is touched until a call is made."""
    return make_provider(spec["provider"], api_key=spec["api_key"], api_base=spec["api_base"],
                         retries=args.retries, wire_api=spec["wire_api"], timeout=args.timeout)


def _same_backend(a, b) -> bool:
    """Two role specs name the same model when their vendor and model match."""
    return (a["provider"], a["model"]) == (b["provider"], b["model"])


def _warn_no_judge(args, challenger, judge) -> None:
    """A verify run whose judge is not a distinct model from the challenger refutes nothing, since
    a deletion needs two different reads to agree. Tell the operator so they wire a distinct judge
    instead of reading a keep-everything report as filtered."""
    if args.verify and not args.dry_run and _same_backend(challenger, judge):
        print("NOTE: the judge model is the same as the challenger, so the verify stage refutes "
              "nothing and keeps every candidate. Set a distinct --judge-model or CODEJURY_JUDGE_MODEL "
              "so a deletion is confirmed by a second model.", file=sys.stderr)


def _warn_secondary_env() -> None:
    """The CODEJURY_SECONDARY_* names were replaced by the per-role CODEJURY_CHALLENGER_* and
    CODEJURY_JUDGE_* names. Warn when the old names are still set so they are not silently ignored."""
    if any(k.startswith("CODEJURY_SECONDARY_") for k in os.environ):
        print("NOTE: CODEJURY_SECONDARY_* is no longer read. Use CODEJURY_CHALLENGER_* for the "
              "skeptic and CODEJURY_JUDGE_* for the confirmer.", file=sys.stderr)


def _distinct_backends(args, specs):
    """The distinct (provider object, model) backends among role specs, for the cross-confirm
    judge set on a coded run. Deduped by vendor and model so the same model is not a judge twice."""
    out = []
    seen = set()
    for spec in specs:
        key = (spec["provider"], spec["model"])
        if key not in seen:
            seen.add(key)
            out.append((_role_provider(args, spec), spec["model"]))
    return tuple(out)


def _warn_roles_under_agent(args) -> None:
    """Under --executor claude-cli the finder and skeptic are the Claude Code agent, so the finder
    and challenger backend flags are ignored. The judge still applies as the confirmer."""
    fields = ("provider", "model", "api_key", "api_base", "wire_api")
    overridden = [r for r in ("finder", "challenger")
                  if any(getattr(args, f"{r}_{f}") for f in fields)]
    if overridden:
        print(f"NOTE: --executor claude-cli ignores the {' and '.join(overridden)} backend flags, "
              "the agent supplies the finder and skeptic. The judge still applies as the confirmer.",
              file=sys.stderr)


def _add_backend_args(target) -> None:
    """The model-backend flags shared by both review paths, so the two parsers cannot drift on
    a default. `target` is a parser or an argument group, both expose add_argument."""
    target.add_argument("--provider", choices=PROVIDERS, default=DEFAULT_PROVIDER)
    target.add_argument("--model", default=DEFAULT_MODEL)
    target.add_argument("--api-key", default=DEFAULT_API_KEY)
    target.add_argument("--api-base", default=DEFAULT_API_BASE)
    target.add_argument("--retries", type=int, default=DEFAULT_RETRIES,
                        help="provider retry attempts on transient failure")
    target.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT,
                        help="per-call deadline in seconds, also honored when a retry holds the bound")


def _add_role_backend_args(target, role: str) -> None:
    """The per-role backend override flags for finder, challenger, or judge. Each field defaults
    to None meaning inherit the base --provider/--model/--api-key/--api-base, resolved at build
    time, so a single-model run sets only --model. A role that overrides the provider to a
    different vendor takes its own key, not the base vendor's."""
    d = DEFAULT_ROLE_BACKENDS[role]
    target.add_argument(f"--{role}-provider", choices=PROVIDERS, default=d["provider"], dest=f"{role}_provider")
    target.add_argument(f"--{role}-model", default=d["model"], dest=f"{role}_model")
    target.add_argument(f"--{role}-api-key", default=d["api_key"], dest=f"{role}_api_key")
    target.add_argument(f"--{role}-api-base", default=d["api_base"], dest=f"{role}_api_base")
    target.add_argument(f"--{role}-wire-api", default=d["wire_api"], dest=f"{role}_wire_api",
                        choices=("chat", "responses"),
                        help=f"openai {role} wire API, responses for the gpt-5 reasoning models")


def _add_audit_args(p) -> None:
    """The diff-audit flags for `review diff`."""
    p.add_argument("--file", default=None, help="unified diff file (default: read stdin)")
    p.add_argument("--repo", default=None, help="repo path for --git-range")
    p.add_argument("--git-range", default=None, help="git range to diff, e.g. origin/main...HEAD")
    p.add_argument("--dry-run", action="store_true",
                   help="run the engine with a mock provider and no key (a built-in demo diff if none is given)")
    p.add_argument("--exclude", action="append", default=None, metavar="PATH",
                   help="drop findings whose file path contains this substring (repeatable)")
    p.add_argument("--mode", choices=("standard", "adversarial"), default="standard")
    p.add_argument("--rounds", type=int, default=3, help="adversarial only: debate rounds")
    _add_backend_args(p)
    # adversarial only: finder scans, challenger refutes, judge decides, each defaults to --model
    for role in ROLES:
        _add_role_backend_args(p, role)
    p.add_argument("--format", choices=_FORMATS, default="text", dest="fmt")
    p.add_argument("--no-filter", action="store_true", help="skip the false-positive filter")
    p.add_argument("--fail-on", choices=_FAIL_ON, default=None, dest="fail_on")
    _add_domain_arg(p)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="codejury")
    parser.add_argument("--version", action="version", version=f"codejury {__version__}")
    sub = parser.add_subparsers(dest="command")

    review = sub.add_parser("review", help="review code for security findings")
    rsub = review.add_subparsers(dest="scope")
    _add_audit_args(rsub.add_parser("diff", help="audit a unified diff (the coded engine)"))
    repo = rsub.add_parser("repo", help="scaffold a whole-repo review for an interactive agent")
    repo.add_argument("directory", help="target repository to review")
    repo.add_argument("--workspace", default=_default_workspace(),
                      help="where to create the review workspace, defaults to a user-private "
                           "directory under XDG_STATE_HOME or ~/.local/state")
    repo.add_argument("--fresh", action="store_true",
                      help="clear a previous review's output in the workspace first")
    # the workspace modes are mutually exclusive, scaffold is the default when none is set.
    # Two at once would otherwise fall to a dispatch precedence and silently run just one, so
    # --run --finalize could finalize and rewrite findings/, argparse rejects the pair instead
    mode = repo.add_mutually_exclusive_group()
    mode.add_argument("--gate", action="store_true",
                      help="check the existing workspace against the Completeness Gate instead of scaffolding, "
                           "exit 0 if it passes, 1 if any item is unmet")
    mode.add_argument("--run", action="store_true",
                      help="run the coded multi-pass engine over the repo, not just scaffold, "
                           "covers every unit each pass, cycles lenses, unions until convergence")
    mode.add_argument("--finalize", action="store_true",
                      help="post-process an existing workspace's candidates in code: dedup, "
                           "adversarially verify, and write the ranked report, resumable")
    repo.add_argument("--dry-run", action="store_true",
                      help="run only: drive the engine with a mock provider and no key, to smoke-test the pipeline")

    _add_backend_args(repo.add_argument_group("model backend"))

    strategy = repo.add_argument_group("review strategy")
    strategy.add_argument("--executor", choices=("api", "claude-cli"), default="api",
                          help="how the finder and skeptic run: 'api' calls the provider once per "
                               "unit, 'claude-cli' runs each unit and its verification as a headless "
                               "`claude -p` agent that reads files itself, using your Claude Code "
                               "access, no provider key")
    strategy.add_argument("--facts", action="store_true", default=False,
                          help="ground review in a tool-extracted call graph, storage layout, and "
                               "read and write sets when the domain binds a facts backend such as "
                               "the EVM slither backend. Off by default since extraction is heavy, "
                               "the result is cached by source content hash so a re-run is free")

    roles = repo.add_argument_group(
        "model roles (advanced)",
        "finder finds, challenger refutes, judge confirms before a deletion. Each field inherits the "
        "base backend when unset, so override only the seat you change, set a different vendor in any "
        "seat for cross-model review, for example a GPT challenger and a Claude judge. A cross-vendor "
        "seat brings its own api-key. A deletion needs the judge to be a distinct model from "
        "the challenger, with none distinct no finding is refuted, the recall-safe default. Ignored "
        "under --executor claude-cli. Usually set through CODEJURY_FINDER_*/CHALLENGER_*/JUDGE_*")
    for role in ROLES:
        _add_role_backend_args(roles, role)

    tuning = repo.add_argument_group("run tuning (advanced)", "only affect --run, sane defaults otherwise")
    tuning.add_argument("--max-passes", type=int, default=24, dest="max_passes",
                        help="cap on diverse passes before stopping")
    tuning.add_argument("--converge-after", type=int, default=2, dest="converge_after",
                        help="stop once this many consecutive passes add no new finding")
    tuning.add_argument("--min-lens-shots", type=int, default=2, dest="min_lens_shots",
                        help="keep going until every lens has reviewed this many times, so a hard "
                             "class is not left to one shot on a repo that converges fast")
    tuning.add_argument("--concurrency", type=int, default=6,
                        help="how many unit sub-reviews to run in parallel within a pass")
    tuning.add_argument("--no-verify", dest="verify", action="store_false", default=True,
                        help="skip the adversarial verification stage, keep every candidate")
    tuning.add_argument("--votes", type=int, default=1,
                        help="independent skeptic votes per candidate, refuted only on a majority")
    _add_domain_arg(repo)

    inst = sub.add_parser("install-slash-command",
                          help="install the /codejury-review-repo slash command for an agent")
    inst.add_argument("--agent", choices=("claude", "codex"), default="claude",
                      help="which agent's command directory to install into")
    inst.add_argument("--dir", default=None, help="explicit target directory, overrides --agent")
    inst.add_argument("--force", action="store_true",
                      help="overwrite an existing codejury-review-repo.md at the destination")
    inst.add_argument("--domain", default="web", metavar="DOMAIN",
                      help="which domain's slash command to install, one of: " + ", ".join(available_domains()))

    args = parser.parse_args(argv)
    try:
        return _dispatch(args, parser)
    except Exception as exc:
        label = getattr(args, "command", None) or "codejury"
        print(f"{label} failed: {exc}", file=sys.stderr)
        return 1


def _dispatch(args, parser) -> int:
    scope = getattr(args, "scope", None)
    if args.command == "review" and scope == "diff":
        if args.dry_run:
            provider = MockProvider(default=_MOCK_REPLY)
            model = "mock"
            diff = _read_diff(args) if (args.file or args.git_range) else _dry_run_diff()
        else:
            provider = make_provider(args.provider, api_key=args.api_key, api_base=args.api_base,
                                     retries=args.retries, timeout=args.timeout)
            model = args.model
            diff = _read_diff(args)
        domain = resolve_domain(args.domain, _diff_paths(diff))
        base = _base_spec(args)
        finder = _role_spec(args, "finder", base)
        challenger = _role_spec(args, "challenger", base)
        judge = _role_spec(args, "judge", base)
        # role backends only matter in adversarial mode, and not in dry-run where the mock
        # provider serves every role, so build them only when they will be used
        build_roles = not args.dry_run and args.mode == "adversarial"
        kept, _, degraded = audit_diff(
            diff, provider=provider, model=model,
            mode=args.mode, max_rounds=args.rounds, filter_findings=not args.no_filter,
            finder_model=finder["model"], challenger_model=challenger["model"], judge_model=judge["model"],
            finder_provider=_role_provider(args, finder) if build_roles else None,
            challenger_provider=_role_provider(args, challenger) if build_roles else None,
            judge_provider=_role_provider(args, judge) if build_roles else None,
            exclude_paths=tuple(args.exclude or ()), domain=domain,
        )
        print(render(args.fmt, kept))
        if degraded:
            # the adversarial judge was unusable and the result fell back to the
            # unjudged set, so this is a failed audit, not a clean pass, invariant 3
            print("error: the adversarial audit degraded on an unusable judge reply, "
                  "the result is incomplete and not a clean pass", file=sys.stderr)
        return 1 if degraded or gate(kept, args.fail_on) else 0

    if args.command == "review" and scope == "repo" and args.gate:
        from codejury.review.repo.gate import check_gate
        project_dir = Path(args.workspace) / Path(args.directory).resolve().name
        result = check_gate(project_dir)
        if result.passed:
            print(f"Completeness Gate PASSED for {project_dir}")
            print("Checked: " + ", ".join(result.checked))
            return 0
        print(f"Completeness Gate FAILED for {project_dir}, {len(result.failures)} item(s) unmet:", file=sys.stderr)
        for f in result.failures:
            print(f"  - {f}", file=sys.stderr)
        print("Run another round to address these, then re-check. Do not report the review complete yet.", file=sys.stderr)
        return 1

    if args.command == "review" and scope == "repo" and args.finalize:
        from codejury.review.repo.engine import finalize_repo_review
        from codejury.review.repo.verifier import ModelRefutationChecker, ModelVerifier
        domain = resolve_domain(args.domain, _repo_file_names(args.directory))
        _warn_secondary_env()
        base = _base_spec(args)
        challenger = _role_spec(args, "challenger", base)
        judge = _role_spec(args, "judge", base)
        provider = None
        # challenger backs the skeptic, judge backs the confirmer, a deletion needs the two to be
        # distinct models so a single read cannot drop a real finding
        if args.executor == "claude-cli":
            from codejury.review.repo.agent import AgentVerifier
            verifier_obj = AgentVerifier(content=domain.paths)
            _warn_roles_under_agent(args)
        elif args.dry_run:
            verifier_obj, provider = None, MockProvider(default='{"real": true, "reason": "[mock]"}')
            args.model = "mock"
        else:
            verifier_obj = ModelVerifier(provider=_role_provider(args, challenger),
                                         model=challenger["model"], content=domain.paths)
        checker_obj = None
        if not args.dry_run and not _same_backend(challenger, judge):
            checker_obj = ModelRefutationChecker(provider=_role_provider(args, judge), model=judge["model"])
        _warn_no_judge(args, challenger, judge)
        print(f"Finalizing {args.directory}: dedup + verify + report ...", file=sys.stderr)
        fr = finalize_repo_review(
            args.directory, args.workspace, verifier=verifier_obj, checker=checker_obj,
            provider=provider, model=args.model, verify=args.verify, votes=args.votes,
            concurrency=args.concurrency, domain=domain,
        )
        kept = len(fr.verify.confirmed) if fr.verify else fr.deduped
        refuted = len(fr.verify.refuted) if fr.verify else 0
        print(f"Finalize done: parsed {fr.parsed} candidates -> {fr.deduped} after dedup -> "
              f"{kept} confirmed, {refuted} refuted, see {fr.workspace}/_refuted.md.")
        print(f"Confirmed findings in {fr.workspace}/findings/ and {fr.workspace}/findings.json, "
              f"PoC reconciliation in {fr.workspace}/_pocs.md")
        if fr.verify and fr.verify.errors:
            print(f"WARNING: {fr.verify.errors} verification calls failed. Re-run to resume.", file=sys.stderr)
            return 1   # fail loud: an incomplete verification is not a clean finalize, invariant 3
        return 0

    if args.command == "review" and scope == "repo" and args.run:
        from codejury.review.repo.engine import run_repo_review
        from codejury.review.repo.verifier import ModelRefutationChecker, ModelVerifier
        domain = resolve_domain(args.domain, _repo_file_names(args.directory))
        _warn_secondary_env()
        base = _base_spec(args)
        finder = _role_spec(args, "finder", base)
        challenger = _role_spec(args, "challenger", base)
        judge = _role_spec(args, "judge", base)
        reviewer_obj = verifier_obj = checker_obj = None
        provider = None
        model = args.model
        judge_backends: tuple = ()
        if args.executor == "claude-cli":
            from codejury.review.repo.agent import AgentReviewer, AgentVerifier
            reviewer_obj = AgentReviewer(content=domain.paths)
            verifier_obj = AgentVerifier(content=domain.paths)
            _warn_roles_under_agent(args)
            if not _same_backend(challenger, judge):
                checker_obj = ModelRefutationChecker(provider=_role_provider(args, judge), model=judge["model"])
        elif args.dry_run:
            provider = MockProvider(default=_REPO_MOCK_REPLY)
            model = "mock"
        else:
            # finder goes through provider+model so the engine builds the unit reviewer with its
            # facts wiring, the skeptic and confirmer are injected from the challenger and judge
            provider = _role_provider(args, finder)
            model = finder["model"]
            verifier_obj = ModelVerifier(provider=_role_provider(args, challenger),
                                         model=challenger["model"], content=domain.paths)
            if not _same_backend(challenger, judge):
                checker_obj = ModelRefutationChecker(provider=_role_provider(args, judge), model=judge["model"])
            # the distinct role models are the cross-confirm judge set, so a singleton is judged
            # by a model that did not surface it when two or more vendors are in play
            judge_backends = _distinct_backends(args, (finder, challenger, judge))

        def _progress(p, lens, new, total):
            print(f"  pass {p} [{lens or 'general'}]  +{new} new  union={total}", file=sys.stderr)

        _warn_no_judge(args, challenger, judge)
        print(f"Running the coded multi-pass engine over {args.directory} ...", file=sys.stderr)
        res = run_repo_review(
            args.directory, args.workspace, provider=provider, model=model,
            reviewer=reviewer_obj, verifier=verifier_obj, checker=checker_obj,
            judge_backends=(judge_backends or None),
            verify=args.verify, votes=args.votes,
            max_passes=args.max_passes, converge_after=args.converge_after,
            min_lens_shots=args.min_lens_shots,
            concurrency=args.concurrency, fresh=args.fresh, on_pass=_progress,
            domain=domain, facts=args.facts,
        )
        acc = res.accumulator
        reported = res.verify.confirmed if res.verify else acc.findings
        by_sev: dict[str, int] = {}
        for c in reported:
            by_sev[c.severity] = by_sev.get(c.severity, 0) + 1
        print(f"Engine done: {res.units} units, {len(acc.new_per_pass)} passes, converged={acc.converged}.")
        if res.verify is not None:
            print(f"Union {len(acc.findings)} -> verified {len(reported)} confirmed, "
                  f"{len(res.verify.refuted)} refuted, see {res.scaffold.workspace}/_refuted.md.")
        print(f"{len(reported)} findings: " + ", ".join(
            f"{by_sev.get(s, 0)} {s}" for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW")))
        failures = acc.errors + (res.verify.errors if res.verify else 0)
        if failures:
            print(f"WARNING: {failures} model calls failed, e.g. provider errors or rate limits. "
                  "Results may be understated. Lower --concurrency or raise --retries and re-run.",
                  file=sys.stderr)
        if not acc.converged:
            print(f"WARNING: the union did not converge within {args.max_passes} passes, it was "
                  "still finding new issues when the cap stopped it. Coverage is incomplete and "
                  "recall is not guaranteed. Raise --max-passes or narrow the scope and re-run.",
                  file=sys.stderr)
        print(f"Findings written to {res.scaffold.workspace}/findings/ and {res.scaffold.workspace}/findings.json")
        # fail loud: a partial run or a run still finding issues at the cap must not exit clean,
        # invariant 3 and the stability red line, so a non-converged run is not reported as done
        return 1 if failures or not acc.converged else 0

    if args.command == "review" and scope == "repo":
        # a bare scaffold consumes none of the run-only options, so flag the common mistake
        # of setting one without --run rather than silently doing nothing with it
        ignored = [flag for flag, used in (
            ("--dry-run", args.dry_run),
            ("--executor", args.executor != "api"),
            ("--no-verify", not args.verify),
        ) if used]
        if ignored:
            print(f"NOTE: {', '.join(ignored)} only affect --run, this bare scaffold ignores them. "
                  "Add --run to drive the coded engine.", file=sys.stderr)
        domain = resolve_domain(args.domain, _repo_file_names(args.directory))
        res = scaffold(args.directory, args.workspace, fresh=args.fresh, domain=domain,
                       facts=args.facts)
        (Path(res.workspace) / "METHODOLOGY.md").write_text(res.methodology, encoding="utf-8")
        if res.cleared:
            print(f"Cleared {len(res.cleared)} prior-run paths in {res.workspace}", file=sys.stderr)
        elif res.had_prior_run:
            print(f"A previous review's output is in {res.workspace}. Re-run with --fresh to clear it "
                  "first.", file=sys.stderr)
        print(f"Workspace ready: {res.workspace}", file=sys.stderr)
        if res.guides:
            print(f"Detected stack: {', '.join(res.guides)}, notes in {res.workspace}/_stack.md", file=sys.stderr)
        print(f"Seeded {len(res.candidate_files)} candidate entrypoint files and "
              f"{len(res.trace_targets)} logic-layer trace targets into "
              f"{res.workspace}/inventory/_entrypoints.md", file=sys.stderr)
        print(f"Methodology: {res.workspace}/METHODOLOGY.md", file=sys.stderr)
        print(
            "This command sets up the review, it does not find anything itself. Next, have an "
            f"interactive agent follow {res.workspace}/METHODOLOGY.md to run the review, or use the "
            "/codejury-review-repo command in Claude Code or Codex. The agent proposes findings in "
            f"{res.workspace}/candidates/, finalize confirms them into {res.workspace}/findings/."
        )
        return 0

    if args.command == "install-slash-command":
        slash_command_file = get_domain(args.domain).paths.slash_command_file
        agent_dirs = {
            "claude": Path.home() / ".claude" / "commands",
            "codex": Path.home() / ".codex" / "prompts",
        }
        target_dir = Path(args.dir) if args.dir else agent_dirs[args.agent]
        dst = target_dir / "codejury-review-repo.md"
        if dst.exists() and not args.force:
            print(f"{dst} already exists. Re-run with --force to overwrite it.", file=sys.stderr)
            return 1
        target_dir.mkdir(parents=True, exist_ok=True)
        dst.write_text(slash_command_file.read_text(encoding="utf-8"), encoding="utf-8")
        print(f"Installed slash command to {dst}")
        print("Run it in the agent with: /codejury-review-repo <repository>")
        return 0

    if args.command == "review":
        print("usage: codejury review {diff,repo} ...", file=sys.stderr)
        print("  diff   audit a unified diff for security findings", file=sys.stderr)
        print("  repo   scaffold a whole-repo review for an interactive agent", file=sys.stderr)
        return 1

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
