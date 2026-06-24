"""Standard diff audit prompt: the security knowledge lives in data, in a rich
prompt, not in a rendered schema. The focus and do-not-report blocks are the
selected domain's, the default domain's when a caller names none, naming the high-value
classes to hunt and the noise to skip, and the prompt asks for findings as a single JSON object."""

from __future__ import annotations

from codejury.domains.registry import default_domain

SYSTEM = (
    "You are a senior application security engineer reviewing a code change. You "
    "report only real, exploitable, high-confidence vulnerabilities, with a "
    "concrete end-to-end exploit scenario for each. You do not pad the report with "
    "style notes or speculation. Respond with a single JSON object and nothing else."
)

# the default domain's prompt blocks, used when a caller selects no domain
FOCUS = default_domain().diff_focus
DO_NOT_REPORT = default_domain().diff_do_not_report

_JSON_SHAPE = (
    '{"findings": [{"file": "path", "line": 0, "severity": "CRITICAL|HIGH|MEDIUM|LOW", '
    '"category": "<one id from the category set>", "description": "...", '
    '"exploit_scenario": "end to end steps", "recommendation": "...", "confidence": 0.0}]}'
)


def category_block(vulnerabilities_dir=None) -> str:
    """The closed category set the model must choose from, the vulnerability ids.
    Reads the domain's vulnerability classes, defaulting to the web domain."""
    from codejury.review.diff.vulnerabilities import allowed_categories

    cats = allowed_categories() if vulnerabilities_dir is None else allowed_categories(vulnerabilities_dir)
    return (
        "Each finding's `category` must be exactly one of these ids "
        "(use `other` only if none fit):\n" + ", ".join(cats) + "\n\n"
        if cats
        else ""
    )


def standard_audit_prompt(diff: str, *, vulnerabilities: str = "", context: str = "", stack: str = "",
                          vulnerabilities_dir=None, focus: str = FOCUS, do_not_report: str = DO_NOT_REPORT) -> str:
    stack_block = f"Conventions of the target's language/framework:\n{stack}\n\n" if stack else ""
    vulnerabilities_block = f"Relevant vulnerability classes for reference:\n{vulnerabilities}\n\n" if vulnerabilities else ""
    context_block = (
        f"Surrounding code for tracing where values come from (not under review):\n"
        f"```\n{context}\n```\n\n"
        if context
        else ""
    )
    return (
        "Review the following code change for security vulnerabilities.\n\n"
        f"{focus}\n{do_not_report}\n"
        f"{category_block(vulnerabilities_dir)}"
        f"{stack_block}"
        f"{vulnerabilities_block}"
        f"Code change (unified diff):\n```diff\n{diff}\n```\n\n"
        f"{context_block}"
        "Report each real vulnerability with a precise file and line, a concrete "
        "exploit scenario, and a calibrated confidence. If there are none, return an "
        "empty findings list.\n\n"
        "Respond with a single JSON object exactly like:\n" + _JSON_SHAPE
    )
