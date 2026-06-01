"""Static analysis for provenance (P1).

The code-graph / data-flow engine that gives the verifier provenance -- whether a
value reaching a sink is attacker-controlled, sanitized, or a trusted constant.
This is the real fix for the taint precision floor that single-file LLM review
cannot reach (see ROADMAP P1). Python / AST based to start.
"""
