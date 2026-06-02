"""Static analysis for provenance (P1).

The code-graph / data-flow engine that gives the verifier provenance: whether a
value reaching a sink is attacker-controlled, sanitized, or a trusted constant.
It targets the taint precision floor that single-file LLM review cannot reach,
see ROADMAP P1. Python AST based, currently intra-procedural plus a one-hop
cross-file caller resolution, not yet a full code graph.
"""
