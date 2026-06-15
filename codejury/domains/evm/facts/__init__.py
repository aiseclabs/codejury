"""Deterministic fact backends for the evm domain, behind the codejury[evm] extra.

Importing this package never imports the heavy tools, each backend lazy-checks its own
toolchain, so the domain loads with no optional dependency installed.
"""
