"""codejury.agents -- the audit roles (finder / challenger / judge / verifier).

An agent reads an AnalysisContext and emits observations. It talks to a model
only through a Provider, never a vendor SDK, so the role logic stays independent
of the backend.
"""
