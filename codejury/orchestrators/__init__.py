"""codejury.orchestrators: strategies for running agents over a context.

single, pipeline, debate, reflexion, challenge, taint, and adaptive. The strategy
is the orchestration axis; a task picks one. Each takes the same agents and
context and returns an AnalysisResult, so they are interchangeable.
"""
