"""codejury.orchestrators -- strategies for running agents over a context.

single / debate / pipeline / reflexion. The strategy is the "any orchestration"
axis; a task picks one. Each takes the same agents and context and returns an
AnalysisResult, so they are interchangeable.
"""
