"""codejury.sources -- where code to audit comes from.

Agents never read files directly; they receive CodeArtifacts from a Source. This
keeps the "any input" axis (diff / file / repo / function) independent from the
rest of the framework.
"""
