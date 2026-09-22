"""Learn and commit the OT behaviour baseline.

The behaviour baseline is the learned "normal" for the OT network: which assets
exist, which pairs talk, and which protocol function codes each service uses. It
is built from normalized contract events (the collector's output) and committed,
so the deviation rules in ``rules/baseline`` have a fixed reference and the
baseline can only change by an explicit, reviewable commit.
"""
