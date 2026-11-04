# Held-out evaluation set

The fixtures beside each rule are a regression check, not a measurement: they
were written with the rule and tuned until they passed. This directory holds a
second, labeled set that is **not** used to tune the rules, so the metrics layer
can report per-rule precision and recall on something closer to an honest
sample.

## Files

| File | Contents | Labels |
| :--- | :--- | :--- |
| `positives.jsonl` | 48 events, 2 per single-event Sigma rule | `rule` is the rule the event must fire |
| `negatives.jsonl` | 1,000 generated benign events, seed `20260202` | none; every rule must stay silent |
| `near-misses.jsonl` | 24 events, 1 per single-event rule | none; each differs from its rule in the decisive field |
| `windows.jsonl` | 26 correlation windows (12 positive, 14 negative) across six rules | `expect` is `match` or `no_match` |

The negatives come from `tools/make_benign.py` with a **different seed** than the
tuning corpus (`20260101`), plus one authored near miss per rule (1,024 events
per rule in total). The generator draws approved hosts, registers,
volumes and session ids from a seeded RNG and shifts the clock by the seed, so
the two corpora share no event. `tests/test_heldout.py` enforces that.

The near misses are the part that makes precision meaningful: a rule that has
gone too broad usually still passes the generated corpus, but fires on the event
that is one field away from its condition.

## Metrics

For each single-event rule:

- `TP` — held-out positives the rule fires on.
- `FN` — held-out positives it does not fire on.
- `FP` — held-out negatives it fires on.
- `TN` — held-out negatives it stays silent on.
- `precision = TP / (TP + FP)`, `recall = TP / (TP + FN)`.
- `false_positive_rate = FP / (FP + TN)`.

Every rate carries a 95% Wilson score interval. The interval is based on the
`TP + FP` denominator for precision and `TP + FN` for recall, so a rule with two
positives has a wide interval by construction. That is the honest result, not a
defect in the harness. The aggregate row pools all rules and is the number to
quote for the ruleset as a whole.

Correlation rules are measured on windows, so their precision and recall are
window-level and are reported separately from the event-level table.

## What this does not prove

- The positives are authored, not captured in the field. They test that each
  rule fires on a fresh instance of the behaviour it targets, not that it
  catches every variant.
- The negatives are generated normal operation, not plant traffic. They bound
  false positives against modelled behaviour; they do not estimate field
  false-positive volume.
- The correlation set has two positive windows per rule, so its per-rule
  interval is wide even though the aggregate is tighter.
- A rule that fires on a near miss is reported, not hidden. The point of the
  set is to surface that, not to make the table green.
