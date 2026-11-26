# Sustained matcher load

Source: `deploy/evidence/load/corpus.jsonl` (7497 distinct events)

| Target EPS | Processed | Dropped | Achieved EPS | p99 | Max queue |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 4000 | 20000 | 0 (0.000%) | 3512.09 | 974996.716 µs | 3625 |
| 20000 | 24839 | 75161 (75.161%) | 3035.76 | 3683689.4 µs | 10000 |

The queue is bounded; a target the matcher cannot sustain shows drops,
not an unbounded queue. This is a single-process Python matcher, not a
production sensor or a pcap replay.
