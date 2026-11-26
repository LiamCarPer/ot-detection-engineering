# Sustained matcher load

Source: `/tmp/opencode/fixed-pilot-events.jsonl` (7497 distinct events)

| Target EPS | Processed | Dropped | Achieved EPS | p99 | Max queue |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 4000 | 20000 | 0 (0.000%) | 3375.22 | 1207040.976 µs | 4113 |
| 20000 | 29184 | 70816 (70.816%) | 3049.55 | 3769432.503 µs | 10000 |

The queue is bounded; a target the matcher cannot sustain shows drops,
not an unbounded queue. This is a single-process Python matcher, not a
production sensor or a pcap replay.
