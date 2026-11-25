# Sustained matcher load

Source: `/tmp/opencode/benign-pilot-events.jsonl` (13949 distinct events)

| Target EPS | Processed | Dropped | Achieved EPS | p99 | Max queue |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 4000 | 20000 | 0 (0.000%) | 3999.98 | 10736.522 µs | 72 |
| 20000 | 35103 | 64897 (64.897%) | 5004.56 | 2252786.429 µs | 10000 |

The queue is bounded; a target the matcher cannot sustain shows drops,
not an unbounded queue. This is a single-process Python matcher, not a
production sensor or a pcap replay.
