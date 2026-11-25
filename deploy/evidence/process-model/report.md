# Process mass-balance model

Model, not plant data. The estimator integrates measured inlet and outlet
flow and never reads the PLC's reported level.

| Scenario | Events | Rule detections | Shadow would detect | Max estimated | Max divergence |
| :-- | --: | --: | :--: | --: | --: |
| normal | 120 | 0 | no | 95.5% | 0.0% |
| unsafe | 121 | 1 | yes | 100.0% | 0.0% |
| spoof | 121 | 1 | no | 100.0% | 60.0% |

The spoof row is the point: the reported level is pinned near 40%, so a
monitor that trusts the register stays quiet, while the mass balance
reaches the 90% envelope and the rule fires.

## Limits

- A two-flow tank model, not a plant. Flow transmitters, density and
  geometry are simplified.
- The estimator's constants must be calibrated per tank; a wrong capacity
  shows up as drift, not as a spoof.
- Offline model evidence; the live lab run is separate.
