# ATT&CK mapping notes

The catalogue pins ATT&CK for ICS. Two mappings need a written justification
because the nearest ICS technique is broader than the behaviour:

| Detection | Tag | Why |
| :-- | :-- | :-- |
| HMI login failure / burst | T0859 Valid Accounts | ATT&CK for ICS has no authentication brute-force technique. Failed authentication is the precursor to Valid Accounts, so T0859 is used as a coverage annotation, not as a claim that an account was obtained. With the enterprise matrix, T1110 Brute Force is more precise. |
| Large transfer from the historian | T0811 Data from Information Repositories | The rule sees a flow volume and direction, not a repository read. The tag marks the collection path the flow could serve. |

A tag is not evidence. `coverage/out/attack_ics_coverage.json` counts the
techniques the catalogue claims; the rule tests and the lab evidence are what
show the behaviour fires. Where a rule only sees the transport, the mapping says
so rather than upgrading the tag to a technique the sensor cannot observe.

## Review trigger

Review a mapping when a rule's visibility changes (a new parser exposes the
actual operation), when ATT&CK for ICS adds a closer technique, or when the
enterprise matrix is adopted alongside ICS. A tag that cannot be defended in one
sentence should be removed, not widened.
