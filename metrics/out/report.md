# Detection Metrics

| Metric | Value |
| :--- | ---: |
| ATT&CK for ICS coverage | 32/97 (33.0%) |
| Rule fixture agreement (precision) | 1.0 |
| Rule fixture agreement (recall) | 1.0 |
| Fixture false-positive rate | 0.0 |
| Sigma single-event false-positive rate | 0.0 (1000 events, 95% CI 0.0–0.0038) |
| All-family false-positive report | `metrics/out/fpr.md` |
| Held-out single-event precision | 1.0 (0.9336–1.0) |
| Held-out single-event recall | 1.0 (0.9336–1.0) |
| Held-out single-event false-positive rate | 0.0 (0.0–0.0001) (30,720 rule-negative evaluations; 1024 events per rule) |
| Held-out correlation recall | 1.0 (0.7719–1.0) (13 positive windows) |
| Held-out YARA recall | 1.0 (0.6756–1.0) (8 positive artifacts) |
| Emulation detection rate (MTTD run) | 100.0% |
| Mean MTTD | 2.45 s |
| Purple-team replay | 14 / 14 lab alert signals (100.0%) |
| Purple-team unexpected alerts | 0 |
| Purple-team benign window | passed |

The purple-team row is a replay of the lab's alert labels, not an execution of this repository's rules; see `docs/PURPLE_TEAM.md`.

## Rule validation

| Rule | TP | FN | FP | TN | Precision | Recall |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: |
| Detection Service Stopped | 1 | 0 | 0 | 2 | 1.0 | 1.0 |
| DNP3 Request From An Unapproved Master Address | 2 | 0 | 0 | 3 | 1.0 | 1.0 |
| DNP3 Cold Or Warm Restart Command | 2 | 0 | 0 | 2 | 1.0 | 1.0 |
| DNP3 Control Operation From Unauthorized Master | 2 | 0 | 0 | 3 | 1.0 | 1.0 |
| DNP3 Unsolicited Responses Disabled | 1 | 0 | 0 | 2 | 1.0 | 1.0 |
| Enterprise Host Probing Multiple Control Zone Ports | 1 | 0 | 0 | 4 | 1.0 | 1.0 |
| Control Zone Egress To The Enterprise Over A Standard Port | 2 | 0 | 0 | 4 | 1.0 | 1.0 |
| Control Zone Host Reaching Multiple Enterprise Destinations | 1 | 0 | 0 | 3 | 1.0 | 1.0 |
| Industrial Protocol Traffic From Enterprise To Control Zone | 2 | 0 | 0 | 3 | 1.0 | 1.0 |
| Enterprise Host Permitted To Reach A Control Zone Service | 2 | 0 | 0 | 4 | 1.0 | 1.0 |
| Connection Reset To An Industrial Service | 3 | 0 | 0 | 5 | 1.0 | 1.0 |
| Large Transfer From OT To An External Destination | 1 | 0 | 0 | 4 | 1.0 | 1.0 |
| HMI Login Failure | 1 | 0 | 0 | 1 | 1.0 | 1.0 |
| HMI Login Failure Burst From One Source | 1 | 0 | 0 | 2 | 1.0 | 1.0 |
| Suspicious Modbus Client Initiated From An Endpoint | 1 | 0 | 0 | 2 | 1.0 | 1.0 |
| Modbus Block Read From Unauthorized Reader | 1 | 0 | 0 | 6 | 1.0 | 1.0 |
| Modbus Coil Write From Unauthorized Control Writer | 2 | 0 | 0 | 4 | 1.0 | 1.0 |
| Modbus Control Asset Enumeration | 1 | 0 | 0 | 5 | 1.0 | 1.0 |
| Modbus Device Identification Scan | 2 | 0 | 0 | 2 | 1.0 | 1.0 |
| Modbus Exception Flood Toward An Operator Interface | 1 | 0 | 0 | 3 | 1.0 | 1.0 |
| Modbus Exception Response | 2 | 0 | 0 | 2 | 1.0 | 1.0 |
| Modbus Write To Safety Critical Parameter Register | 3 | 0 | 0 | 3 | 1.0 | 1.0 |
| Modbus Process State Read From Unauthorized Source | 2 | 0 | 0 | 5 | 1.0 | 1.0 |
| Modbus Register Enumeration From One Host | 1 | 0 | 0 | 4 | 1.0 | 1.0 |
| Modbus Write From Unauthorized Control Writer | 2 | 0 | 0 | 4 | 1.0 | 1.0 |
| OPC UA Address Space Browse | 2 | 0 | 0 | 4 | 1.0 | 1.0 |
| OPC UA Method Call Request | 1 | 0 | 0 | 4 | 1.0 | 1.0 |
| OPC UA Address Space Enumeration | 1 | 0 | 0 | 3 | 1.0 | 1.0 |
| OPC UA Write Request | 1 | 0 | 0 | 5 | 1.0 | 1.0 |
| PLC Logic Integrity Verification Failed | 1 | 0 | 0 | 1 | 1.0 | 1.0 |
| Process Safety Violation From Physics-Aware Monitor | 2 | 0 | 0 | 3 | 1.0 | 1.0 |
| S7comm PLC Control Or Stop | 2 | 0 | 0 | 2 | 1.0 | 1.0 |
| S7comm Program Download | 2 | 0 | 0 | 2 | 1.0 | 1.0 |
| S7comm Program Upload | 2 | 0 | 0 | 2 | 1.0 | 1.0 |
| OT Device Configuration Change | 1 | 0 | 0 | 2 | 1.0 | 1.0 |
| OT Device Restart | 1 | 0 | 0 | 2 | 1.0 | 1.0 |
| Network Interface Down On An OT Device | 1 | 0 | 0 | 2 | 1.0 | 1.0 |

## Held-out single-event rules

54 labeled positives against 1024 held-out negatives (generated from a different seed than the tuning corpus, plus one near miss per rule).

| Rule | Pos | Neg | TP | FN | FP | TN | Precision (95% CI) | Recall (95% CI) | FP rate (95% CI) |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Detection Service Stopped | 1 | 1024 | 1 | 0 | 0 | 1024 | 1.0 (0.2065–1.0) | 1.0 (0.2065–1.0) | 0.0 (0.0–0.0037) |
| DNP3 Request From An Unapproved Master Address | 2 | 1024 | 2 | 0 | 0 | 1024 | 1.0 (0.3424–1.0) | 1.0 (0.3424–1.0) | 0.0 (0.0–0.0037) |
| DNP3 Cold Or Warm Restart Command | 2 | 1024 | 2 | 0 | 0 | 1024 | 1.0 (0.3424–1.0) | 1.0 (0.3424–1.0) | 0.0 (0.0–0.0037) |
| DNP3 Control Operation From Unauthorized Master | 2 | 1024 | 2 | 0 | 0 | 1024 | 1.0 (0.3424–1.0) | 1.0 (0.3424–1.0) | 0.0 (0.0–0.0037) |
| DNP3 Unsolicited Responses Disabled | 2 | 1024 | 2 | 0 | 0 | 1024 | 1.0 (0.3424–1.0) | 1.0 (0.3424–1.0) | 0.0 (0.0–0.0037) |
| Control Zone Egress To The Enterprise Over A Standard Port | 2 | 1024 | 2 | 0 | 0 | 1024 | 1.0 (0.3424–1.0) | 1.0 (0.3424–1.0) | 0.0 (0.0–0.0037) |
| Industrial Protocol Traffic From Enterprise To Control Zone | 2 | 1024 | 2 | 0 | 0 | 1024 | 1.0 (0.3424–1.0) | 1.0 (0.3424–1.0) | 0.0 (0.0–0.0037) |
| Enterprise Host Permitted To Reach A Control Zone Service | 2 | 1024 | 2 | 0 | 0 | 1024 | 1.0 (0.3424–1.0) | 1.0 (0.3424–1.0) | 0.0 (0.0–0.0037) |
| Connection Reset To An Industrial Service | 2 | 1024 | 2 | 0 | 0 | 1024 | 1.0 (0.3424–1.0) | 1.0 (0.3424–1.0) | 0.0 (0.0–0.0037) |
| Large Transfer From OT To An External Destination | 2 | 1024 | 2 | 0 | 0 | 1024 | 1.0 (0.3424–1.0) | 1.0 (0.3424–1.0) | 0.0 (0.0–0.0037) |
| HMI Login Failure | 1 | 1024 | 1 | 0 | 0 | 1024 | 1.0 (0.2065–1.0) | 1.0 (0.2065–1.0) | 0.0 (0.0–0.0037) |
| Suspicious Modbus Client Initiated From An Endpoint | 1 | 1024 | 1 | 0 | 0 | 1024 | 1.0 (0.2065–1.0) | 1.0 (0.2065–1.0) | 0.0 (0.0–0.0037) |
| Modbus Block Read From Unauthorized Reader | 1 | 1024 | 1 | 0 | 0 | 1024 | 1.0 (0.2065–1.0) | 1.0 (0.2065–1.0) | 0.0 (0.0–0.0037) |
| Modbus Coil Write From Unauthorized Control Writer | 1 | 1024 | 1 | 0 | 0 | 1024 | 1.0 (0.2065–1.0) | 1.0 (0.2065–1.0) | 0.0 (0.0–0.0037) |
| Modbus Device Identification Scan | 2 | 1024 | 2 | 0 | 0 | 1024 | 1.0 (0.3424–1.0) | 1.0 (0.3424–1.0) | 0.0 (0.0–0.0037) |
| Modbus Exception Response | 2 | 1024 | 2 | 0 | 0 | 1024 | 1.0 (0.3424–1.0) | 1.0 (0.3424–1.0) | 0.0 (0.0–0.0037) |
| Modbus Write To Safety Critical Parameter Register | 2 | 1024 | 2 | 0 | 0 | 1024 | 1.0 (0.3424–1.0) | 1.0 (0.3424–1.0) | 0.0 (0.0–0.0037) |
| Modbus Process State Read From Unauthorized Source | 2 | 1024 | 2 | 0 | 0 | 1024 | 1.0 (0.3424–1.0) | 1.0 (0.3424–1.0) | 0.0 (0.0–0.0037) |
| Modbus Write From Unauthorized Control Writer | 2 | 1024 | 2 | 0 | 0 | 1024 | 1.0 (0.3424–1.0) | 1.0 (0.3424–1.0) | 0.0 (0.0–0.0037) |
| OPC UA Address Space Browse | 2 | 1024 | 2 | 0 | 0 | 1024 | 1.0 (0.3424–1.0) | 1.0 (0.3424–1.0) | 0.0 (0.0–0.0037) |
| OPC UA Method Call Request | 2 | 1024 | 2 | 0 | 0 | 1024 | 1.0 (0.3424–1.0) | 1.0 (0.3424–1.0) | 0.0 (0.0–0.0037) |
| OPC UA Write Request | 2 | 1024 | 2 | 0 | 0 | 1024 | 1.0 (0.3424–1.0) | 1.0 (0.3424–1.0) | 0.0 (0.0–0.0037) |
| PLC Logic Integrity Verification Failed | 1 | 1024 | 1 | 0 | 0 | 1024 | 1.0 (0.2065–1.0) | 1.0 (0.2065–1.0) | 0.0 (0.0–0.0037) |
| Process Safety Violation From Physics-Aware Monitor | 2 | 1024 | 2 | 0 | 0 | 1024 | 1.0 (0.3424–1.0) | 1.0 (0.3424–1.0) | 0.0 (0.0–0.0037) |
| S7comm PLC Control Or Stop | 2 | 1024 | 2 | 0 | 0 | 1024 | 1.0 (0.3424–1.0) | 1.0 (0.3424–1.0) | 0.0 (0.0–0.0037) |
| S7comm Program Download | 2 | 1024 | 2 | 0 | 0 | 1024 | 1.0 (0.3424–1.0) | 1.0 (0.3424–1.0) | 0.0 (0.0–0.0037) |
| S7comm Program Upload | 2 | 1024 | 2 | 0 | 0 | 1024 | 1.0 (0.3424–1.0) | 1.0 (0.3424–1.0) | 0.0 (0.0–0.0037) |
| OT Device Configuration Change | 2 | 1024 | 2 | 0 | 0 | 1024 | 1.0 (0.3424–1.0) | 1.0 (0.3424–1.0) | 0.0 (0.0–0.0037) |
| OT Device Restart | 2 | 1024 | 2 | 0 | 0 | 1024 | 1.0 (0.3424–1.0) | 1.0 (0.3424–1.0) | 0.0 (0.0–0.0037) |
| Network Interface Down On An OT Device | 2 | 1024 | 2 | 0 | 0 | 1024 | 1.0 (0.3424–1.0) | 1.0 (0.3424–1.0) | 0.0 (0.0–0.0037) |
| **All single-event rules** | 54 | 1024 each | 54 | 0 | 0 | 30720 | 1.0 (0.9336–1.0) | 1.0 (0.9336–1.0) | 0.0 (0.0–0.0001) |

## Held-out correlation rules

13 positive windows against 15 negative windows.

| Rule | Pos | Neg | TP | FN | FP | TN | Precision (95% CI) | Recall (95% CI) |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Enterprise Host Probing Multiple Control Zone Ports | 2 | 2 | 2 | 0 | 0 | 2 | 1.0 (0.3424–1.0) | 1.0 (0.3424–1.0) |
| Control Zone Host Reaching Multiple Enterprise Destinations | 2 | 2 | 2 | 0 | 0 | 2 | 1.0 (0.3424–1.0) | 1.0 (0.3424–1.0) |
| HMI Login Failure Burst From One Source | 1 | 1 | 1 | 0 | 0 | 1 | 1.0 (0.2065–1.0) | 1.0 (0.2065–1.0) |
| Modbus Control Asset Enumeration | 2 | 4 | 2 | 0 | 0 | 4 | 1.0 (0.3424–1.0) | 1.0 (0.3424–1.0) |
| Modbus Exception Flood Toward An Operator Interface | 2 | 2 | 2 | 0 | 0 | 2 | 1.0 (0.3424–1.0) | 1.0 (0.3424–1.0) |
| Modbus Register Enumeration From One Host | 2 | 2 | 2 | 0 | 0 | 2 | 1.0 (0.3424–1.0) | 1.0 (0.3424–1.0) |
| OPC UA Address Space Enumeration | 2 | 2 | 2 | 0 | 0 | 2 | 1.0 (0.3424–1.0) | 1.0 (0.3424–1.0) |
| **All correlation rules** | 13 | 15 | 13 | 0 | 0 | 15 | 1.0 (0.7719–1.0) | 1.0 (0.7719–1.0) |

## Held-out YARA rules

8 labeled artifacts against 8 shared negative artifacts.

| Rule | Pos | Neg | TP | FN | FP | TN | Precision (95% CI) | Recall (95% CI) |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| OT_Macro_Document_With_Embedded_PE | 2 | 8 | 2 | 0 | 0 | 8 | 1.0 (0.3424–1.0) | 1.0 (0.3424–1.0) |
| OT_PowerShell_Dropper_On_EWS | 2 | 8 | 2 | 0 | 0 | 8 | 1.0 (0.3424–1.0) | 1.0 (0.3424–1.0) |
| OT_S7_Firmware_With_Embedded_PE | 2 | 8 | 2 | 0 | 0 | 8 | 1.0 (0.3424–1.0) | 1.0 (0.3424–1.0) |
| OT_Siemens_Project_File_With_Embedded_PE | 2 | 8 | 2 | 0 | 0 | 8 | 1.0 (0.3424–1.0) | 1.0 (0.3424–1.0) |
| **All YARA rules** | 8 | 8 | 8 | 0 | 0 | 32 | 1.0 (0.6756–1.0) | 1.0 (0.6756–1.0) |

## Baseline

0 of 1000 benign events matched a rule.
95% Wilson interval on the false-positive rate: 0.0–0.0038.
