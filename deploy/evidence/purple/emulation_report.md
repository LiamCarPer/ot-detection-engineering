# Adversary Emulation Results

Plan: Water treatment OT emulation

- Expectations: 14 / 14 detected (100.0%)
- Mean MTTD: n/a s
- Unexpected alerts in step windows: 0
- Benign window: passed (0 alert(s))

| Step | Technique | Signal | Detected | MTTD (s) |
| :--- | :--- | :--- | :--- | ---: |
| Enterprise host reaches the control zone | T0886 | CROSS_ZONE_VIOLATION | yes |  |
| Enterprise host writes a Modbus register | T1692.001 | UNAUTHORIZED_MODBUS_WRITE | yes |  |
| Modbus exception burst | T0806 | OT_BRUTE_FORCE_SCAN | yes |  |
| Unsafe command while the process is in a danger state | T0831 | PROCESS_SAFETY_VIOLATION | yes |  |
| DNP3 control, restart and unsolicited-response changes | T1692.001 | DNP3_UNAUTHORIZED_CONTROL | yes |  |
| DNP3 control, restart and unsolicited-response changes | T0816 | DNP3_RESTART_COMMAND | yes |  |
| DNP3 control, restart and unsolicited-response changes | T0878 | DNP3_UNSOLICITED_DISABLED | yes |  |
| OPC UA browse, write and method call | T0888 | OPCUA_BROWSE_REQUEST | yes |  |
| OPC UA browse, write and method call | T1692.001 | OPCUA_WRITE_REQUEST | yes |  |
| OPC UA browse, write and method call | T0871 | OPCUA_METHOD_CALL | yes |  |
| S7comm program download, upload and mode change | T0843 | S7COMM_PROGRAM_DOWNLOAD | yes |  |
| S7comm program download, upload and mode change | T0845 | S7COMM_PROGRAM_UPLOAD | yes |  |
| S7comm program download, upload and mode change | T0858 | S7COMM_CHANGE_OPERATING_MODE | yes |  |
| PowerShell Modbus write from the operator workstation | T1692.001 | UNAUTHORIZED_MODBUS_WRITE | yes |  |
