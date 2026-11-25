# Lab benign capture

Capture: `/media/liamcarvajal/Storage/code/ot-security-lab/detection/logs/benign-pilot-10m.pcap`  
SHA-256: `5eeedf309d35714925a9b49c2d6999880649b918c4600a1afd7103cf2c111f17`  
Size: 7,366,183 bytes  
Window: 2026-11-25T03:45:31.738057+00:00 to 2026-11-25T03:55:00.410424+00:00 (0.16 h)  
Normalized events: 13,949 (88304.62 / h)

| Family | Result |
| :-- | :-- |
| Sigma single-event | 0 / 13949 events |
| Sigma correlation | 0 fired |
| Behaviour baseline | 0 events |
| Conduit | 0 events |
| Stateful | 0 fired |
| Native Suricata | 0 alerts |
| Host/auth/PLC/health | not observed in a network capture |

## Native alerts

- none

## Rules with any match

- none

This is real lab background traffic, not a plant. Host, auth, PLC and
health families are measured on their own committed samples, not here.
