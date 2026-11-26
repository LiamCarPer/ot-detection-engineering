# Sample provenance

`attack.json` and `benign.json` are **labelled** SNMP exports written in the
shape `snmptrapd` (or a poller) produces: one record per trap or poll with the
device, an event type, the OID, the value and a severity.

These original fixtures are authored in that shape. A real net-snmp switch and
poller were added to the lab for the 0.5-hour protocol window; the adapter
consumes both the fixtures and the live JSONL.

To capture real traps:

```bash
snmptrapd -f -Lo -M /usr/share/snmp/mibs -m ALL -p 162
# or poll a device and emit JSON:
snmpwalk -v2c -c public 172.21.0.10 1.3.6.1.6.3.1.1.5
```

`attack.json` carries a device restart, an interface-down trap and a
configuration-change notification; `benign.json` carries a link-up and a
heartbeat, which no rule fires on.
