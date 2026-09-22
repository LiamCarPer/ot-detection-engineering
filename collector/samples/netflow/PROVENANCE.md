# Sample provenance

`flows.json` is a **labelled** NetFlow/IPFIX export written in the shape
`nfdump -o json` (or an IPFIX collector) produces: one record per flow with the
endpoints, ports, protocol, byte and packet counts, duration and flow state.

The lab has no flow exporter on the wire, so this sample is authored in that
shape rather than captured. The adapter (`collector/sources/netflow.py`) is the
same code a real exporter feeds, and the contract is the same one Zeek's
`conn.log` maps to.

To capture real NetFlow:

```bash
softflowd -i eth0 -n 172.24.0.20:2055        # or: nprobe -i eth0 -n 172.24.0.20:2055
nfcapd -w -D -l /flows -p 2055
nfdump -r /flows/nfcapd.current -o json > flows.json
```
