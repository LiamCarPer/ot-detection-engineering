"""Generate small PCAPs that exercise the native protocol rules.

Functional validation needs traffic, and the repository ships its own so the
proof is reproducible without a live plant. Each capture is a benign and an
attack variant for Modbus, DNP3, OPC UA and S7comm. Sessions include a full TCP
handshake so Suricata treats them as established flows, which the
``flow:to_server,established`` rules require.

The DNP3 frames use the same CRC-16/DNP as tools/dnp3-dpi (the Rust decoder),
pinned to the standard check value ``0xEA82``.

Usage:
    python tools/make_captures.py --out tests/captures
"""

from __future__ import annotations

import argparse
from pathlib import Path

from scapy.all import IP, TCP, Ether, Packet, Raw, wrpcap

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUT = REPO_ROOT / "tests" / "captures"

CLIENT_MAC = "02:00:00:00:00:01"
SERVER_MAC = "02:00:00:00:00:02"

# Lab addressing, aligned with the Suricata rule allowlists.
HMI = "172.21.0.20"          # authorized control writer / master / client
ATTACKER = "172.24.0.10"     # unauthorized
MODBUS_PLC = "172.21.0.10"
DNP3_OUTSTATION = "172.31.0.10"
OPCUA_SERVER = "172.31.0.10"
S7_PLC = "172.21.0.10"


def crc_dnp(data: bytes) -> int:
    """CRC-16/DNP, mirroring tools/dnp3-dpi/src/crc.rs."""
    crc = 0
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA6BC if crc & 1 else crc >> 1
    return (~crc) & 0xFFFF


def modbus_request(transaction: int, unit: int, function: int, data: bytes) -> bytes:
    pdu = bytes([function]) + data
    header = transaction.to_bytes(2, "big") + b"\x00\x00" + (len(pdu) + 1).to_bytes(2, "big")
    return header + bytes([unit]) + pdu


def dnp3_frame(control: int, destination: int, source: int, user_data: bytes) -> bytes:
    header = (
        bytes([0x05, 0x64, 5 + len(user_data), control])
        + destination.to_bytes(2, "little")
        + source.to_bytes(2, "little")
    )
    frame = header + crc_dnp(header).to_bytes(2, "little")
    for index in range(0, len(user_data), 16):
        block = user_data[index : index + 16]
        frame += block + crc_dnp(block).to_bytes(2, "little")
    return frame


def dnp3_application(function: int, objects: bytes = b"", response_iin: int | None = None) -> bytes:
    transport = 0xC0  # FIR + FIN, sequence 0
    application = 0xC0  # FIR + FIN, sequence 0
    body = bytes([application, function])
    if response_iin is not None:
        body += response_iin.to_bytes(2, "little")
    return bytes([transport]) + body + objects


CROB = bytes([12, 1, 0x17, 0, 0, 0, 0, 3])  # group 12 var 1, one CROB, LATCH_ON
BINARY_INPUT_READ = bytes([1, 0, 0x06])       # group 1 var 0, all objects
DEVICE_ATTRIBUTE_READ = bytes([0, 0, 0x06])   # group 0 var 0, all objects


def tcp_session(
    client: str,
    client_port: int,
    server: str,
    server_port: int,
    client_payloads: list[bytes],
    server_payloads: list[bytes] | None = None,
) -> list[Packet]:
    """Build a complete TCP session with a handshake, data and teardown."""
    server_payloads = server_payloads or []
    seq_c, seq_s = 1000, 5000
    packets: list[Packet] = []

    def add(src: str, dst: str, sport: int, dport: int, flags: str, seq: int, ack: int,
            payload: bytes = b"") -> None:
        src_mac, dst_mac = (CLIENT_MAC, SERVER_MAC) if src == client else (SERVER_MAC, CLIENT_MAC)
        packet = (
            Ether(src=src_mac, dst=dst_mac)
            / IP(src=src, dst=dst)
            / TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=ack)
        )
        if payload:
            packet = packet / Raw(load=payload)
        packets.append(packet)

    add(client, server, client_port, server_port, "S", seq_c, 0)
    add(server, client, server_port, client_port, "SA", seq_s, seq_c + 1)
    add(client, server, client_port, server_port, "A", seq_c + 1, seq_s + 1)
    ack_c, ack_s = seq_c + 1, seq_s + 1

    for payload in client_payloads:
        add(client, server, client_port, server_port, "PA", ack_c, ack_s, payload)
        ack_c += len(payload)
        add(server, client, server_port, client_port, "A", ack_s, ack_c)
    for payload in server_payloads:
        add(server, client, server_port, client_port, "PA", ack_s, ack_c, payload)
        ack_s += len(payload)
        add(client, server, client_port, server_port, "A", ack_c, ack_s)

    add(client, server, client_port, server_port, "FA", ack_c, ack_s)
    add(server, client, server_port, client_port, "FA", ack_s, ack_c + 1)
    add(client, server, client_port, server_port, "A", ack_c + 1, ack_s + 1)
    return packets


def modbus_sessions(attacker: bool) -> list[Packet]:
    source = ATTACKER if attacker else HMI
    sessions = [
        tcp_session(
            source,
            41000,
            MODBUS_PLC,
            502,
            [modbus_request(1, 1, 6, b"\x04\x00\x00\x01")],
            [modbus_request(1, 1, 6, b"\x04\x00\x00\x01")],
        ),
        tcp_session(
            source,
            41001,
            MODBUS_PLC,
            502,
            [modbus_request(2, 1, 16, b"\x01\x00\x00\x01\x02\x00\x01")],
            [modbus_request(2, 1, 16, b"\x01\x00\x00\x01")],
        ),
    ]
    if not attacker:
        sessions.append(
            tcp_session(
                source,
                41002,
                MODBUS_PLC,
                502,
                [modbus_request(3, 1, 3, b"\x00\x00\x00\x0a")],
                [modbus_request(3, 1, 3, b"\x14" + b"\x00" * 20)],
            )
        )
    else:
        # A write far above any plausible register map, which the brute-force
        # rule matches on the address.
        sessions.append(
            tcp_session(
                source,
                41010,
                MODBUS_PLC,
                502,
                [modbus_request(200, 1, 6, b"\xc3\x50\x00\x01")],  # address 50000
                [modbus_request(200, 1, 6, b"\xc3\x50\x00\x01")],
            )
        )
    return [packet for session in sessions for packet in session]


def dnp3_sessions(attacker: bool) -> list[Packet]:
    source = ATTACKER if attacker else HMI
    link_source = 7 if attacker else 1
    if attacker:
        functions = [
            dnp3_application(3, CROB),                   # select
            dnp3_application(4, CROB),                   # operate
            dnp3_application(5, CROB),                   # direct operate
            dnp3_application(6, CROB),                   # direct operate no ack
            dnp3_application(2, bytes([10, 2, 0x17, 0, 0, 0, 0, 1])),  # write
            dnp3_application(1, DEVICE_ATTRIBUTE_READ),  # device attribute scan
            dnp3_application(21),                        # disable unsolicited
            dnp3_application(13),                        # cold restart
            dnp3_application(14),                        # warm restart
        ]
    else:
        functions = [dnp3_application(1, BINARY_INPUT_READ)]
    payloads = [dnp3_frame(0x44, 1, link_source, body) for body in functions]
    session = tcp_session(source, 42000, DNP3_OUTSTATION, 20000, payloads)
    return session


def opcua_sessions(attacker: bool) -> list[Packet]:
    source = ATTACKER if attacker else HMI
    # HEL and OPN message headers; Suricata matches on the 3-byte message type.
    hel = b"HEL" + b"F" + (28).to_bytes(4, "little") + b"\x00" * 20
    opn = b"OPN" + b"F" + (24).to_bytes(4, "little") + b"\x00" * 16
    return tcp_session(source, 43000, OPCUA_SERVER, 4840, [hel, opn])


def s7comm_job(function: int, extra_params: bytes = b"", data: bytes = b"") -> bytes:
    """Build a TPKT/COTP/S7comm job with the function code at offset 17."""
    params = bytes([function]) + extra_params
    s7 = (
        bytes([0x32, 0x01, 0x00, 0x00, 0x00, 0x01])
        + len(params).to_bytes(2, "big")
        + len(data).to_bytes(2, "big")
        + params
        + data
    )
    cotp = bytes([0x02, 0xF0, 0x80])  # COTP DT
    total = 4 + len(cotp) + len(s7)
    return bytes([0x03, 0x00]) + total.to_bytes(2, "big") + cotp + s7


def s7comm_sessions(attacker: bool) -> list[Packet]:
    source = ATTACKER if attacker else HMI
    if attacker:
        # Download, upload, PLC control/stop and an unauthorized write.
        functions = [0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x28, 0x29, 0x05]
    else:
        # Setup communication and a read: normal engineering traffic.
        functions = [0xF0, 0x04]
    payloads = [s7comm_job(function) for function in functions]
    return tcp_session(source, 44000, S7_PLC, 102, payloads)


def build_captures() -> dict[str, list[Packet]]:
    captures = {
        "modbus_benign.pcap": modbus_sessions(attacker=False),
        "modbus_attack.pcap": modbus_sessions(attacker=True),
        "dnp3_benign.pcap": dnp3_sessions(attacker=False),
        "dnp3_attack.pcap": dnp3_sessions(attacker=True),
        "opcua_benign.pcap": opcua_sessions(attacker=False),
        "opcua_attack.pcap": opcua_sessions(attacker=True),
        "s7comm_benign.pcap": s7comm_sessions(attacker=False),
        "s7comm_attack.pcap": s7comm_sessions(attacker=True),
    }
    for packets in captures.values():
        for index, packet in enumerate(packets):
            packet.time = 1_700_000_000 + index * 0.001
    return captures


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", default=str(DEFAULT_OUT))
    args = parser.parse_args(argv)

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    for name, packets in sorted(build_captures().items()):
        wrpcap(str(out_dir / name), packets)
        print(f"wrote {out_dir / name} ({len(packets)} packets)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
