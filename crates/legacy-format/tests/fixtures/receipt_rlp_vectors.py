"""Independent, dependency-free RLP vectors. Run from this directory to regenerate.
Synthetic receipts; intentionally arbitrary stored blooms, not authenticated chain data.
"""
from pathlib import Path

def magnitude(n):
    return n.to_bytes((n.bit_length() + 7) // 8, "big")

def rlp(value):
    if isinstance(value, int):
        value = magnitude(value)
    if isinstance(value, list):
        payload = b"".join(map(rlp, value))
        offset = 0xc0
    else:
        if len(value) == 1 and value[0] < 0x80:
            return value
        payload = value
        offset = 0x80
    if len(payload) < 56:
        return bytes([offset + len(payload)]) + payload
    size = magnitude(len(payload))
    return bytes([offset + 55 + len(size)]) + size + payload

vectors = {
    "receipt_failure_rlp.hex": rlp([0, 0, bytes(256), []]),
    "receipt_state_rlp.hex": rlp([bytes([0x44])*32, 21000, bytes(256), []]),
    "receipt_logs_rlp.hex": rlp([1, 50000, bytes([0x22])*256, [
        [bytes([0x11])*20, [bytes([0x33])*32, bytes(32)], bytes(range(56))],
        [bytes([0x55])*20, [], b""],
    ]]),
}
for name, value in vectors.items():
    Path(__file__).with_name(name).write_text(value.hex() + "\n")
