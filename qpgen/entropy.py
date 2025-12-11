"""
Entropy amplifier:
Takes raw quantum bits and amplifies/mixes them using a cryptographic hash.
"""

from __future__ import annotations

import hashlib
from typing import List


def bits_to_bytes(bits: List[int]) -> bytes:
    """
    Pack a list of bits [0,1,1,0,...] into bytes (8 bits per byte).
    If bits length is not a multiple of 8, pad with zeros at the end.
    """
    if not bits:
        return b""

    # Pad to multiple of 8
    pad_len = (8 - (len(bits) % 8)) % 8
    bits_padded = bits + [0] * pad_len

    byte_values = []
    for i in range(0, len(bits_padded), 8):
        byte = 0
        for bit in bits_padded[i : i + 8]:
            byte = (byte << 1) | bit
        byte_values.append(byte)

    return bytes(byte_values)


def bytes_to_bits(data: bytes) -> List[int]:
    """
    Convert bytes back into a list of bits (0/1).
    """
    out_bits: List[int] = []
    for byte in data:
        for i in range(8):
            # Extract bits from MSB to LSB
            out_bits.append((byte >> (7 - i)) & 1)
    return out_bits


def amplify_entropy(bits: List[int], rounds: int = 1) -> List[int]:
    """
    Apply SHA-256 hashing `rounds` times to amplify and mix entropy.

    Concept:
    - Convert bits → bytes
    - Repeatedly hash with SHA-256
    - Convert final digest bytes back to bits.
    """
    if rounds <= 0:
        return bits

    data = bits_to_bytes(bits)
    for _ in range(rounds):
        data = hashlib.sha256(data).digest()

    return bytes_to_bits(data)
