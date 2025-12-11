"""
Mapping logic: Convert a bitstream into an alphanumeric (or custom) password.
"""

from __future__ import annotations

import math
from typing import List

from .config import QuantumPassConfig, DEFAULT_CONFIG


def bits_to_password(
    bits: List[int],
    config: QuantumPassConfig | None = None,
) -> str:
    """
    Turn a list of bits into a password string using the configured alphabet.

    We:
    - Use 8 bits per character.
    - Group bits into 8-bit chunks.
    - Interpret each chunk as an integer and map it into the alphabet with modulo.
    - Truncate to the desired password length.
    """

    cfg = config or DEFAULT_CONFIG
    alphabet = cfg.alphabet
    alphabet_size = len(alphabet)

    bits_per_char = 8

    needed_bits = cfg.password_length * bits_per_char
    if len(bits) < needed_bits:
        # Not enough bits: simple fallback, repeat the stream.
        # (You can also re-run the quantum engine instead if you want.)
        repeats = (needed_bits + len(bits) - 1) // len(bits)
        bits = (bits * repeats)[:needed_bits]
    else:
        bits = bits[:needed_bits]

    password_chars: list[str] = []

    for i in range(0, needed_bits, bits_per_char):
        chunk = bits[i : i + bits_per_char]

        # Convert chunk bits → integer index
        value = 0
        for bit in chunk:
            value = (value << 1) | bit

        password_chars.append(alphabet[value % alphabet_size])

    return "".join(password_chars)
