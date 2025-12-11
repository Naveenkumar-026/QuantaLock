"""
Configuration for the Quantum Superposition Password Generator.
"""

from dataclasses import dataclass


@dataclass
class QuantumPassConfig:
    # Number of qubits to prepare in superposition.
    # Each qubit gives one raw bit.
    # NOTE: Keep this <= backend limit (often 20–29 for local simulators).
    num_qubits: int = 20

    # Desired password length in characters.
    password_length: int = 20

    # How many rounds of entropy amplification (hash mixing) to apply.
    entropy_rounds: int = 2
    quantum_streams: int = 2
    # Alphabet can be any length.
    # Mapping uses 8-bit chunks and modulo into this alphabet.
    alphabet: str = (
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789"
        "!@#$%^&*()-_=+[];:,.<>?/|~"
    )


# Default configuration instance you can import elsewhere
DEFAULT_CONFIG = QuantumPassConfig()
