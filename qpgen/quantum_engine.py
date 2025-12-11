from __future__ import annotations

"""
Quantum engine: builds a circuit, puts qubits in superposition,
measures them in alternating bases, and returns raw bitstrings.
"""
from typing import List
from qiskit import QuantumCircuit
from qiskit_aer import AerSimulator
from qiskit import transpile

from .config import QuantumPassConfig, DEFAULT_CONFIG


class QuantumEngine:
    """
    Encapsulates all quantum-circuit-related logic.
    """

    def __init__(self, config: QuantumPassConfig | None = None) -> None:
        self.config = config or DEFAULT_CONFIG
        # Local simulator backend.
        self.backend = AerSimulator()

        # Optional metadata storage for GUI / advanced inspection.
        self.last_raw_bits: list[int] | None = None
        self.last_measurement_basis: list[str] | None = None
        self.last_circuit: QuantumCircuit | None = None

        # Safety: ensure requested num_qubits does not exceed backend capability.
        backend_cfg = self.backend.configuration()
        max_qubits = getattr(backend_cfg, "num_qubits", None)

        if max_qubits is not None and self.config.num_qubits > max_qubits:
            raise ValueError(
                f"Configured num_qubits={self.config.num_qubits} exceeds "
                f"backend limit ({max_qubits}). "
                "Lower num_qubits in QuantumPassConfig."
            )

    def _build_circuit(self) -> tuple[QuantumCircuit, list[str]]:

        """
        Prepare N qubits, put them in superposition, then measure
        in alternating bases (Z, X, Z, X, …).
        """
        n = self.config.num_qubits
        # Track which basis each qubit will be measured in: "Z" or "X"
        measurement_basis: list[str] = []

        # Create a circuit with n qubits and n classical bits
        qc = QuantumCircuit(n, n)

        # 1) Put all qubits into superposition with H gate.
        for i in range(n):
            qc.h(i)

        # 2) Alternate measurement basis:
        #    - even index (0,2,4...): measure in Z basis directly.
        #    - odd index (1,3,5...): apply H again → measure in X basis.
        for i in range(n):
            if i % 2 == 1:
                # Odd indices: measure in X-basis (apply extra H)
                measurement_basis.append("X")
                qc.h(i)
            else:
                # Even indices: measure in Z-basis (computational)
                measurement_basis.append("Z")
            qc.measure(i, i)

        return qc, measurement_basis


    def get_raw_bits_with_meta(self) -> tuple[list[int], list[str], QuantumCircuit]:
        """
        Run the quantum circuit once and return:
        - list of bits (0/1)
        - list of measurement bases per qubit: "Z" or "X"
        """
        qc, measurement_basis = self._build_circuit()

        # Transpile for the simulator backend
        tqc = transpile(qc, self.backend)

        # Run with a single shot: one random outcome
        result = self.backend.run(tqc, shots=1).result()
        counts = result.get_counts()

        # counts is a dict like {'0101...': 1}
        # Extract the only key.
        bitstring = next(iter(counts.keys()))

        # Qiskit orders bits as [q_(n-1) ... q_0]; reverse so index 0 is first qubit.
        bitstring = bitstring[::-1]

        bits = [int(b) for b in bitstring]

        # Remember for any caller that wants to inspect later.
        self.last_raw_bits = bits
        self.last_measurement_basis = measurement_basis
        self.last_circuit = qc

        return bits, measurement_basis, qc

    def get_raw_bits(self) -> list[int]:
        """
        Compatibility helper: return only the raw bits, without metadata.
        """
        bits, _basis, _circuit = self.get_raw_bits_with_meta()
        return bits

