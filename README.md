# QuantaLock
### *Quantum-Seeded Password Generator & Secure Vault*

![build](https://img.shields.io/badge/build-passing-brightgreen)
![security](https://img.shields.io/badge/security-quantum--grade-purple)
![python](https://img.shields.io/badge/python-3.11%2B-blue)
![platform](https://img.shields.io/badge/platform-offline%20only-critical)
![encryption](https://img.shields.io/badge/encryption-PBKDF2%20%7C%20AES--128-orange)
![license](https://img.shields.io/badge/license-MIT-lightgrey)

QuantaLock is a next-generation security tool that uses real quantum randomness, cryptographic entropy amplification, and device-bound encryption to generate and store ultra-secure passwords.
It combines a quantum simulator, entropy mixing engine, and zero-trust vault into one simple system.

QuantaLock works fully offline and never sends data anywhere.

---

# Key Features

## 1. Quantum-Based Password Generation
QuantaLock prepares qubits in superposition and measures them in alternating bases (Z/X) to produce raw quantum bits.

## 2. Entropy Amplification (SHA-256 Rounds)
Quantum output is mixed and strengthened using SHA-256 hashing.

## 3. Multi-Stream Quantum XOR Mixing
Multiple quantum streams can be XOR-combined to increase unpredictability.

## 4. Secure Vault with Device Binding
Protected by:
- Master password
- Quantum-derived salt (q_salt)
- Device-bound secret & fingerprint
- PBKDF2-HMAC-SHA256 (300k iterations)

Even if the vault file is copied, it cannot be decrypted on another device.

## 5. Integrity Guard
- Detects tampering
- Validates vault header
- Maintains encrypted code backups

## 6. Full GUI + CLI Support
- GUI (`run_qpgen_gui.py`)
- CLI (`run_qpgen.py`)

---

# How It Works (Flowstate Overview)

## Password Generation Flowstate
Quantum Circuit → Raw Bits → Entropy Mixer (SHA-256) → 8-bit Chunking → Alphabet Mapping → Final Password

## Vault Security Flowstate
Master Password + Quantum Salt + Device Secret + System Fingerprint
→ PBKDF2 Key Derivation (300k)
→ Fernet AES-128 Encryption
→ Secure Encrypted Vault + Automatic Backup

## Quantum Engine Flowstate
Superposition (H-gates) → Z/X Measurements → Raw Bitstream

---

# Project Structure (Core Files)

- `quantum_engine.py` — Quantum circuit builder & bit generator  
- `entropy.py` — SHA-256 entropy mixer  
- `mapping.py` — Bit-to-character mapping  
- `vault.py` — AES-encrypted vault  
- `guard.py` — Integrity & hardware binding  
- `cli.py` — Command-line generator  
- `gui_qt.py` — GUI application  
- `config.py` — Configurable parameters  

---

# Usage

## Command Line
```
python run_qpgen.py
```

## GUI
```
python run_qpgen_gui.py
```

Allows:
- Unlocking the vault
- Adding/updating entries
- Rotating passwords
- Viewing metadata

---

# Configuration

Inside `config.py`:

- `num_qubits` — quantum entropy source  
- `password_length` — final password length  
- `entropy_rounds` — SHA-256 passes  
- `quantum_streams` — multi-stream XOR  
- `alphabet` — allowed characters  

---

# Security Model Summary

## 1. High-entropy randomness
Superposition → unpredictable measurement outcomes.

## 2. Strong cryptographic mixing
SHA-256 amplification.

## 3. Device locking
Vault keys are bound to the originating machine.

## 4. Anti-tamper checks
IntegrityGuard validates critical code and header integrity.

## 5. Encrypted backups
Vault and code backups are stored securely and locally.

---

# Why QuantaLock?

Traditional password generators rely on pseudo-randomness.
QuantaLock uses **quantum entropy**, **cryptographic reinforcement**, and **hardware binding** to produce passwords far beyond typical systems.

Offline. Zero-tracking. Industrial-grade security with simplicity.

<!-- keywords: quantum security, entropy engine, quantum randomness, password generator, zero trust vault -->
