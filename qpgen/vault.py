"""
Quantum-seeded password vault.

Passwords are encrypted locally with a key derived from:
- A user-provided master password
- Quantum randomness from the QuantumEngine (stored as q_salt)

Vault file format (JSON text):
{
  "version": 1,
  "q_salt": "<base64>",
  "data": "<base64 ciphertext>"
}
"""

from __future__ import annotations

from dataclasses import dataclass, asdict
from pathlib import Path
from typing import List
from datetime import datetime, timezone
import json
import base64
import hashlib
import os
import shutil

from cryptography.fernet import Fernet, InvalidToken  # pip install cryptography

from .config import DEFAULT_CONFIG
from .quantum_engine import QuantumEngine
from .entropy import amplify_entropy, bits_to_bytes

def _default_vault_path() -> Path:
    """
    Choose an OS-specific, user-local path for the vault file instead of
    the current working directory, so the location is less obvious and
    not tied to where the EXE/script is run from.
    """
    if os.name == "nt":
        base = os.getenv("APPDATA")
        base_path = Path(base) if base else Path.home() / "AppData" / "Roaming"
    else:
        base = os.getenv("XDG_DATA_HOME")
        base_path = Path(base) if base else Path.home() / ".local" / "share"

    vault_dir = base_path / "qpgen_vault"
    try:
        vault_dir.mkdir(parents=True, exist_ok=True)
    except Exception:
        # Fallback: hidden vault directory in the home folder
        vault_dir = Path.home() / ".qpgen_vault"
        vault_dir.mkdir(parents=True, exist_ok=True)

    return vault_dir / "quantum_vault.bin"


VAULT_FILE = _default_vault_path()
VAULT_VERSION = 1
KDF_ITERATIONS = 300_000

@dataclass
class VaultEntry:
    label: str
    username: str
    password: str
    # When this entry was first created (UTC ISO string).
    created_at: str = ""
    # When the password was last rotated / changed (UTC ISO string).
    last_rotated_at: str = ""

class QuantumVaultError(Exception):
    """Generic vault error."""


class QuantumVault:
    """
    Encrypted password vault.

    Encryption key = SHA-256(master_password || q_salt),
    encoded as urlsafe base64 for Fernet.
    """

    def __init__(self, path: Path | None = None) -> None:
        self.path = path or VAULT_FILE
        self._fernet: Fernet | None = None
        self._entries: list[VaultEntry] = []
        self._q_salt: bytes | None = None
        self._hardware_binding = None

    # ---------- backup helpers ----------

    def _backup_path(self) -> Path:
        """
        Compute a separate, rotated location for the vault backup.

        We keep the backup in a sibling 'backup' directory next to the
        vault file so it is not stored in exactly the same place.
        """
        base_dir = self.path.parent
        backup_dir = base_dir / "backup"
        try:
            backup_dir.mkdir(parents=True, exist_ok=True)
        except Exception:
            # Fallback: use the same directory if backup dir cannot be created.
            backup_dir = base_dir
        return backup_dir / (self.path.name + ".bak")

    def backup_to_disk(self) -> None:
        """
        Copy the current encrypted vault file to the backup location.

        This never touches decrypted entries – it only copies the
        already-encrypted vault file. The backup is always kept at
        the latest state by overwriting the previous .bak file.
        """
        if not self.exists():
            return

        bpath = self._backup_path()
        try:
            shutil.copy2(self.path, bpath)
        except Exception:
            # Best-effort only; failure here must not break normal saving.
            pass

    def restore_from_backup(self) -> bool:
        """
        Restore the vault file from its latest backup.

        Returns True if a backup existed and was successfully restored.
        """
        bpath = self._backup_path()
        if not bpath.exists():
            return False

        try:
            # Try to preserve the corrupted file as *.corrupt for forensics.
            if self.path.exists():
                try:
                    corrupt = self.path.with_suffix(self.path.suffix + ".corrupt")
                    self.path.replace(corrupt)
                except Exception:
                    # If we cannot rename, we will overwrite directly.
                    pass

            shutil.copy2(bpath, self.path)
            return True
        except Exception:
            return False

    # ---------- helpers ----------

    def exists(self) -> bool:
        """Return True if a vault file already exists on disk."""
        return self.path.exists()

    def _generate_q_salt(self) -> bytes:
        """
        Generate a 32-byte quantum-derived salt.

        We use the QuantumEngine to get raw bits, amplify them,
        then pack into bytes and trim/expand to 32 bytes.
        """
        engine = QuantumEngine(DEFAULT_CONFIG)
        bits, _, _ = engine.get_raw_bits_with_meta()
        q_bits = amplify_entropy(bits, rounds=2)
        q_bytes = bits_to_bytes(q_bits)

        if not q_bytes:
            # Extremely unlikely, but fall back to deterministic zeros
            q_bytes = b"\x00" * 32

        if len(q_bytes) < 32:
            # Repeat to reach 32 bytes
            repeat = (32 + len(q_bytes) - 1) // len(q_bytes)
            q_bytes = (q_bytes * repeat)[:32]
        else:
            q_bytes = q_bytes[:32]
        return q_bytes

    @staticmethod
    def _now_iso() -> str:
        """
        Current UTC time in ISO format (seconds precision).
        Stored on each vault entry for age / rotation analysis.
        """
        return datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    
    def _derive_key(self, master_password: str, q_salt: bytes) -> bytes:
        """
        Deterministic key derivation from master password and quantum salt,
        additionally bound to this device via HardwareBinding.

        Uses PBKDF2-HMAC-SHA256 with a high iteration count so that
        offline brute-force attacks against the master password are
        significantly more expensive, and augments the salt with a
        device-local secret and system fingerprint.
        """
        # Local import to avoid potential circular imports at module import time.
        from .guard import HardwareBinding

        iterations = KDF_ITERATIONS

        binder = getattr(self, "_hardware_binding", None)
        if binder is None:
            binder = HardwareBinding()
            self._hardware_binding = binder

        bound_salt = binder.bind_salt(q_salt)

        dk = hashlib.pbkdf2_hmac(
            "sha256",
            master_password.encode("utf-8"),
            bound_salt,
            iterations,
            dklen=32,
        )
        return base64.urlsafe_b64encode(dk)

    # ---------- lifecycle ----------

    def initialize(self, master_password: str) -> None:
        """
        First-time setup: create a new vault with a fresh quantum salt.

        If the vault file already exists, this refuses to overwrite it.
        """
        if self.exists():
            raise QuantumVaultError("Vault already exists; cannot initialize.")

        self._q_salt = self._generate_q_salt()
        key = self._derive_key(master_password, self._q_salt)
        self._fernet = Fernet(key)
        self._entries = []
        self.save()

    def unlock(self, master_password: str) -> None:
        """
        Unlock the vault by loading the q_salt from disk and deriving the key.

        Raises QuantumVaultError if the file is missing, password is wrong,
        or the file is corrupted.
        """
        if not self.exists():
            raise QuantumVaultError("Vault file not found. Create it first.")

        raw = self.path.read_text(encoding="utf-8")
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise QuantumVaultError(
                "Vault file is corrupted or in an old format."
            ) from exc

        if payload.get("version") != VAULT_VERSION:
            raise QuantumVaultError("Unsupported vault version.")

        try:
            q_salt = base64.b64decode(payload["q_salt"])
            ciphertext = base64.b64decode(payload["data"])
        except Exception as exc:  # noqa: BLE001
            raise QuantumVaultError("Vault file is corrupted.") from exc

        key = self._derive_key(master_password, q_salt)
        fernet = Fernet(key)

        try:
            plaintext = fernet.decrypt(ciphertext)
        except InvalidToken as exc:
            raise QuantumVaultError(
                "Invalid master password or corrupted vault."
            ) from exc

        try:
            raw_list = json.loads(plaintext.decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise QuantumVaultError("Vault data is corrupted.") from exc
        finally:
            # Best-effort scrubbing of decrypted plaintext from memory.
            if isinstance(plaintext, (bytes, bytearray)):
                try:
                    mutable = bytearray(plaintext)
                    for i in range(len(mutable)):
                        mutable[i] = 0
                    plaintext = bytes(mutable)
                except Exception:
                    # Fallback: at least drop the reference.
                    plaintext = b""
            else:
                plaintext = b""

        self._q_salt = q_salt
        self._fernet = fernet
        self._entries = [VaultEntry(**item) for item in raw_list]

    def lock(self) -> None:
        """Forget entries and key in memory."""
        self._entries = []
        self._fernet = None
        self._q_salt = None

    def save(self) -> None:
        """Encrypt current entries and write to disk."""
        if self._fernet is None or self._q_salt is None:
            raise QuantumVaultError("Vault is locked; cannot save.")

        raw_list = [asdict(e) for e in self._entries]
        plaintext = json.dumps(raw_list, indent=2).encode("utf-8")
        ciphertext = self._fernet.encrypt(plaintext)

        payload = {
            "version": VAULT_VERSION,
            "q_salt": base64.b64encode(self._q_salt).decode("ascii"),
            "data": base64.b64encode(ciphertext).decode("ascii"),
        }
        self.path.write_text(json.dumps(payload), encoding="utf-8")
        self.backup_to_disk()
        
    def get_header_for_integrity(self) -> dict:
        """
        Return a lightweight, non-sensitive header describing the vault file.

        This is used by IntegrityGuard to detect tampering. It never
        exposes decrypted entries.
        """
        if not self.exists():
            return {}

        try:
            raw = self.path.read_text(encoding="utf-8")
            payload = json.loads(raw)
        except Exception:
            return {}

        return {
            "version": int(payload.get("version", 0)),
            "q_salt": str(payload.get("q_salt", "")),
        }

    # ---------- master password change ----------

    def change_master_password(self, old_password: str, new_password: str) -> None:
        """
        Change the master password safely.

        Steps:
        - Unlock with the old password (validates it and loads entries).
        - Generate a *new* quantum salt.
        - Re-encrypt all entries under the new key.
        """
        if not self.exists():
            raise QuantumVaultError("Vault does not exist yet.")

        # This will raise if old_password is wrong.
        self.unlock(old_password)

        # Re-salt with fresh quantum randomness
        self._q_salt = self._generate_q_salt()
        key = self._derive_key(new_password, self._q_salt)
        self._fernet = Fernet(key)

        # Save entries with new key
        self.save()

    # ---------- entries API ----------

    @property
    def entries(self) -> List[VaultEntry]:
        return list(self._entries)

    def add_or_update(self, entry: VaultEntry) -> None:
        """
        Insert or replace by label.

        - Preserve original created_at when updating.
        - Always refresh last_rotated_at when the entry is changed.
        """
        now = self._now_iso()

        for i, existing in enumerate(self._entries):
            if existing.label == entry.label:
                # Keep original creation time if present.
                entry.created_at = getattr(existing, "created_at", "") or now
                # Any change counts as a rotation/update.
                entry.last_rotated_at = now
                self._entries[i] = entry
                return

        # New entry
        entry.created_at = getattr(entry, "created_at", "") or now
        entry.last_rotated_at = now
        self._entries.append(entry)

    def delete(self, label: str) -> None:
        self._entries = [e for e in self._entries if e.label != label]
