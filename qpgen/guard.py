"""
Integrity and hardware binding helpers for the quantum password vault.

This module provides two main primitives:

- HardwareBinding: derives a device-bound "extra salt" so that the vault
  cannot be decrypted on a different machine, even with the correct master
  password.

- IntegrityGuard: maintains a small manifest of hashes for critical source
  files and the vault header, and verifies them before unlocking.
"""

from __future__ import annotations

import json
import hashlib
import os
import shutil
import platform
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, Optional, Tuple
import base64
from cryptography.fernet import Fernet  # already a dependency via vault.py

def _mark_dir_hidden_windows(path: Path) -> None:
    """
    Best-effort: on Windows, mark the given directory as hidden/system
    so it is not casually visible in Explorer. No effect on other OSes.
    """
    if os.name != "nt":
        return
    try:
        import ctypes

        FILE_ATTRIBUTE_HIDDEN = 0x2
        FILE_ATTRIBUTE_SYSTEM = 0x4

        # Convert to wide string for WinAPI
        GetFileAttributesW = ctypes.windll.kernel32.GetFileAttributesW
        SetFileAttributesW = ctypes.windll.kernel32.SetFileAttributesW

        attrs = GetFileAttributesW(str(path))
        if attrs == -1:
            # Path not found or other error – nothing to do
            return

        new_attrs = attrs | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM
        SetFileAttributesW(str(path), new_attrs)
    except Exception:
        # Never break the app because of cosmetic hiding
        return

# ---------- hardware binding ----------

@dataclass
class HardwareBinding:
    """
    Combine quantum salt with a device-bound secret and a coarse
    system fingerprint, then feed that into the KDF.

    This makes a copied vault file unusable on a different machine
    even if the attacker knows the master password.
    """

    secret_path: Optional[Path] = None

    def __post_init__(self) -> None:
        if self.secret_path is None:
            # Store in the user's home directory by default.
            home = Path(os.path.expanduser("~"))
            self.secret_path = home / ".qpgen_device_secret.bin"

    # --- public API ---

    def bind_salt(self, q_salt: bytes) -> bytes:
        """
        Return an augmented salt that includes:

        - the original quantum salt
        - a local device secret
        - a hashed system fingerprint
        """
        secret = self._load_or_create_secret()
        fp = self._system_fingerprint()
        return q_salt + secret + fp

    # --- internals ---

    def _load_or_create_secret(self) -> bytes:
        """
        Load a 32-byte secret from disk, or create a new one if missing.

        If writing fails for any reason, we still return a process-local
        secret so that the vault remains usable, but the binding becomes
        weaker (only for that session).
        """
        path = self.secret_path
        assert path is not None

        try:
            if path.exists():
                data = path.read_bytes()
                if len(data) == 32:
                    return data
        except Exception:
            # Fall through to regeneration
            pass

        secret = os.urandom(32)
        try:
            # Best-effort write. If it fails, the binding is weaker but
            # the user is not locked out.
            path.write_bytes(secret)
        except Exception:
            pass
        return secret

    def _system_fingerprint(self) -> bytes:
        """
        Build a coarse, non-sensitive fingerprint of the current system.

        We avoid anything like exact MAC addresses; instead we use a mix of
        platform strings that are stable enough to differentiate machines.
        """
        pieces = [
            platform.system(),
            platform.release(),
            platform.version(),
            platform.machine(),
            platform.node(),  # hostname
        ]
        raw = "|".join(pieces).encode("utf-8", "replace")
        return hashlib.sha256(raw).digest()


# ---------- integrity guard ----------


@dataclass
class IntegrityGuard:
    """
    Maintain and verify a simple integrity manifest for:

    - Critical qpgen source files.
    - The vault header (version + q_salt).

    The manifest is stored in a small JSON file next to this module.
    On first run (no manifest yet), we create it and return ok=True so
    that the user is not locked out.
    """

    root_dir: Path | None = None
    manifest_path: Path | None = None
    backup_dir: Path | None = None

    @dataclass
    class IntegrityGuard:
        """
        Maintain and verify a simple integrity manifest for:
        ...
        """

        root_dir: Path | None = None
        manifest_path: Path | None = None
        backup_dir: Path | None = None

        # Tracks any live files that were renamed to "*.corrupt"
        # during the last restore_code_backups() call.
        last_corrupt_paths: list[Path] = field(
            default_factory=list, init=False, repr=False
        )

    def __post_init__(self) -> None:
        # Where the live code lives (qpgen package directory)
        if self.root_dir is None:
            self.root_dir = Path(__file__).resolve().parent

        # Keep the manifest near the code so integrity state is tied
        # to this particular installation.
        if self.manifest_path is None:
            self.manifest_path = self.root_dir / "integrity_manifest.json"

        # Code backups live in a separate, hidden, OS-specific directory.
        if self.backup_dir is None:
            self.backup_dir = self._default_backup_dir()

    def _default_backup_dir(self) -> Path:
        """
        Choose an OS-specific, user-local, semi-hidden directory for
        encrypted code backups.
        """
        if os.name == "nt":
            base = os.getenv("LOCALAPPDATA") or os.getenv("APPDATA")
            if base:
                base_path = Path(base)
            else:
                base_path = Path.home() / "AppData" / "Local"
            backup_root = base_path / "qpgen_secure" / "code_backups"
        else:
            base = os.getenv("XDG_DATA_HOME")
            if base:
                base_path = Path(base)
            else:
                base_path = Path.home() / ".local" / "share"
            backup_root = base_path / "qpgen_secure" / "code_backups"

        return backup_root

    # --- public API ---

    def verify(self, vault_header: Dict | None = None) -> Tuple[bool, str]:
        """
        Verify that the current hashes match the stored manifest.

        Returns (ok, message). If the manifest does not exist, it is
        created automatically and (True, "initialized") is returned.
        """
        manifest_path = self.manifest_path
        assert manifest_path is not None

        current = self._compute_state(vault_header=vault_header)

        if not manifest_path.exists():
            # First run or manifest intentionally removed.
            self._write_manifest(current)
            return True, "Integrity manifest initialized."

        try:
            stored = json.loads(manifest_path.read_text(encoding="utf-8"))
        except Exception as exc:
            return False, f"Failed to read integrity manifest: {exc!r}"

        if stored == current:
            return True, "Integrity check passed."

        # Compute a minimal diff description.
        diffs = []
        stored_files = stored.get("files", {})
        current_files = current.get("files", {})
        for name, h in current_files.items():
            if name not in stored_files:
                diffs.append(f"+ {name} (new)")
            elif stored_files[name] != h:
                diffs.append(f"* {name} (modified)")
        for name in stored_files:
            if name not in current_files:
                diffs.append(f"- {name} (missing now)")

        # Vault header diff
        if stored.get("vault_header") != current.get("vault_header"):
            diffs.append("vault_header changed")

        detail = "; ".join(diffs) if diffs else "Unknown mismatch."
        return False, f"Integrity manifest mismatch: {detail}"

    # --- helpers ---

    def _compute_state(self, vault_header: Dict | None = None) -> Dict:
        files = {}
        for rel in self._critical_files():
            path = self.root_dir / rel
            try:
                data = path.read_bytes()
            except FileNotFoundError:
                # Missing files are still recorded explicitly.
                files[rel] = "<missing>"
                continue
            h = hashlib.sha256(data).hexdigest()
            files[rel] = h

        state = {
            "files": files,
            "vault_header": vault_header or {},
        }
        return state

    @staticmethod
    def _critical_files() -> Iterable[str]:
        """
        Relative paths (from the qpgen package directory) of files
        we want to protect with integrity checking.
        """
        return [
            "vault.py",
            "gui_qt.py",
            "config.py",
            "quantum_engine.py",
            "entropy.py",
            "mapping.py",
            "cli.py",
            "__init__.py",
            "../run_qpgen.py",
            "../run_qpgen_gui.py",
            "guard.py",
        ]

    def _ensure_backup_dir(self) -> Optional[Path]:
        """
        Make sure the backup directory exists and, on Windows,
        mark it as hidden/system.

        All code backups stored here are already encrypted with a
        local Fernet key (see _get_or_create_backup_key).
        """
        backup_dir = self.backup_dir
        if backup_dir is None:
            return None

        try:
            backup_dir.mkdir(parents=True, exist_ok=True)
            _mark_dir_hidden_windows(backup_dir)
        except Exception:
            return None

        return backup_dir

    # --- encrypted backup helpers ---

    def _backup_key_path(self) -> Optional[Path]:
        """
        Path where the local backup encryption key is stored.
        One key per backup_dir.
        """
        backup_dir = self.backup_dir
        if backup_dir is None:
            return None
        return backup_dir / ".code_backup.key"

    def _get_or_create_backup_key(self) -> Optional[bytes]:
        """
        Load or create a symmetric key for encrypting code backups.

        This key never leaves the local machine. Losing it only means
        old backups cannot be restored (you can always re-clone code).
        """
        path = self._backup_key_path()
        if path is None:
            return None

        try:
            if path.exists():
                key = path.read_bytes().strip()
                if key:
                    return key
        except Exception:
            # fall through to regeneration
            pass

        key = Fernet.generate_key()
        try:
            path.write_bytes(key)
        except Exception:
            # best-effort: if we cannot persist the key, skip encryption
            return None
        return key

    def _load_backup_key(self) -> Optional[bytes]:
        """
        Load the backup key without creating a new one.

        Used during restore so we do not accidentally generate a key
        that does not match existing encrypted backups.
        """
        path = self._backup_key_path()
        if path is None or not path.exists():
            return None
        try:
            key = path.read_bytes().strip()
            return key or None
        except Exception:
            return None

    def create_code_backups(self) -> None:
        """
        Create / refresh backup copies of all critical source files.

        Backups are encrypted with a local key when possible.
        """
        if self.root_dir is None:
            return

        backup_dir = self._ensure_backup_dir()
        if backup_dir is None:
            return

        key = self._get_or_create_backup_key()
        fernet = Fernet(key) if key is not None else None

        for rel in self._critical_files():
            src = self.root_dir / rel
            # encrypted backup file name, e.g. gui_qt.py.enc
            enc_dst = backup_dir / f"{rel}.enc"
            plain_dst = backup_dir / rel

            try:
                src_data = src.read_bytes()
            except Exception:
                continue

            # Ensure parent dir for nested paths
            try:
                enc_dst.parent.mkdir(parents=True, exist_ok=True)
            except Exception:
                continue

            try:
                if fernet is not None:
                    enc = fernet.encrypt(src_data)
                    enc_dst.write_bytes(enc)
                    # Optionally remove any old plaintext backup
                    if plain_dst.exists():
                        plain_dst.unlink(missing_ok=True)
                else:
                    # Fallback: plain copy if no key
                    shutil.copy2(src, plain_dst)
            except Exception:
                # Ignore individual failures
                continue

    def restore_code_backups(self) -> Tuple[bool, str]:
        """
        Restore critical source files from their latest backup copies.

        Prefers encrypted backups; falls back to plaintext copies for
        compatibility with older installations.
        """
        if self.root_dir is None:
            return False, "No root_dir set for IntegrityGuard."

        backup_dir = self._ensure_backup_dir()
        if backup_dir is None:
            return False, "No backup directory available."

        key = self._load_backup_key()
        fernet = Fernet(key) if key is not None else None

        restored: list[str] = []
        # Reset the list of renamed corrupt files for this restore run.
        self.last_corrupt_paths = []


        for rel in self._critical_files():
            enc_src = backup_dir / f"{rel}.enc"
            plain_src = backup_dir / rel
            dst = self.root_dir / rel

            use_encrypted = enc_src.exists() and fernet is not None
            use_plain = plain_src.exists()

            if not use_encrypted and not use_plain:
                continue

            try:
                if dst.exists():
                    try:
                        corrupt = dst.with_suffix(dst.suffix + ".corrupt")
                        dst.replace(corrupt)
                        # Remember this renamed file so the GUI can offer deletion.
                        self.last_corrupt_paths.append(corrupt)
                    except Exception:
                        # If we cannot rename, we overwrite directly.
                        pass

                if use_encrypted:
                    data_enc = enc_src.read_bytes()
                    data = fernet.decrypt(data_enc)
                    dst.write_bytes(data)
                else:
                    shutil.copy2(plain_src, dst)

                restored.append(rel)
            except Exception:
                continue

        if not restored:
            return False, "No backups found for critical files."

        return True, f"Restored from backup: {', '.join(restored)}"

    def _write_manifest(self, state: Dict) -> None:
        manifest_path = self.manifest_path
        assert manifest_path is not None
        try:
            manifest_path.write_text(json.dumps(state, indent=2), encoding="utf-8")
        except Exception:
            # Best-effort only; failure just means we skip persistent integrity.
            return

        # On successful manifest write, refresh backups of critical files.
        try:
            self.create_code_backups()
        except Exception:
            # Backup is best-effort; ignore failures here.
            pass
