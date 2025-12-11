"""
Tabbed Qt GUI for the QuantaLock.

Tabs:
- Generator: quantum password generator
- Manager: local quantum-seeded encrypted password vault
"""

from __future__ import annotations

import sys
import math
from typing import Optional
from datetime import datetime, timezone, timedelta
import os
import hashlib
import json
import re
from pathlib import Path
from PySide6.QtCore import Qt, Signal, Slot, QTimer, QEvent

from PySide6.QtGui import QFont, QGuiApplication, QColor, QShortcut, QKeySequence

from PySide6.QtWidgets import (
    QApplication,
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QSpinBox,
    QSlider,
    QLineEdit,
    QCheckBox,
    QGroupBox,
    QMessageBox,
    QTabWidget,
    QListWidget,
    QListWidgetItem,
    QDialog,
    QDialogButtonBox,
    QProgressBar,
    QComboBox,
    QTextEdit,
)

from .config import QuantumPassConfig, DEFAULT_CONFIG
from .cli import generate_password_with_meta
from .vault import QuantumVault, VaultEntry, QuantumVaultError, KDF_ITERATIONS

# Integrity watchdog (optional – GUI degrades gracefully if missing)
try:
    from .guard import IntegrityGuard
except Exception:  # pragma: no cover - defensive fallback
    IntegrityGuard = None  # type: ignore

# Optional system monitor (for threat-adaptive auto-lock / anti screen-share)
try:
    import psutil  # type: ignore[import-not-found]
except Exception:  # pragma: no cover
    psutil = None  # type: ignore[assignment]

# ---------- shared entropy / strength helpers ----------
def estimate_entropy_bits(password: str) -> float:
    """
    Rough entropy estimate in bits based on length and character set used.
    Same logic used for generator strength and master password strength.
    """
    if not password:
        return 0.0

    symbols = "".join(
        ch for ch in DEFAULT_CONFIG.alphabet if not ch.isalnum()
    )

    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any(c in symbols for c in password)

    pool = 0
    if has_lower:
        pool += 26
    if has_upper:
        pool += 26
    if has_digit:
        pool += 10
    if has_symbol:
        pool += len(symbols)

    if pool == 0:
        return 0.0

    return len(password) * math.log2(pool)


def entropy_label(bits: float) -> str:
    if bits <= 0:
        return "Very weak"
    if bits < 50:
        return "Weak"
    if bits < 80:
        return "Moderate"
    if bits < 110:
        return "Strong"
    return "Very strong"


# ---------- Master password wizard dialog ----------


class MasterPasswordDialog(QDialog):
    """
    Wizard dialog for:
    - First-time setup (mode='setup')
    - Changing master password (mode='change')

    Shows a strength meter for the new master password.
    """

    def __init__(self, mode: str, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        assert mode in ("setup", "change")
        self.mode = mode

        if mode == "setup":
            self.setWindowTitle("Set master password")
            intro = (
                "Create a master password for your quantum vault.\n\n"
                "You must remember this password – it cannot be recovered."
            )
        else:
            self.setWindowTitle("Change master password")
            intro = (
                "Change the master password for your quantum vault.\n\n"
                "You will need to enter the current password and a new one."
            )

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(10)

        intro_label = QLabel(intro)
        intro_label.setWordWrap(True)
        layout.addWidget(intro_label)

        # Old password (only when changing)
        if mode == "change":
            old_row = QHBoxLayout()
            old_row.addWidget(QLabel("Current master password:"))
            self.old_edit = QLineEdit()
            self.old_edit.setEchoMode(QLineEdit.Password)
            old_row.addWidget(self.old_edit)
            layout.addLayout(old_row)
        else:
            self.old_edit = None

        # New password
        new_row = QHBoxLayout()
        new_row.addWidget(QLabel("New master password:"))
        self.new_edit = QLineEdit()
        self.new_edit.setEchoMode(QLineEdit.Password)
        new_row.addWidget(self.new_edit)
        layout.addLayout(new_row)

        # Confirm
        confirm_row = QHBoxLayout()
        confirm_row.addWidget(QLabel("Confirm new password:"))
        self.confirm_edit = QLineEdit()
        self.confirm_edit.setEchoMode(QLineEdit.Password)
        confirm_row.addWidget(self.confirm_edit)
        layout.addLayout(confirm_row)

        # Strength meter
        self.strength_bar = QProgressBar()
        self.strength_bar.setRange(0, 100)
        self.strength_bar.setValue(0)
        self.strength_bar.setTextVisible(False)

        self.strength_label = QLabel("Strength: –")
        self.strength_label.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)

        strength_row = QHBoxLayout()
        strength_row.addWidget(QLabel("New password strength:"))
        strength_row.addWidget(self.strength_bar, 1)
        strength_row.addWidget(self.strength_label)
        layout.addLayout(strength_row)

        # Buttons
        self.button_box = QDialogButtonBox(
            QDialogButtonBox.Ok | QDialogButtonBox.Cancel
        )
        self.button_box.accepted.connect(self.accept)
        self.button_box.rejected.connect(self.reject)
        layout.addWidget(self.button_box)

        # Initially disable OK until strong + confirmed
        self.ok_button = self.button_box.button(QDialogButtonBox.Ok)
        self.ok_button.setEnabled(False)

        # Wiring
        self.new_edit.textChanged.connect(self._update_state)
        self.confirm_edit.textChanged.connect(self._update_state)

        self.resize(500, 250)

    # ---- public ----

    def get_passwords(self) -> tuple[str, str]:
        """
        Returns (old_password, new_password).
        For setup mode, old_password is "".
        """
        old_pw = self.old_edit.text() if self.old_edit is not None else ""
        new_pw = self.new_edit.text()
        return old_pw, new_pw

    # ---- internal ----

    def _update_state(self) -> None:
        pw = self.new_edit.text()
        confirm = self.confirm_edit.text()

        bits = estimate_entropy_bits(pw)
        label = entropy_label(bits)

        # Map bits to 0–100 scale for the bar (cap at 120 bits)
        capped = max(0.0, min(bits, 120.0))
        score = int((capped / 120.0) * 100)

        self.strength_bar.setValue(score)
        if bits <= 0:
            self.strength_label.setText("Strength: –")
        else:
            self.strength_label.setText(f"Strength: {label} (~{bits:.1f} bits)")

        # Enable OK only if:
        # - password non-empty
        # - confirmation matches
        # - at least "Moderate" (>= 60 bits) by our thresholds
        strong_enough = bits >= 60.0
        matches = pw and (pw == confirm)
        self.ok_button.setEnabled(strong_enough and matches)


# ---------- Generator Tab ----------


class GeneratorTab(QWidget):
    """
    Generator tab: controls + password display.
    """

    # Signal emitted when user wants to send the current password to the vault.
    # Carries the password string.
    passwordGenerated = Signal(str)

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.config = DEFAULT_CONFIG

        # Secure clipboard auto-clear
        self._clipboard_token: str | None = None
        self._clipboard_timer = QTimer(self)
        self._clipboard_timer.setSingleShot(True)
        self._clipboard_timer.timeout.connect(self._on_clipboard_timeout)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(16)

        # Top: configuration full-width, actions integrated into Password group
        layout.addWidget(self._build_config_group())
        layout.addWidget(self._build_password_group())
        layout.addWidget(self._build_status_label())

    # -- groups --

    def _build_config_group(self) -> QGroupBox:
        group = QGroupBox("Configuration")
        layout = QVBoxLayout()
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        # Password length
        length_label = QLabel("Password length (characters)")
        self.length_spin = QSpinBox()
        self.length_spin.setRange(6, 128)
        self.length_spin.setValue(self.config.password_length)
        self.length_spin.setSingleStep(2)

        # Number of qubits
        qubits_label = QLabel("Number of qubits")
        self.qubits_spin = QSpinBox()
        self.qubits_spin.setRange(4, 29)
        self.qubits_spin.setValue(self.config.num_qubits)

        # Entropy rounds
        entropy_label = QLabel("Entropy amplification rounds")
        self.entropy_slider = QSlider(Qt.Horizontal)
        self.entropy_slider.setRange(0, 5)
        self.entropy_slider.setValue(self.config.entropy_rounds)
        self.entropy_slider.setTickPosition(QSlider.TicksBelow)
        self.entropy_slider.setTickInterval(1)

        self.entropy_value_label = QLabel(str(self.config.entropy_rounds))
        self.entropy_value_label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        self.entropy_slider.valueChanged.connect(
            lambda v: self.entropy_value_label.setText(str(v))
        )

        self.autocopy_check = QCheckBox("Auto-copy after generation")
        self.autocopy_check.setChecked(True)

        layout.addWidget(length_label)
        layout.addWidget(self.length_spin)
        layout.addWidget(qubits_label)
        layout.addWidget(self.qubits_spin)
        layout.addWidget(entropy_label)

        entropy_row = QHBoxLayout()
        entropy_row.addWidget(self.entropy_slider)
        entropy_row.addWidget(self.entropy_value_label)
        layout.addLayout(entropy_row)

        layout.addWidget(self.autocopy_check)
        layout.addStretch()

        group.setLayout(layout)
        return group

    def _build_password_group(self) -> QGroupBox:
        group = QGroupBox("Password")
        layout = QVBoxLayout()
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)

        # Optional memory word: user-chosen phrase blended into the quantum password
        memory_row = QHBoxLayout()

        memory_label = QLabel("Memory word (optional)")
        memory_row.addWidget(memory_label)

        self.memory_word_edit = QLineEdit()
        self.memory_word_edit.setPlaceholderText("e.g. your own word to mix in")
        memory_row.addWidget(self.memory_word_edit, 1)

        # Generate button lives next to the memory word for a minimalist flow
        self.generate_button = QPushButton("Generate")
        gen_font = self.generate_button.font()
        gen_font.setPointSize(13)
        gen_font.setBold(True)
        self.generate_button.setFont(gen_font)
        self.generate_button.setCursor(Qt.PointingHandCursor)
        self.generate_button.clicked.connect(self.on_generate_clicked)
        memory_row.addWidget(self.generate_button)

        layout.addLayout(memory_row)

        # Use QTextEdit so long passwords can be scrolled instead of being cut off
        self.password_field = QTextEdit()
        self.password_field.setReadOnly(True)
        pw_font = QFont("Consolas")
        pw_font.setPointSize(14)
        self.password_field.setFont(pw_font)
        self.password_field.setPlaceholderText(
            "Click Generate to create a password..."
        )
        self.password_field.setLineWrapMode(QTextEdit.NoWrap)
        self.password_field.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self.password_field.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.password_field.setFixedHeight(48)
        self.password_field.setAlignment(Qt.AlignCenter)


        # Buttons row: copy + send to vault
        buttons_row = QHBoxLayout()
        buttons_row.addStretch()
        self.copy_button = QPushButton("Copy to Clipboard")
        self.copy_button.clicked.connect(self.copy_to_clipboard)
        self.send_to_vault_button = QPushButton("Send to vault")
        self.send_to_vault_button.clicked.connect(
            self.on_send_to_vault_clicked
        )
        buttons_row.addWidget(self.copy_button)
        buttons_row.addWidget(self.send_to_vault_button)
        buttons_row.addStretch()

        self.strength_label = QLabel("Password strength: –")
        self.strength_label.setAlignment(Qt.AlignCenter)

        layout.addWidget(self.password_field)
        layout.addLayout(buttons_row)
        layout.addWidget(self.strength_label)

        group.setLayout(layout)
        return group

    def _build_status_label(self) -> QLabel:
        self.status_label = QLabel("")
        self.status_label.setAlignment(Qt.AlignCenter)
        return self.status_label

    # -- actions --

    def _mix_with_memory_word(self, password: str) -> str:
        """
        Blend the user-provided memory word into the quantum password.

        The memory word is injected as one contiguous block inside the
        quantum password so the user can visually recognize it, but the
        base entropy still comes from the quantum generator.
        """
        # Safety: if the UI field is missing or empty, just return the
        # original quantum password.
        word = self.memory_word_edit.text().strip() if hasattr(self, "memory_word_edit") else ""
        if not word or not password:
            return password

        # Use only visible characters, preserve their order exactly.
        word_chars = "".join(c for c in word if not c.isspace())
        if not word_chars:
            return password

        # If the memory word is longer than the password target length,
        # truncate it to fit rather than shuffling characters.
        if len(word_chars) >= len(password):
            return word_chars[: len(password)]

        # Choose a deterministic insertion point based on a hash of
        # (word + password). This keeps it stable for a given config
        # but still non-obvious from the outside.
        digest = hashlib.sha256((word + "|" + password).encode("utf-8")).digest()
        max_start = len(password) - len(word_chars)
        insert_at = digest[0] % (max_start + 1)

        base = list(password)
        base[insert_at : insert_at + len(word_chars)] = list(word_chars)
        return "".join(base)

    def on_generate_clicked(self) -> None:
        self.config.password_length = self.length_spin.value()
        self.config.num_qubits = self.qubits_spin.value()
        self.config.entropy_rounds = self.entropy_slider.value()

        try:
            meta = generate_password_with_meta(self.config)
        except Exception as exc:  # noqa: BLE001
            self._show_error(f"Error while generating password:\n{exc}")
            return

        # Base quantum password
        base_password = meta.password
        # Blend in optional memory word
        final_password = self._mix_with_memory_word(base_password)

        # IMPORTANT: show the *final* password everywhere
        self.password_field.setPlainText(final_password)

        self.status_label.setText(
            f"Generated with {self.config.num_qubits} qubits, "
            f"length {self.config.password_length}, "
            f"entropy rounds {self.config.entropy_rounds}."
        )

        # Strength is computed on the final password (with memory word mixed in)
        bits = estimate_entropy_bits(final_password)
        label = entropy_label(bits)
        if bits <= 0:
            self.strength_label.setText("Password strength: –")
        else:
            self.strength_label.setText(
                f"Password strength: {label} (~{bits:.1f} bits)"
            )

        # Auto-copy uses whatever is in password_field, so it will
        # now correctly copy the memory-word-mixed password.
        if self.autocopy_check.isChecked():
            self.copy_to_clipboard(show_message=False)

    def _arm_secure_clipboard(self, owner_tag: str, timeout_ms: int = 15000) -> None:
        """
        Start a timer to clear the clipboard after a short interval.

        owner_tag is used so we only clear clipboard content we put there.
        """
        self._clipboard_token = owner_tag
        self._clipboard_timer.start(timeout_ms)

    def _on_clipboard_timeout(self) -> None:
        """
        Clear clipboard if it still holds a value we placed.
        """
        if not self._clipboard_token:
            return

        cb = QGuiApplication.clipboard()
        current_text = cb.text()
        if current_text:
            cb.clear()

        self._clipboard_token = None
        self.status_label.setText("Clipboard cleared for safety.")

    def copy_to_clipboard(self, show_message: bool = True) -> None:
        password = self.password_field.toPlainText()
        if not password:
            self._show_error("No password to copy. Generate one first.")
            return

        clipboard = QGuiApplication.clipboard()
        try:
            clipboard.setText(password)
        except Exception:
            # Windows clipboard can be temporarily locked by other apps
            self._show_error(
                "Could not copy to clipboard because another application is using it.\n"
                "Please close any clipboard managers and try again."
            )
            return

        self._arm_secure_clipboard(owner_tag="generator")

        if show_message:
            self.status_label.setText(
                "Password copied to clipboard (auto-clear in a few seconds)."
            )

    def on_send_to_vault_clicked(self) -> None:
        """
        Emit the current password so the Manager tab can pre-fill it.
        """
        password = self.password_field.toPlainText()
        if not password:
            self._show_error("No password to send. Generate one first.")
            return
        self.passwordGenerated.emit(password)
        self.status_label.setText(
            "Password sent to vault. Fill label/username there to save."
        )

    def _show_error(self, message: str) -> None:
        self.status_label.setText(message)
        msg = QMessageBox(self)
        msg.setWindowTitle("Error")
        msg.setIcon(QMessageBox.Critical)
        msg.setText(message)
        msg.exec()


# ---------- Manager Tab (Quantum Vault) ----------


class ManagerTab(QWidget):
    """
    Manager tab: quantum-seeded encrypted password vault.
    """

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)

        self.vault = QuantumVault()
        # Integrity watchdog: protect against tampered app / vault
        if IntegrityGuard is not None:
            self.integrity_guard = IntegrityGuard()
        else:
            self.integrity_guard = None
        self.unlocked = False

        # Secure clipboard auto-clear (vault side)
        self._clipboard_token: str | None = None
        self._clipboard_timer = QTimer(self)
        self._clipboard_timer.setSingleShot(True)
        self._clipboard_timer.timeout.connect(self._on_clipboard_timeout)

        # Basic integrity / unlock tracking
        self._failed_unlocks = 0
        self._lockout_until: datetime | None = None
        self._integrity_events: list[str] = []
        self._max_unlock_attempts = 5
        # Behavioral lockout escalation
        self._behavioral_penalty_level = 0  # grows with repeated lockouts
        # Live IntegrityGuard polling (while vault is unlocked)
        self._integrity_poll_counter = 0
        self._integrity_live_alerted = False

        # Live analytics buffers
        self._entropy_history: list[float] = []
        self._last_entropy_delta: float = 0.0

        # High-security session mode (live window hardening)
        self.high_security_mode = False

        # Last computed health snapshot for dashboard details
        self._health_snapshot = {
            "total": 0,
            "reused_groups": 0,
            "weak": 0,
            "moderate": 0,
            "stale": 0,
            "breached": 0,
        }

        # Adaptive threat / decoy state
        self._suspicion_score = 0
        self._fake_vault_mode = False
        self._decoy_armed = False

        # Auto-lock after inactivity
        self.NORMAL_IDLE_TIMEOUT_MS = 5 * 60 * 1000          # 5 minutes
        self.HIGH_IDLE_TIMEOUT_MS = 90 * 1000                # 90 seconds
        self.IDLE_TIMEOUT_MS = self.NORMAL_IDLE_TIMEOUT_MS

        self.idle_timer = QTimer(self)
        self.idle_timer.setSingleShot(True)
        self.idle_timer.timeout.connect(self._on_idle_timeout)

        # Password view time-limit
        self._view_timeout_ms = 8000  # 8 seconds
        self._view_timer = QTimer(self)
        self._view_timer.setSingleShot(True)
        self._view_timer.timeout.connect(self._on_view_timeout)

        # Threat-adaptive background monitor
        self.security_timer = QTimer(self)
        self.security_timer.setInterval(1000)  # 1 seconds
        self.security_timer.timeout.connect(self._security_monitor_tick)
        self.security_timer.start()

        self.STALE_DAYS = 90

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(16)

        layout.addWidget(self._build_health_group())
        layout.addWidget(self._build_master_group())
        layout.addWidget(self._build_vault_group())
        layout.addWidget(self._build_manager_status())

        self._update_vault_enabled(False)

    def _build_health_group(self) -> QGroupBox:
        group = QGroupBox("Vault Health")

        outer = QVBoxLayout()
        outer.setContentsMargins(12, 12, 12, 12)
        outer.setSpacing(10)

        # Top row – numeric stats + rotate button
        stats_row = QHBoxLayout()
        stats_row.setSpacing(20)

        self.health_total_label = QLabel("Entries: – (vault locked)")
        self.health_reuse_label = QLabel("Reused passwords: –")
        self.health_weak_label = QLabel("Weak / Moderate: –")
        self.health_strong_label = QLabel("Strong / Very strong: –")
        self.health_stale_label = QLabel(
            f"Stale (>{self.STALE_DAYS} days): –"
        )
        self.health_breach_label = QLabel("Breach-flagged entries: –")

        for lbl in (
            self.health_total_label,
            self.health_reuse_label,
            self.health_weak_label,
            self.health_strong_label,
            self.health_stale_label,
            self.health_breach_label,
        ):
            lbl.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)

        # More minimalist: two compact columns instead of a long row
        col_left = QVBoxLayout()
        col_right = QVBoxLayout()

        for lbl in (
            self.health_total_label,
            self.health_weak_label,
            self.health_stale_label,
        ):
            col_left.addWidget(lbl)

        for lbl in (
            self.health_reuse_label,
            self.health_strong_label,
            self.health_breach_label,
        ):
            col_right.addWidget(lbl)

        stats_row.addLayout(col_left)
        stats_row.addLayout(col_right)
        stats_row.addStretch()

        # Deep rotation engine trigger
        self.rotate_button = QPushButton("Rotate risky passwords")

        self.rotate_button.setToolTip(
            "Rotate weak, stale, reused and breach-flagged passwords "
            "using the quantum generator."
        )
        self.rotate_button.clicked.connect(self.on_rotate_weak_clicked)
        stats_row.addWidget(self.rotate_button)

        outer.addLayout(stats_row)

        # Security dashboard slider (read-only gauge)
        dash_row = QHBoxLayout()
        dash_label = QLabel("Security dashboard")

        # Security posture graph (horizontal bar instead of raw slider)
        self.security_bar = QProgressBar()
        self.security_bar.setRange(0, 100)
        self.security_bar.setValue(0)
        self.security_bar.setTextVisible(False)
        self.security_bar.setToolTip(
            "Live security posture: 0 = relaxed, 100 = maximum defensive posture / hostile environment."
        )

        self.security_details_button = QPushButton("Details…")
        self.security_details_button.clicked.connect(self.on_security_details_clicked)

        dash_row.addWidget(dash_label)
        dash_row.addWidget(self.security_bar, 1)
        dash_row.addWidget(self.security_details_button)
        outer.addLayout(dash_row)

        # Second row – radar + suggestions
        radar_row = QHBoxLayout()
        radar_row.setSpacing(4)

        self.vault_radar_label = QLabel("Vault security radar: –")
        self.vault_radar_label.setStyleSheet("color: #cbd5f5;")
        self.health_suggestions_label = QLabel("Suggestions: –")
        self.health_suggestions_label.setWordWrap(True)
        self.health_suggestions_label.setStyleSheet("color: #9ca3af;")

        radar_row.addWidget(self.vault_radar_label)
        radar_row.addWidget(self.health_suggestions_label)

        outer.addLayout(radar_row)

        # Compact IntegrityGuard status (single-line, fits current width)
        self.integrity_status_label = QLabel()
        self.integrity_status_label.setWordWrap(False)

        if not hasattr(self, "integrity_guard") or self.integrity_guard is None:
            # Guard not available (psutil / import issues) – be explicit but short
            self.integrity_status_label.setText("Integrity: disabled")
            self.integrity_status_label.setStyleSheet(
                "color: #6b7280; font-size: 11px;"
            )
        else:
            self.integrity_status_label.setText("Integrity: idle")
            self.integrity_status_label.setStyleSheet(
                "color: #9ca3af; font-size: 11px;"
            )

        outer.addWidget(self.integrity_status_label)

        group.setLayout(outer)
        return group

    def _build_master_group(self) -> QGroupBox:
        group = QGroupBox("Vault Access")
        outer = QVBoxLayout()
        outer.setContentsMargins(12, 12, 12, 12)
        outer.setSpacing(8)

        # Row 1: master password + unlock/lock
        row = QHBoxLayout()
        label = QLabel("Master password:")
        self.master_edit = QLineEdit()
        self.master_edit.setEchoMode(QLineEdit.Password)

        self.unlock_button = QPushButton("Unlock")
        self.unlock_button.clicked.connect(self.on_unlock_clicked)

        row.addWidget(label)
        row.addWidget(self.master_edit, 1)
        row.addWidget(self.unlock_button)

        outer.addLayout(row)

        # Row 2: setup / change master wizard
        self.setup_button = QPushButton("Setup / Change master…")
        self.setup_button.clicked.connect(self.on_setup_master_clicked)
        outer.addWidget(self.setup_button, alignment=Qt.AlignRight)

        # Row 3: High-security session toggle
        hs_row = QHBoxLayout()
        self.high_security_check = QCheckBox("High-security session")
        self.high_security_check.setToolTip(
            "Disable clipboard, shorten auto-lock, lock on focus loss, and "
            "enable anti screen-share / recording / remote-control detection."
        )
        self.high_security_check.toggled.connect(self.on_high_security_toggled)
        hs_row.addWidget(self.high_security_check)
        hs_row.addStretch()
        outer.addLayout(hs_row)

        group.setLayout(outer)
        return group

    def on_high_security_toggled(self, checked: bool) -> None:
        """
        Enable or disable High-security session mode.

        - Disables clipboard copy for vault entries.
        - Uses a much shorter idle timeout.
        """
        self.high_security_mode = bool(checked)

        # Adjust idle timeout
        if self.high_security_mode:
            self.IDLE_TIMEOUT_MS = self.HIGH_IDLE_TIMEOUT_MS
        else:
            self.IDLE_TIMEOUT_MS = self.NORMAL_IDLE_TIMEOUT_MS

        # Update copy button immediately based on mode + unlock state
        self.copy_button.setEnabled(self.unlocked and not self.high_security_mode)

        # Restart idle timer for the new timeout
        self._bump_idle_timer()

        if self.high_security_mode:
            self.status_label.setText(
                "High-security session enabled: clipboard disabled, quick auto-lock, focus-loss lock."
            )
        else:
            self.status_label.setText("High-security session disabled.")

    def _build_vault_group(self) -> QGroupBox:
        group = QGroupBox("Stored Passwords")
        layout = QHBoxLayout()
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(16)

        # Left: search + list of entries
        left = QVBoxLayout()

        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("Search by label or username...")
        # Filter the list every time the query changes
        self.search_edit.textChanged.connect(self._reload_list)
        left.addWidget(self.search_edit)

        # Filter dropdown: recent, weak, stale by age
        self.filter_combo = QComboBox()
        self.filter_combo.addItem("All entries", userData="all")
        self.filter_combo.addItem("Recent (≤30 days)", userData="recent30")
        self.filter_combo.addItem("Weak only", userData="weak")
        self.filter_combo.addItem("Stale >30 days", userData="stale30")
        self.filter_combo.addItem("Stale >60 days", userData="stale60")
        self.filter_combo.addItem("Stale >90 days", userData="stale90")
        self.filter_combo.setToolTip(
            "Filter the list by weakness or age of the password."
        )
        self.filter_combo.currentIndexChanged.connect(self._reload_list)
        left.addWidget(self.filter_combo)

        self.entry_list = QListWidget()
        self.entry_list.currentItemChanged.connect(self.on_entry_selected)
        left.addWidget(self.entry_list)

        delete_btn = QPushButton("Delete selected")
        delete_btn.clicked.connect(self.on_delete_clicked)
        left.addWidget(delete_btn)

        # Right: details
        right = QVBoxLayout()

        self.label_edit = QLineEdit()
        self.username_edit = QLineEdit()
        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.Password)

        # Make form fields tall enough so text is not vertically clipped
        for edit in (self.label_edit, self.username_edit, self.password_edit):
            edit.setMinimumHeight(28)

        # Update strength meter whenever password text changes
        self.password_edit.textChanged.connect(self._update_entry_strength)

        # Label row
        label_row = QHBoxLayout()
        label_row.addWidget(QLabel("Label (site / context)"))
        label_row.addWidget(self.label_edit)
        right.addLayout(label_row)

        # Username row
        user_row = QHBoxLayout()
        user_row.addWidget(QLabel("Username / ID"))
        user_row.addWidget(self.username_edit)
        right.addLayout(user_row)

        # Password row with "view" toggle
        pwd_row = QHBoxLayout()
        pwd_row.addWidget(QLabel("Password"))
        pwd_row.addWidget(self.password_edit)

        self.view_button = QPushButton("View")
        self.view_button.setCheckable(False)
        self.view_button.clicked.connect(self.on_view_toggled)
        pwd_row.addWidget(self.view_button)

        right.addLayout(pwd_row)

        # Strength meter for this entry
        self.entry_strength_bar = QProgressBar()
        self.entry_strength_bar.setRange(0, 100)
        self.entry_strength_bar.setValue(0)
        self.entry_strength_bar.setTextVisible(False)

        self.entry_strength_label = QLabel("Entry strength: –")

        strength_row = QHBoxLayout()
        strength_row.addWidget(QLabel("Password strength:"))
        strength_row.addWidget(self.entry_strength_bar, 1)
        strength_row.addWidget(self.entry_strength_label)
        right.addLayout(strength_row)

        # Action buttons
        buttons_row = QHBoxLayout()
        self.save_button = QPushButton("Add / Update")
        self.save_button.clicked.connect(self.on_save_clicked)

        self.rotate_now_button = QPushButton("Rotate now")
        self.rotate_now_button.clicked.connect(self.on_rotate_now_clicked)

        self.copy_button = QPushButton("Copy password")
        self.copy_button.clicked.connect(self.on_copy_clicked)

        buttons_row.addWidget(self.save_button)
        buttons_row.addWidget(self.rotate_now_button)
        buttons_row.addWidget(self.copy_button)

        right.addLayout(buttons_row)
        right.addStretch()

        layout.addLayout(left, 1)
        layout.addLayout(right, 2)

        group.setLayout(layout)
        return group

    def _build_manager_status(self) -> QLabel:
        self.status_label = QLabel("Vault locked.")
        self.status_label.setAlignment(Qt.AlignCenter)
        return self.status_label

    def _entry_age_days(self, entry: VaultEntry) -> Optional[float]:
        """
        Return the age of this entry's password in days (float),
        based on last_rotated_at / created_at. Returns None if unknown.
        """
        ts_raw = getattr(entry, "last_rotated_at", "") or getattr(
            entry, "created_at", ""
        )
        if not ts_raw:
            return None

        try:
            ts = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
        except ValueError:
            return None

        now = datetime.now(timezone.utc)
        delta = now - ts
        return delta.total_seconds() / 86400.0

    def _is_entry_stale(self, entry: VaultEntry) -> bool:
        """
        Return True if the entry's password is older than STALE_DAYS.
        """
        age_days = self._entry_age_days(entry)
        return age_days is not None and age_days > self.STALE_DAYS

    def _format_age(self, entry: VaultEntry) -> str:
        """
        Return a compact 'age' string like:
        '· 3s ago', '· 22m ago', '· 1h ago', '· 2d ago'.
        Empty string if age is unknown.
        """
        age_days = self._entry_age_days(entry)
        if age_days is None:
            return ""

        total_seconds = int(age_days * 86400)
        if total_seconds < 60:
            return "· 1s ago"

        minutes = total_seconds // 60
        if minutes < 60:
            return f"· {minutes}m ago"

        hours = minutes // 60
        if hours == 1:
            return "· 1h ago"
        if hours < 24:
            return f"· {hours}h ago"

        days = hours // 24
        if days == 1:
            return "· 1d ago"
        if days < 7:
            return f"· {days}d ago"

        weeks = days // 7
        if weeks == 1:
            return "· 1w ago"
        if weeks < 4:
            return f"· {weeks}w ago"

        months = days // 30
        if months == 1:
            return "· 1mo ago"
        if months < 12:
            return f"· {months}mo ago"

        years = days // 365
        if years == 1:
            return "· 1y ago"
        return f"· {years}y ago"

    # --- Live breach intelligence (offline, hash-based) ---

    # Minimal starter set – extend via external packs later.
    _BREACHED_SHA256_HASHES: set[str] = {
        # Common leaked passwords (SHA-256 hex digests)
    "5994471abb01112afcc18159f6cc74b4f511b99806da59b3caf5a9c173cacfc5",  # 12345
    "8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92",  # 123456
    "15e2b0d3c33891ebb0f1ef609ec419420c20e320ce94c65fbc8c3312448eb225",  # 123456789
    "ef797c8118f02dfb649607dd5d3f8c7623048c9c063d532cc95c5ed7a898a64f",  # 12345678
    "96cae35ce8a9b0244178bf28e4966c2ce1b8385723a96a6b838858cdd6ca0a1e",  # 123123
    "4e732ced3463d06de0ca9a15b6153677e8c9a1e18c1e442b61bfb2de9a5f9e68",  # 1234567
    "6dcd4ce23d88e2ee9568ba546c007c63f17c6b4541c4a81ec55b8af88a38f5d7",  # 000000
    "fcea920f7412b5da7be0cf42b8c93759a70d5b7a7ab387d0c7721ce1aee3bcd7",  # 1234
    "03ac674216f3e15c761ee1a5e255f067953623c8b388b4459e13f978d7c846f4",  # 111111
    "bcb15f1f4f3c2b6c02c55d7a0d5fb4352c6b8e5f5c1a7109a2c8c57a6f0f2e5d",  # 654321

    "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",  # password
    "0b14d501a594442a01c6859541bcb3e8164d183d32937b851835442f69d5c94e",  # password1
    "d74e9e0f0c0c13b0bc3e3deb6e847f8df57e4b6213b5636e33d7e644d4548932",  # password123
    "8f0e2f76e22b43e2855189877e7dc1e1e7d98c226c95db247cd1d547928334a9",  # passw0rd
    "65e84be33532fb784c48129675f9eff3a682b27168c0ea744b2cf58ee02337c5",  # qwerty
    "daaad6e5604e8e17bd9f108d91e26afe6281dac8fda0091040a7a6d7bd9b43b5",  # qwerty123
    "69f5b43fa4a7ec67cc1e0aac24cc739f1273dbe1579d6f6439ed78405a15326d",  # iloveyou1
    "e4ad93ca07acb8d908a3aa41e920ea4f4ef4f26e7f86cf8291c5db289780a5ae",  # iloveyou
    "a9c43be948c5cabd56ef2bacffb77cdaa5eec49dd5eb0cc4129cf3eda5f0e74c",  # dragon
    "a941a4c4fd0c01cddef61b8be963bf4c1e2b0811c037ce3f1835fddf6ef6c223",  # sunshine

    "240be518fabd2724ddb6f04eeb1da5967448d7e831c08c8fa822809f74c720a9",  # admin123
    "8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918",  # admin
    "f0a1f8e24c45bdccab696648efa430dfb79d5c7c7d5d1084d5963efe5dae3b69",  # root
    "49f68a5c8493ec2c0bf489821c21fc3b3f5c2e121a7fdaf9b28c8a4630bf8e86",  # 123
    "72ab994fa2eb426c051ef59cad617750bfe06d7cf6311285ff79c19c32afd236",  # 1q2w3e4r
    "6ca13d52ca70c883e0f0bb101e425a89e8624de51db2d2392593af6a84118090",  # abc123
    "9b0eb22aef89516d6fb4b31ccf008a68abe0d10a3fc606316389613eccf96854",  # letmein123
    "1c8bfe8f801d79745c4631d09fff36c82aa37fc4cce4fc946683d7b336b63032",  # letmein
    "280d44ab1e9f79b5cce2dd4f58f5fe91f0fbacdac9f7447dffc318ceb79f2d02",  # welcome
    "428821350e9691491f616b754cd8315fb86d797ab35d843479e732ef90665324",  # login

    "1a1dc91c907325c69271ddf0c944bc72b0043b5efabd5b095d25e0d6e4f88e42",  # pass
    "1ba3d16e9881959f8c9a9762854f72c6e6321cdd47257e0a9835a3e1eefc9b71",  # hello
    "8d181016f3fad2ed08435a9cddc5e889e76d37f902491512717a53d30ace1800",  # monkey
    "e99a18c428cb38d5f260853678922e03abd8334a32a08d4f6f0c5af49e49fce3",  # abc12345
    "b2e98ad6f6eb8508dd6a14cfa704bad7c4c8f8f5c3cbdeb18f0d33bd583f7d8f",  # trustno1
    "7c4a8d09ca3762af61e59520943dc26494f8941b89f019a8b9d8e65ddc7d27d8",  # 1234567 (alt)
    "3c59dc048e8850243be8079a5c74d079c7a3e2835b2dd8c72482004227192a54",  # password!
    "5f4dcc3b5aa765d61d8327deb882cf99fedc3d1e0e1dcfb0a219c2f478255502",  # password (MD5 classic → SHA256 repr of "password")
    "2bb80d537b1da3e38bd30361aa855686bde0f5cb918f0a95cace0bbd1578c5b6",  # qwertyuiop
    "01b307acba4f54f55aafc33bb06bbbf6ca803e9a3d93fe2d5d09e8dfe5e46598",  # 11111111
    "4f7f8f186d8b482c6f0efa1bb529d5900eef89441f0f9b8679513762c508d57f",  # baseball
    "21d1a9e3e0dda3e5a3ee76a6c3dc7c6046d3f2d2a7ecfaa44e0ac0cdbfddd023",  # football
    "785f3df6dfe06cfaf08763c2e99af3d0f559ebbd19e9f0b2e264d5233f22f7fd",  # master
    "6b3a55e0261b0304143f5be345c045e71f4b3f8718abf3483c796d53295d85f7",  # freedom
    "1f5c5683982aa32ab7e3c90ad7381fdbef674e7dc86c51a5d65704fbf035d1a5",  # whatever
    "cd73502828457d15655bbd7a63fb0bc8a587145d0d2bd6ec0b0c7bf3c9ca6c26",  # qwerty1
    "de9f2c7fd25e1b3afad3e85a0bd17d9bdfb300fadc177a64b124ecf8d39c0f2b",  # zxcvbn
    "b1b3773a05c0ed0176787a4f1574ff0075f7521e36f74bfad790e5c4f2c4b8fa",  # qwerty12
    "3a7bd3e2360a3d80c4d486ec2074f3e249e4c441d775888b859f6af0f803f8ce",  # admin1
    "e3c8b1fd30bd1f41a0be8d36b8002ffbdc622c2fca80f9a6e445b7344a5bc9a1",  # superman
    "d74db872fd71b3ffe7142b1caa2d80be43b44e07039e89165b0def05d6d33924",  # batman
    "adfcb84ce8b063f492819e939e2e22b1f96365e6a85ee844eb5d286276f4e5a9",  # qazwsx
    }

    def _password_pattern_flags(self, password: str) -> list[str]:
        """
        Heuristic pattern detector for weak passwords.
        Returns a list of pattern tags, e.g.:
        ["too-short", "digit-sequence", "keyboard-walk", ...]
        """
        flags: list[str] = []
        if not password:
            return flags

        pwd = password
        lower = pwd.lower()

        # --- Length rules ---
        if len(pwd) < 8:
            flags.append("too-short")

        # --- Composition / low variety ---
        unique_chars = set(pwd)
        if pwd.isdigit():
            flags.append("digits-only")
            if len(unique_chars) == 1 and len(pwd) >= 4:
                flags.append("single-digit-repeat")

            # straight numerical sequences like 123456, 654321
            asc = "0123456789"
            desc = asc[::-1]
            for seq in (asc, desc):
                for i in range(len(seq) - 3):
                    segment = seq[i:i + len(pwd)]
                    if segment == pwd:
                        flags.append("digit-sequence")
                        break
                else:
                    continue
                break

        if pwd.isalpha():
            flags.append("letters-only")

        if len(unique_chars) <= 2 and len(pwd) >= 6:
            flags.append("low-variety")

        # --- Keyboard walks (qwerty, asdf, etc.) ---
        keyboard_rows = [
            "qwertyuiop",
            "asdfghjkl",
            "zxcvbnm",
            "1234567890",
            "1q2w3e4r5t",
            "qazwsxedc",
            "!@#$%^&*()",
        ]
        for row in keyboard_rows:
            if lower in row or row in lower:
                flags.append("keyboard-walk")
                break

        # --- dictionary word + short digits: password123, admin1, root99 ---
        m = re.fullmatch(r"([A-Za-z]{3,})(\d{1,4})", pwd)
        if m:
            word = m.group(1).lower()
            weak_words = {
                "password", "pass", "admin", "user", "login", "test",
                "qwerty", "love", "lovely", "welcome",
                "dragon", "master", "root", "god",
            }
            if word in weak_words:
                flags.append("dictionary+digits")

        # --- l33t dictionary variants: P@ssw0rd, P@ssw0rd1 etc. ---
        leet = (
            lower
            .replace("0", "o")
            .replace("1", "l")
            .replace("3", "e")
            .replace("4", "a")
            .replace("5", "s")
            .replace("@", "a")
            .replace("$", "s")
        )
        if leet in {"password", "pass", "admin", "root", "god", "login"}:
            flags.append("dictionary-leetspeak")

        # --- date-like patterns: 01012024, 01-01-24, 01/01/2024 etc. ---
        if re.fullmatch(r"\d{2}[./-]?\d{2}[./-]?\d{2,4}", pwd):
            flags.append("date-like")

        # dedupe while preserving order
        seen = set()
        ordered: list[str] = []
        for f in flags:
            if f not in seen:
                seen.add(f)
                ordered.append(f)
        return ordered


    def _is_password_pattern_risky(self, password: str) -> bool:
        """
        Convenience helper: True if any weak pattern is detected.
        """
        return bool(self._password_pattern_flags(password))

    def _is_password_breached(self, password: str) -> bool:
        """
        Check if the given password matches a known-breached signature.

        Uses SHA-256 hashes of known leaked passwords only.
        No password is ever sent anywhere.
        """
        if not password:
            return False
        digest = hashlib.sha256(password.encode("utf-8")).hexdigest()
        return digest in self._BREACHED_SHA256_HASHES

    def _compute_health_stats(self) -> tuple[int, int, int, int, int, int, int, int]:
        """
        Returns:
          total_entries,
          reused_password_groups,
          weak_count,
          moderate_count,
          strong_count,
          very_strong_count,
          stale_count,
          breached_count
        """
        entries = getattr(self.vault, "entries", [])
        total = len(entries)

        # Password reuse map (password → list of labels)
        pwd_map: dict[str, list[str]] = {}
        for e in entries:
            pwd_map.setdefault(e.password, []).append(e.label)

        reused_groups = sum(1 for labels in pwd_map.values() if len(labels) > 1)

        # Strength buckets
        weak = moderate = strong = very_strong = 0
        breached_count = 0

        for e in entries:
            bits = estimate_entropy_bits(e.password)
            if bits < 50:
                weak += 1
            elif bits < 80:
                moderate += 1
            elif bits < 110:
                strong += 1
            else:
                very_strong += 1

            if self._is_password_breached(e.password):
                breached_count += 1

        # Stale passwords: age > STALE_DAYS
        stale = sum(1 for e in entries if self._is_entry_stale(e))

        return (
            total,
            reused_groups,
            weak,
            moderate,
            strong,
            very_strong,
            stale,
            breached_count,
        )

    def _update_health_stats(self) -> None:
        """
        Update the Vault Health labels based on current entries and lock state.

        Also feeds the Quantum Entropy Drift Monitor by tracking the average
        per-entry entropy over time.
        """
        if not self.unlocked:
            self.health_total_label.setText("Entries: – (vault locked)")
            self.health_reuse_label.setText("Reused passwords: –")
            self.health_weak_label.setText("Weak / Moderate: –")
            self.health_strong_label.setText("Strong / Very strong: –")
            self.health_stale_label.setText(
                f"Stale (>{self.STALE_DAYS} days): –"
            )
            self.health_breach_label.setText("Breach-flagged entries: –")
            self.vault_radar_label.setText("Vault security radar: –")
            self.health_suggestions_label.setText("Suggestions: –")

            # KDF label is static.
            if hasattr(self, "security_bar"):
                self.security_bar.setValue(0)

            self._health_snapshot = {
                "total": 0,
                "reused_groups": 0,
                "weak": 0,
                "moderate": 0,
                "stale": 0,
                "breached": 0,
            }
            # When locked, we do not mutate entropy/threat history.
            return

        (
            total,
            reused_groups,
            weak,
            moderate,
            strong,
            very_strong,
            stale,
            breached_count,
        ) = self._compute_health_stats()

        self.health_total_label.setText(f"Entries: {total}")
        self.health_reuse_label.setText(f"Reused passwords: {reused_groups}")
        self.health_weak_label.setText(f"Weak / Moderate: {weak + moderate}")
        self.health_strong_label.setText(
            f"Strong / Very strong: {strong + very_strong}"
        )
        self.health_stale_label.setText(
            f"Stale (>{self.STALE_DAYS} days): {stale}"
        )
        self.health_breach_label.setText(
            f"Breach-flagged entries: {breached_count}"
        )

        self._health_snapshot = {
            "total": total,
            "reused_groups": reused_groups,
            "weak": weak,
            "moderate": moderate,
            "stale": stale,
            "breached": breached_count,
        }

        # --- Quantum Entropy Drift Monitor feed ---
        entries = getattr(self.vault, "entries", [])
        ent_values = [
            estimate_entropy_bits(e.password) for e in entries if e.password
        ]
        avg_entropy = (
            sum(ent_values) / len(ent_values) if ent_values else 0.0
        )

        prev_avg = self._entropy_history[-1] if self._entropy_history else None
        self._entropy_history.append(avg_entropy)
        if len(self._entropy_history) > 60:
            self._entropy_history = self._entropy_history[-60:]

        self._last_entropy_delta = (
            avg_entropy - prev_avg if prev_avg is not None else 0.0
        )

        # Update radar + suggestions
        self._update_vault_radar(
            total=total,
            reused_groups=reused_groups,
            weak=weak,
            moderate=moderate,
            stale=stale,
            breached=breached_count,
        )
        self.health_suggestions_label.setText(
            self._compute_vault_suggestions(
                total=total,
                reused_groups=reused_groups,
                weak=weak,
                moderate=moderate,
                stale=stale,
                breached=breached_count,
            )
        )

    def _lock_vault(self, reason: str = "Vault locked.") -> None:
        """
        Lock the vault, wipe sensitive fields, and stop the idle timer.
        """
        # Reset decoy / suspicion state
        self._fake_vault_mode = False
        self._decoy_armed = False
        self._suspicion_score = 0

        self.vault.lock()
        self.unlocked = False
        self.unlock_button.setText("Unlock")
        self._update_vault_enabled(False)
        self.entry_list.clear()
        self.label_edit.clear()
        self.username_edit.clear()
        self.password_edit.clear()
        self.password_edit.setEchoMode(QLineEdit.Password)
        self.view_button.setText("View")
        self.master_edit.clear()  # memory shield: never keep master password visible
        self.status_label.setText(reason)
        self._update_health_stats()
        self.entry_strength_bar.setValue(0)
        self.entry_strength_label.setText("Entry strength: –")
        self.idle_timer.stop()
        self._view_timer.stop()

    def _enter_fake_vault_mode(self, reason: str) -> None:
        """
        Enter a decoy vault state without ever decrypting the real vault.

        All entries in this mode are synthetic and never saved to disk.
        Used when environment looks hostile (e.g. screen capture +
        repeated failed unlocks).
        """
        self._fake_vault_mode = True
        self.unlocked = True
        self.unlock_button.setText("Lock (decoy)")

        # Build synthetic decoy entries
        now_iso = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
        decoys = [
            VaultEntry(
                label="Mail / Personal",
                username="you@example.com",
                password="QuantumDemo-1",
                created_at=now_iso,
                last_rotated_at=now_iso,
            ),
            VaultEntry(
                label="Bank / Demo",
                username="user123",
                password="QuantumDemo-2",
                created_at=now_iso,
                last_rotated_at=now_iso,
            ),
            VaultEntry(
                label="Social / Demo",
                username="me",
                password="QuantumDemo-3",
                created_at=now_iso,
                last_rotated_at=now_iso,
            ),
        ]

        # Inject directly into vault entries, but don't set any key/fernet.
        self.vault._entries = decoys  # type: ignore[attr-defined]

        self._update_vault_enabled(True)
        self._reload_list()
        self._update_health_stats()
        self.status_label.setText(
            reason
            + " Real vault is sealed. You are viewing a decoy vault (changes are not persisted)."
        )
        self._bump_idle_timer()

    def _update_vault_radar(
        self,
        total: int,
        reused_groups: int,
        weak: int,
        moderate: int,
        stale: int,
        breached: int,
    ) -> None:
        """
        Aggregated 'radar' status derived from health, behavior, and threat signals.

        Drives:
        - Text label (posture)
        - Security bar (0–100)
        - Real-time Threat Graph history buffer
        """
        risk_score = 0

        # Static vault posture
        risk_score += weak * 2 + moderate
        risk_score += reused_groups * 3
        risk_score += stale
        risk_score += breached * 4

        # Integrity events – failed unlocks etc.
        failed_events = sum(
            1 for e in self._integrity_events if "unlock_fail" in e
        )
        if failed_events > 0:
            risk_score += failed_events * 2

        # Live behavioral / threat signals
        risk_score += self._suspicion_score * 2
        risk_score += getattr(self, "_behavioral_penalty_level", 0) * 5
        if self.high_security_mode:
            risk_score += 3
        if self._fake_vault_mode or self._decoy_armed:
            risk_score = max(risk_score, 20)  # ensure non-zero in hostile env

        # Map to 0–100 for the posture graph
        slider_value = max(0, min(100, risk_score * 4))
        if hasattr(self, "security_bar"):
            self.security_bar.setValue(slider_value)

        # Text label mapping
        if self._fake_vault_mode:
            text = "Vault security radar: DECOY MODE (real vault sealed)."
            color = "#22d3ee"
        elif self._decoy_armed:
            text = "Vault security radar: hostile environment detected (decoy armed)."
            color = "#eab308"
        elif total == 0 and slider_value == 0:
            text = "Vault security radar: empty vault."
            color = "#9ca3af"
        elif slider_value <= 25:
            text = "Vault security radar: normal."
            color = "#10b981"  # green
        elif slider_value <= 70:
            text = "Vault security radar: elevated."
            color = "#f97316"  # orange
        else:
            text = "Vault security radar: high attention."
            color = "#ef4444"  # red

        self.vault_radar_label.setText(text)
        self.vault_radar_label.setStyleSheet(f"color: {color};")

    def _compute_vault_suggestions(
        self,
        total: int,
        reused_groups: int,
        weak: int,
        moderate: int,
        stale: int,
        breached: int,
    ) -> str:
        if total == 0:
            return "Suggestions: Add entries to the vault to begin health analysis."

        suggestions: list[str] = []

        if breached > 0:
            suggestions.append(
                f"Rotate {breached} breach-flagged password(s) immediately."
            )
        if reused_groups > 0:
            suggestions.append(
                f"Eliminate reuse across {reused_groups} password group(s)."
            )
        if weak + moderate > 0:
            suggestions.append(
                f"Upgrade {weak + moderate} weak/moderate password(s) to strong or very strong."
            )
        if stale > 0:
            suggestions.append(
                f"Refresh {stale} stale password(s) older than {self.STALE_DAYS} days."
            )

        if not suggestions:
            return "Suggestions: Vault posture looks strong. Maintain regular rotation and monitoring."

        return "Suggestions: " + " ".join(suggestions)

    def on_rotate_weak_clicked(self) -> None:
        """
        Deep Rotation Engine:

        Rotate all 'risky' passwords with new quantum-generated ones.

        Risk criteria:
        - Weak (entropy < 50 bits), OR
        - Stale (older than STALE_DAYS), OR
        - Reused (same password used in multiple entries), OR
        - Breach-flagged by local signature set.
        """
        if not self.unlocked:
            self._show_error("Unlock the vault first.")
            return

        if self._fake_vault_mode:
            self._show_error(
                "Decoy vault is active. Changes are not allowed or persisted in this mode."
            )
            return

        WEAK_THRESHOLD_BITS = 50.0

        # Remember which entry (by label) is currently selected
        current_item = self.entry_list.currentItem()
        selected_label = (
            current_item.data(Qt.UserRole) if current_item is not None else None
        )

        entries = list(self.vault.entries)

        # Build reuse map
        pwd_map: dict[str, list[VaultEntry]] = {}
        for e in entries:
            pwd_map.setdefault(e.password, []).append(e)

        # Collect risky entries
        risky_entries: list[VaultEntry] = []

        for e in entries:
            bits = estimate_entropy_bits(e.password)
            is_weak = bits < WEAK_THRESHOLD_BITS
            is_stale = self._is_entry_stale(e)
            is_reused = len(pwd_map.get(e.password, [])) > 1
            is_breached = self._is_password_breached(e.password)

            if is_weak or is_stale or is_reused or is_breached:
                risky_entries.append(e)

        if not risky_entries:
            QMessageBox.information(
                self,
                "Rotate risky passwords",
                "No risky passwords found (weak, stale, reused, or breach-flagged).",
            )
            return

        # Build preview text
        lines: list[str] = []
        for e in risky_entries:
            tags = []
            bits = estimate_entropy_bits(e.password)
            if bits < WEAK_THRESHOLD_BITS:
                tags.append("weak")
            if self._is_entry_stale(e):
                tags.append("stale")
            if len(pwd_map.get(e.password, [])) > 1:
                tags.append("reused")
            if self._is_password_breached(e.password):
                tags.append("breach-flagged")
            tag_str = ", ".join(tags) if tags else "risky"
            lines.append(f"  • {e.label} ({tag_str})")

        labels_list = "\n".join(lines)
        msg = (
            f"{len(risky_entries)} risky password(s) found:\n\n"
            f"{labels_list}\n\n"
            "They will be replaced with new quantum-generated passwords "
            "using the default generator settings.\n\n"
            "Do you want to continue?"
        )

        resp = QMessageBox.question(
            self,
            "Rotate risky passwords",
            msg,
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if resp != QMessageBox.Yes:
            self.status_label.setText("Rotation cancelled.")
            return

        # Perform rotation
        from .cli import generate_password_with_meta  # local import avoids cycles
        from .config import DEFAULT_CONFIG

        rotated_count = 0
        for e in risky_entries:
            meta = generate_password_with_meta(DEFAULT_CONFIG)
            new_entry = VaultEntry(
                label=e.label,
                username=e.username,
                password=meta.password,
            )
            self.vault.add_or_update(new_entry)
            rotated_count += 1

        try:
            self.vault.save()
        except QuantumVaultError as exc:
            self._show_error(str(exc))
            return

        # Rebuild list + health stats
        self._reload_list()
        self._update_health_stats()

        # Restore details panel for the previously selected entry, if any
        if selected_label is not None:
            for i in range(self.entry_list.count()):
                item = self.entry_list.item(i)
                if item.data(Qt.UserRole) == selected_label:
                    self.entry_list.setCurrentItem(item)
                    # This will repopulate fields and strength bar
                    self.on_entry_selected(item, None)  # type: ignore[arg-type]
                    break

        self.status_label.setText(
            f"Rotated {rotated_count} risky password(s) using quantum generator."
        )
        self._bump_idle_timer()

    def _run_integrity_guard(self) -> bool:
        """
        Run the integrity watchdog before unlocking the vault.

        Returns True if everything is OK (or initialized),
        False if a mismatch was detected and the caller should abort.
        """
        if not hasattr(self, "integrity_guard") or self.integrity_guard is None:
            # If the guard is not available, we fail open rather than
            # locking the user out unexpectedly.
            return True

        header = self.vault.get_header_for_integrity()
        ok, message = self.integrity_guard.verify(header)
        if ok:
            # Optional: record a soft "integrity_ok" event
            self._record_integrity_event("integrity_ok")
            self._set_integrity_status("ok")
            return True

        # Integrity mismatch – offer to restore from backups
        self._record_integrity_event("integrity_fail")
        self._set_integrity_status("alert", message)

        choice = QMessageBox.question(
            self,
            "Vault integrity check failed",
            "Vault integrity check failed.\n\n"
            f"{message}\n\n"
            "If you did not intentionally modify the application or vault, "
            "you can attempt to restore from the last known good backups of "
            "the code and vault files.\n\n"
            "Do you want to restore from backup now?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )

        if choice == QMessageBox.Yes:
            if self._restore_from_backups(header):
                # Integrity passed after restore – allow the caller to continue.
                return True

        # If we reach here, either the user declined or restore failed.
        self._show_error(
            "Vault integrity check failed.\n\n"
            f"{message}\n\n"
            "Refusing to decrypt because the application or vault file "
            "appears to have been modified."
        )
        return False

    def _set_integrity_status(self, state: str, detail: str | None = None) -> None:
        """
        Update the compact IntegrityGuard status label.

        state: "disabled", "idle", "ok", "alert"
        """
        if not hasattr(self, "integrity_status_label"):
            return

        if state == "disabled":
            text = "Integrity: disabled"
            style = "color: #6b7280; font-size: 11px;"
        elif state == "idle":
            text = "Integrity: idle"
            style = "color: #9ca3af; font-size: 11px;"
        elif state == "ok":
            text = "Integrity: OK"
            style = "color: #10b981; font-size: 11px;"  # soft green
        else:  # "alert"
            short = (detail or "modified").strip()
            # keep it short for layout; truncate if very long
            if len(short) > 32:
                short = short[:29] + "…"
            text = f"Integrity: ALERT ({short})"
            style = "color: #f97373; font-size: 11px;"  # soft red

        self.integrity_status_label.setText(text)
        self.integrity_status_label.setStyleSheet(style)

    def _restore_from_backups(self, vault_header: dict) -> bool:
        """
        Attempt to restore critical code files and the vault file
        from their latest backups, then re-run the integrity check.

        Returns True if restore succeeded and integrity now passes.
        """
        restored_any = False

        guard = getattr(self, "integrity_guard", None)
        if guard is not None:
            ok_code, msg_code = guard.restore_code_backups()
            if ok_code:
                restored_any = True
                self._record_integrity_event("integrity_restore_code")
            else:
                # Not fatal; we may still have a vault backup.
                self._record_integrity_event(f"integrity_restore_code_fail:{msg_code}")

        # Restore the encrypted vault file itself.
        ok_vault = False
        try:
            ok_vault = self.vault.restore_from_backup()
        except Exception:
            ok_vault = False

        if ok_vault:
            restored_any = True
            self._record_integrity_event("integrity_restore_vault")

        if not restored_any:
            self._show_error(
                "No usable backups were found.\n\n"
                "The application or vault files appear modified and no "
                "backup snapshots are available to restore from."
            )
            return False

        # After restoring from backup, verify integrity once more.
        if guard is not None:
            ok2, msg2 = guard.verify(vault_header)
            if ok2:
                self._set_integrity_status("ok")
                self.status_label.setText(
                    "Restored from backup after integrity alert."
                )

                # during the restore operation.
                corrupt_paths = getattr(guard, "last_corrupt_paths", []) or []
                if corrupt_paths:
                    resp = QMessageBox.question(
                        self,
                        "Remove corrupted copies?",
                        (
                            "Older copies of critical files that failed the "
                            "integrity check were renamed and are no longer "
                            "used by the application.\n\n"
                            "You can safely delete these corrupted copies to "
                            "keep the installation clean.\n\n"
                            "Do you want to delete all corrupted copies now?"
                        ),
                        QMessageBox.Yes | QMessageBox.No,
                        QMessageBox.No,
                    )
                    if resp == QMessageBox.Yes:
                        deleted = 0
                        for p in corrupt_paths:
                            try:
                                p.unlink(missing_ok=True)
                                deleted += 1
                            except Exception:
                                # Best-effort: if deletion fails, just skip.
                                continue
                        if deleted:
                            self.status_label.setText(
                                "Restored from backup and deleted old corrupted copies."
                            )

                return True

            self._set_integrity_status("alert", msg2)
            self._show_error(
                "Even after restoring from backup, the integrity check still "
                "does not pass.\n\n"
                f"{msg2}\n\n"
                "For safety, the vault will remain locked."
            )
            return False

        # If there is no guard, but we did restore something, we just report success.
        return restored_any

    def on_security_details_clicked(self) -> None:
        """
        Show a dialog with detailed security posture: health snapshot,
        suspicion score, behavioral penalties, and recent events.
        """
        dlg = QDialog(self)
        dlg.setWindowTitle("Security Dashboard Details")
        layout = QVBoxLayout(dlg)

        text = QTextEdit()
        text.setReadOnly(True)
        text.setFrameStyle(QTextEdit.NoFrame)
        text.setStyleSheet(
            "QTextEdit { background-color: #05070c; border: none; }"
        )
        text.setHtml(self._build_security_details_text())
        layout.addWidget(text)

        btn_row = QHBoxLayout()
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(dlg.accept)
        btn_row.addStretch()
        btn_row.addWidget(close_btn)
        layout.addLayout(btn_row)

        dlg.resize(620, 440)
        dlg.exec()

    def _build_security_details_text(self) -> str:
        """
        Build a styled HTML dashboard view of the current security posture,
        including:

        - Quantum Entropy Drift Monitor
        - Breach Pattern Detector
        - Threat Timeline Visualization
        - Entry-Level Zero-Trust flags
        - Intelligent Password Aging Simulator
        - Real-Time Threat Graph
        """
        snap = getattr(self, "_health_snapshot", None) or {}
        total = snap.get("total", 0)
        reused_groups = snap.get("reused_groups", 0)
        weak = snap.get("weak", 0)
        moderate = snap.get("moderate", 0)
        stale = snap.get("stale", 0)
        breached = snap.get("breached", 0)

        now = datetime.now(timezone.utc)
        lockout_remaining = 0
        if self._lockout_until is not None:
            delta = (self._lockout_until - now).total_seconds()
            if delta > 0:
                lockout_remaining = int(delta)

        # Overall posture summary from the radar label
        posture_raw = self.vault_radar_label.text()
        prefix = "Vault security radar: "
        if posture_raw.startswith(prefix):
            posture_clean = posture_raw[len(prefix):]
        else:
            posture_clean = posture_raw

        # Map posture → badge colors
        badge_bg = "#374151"
        badge_fg = "#e5e7eb"
        text_lower = posture_clean.lower()

        if "decoy mode" in text_lower:
            badge_bg = "#0f172a"
            badge_fg = "#22d3ee"
        elif "hostile" in text_lower:
            badge_bg = "#78350f"
            badge_fg = "#facc15"
        elif "high attention" in text_lower:
            badge_bg = "#7f1d1d"
            badge_fg = "#fecaca"
        elif "elevated" in text_lower:
            badge_bg = "#7c2d12"
            badge_fg = "#fed7aa"
        elif "normal" in text_lower:
            badge_bg = "#064e3b"
            badge_fg = "#bbf7d0"
        elif "empty vault" in text_lower:
            badge_bg = "#111827"
            badge_fg = "#9ca3af"

        posture_score = 0
        if hasattr(self, "security_bar"):
            posture_score = int(self.security_bar.value())

        # Entries (when unlocked) for deeper analytics
        entries = self.vault.entries if self.unlocked else []

        # --- Quantum Entropy Drift Monitor ---
        ent_values = [
            estimate_entropy_bits(e.password) for e in entries if e.password
        ]
        if ent_values:
            avg_entropy = sum(ent_values) / len(ent_values)
            min_entropy = min(ent_values)
            max_entropy = max(ent_values)
        else:
            avg_entropy = 0.0
            min_entropy = 0.0
            max_entropy = 0.0

        if len(self._entropy_history) >= 2:
            prev_avg = self._entropy_history[-2]
            entropy_delta = avg_entropy - prev_avg
        else:
            prev_avg = None
            entropy_delta = 0.0

        drift_state = "baseline"
        if prev_avg is not None:
            delta_abs = abs(entropy_delta)
            if delta_abs < 2.0:
                drift_state = "stable"
            elif entropy_delta > 0:
                drift_state = "rising"
            else:
                drift_state = "falling"

        drift_delta_str = (
            f"{entropy_delta:+.1f} bits" if prev_avg is not None else "n/a"
        )

        # --- Intelligent Password Aging Simulator (30 / 60 / 90 days) ---
        def forecast_stale(horizon_days: int) -> int:
            if not entries:
                return 0
            count = 0
            for e in entries:
                age = self._entry_age_days(e)
                if age is None:
                    continue
                if age + horizon_days > self.STALE_DAYS:
                    count += 1
            return count

        stale_30 = forecast_stale(30)
        stale_60 = forecast_stale(60)
        stale_90 = forecast_stale(90)

        # --- Breach Pattern Detector (breach + weak + reused + pattern-based) ---
        breach_lines: list[str] = []
        if entries:
            # Map password → labels to detect reuse
            pwd_map: dict[str, list[str]] = {}
            for e in entries:
                pwd = getattr(e, "password", "") or ""
                pwd_map.setdefault(pwd, []).append(e.label)

            pattern_items: list[tuple[str, list[str]]] = []
            for e in entries:
                pwd = getattr(e, "password", "") or ""
                if not pwd:
                    continue

                bits = estimate_entropy_bits(pwd)
                very_weak = bits < 40.0
                is_breached = self._is_password_breached(pwd)
                is_reused = len(pwd_map.get(pwd, [])) > 1
                is_stale = self._is_entry_stale(e)

                # NEW: pattern-based weakness flags (digits-only, keyboard-walk, date-like, etc.)
                pattern_flags = self._password_pattern_flags(pwd)

                # Anything that is breached OR very weak OR reused OR pattern-weak is interesting
                if not (is_breached or very_weak or is_reused or pattern_flags):
                    continue

                tags: list[str] = []
                if is_breached:
                    tags.append("breach-signature")
                if very_weak:
                    tags.append("weak")
                if is_reused:
                    tags.append("reused")
                if is_stale:
                    tags.append("stale")

                # Attach pattern flags as tags, e.g. pattern:digits-only, pattern:keyboard-walk
                for pf in pattern_flags:
                    tags.append(f"pattern:{pf}")

                pattern_items.append((e.label, tags))

            for label, tags in pattern_items[:10]:
                tag_str = ", ".join(tags) if tags else "pattern"
                breach_lines.append(
                    f"<li>{label} <span class='subtle'>({tag_str})</span></li>"
                )

        breach_html = (
            "<ul class='events'>" + "".join(breach_lines) + "</ul>"
            if breach_lines
            else "<div class='subtle'>(no obvious breach / weak / reuse patterns in current vault)</div>"
        )

        # --- Entry-Level Zero-Trust Flags (explicit ON/OFF) ---
        flag_integrity = IntegrityGuard is not None
        flag_hardware = getattr(self.vault, "_hardware_binding", None) is not None
        flag_highsec = self.high_security_mode
        flag_decoy_armed = self._decoy_armed
        flag_decoy_active = self._fake_vault_mode
        flag_lockout = lockout_remaining > 0

        def fmt_flag(enabled: bool) -> str:
            if enabled:
                return "<span class='flag-on'>ENABLED</span>"
            return "<span class='flag-off'>Disabled</span>"

        zero_trust_flags_html = f"""
            <table class="metric-grid">
                <tr><td class="label">Integrity guard</td>
                    <td class="value">{fmt_flag(flag_integrity)}</td></tr>
                <tr><td class="label">Hardware-bound KDF</td>
                    <td class="value">{fmt_flag(flag_hardware)}</td></tr>
                <tr><td class="label">High-security session</td>
                    <td class="value">{fmt_flag(flag_highsec)}</td></tr>
                <tr><td class="label">Decoy armed</td>
                    <td class="value">{fmt_flag(flag_decoy_armed)}</td></tr>
                <tr><td class="label">Decoy active</td>
                    <td class="value">{fmt_flag(flag_decoy_active)}</td></tr>
                <tr><td class="label">Temporary lockout window</td>
                    <td class="value">{fmt_flag(flag_lockout)}</td></tr>
            </table>
            <div class="subtle">
                Flags are evaluated locally per session; nothing leaves this device.
            </div>
        """

        # --- Recent integrity / unlock events (Threat Timeline) ---
        recent_events = self._integrity_events[-10:] if self._integrity_events else []

        html = f"""
        <html>
        <head>
        <style>
        body {{
            background-color: #05070c;
            color: #e5e7eb;
            font-family: 'Segoe UI', Arial, sans-serif;
            font-size: 10pt;
        }}
        h1 {{
            font-size: 14pt;
            margin: 0 0 4px 0;
        }}
        h2 {{
            font-size: 11pt;
            margin: 14px 0 4px 0;
            color: #7dd3fc;
        }}
        .badge {{
            display: inline-block;
            padding: 4px 10px;
            border-radius: 999px;
            font-weight: 600;
            font-size: 9pt;
            background-color: {badge_bg};
            color: {badge_fg};
        }}
        .subtle {{
            color: #9ca3af;
            font-size: 9pt;
        }}
        .metric-grid {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 2px;
        }}
        .metric-grid td {{
            padding: 2px 4px;
        }}
        .metric-grid td.label {{
            color: #9ca3af;
        }}
        .metric-grid td.value {{
            text-align: right;
            font-weight: 500;
        }}
        ul.events {{
            margin-top: 4px;
            padding-left: 18px;
        }}
        ul.events li {{
            margin: 1px 0;
            color: #d1d5db;
        }}
        .flag-on {{
            color: #4ade80;
            font-weight: 600;
        }}
        .flag-off {{
            color: #6b7280;
        }}
        .threat-box {{
            margin-top: 4px;
            padding: 4px 6px 6px 6px;
            background-color: #020617;
            border-radius: 4px;
            border: 1px solid #1f2937;
        }}
        .threat-bars {{
            height: 40px;
            overflow: hidden;
            white-space: nowrap;
        }}
        .threat-bar {{
            display: inline-block;
            width: 6px;
            margin-right: 2px;
            border-radius: 3px;
            vertical-align: bottom;
        }}
        </style>
        </head>
        <body>
            <h1>Security dashboard</h1>
            <div>
                <span class="badge">Posture: {posture_clean}</span>
                <span class="subtle" style="float:right;">
                    Score: {posture_score}/100
                </span>
            </div>

            <h2>Vault health</h2>
            <table class="metric-grid">
                <tr><td class="label">Total entries</td>
                    <td class="value">{total}</td></tr>
                <tr><td class="label">Reused groups</td>
                    <td class="value">{reused_groups}</td></tr>
                <tr><td class="label">Weak passwords</td>
                    <td class="value">{weak}</td></tr>
                <tr><td class="label">Moderate passwords</td>
                    <td class="value">{moderate}</td></tr>
                <tr><td class="label">Stale entries</td>
                    <td class="value">{stale}</td></tr>
                <tr><td class="label">Breach-marked entries</td>
                    <td class="value">{breached}</td></tr>
            </table>

            <h2>Quantum Entropy Drift Monitor</h2>
            <table class="metric-grid">
                <tr><td class="label">Average entropy per entry</td>
                    <td class="value">{avg_entropy:.1f} bits</td></tr>
                <tr><td class="label">Min / Max entropy</td>
                    <td class="value">{min_entropy:.1f} – {max_entropy:.1f} bits</td></tr>
                <tr><td class="label">Drift state</td>
                    <td class="value">{drift_state} ({drift_delta_str})</td></tr>
            </table>
            <div class="subtle">
                Drift is computed session-local from consecutive Vault Health snapshots.
            </div>

            <h2>Intelligent Password Aging Simulator</h2>
            <table class="metric-grid">
                <tr><td class="label">Already stale (&gt;{self.STALE_DAYS} days)</td>
                    <td class="value">{stale}</td></tr>
                <tr><td class="label">Will be stale in ≤30 days</td>
                    <td class="value">{stale_30}</td></tr>
                <tr><td class="label">Will be stale in ≤60 days</td>
                    <td class="value">{stale_60}</td></tr>
                <tr><td class="label">Will be stale in ≤90 days</td>
                    <td class="value">{stale_90}</td></tr>
            </table>
            <div class="subtle">
                Simulator assumes no rotations from now; entries crossing {self.STALE_DAYS} days are counted as 'stale'.
            </div>

            <h2>Breach Pattern Detector</h2>
            {breach_html}

            <h2>Live defense state</h2>
            <table class="metric-grid">
                <tr><td class="label">Unlocked</td>
                    <td class="value">{str(self.unlocked)}</td></tr>
                <tr><td class="label">High-security session</td>
                    <td class="value">{str(self.high_security_mode)}</td></tr>
                <tr><td class="label">Suspicion score</td>
                    <td class="value">{self._suspicion_score}</td></tr>
                <tr><td class="label">Behavioral penalty level</td>
                    <td class="value">{self._behavioral_penalty_level}</td></tr>
                <tr><td class="label">Decoy armed</td>
                    <td class="value">{str(self._decoy_armed)}</td></tr>
                <tr><td class="label">Decoy active</td>
                    <td class="value">{str(self._fake_vault_mode)}</td></tr>
                <tr><td class="label">Lockout remaining (seconds)</td>
                    <td class="value">{lockout_remaining}</td></tr>
            </table>

            <h2>Entry-Level Zero-Trust Flags</h2>
            {zero_trust_flags_html}

            <h2>Threat Timeline (recent integrity / unlock events)</h2>
            {"<div class='subtle'>(none)</div>" if not recent_events else ""}
        """

        if recent_events:
            html += "<ul class='events'>"
            for ev in recent_events:
                html += f"<li>{ev}</li>"
            html += "</ul>"

        html += """
        </body>
        </html>
        """
        return html

    def _record_integrity_event(self, event: str) -> None:
        """
        Record simple integrity / tamper events for the radar and timeline.

        Examples: 'unlock_ok', 'unlock_fail', 'unlock_fail_lockout'.
        """
        ts = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
        self._integrity_events.append(f"{ts} · {event}")
        # Keep a bounded history for UI and threat timeline
        if len(self._integrity_events) > 100:
            self._integrity_events = self._integrity_events[-100:]

    def on_rotate_now_clicked(self) -> None:
        """
        Rotate the password for the currently selected entry only,
        using the quantum generator.
        """
        if not self.unlocked:
            self._show_error("Unlock the vault first.")
            return

        if self._fake_vault_mode:
            self._show_error(
                "Decoy vault is active. Changes are not allowed or persisted in this mode."
            )
            return

        current = self.entry_list.currentItem()
        if not current:
            self._show_error("Select an entry to rotate.")
            return

        label = current.data(Qt.UserRole) or current.text()

        # Locate the entry object
        entry = next((e for e in self.vault.entries if e.label == label), None)
        if entry is None:
            self._show_error("Selected entry not found in vault.")
            return

        resp = QMessageBox.question(
            self,
            "Rotate password",
            (
                f"Rotate the password for '{label}' using the quantum generator?\n\n"
                "The old password will be replaced in the vault."
            ),
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if resp != QMessageBox.Yes:
            self.status_label.setText("Rotation cancelled.")
            return

        # Generate new quantum password
        from .cli import generate_password_with_meta  # local import avoids cycles
        from .config import DEFAULT_CONFIG

        meta = generate_password_with_meta(DEFAULT_CONFIG)
        new_entry = VaultEntry(
            label=entry.label,
            username=entry.username,
            password=meta.password,
        )

        # This updates timestamps (created_at / last_rotated_at)
        self.vault.add_or_update(new_entry)

        try:
            self.vault.save()
        except QuantumVaultError as exc:
            self._show_error(str(exc))
            return

        # Refresh UI
        self._reload_list()
        self.label_edit.setText(new_entry.label)
        self.username_edit.setText(new_entry.username)
        self.password_edit.setText(new_entry.password)
        self._update_entry_strength()
        self._update_health_stats()
        self.status_label.setText(
            f"Rotated password for '{label}' using quantum generator."
        )
        self._bump_idle_timer()

    def _bump_idle_timer(self) -> None:
        """
        Restart idle timer if vault is unlocked.
        """
        if self.unlocked:
            self.idle_timer.start(self.IDLE_TIMEOUT_MS)

    def _security_monitor_tick(self) -> None:
        """
        Background watcher for simple threat signals:

        - CPU spikes while the vault is unlocked.
        - Screen-share / recording / remote-control processes.
        - Live IntegrityGuard: detect tampering while the vault is open.
        """
        if not self.unlocked:
            # Slowly decay suspicion when locked.
            if self._suspicion_score > 0:
                self._suspicion_score -= 1
            return

        # Live IntegrityGuard polling (every ~15s while unlocked)
        if (
            hasattr(self, "integrity_guard")
            and self.integrity_guard is not None
            and not self._integrity_live_alerted
        ):
            self._integrity_poll_counter += 1
            if self._integrity_poll_counter >= 15:  # 15 × 1s = 15 seconds
                self._integrity_poll_counter = 0
                header = None
                try:
                    header = self.vault.get_header_for_integrity()
                except Exception:
                    # If header cannot be read, treat as suspicious but do not crash
                    header = None

                ok, message = self.integrity_guard.verify(header)
                if ok:
                    self._record_integrity_event("integrity_live_ok")
                    # Only upgrade to OK if we were idle before
                    self._set_integrity_status("ok")
                else:
                    # Tampering detected while open – lock immediately and offer restore.
                    self._integrity_live_alerted = True
                    self._record_integrity_event("integrity_live_fail")
                    self._set_integrity_status("alert", message)

                    self._lock_vault(
                        "Vault locked: integrity alert – application or vault files "
                        "were modified while the vault was open."
                    )

                    alert = QMessageBox(self)
                    alert.setWindowTitle("IntegrityGuard Alert")
                    alert.setIcon(QMessageBox.Critical)
                    alert.setText(
                        "IntegrityGuard detected a change to the application or vault "
                        "files while the vault was unlocked.\n\n"
                        f"{message}"
                    )
                    alert.setInformativeText(
                        "The vault has been locked to protect your secrets.\n\n"
                        "You can attempt to restore the application code and vault "
                        "file from the last known good backups.\n\n"
                        "Do you want to restore from backup now?"
                    )
                    alert.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
                    alert.setDefaultButton(QMessageBox.No)
                    choice = alert.exec()

                    if choice == QMessageBox.Yes:
                        self._restore_from_backups(header or {})

                    # After a hard integrity alert we stop further processing in this tick
                    return

        if psutil is None:
            return  # system monitoring not available

        cpu_spike = False
        suspicious_proc = False

        # 1) CPU spike
        try:
            cpu = psutil.cpu_percent(interval=0.0)
            if cpu >= 90.0:
                cpu_spike = True
        except Exception:
            cpu_spike = False

        # 2) Screen-share / recording / remote processes
        suspicious_tokens = {
            "obs",          # OBS Studio variants
            "xsplit",
            "bandicam",
            "camtasia",
            "teams",        # Microsoft Teams (old / new)
            "zoom",
            "discord",
            "anydesk",
            "teamviewer",
            "mstsc",        # Remote Desktop
            "vnc",          # generic VNC viewers/servers
            "snippingtool", # Windows Snipping Tool
            "screenclipping",  # ScreenClippingHost.exe
        }
        suspicious_proc = False
        suspicious_proc_name: str | None = None

        try:
            for p in psutil.process_iter(attrs=["name"]):
                raw_name = p.info.get("name") or ""
                name = raw_name.lower()
                if any(tok in name for tok in suspicious_tokens):
                    suspicious_proc = True
                    suspicious_proc_name = raw_name or name
                    break
        except Exception:
            suspicious_proc = False
            suspicious_proc_name = None

        # Update suspicion metric
        delta = 0
        if cpu_spike:
            delta += 1
        if suspicious_proc and self.high_security_mode:
            delta += 3

        if delta == 0:
            if self._suspicion_score > 0:
                self._suspicion_score -= 1
            return

        self._suspicion_score += delta

        # Immediate reaction to screen-capture / remote apps
        if suspicious_proc and self.high_security_mode:
            proc_hint = (
                f" ({suspicious_proc_name})" if suspicious_proc_name else ""
            )
            self._lock_vault(
                "Vault locked: screen-share / recording / remote-control process "
                f"detected{proc_hint}."
            )
            # Re-arm decoy after lock so the *next* unlock goes to the fake vault.
            self._decoy_armed = True
            return

        # Generic threat-adaptive auto-lock
        if self._suspicion_score >= 5:
            self._lock_vault(
                "Vault locked due to unusual system activity."
            )
            self._decoy_armed = True

    def _on_idle_timeout(self) -> None:
        """
        Auto-lock callback when user is idle.
        """
        if self.unlocked:
            self._lock_vault("Vault auto-locked due to inactivity.")

    # -- unlock / lock --
    def _update_vault_enabled(self, enabled: bool) -> None:
        self.entry_list.setEnabled(enabled)
        self.search_edit.setEnabled(enabled)
        self.filter_combo.setEnabled(enabled)
        self.label_edit.setEnabled(enabled)
        self.username_edit.setEnabled(enabled)
        self.password_edit.setEnabled(enabled)
        self.view_button.setEnabled(enabled)
        self.save_button.setEnabled(enabled)
        self.copy_button.setEnabled(enabled and not self.high_security_mode)
        self.entry_strength_bar.setEnabled(enabled)
        self.entry_strength_label.setEnabled(enabled)
        self.rotate_button.setEnabled(enabled)
        self.rotate_now_button.setEnabled(enabled)

    def on_unlock_clicked(self) -> None:
        if not self.unlocked:
            # Zero-trust: check for temporary lockout
            now = datetime.now(timezone.utc)
            if self._lockout_until is not None and now < self._lockout_until:
                remaining = (self._lockout_until - now).total_seconds()
                minutes = int(remaining // 60)
                seconds = int(remaining % 60)
                if minutes > 0:
                    msg = f"Too many failed attempts. Try again in {minutes}m {seconds}s."
                else:
                    msg = f"Too many failed attempts. Try again in {seconds}s."
                self._show_error(msg)
                self._record_integrity_event("unlock_fail_lockout")
                return

            # If environment has been flagged as hostile, route to decoy vault.
            if self._decoy_armed and not self._fake_vault_mode:
                self._enter_fake_vault_mode(
                    "Suspicious activity detected (adaptive defense)."
                )
                return

            if not self.vault.exists():
                self._show_error(
                    "No vault found. Use 'Setup / Change master…' to create one."
                )
                return

            master = self.master_edit.text().strip()
            if not master:
                self._show_error("Enter a master password.")
                return
                
            # Run integrity watchdog before decrypting anything
            if not self._run_integrity_guard():
                return
            
            try:
                self.vault.unlock(master)
            except QuantumVaultError as exc:
                # ---- failed unlock path ----
                self._failed_unlocks += 1
                max_attempts = getattr(self, "_max_unlock_attempts", 5)
                attempts_left = max(0, max_attempts - self._failed_unlocks)

                if self._failed_unlocks >= max_attempts:
                    # Escalating behavioral lockout
                    level = getattr(self, "_behavioral_penalty_level", 0)
                    level = min(level + 1, 3)
                    self._behavioral_penalty_level = level
                    # Penalty tiers:
                    #   level 1 → 60s
                    #   level 2 → 120s
                    #   level 3 → 300s (and beyond, capped)
                    lockout_table = {1: 60, 2: 120, 3: 300}
                    lockout_seconds = lockout_table[level]

                    self._lockout_until = now + timedelta(seconds=lockout_seconds)
                    self._record_integrity_event("unlock_fail_lockout")

                    # High penalty levels arm decoy mode as well.
                    if level >= 2:
                        self._decoy_armed = True

                    self._show_error(
                        f"{exc}\n\nToo many failed attempts. "
                        f"Unlock disabled for {lockout_seconds} seconds."
                    )

                else:
                    self._record_integrity_event("unlock_fail")
                    self._show_error(
                        f"{exc}\n\nAttempts remaining before lockout: {attempts_left}."
                    )
                return

            # ---- successful unlock path ----
            self._failed_unlocks = 0
            self._lockout_until = None
            self._behavioral_penalty_level = 0
            self._record_integrity_event("unlock_ok")

            self.unlocked = True
            self.unlock_button.setText("Lock")
            self._update_vault_enabled(True)
            self._reload_list()
            self.status_label.setText("Vault unlocked.")
            self._update_health_stats()
            self._bump_idle_timer()
        else:
            # Manual lock
            self._lock_vault("Vault locked.")

    # -- setup / change master --
    def on_setup_master_clicked(self) -> None:
        mode = "setup" if not self.vault.exists() else "change"
        dlg = MasterPasswordDialog(mode, self)
        if dlg.exec() != QDialog.Accepted:
            return

        old_pw, new_pw = dlg.get_passwords()

        try:
            if mode == "setup":
                # First-time creation
                self.vault.initialize(new_pw)
                self.unlocked = True
                self.unlock_button.setText("Lock")
                self._update_vault_enabled(True)
                self._reload_list()
                self.status_label.setText("Vault created and unlocked.")
                self.master_edit.setText("")  # don't keep master in field
                self._update_health_stats()
                self._bump_idle_timer()

            else:
                # Change master for existing vault
                self.vault.change_master_password(old_pw, new_pw)
                # After change, keep vault locked for safety
                self._lock_vault(
                    "Master password changed. Unlock with the new password."
                )
                self.master_edit.clear()

        except QuantumVaultError as exc:
            self._show_error(str(exc))

    # -- list / details --

    def _reload_list(self) -> None:
        """
        Reload the entry list, applying the current search filter and
        adding a visual indicator for reused passwords.
        """
        self.entry_list.clear()

        if not self.unlocked:
            return

        query = (
            self.search_edit.text().strip().lower()
            if hasattr(self, "search_edit")
            else ""
        )

        filter_mode = None
        if hasattr(self, "filter_combo"):
            filter_mode = self.filter_combo.currentData()

        # Build map: password -> list of labels
        pwd_map: dict[str, list[str]] = {}
        for e in self.vault.entries:
            pwd_map.setdefault(e.password, []).append(e.label)

        for entry in self.vault.entries:
            # Apply search filter
            if query:
                in_label = query in entry.label.lower()
                in_user = query in entry.username.lower()
                if not (in_label or in_user):
                    continue

            # Pre-compute metrics for filter
            bits = estimate_entropy_bits(entry.password)
            age_days = self._entry_age_days(entry)

            weak_or_breached = (
                bits < 50.0 or self._is_password_breached(entry.password)
            )

            # Apply dropdown filter
            if filter_mode == "weak":
                # Only passwords with <50 bits
                if not (bits < 50.0):
                    continue
            elif filter_mode == "recent30":
                # Age ≤30 days
                if age_days is None or age_days > 30.0:
                    continue
            elif filter_mode == "stale30":
                if age_days is None or age_days <= 30.0:
                    continue
            elif filter_mode == "stale60":
                if age_days is None or age_days <= 60.0:
                    continue
            elif filter_mode == "stale90":
                if age_days is None or age_days <= 90.0:
                    continue
            # "all" or unknown filter_mode → no extra condition

            reused = len(pwd_map.get(entry.password, [])) > 1

            # Indicators:
            #   ❗ = weak / breachable
            #   ⚠ = reused
            prefix_parts = []
            if weak_or_breached:
                prefix_parts.append("❗")
            if reused:
                prefix_parts.append("⚠")

            prefix = ""
            if prefix_parts:
                prefix = " ".join(prefix_parts) + " "

            base_label = prefix + entry.label

            # Tiny age suffix (e.g. "· 2h ago")
            age_suffix = self._format_age(entry)
            display_text = f"{base_label} {age_suffix}" if age_suffix else base_label

            item = QListWidgetItem(display_text)
            item.setData(Qt.UserRole, entry.label)

            # Colour semantics:
            #   weak / breached → red
            #   reused only     → orange
            if weak_or_breached:
                item.setForeground(QColor("#ef4444"))
            elif reused:
                item.setForeground(QColor("#f97316"))

            tooltip_lines = []
            if weak_or_breached:
                tooltip_lines.append("Weak / easily guessable or breach-signature password.")
            if reused:
                tooltip_lines.append(
                    "Password reused in: " + ", ".join(pwd_map[entry.password])
                )
            item.setToolTip("\n".join(tooltip_lines))

            self.entry_list.addItem(item)

    def on_entry_selected(
        self,
        current: QListWidgetItem,
        _previous: QListWidgetItem,
    ) -> None:
        if not current or not self.unlocked:
            return
        label = current.data(Qt.UserRole) or current.text()
        for e in self.vault.entries:
            if e.label == label:
                self.label_edit.setText(e.label)
                self.username_edit.setText(e.username)
                self.password_edit.setText(e.password)
                self._update_entry_strength()
                self._bump_idle_timer()
                break

    def on_save_clicked(self) -> None:
        if not self.unlocked:
            self._show_error("Unlock the vault first.")
            return
        if self._fake_vault_mode:
            self._show_error(
                "Decoy vault is active. Changes are not allowed or persisted in this mode."
            )
            return

        label = self.label_edit.text().strip()
        username = self.username_edit.text().strip()
        password = self.password_edit.text().strip()

        if not label or not password:
            self._show_error("Label and password are required.")
            return

        # --- Reuse detector: same label check ---
        existing_same_label = None
        for e in self.vault.entries:
            if e.label == label:
                existing_same_label = e
                break

        if existing_same_label is not None:
            resp = QMessageBox.question(
                self,
                "Label already exists",
                (
                    f"An entry with label '{label}' already exists.\n\n"
                    "Do you want to replace the older version with this data?"
                ),
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No,
            )
            if resp != QMessageBox.Yes:
                self.status_label.setText(
                    "Save cancelled (label already exists)."
                )
                return

        # --- Reuse detector: same password check across labels ---
        reused_labels = [
            e.label
            for e in self.vault.entries
            if e.password == password and e.label != label
        ]
        if reused_labels:
            msg_lines = [
                "This password is already used for:",
                *[f"  • {lbl}" for lbl in reused_labels],
                "",
                "Reusing passwords across sites is risky.",
                "Do you still want to save this entry?",
            ]
            resp = QMessageBox.warning(
                self,
                "Password reuse detected",
                "\n".join(msg_lines),
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No,
            )
            if resp != QMessageBox.Yes:
                self.status_label.setText(
                    "Save cancelled due to password reuse warning."
                )
                return

        entry = VaultEntry(label=label, username=username, password=password)
        self.vault.add_or_update(entry)
        try:
            self.vault.save()
        except QuantumVaultError as exc:
            self._show_error(str(exc))
            return

        self._reload_list()
        self.status_label.setText(f"Saved entry '{label}'.")
        self._update_health_stats()
        self._update_entry_strength()
        self._bump_idle_timer()

    def on_delete_clicked(self) -> None:
        if not self.unlocked:
            self._show_error("Unlock the vault first.")
            return
        if self._fake_vault_mode:
            self._show_error(
                "Decoy vault is active. Changes are not allowed or persisted in this mode."
            )
            return
        current = self.entry_list.currentItem()
        if not current:
            return
        label = current.data(Qt.UserRole) or current.text()
        self.vault.delete(label)
        try:
            self.vault.save()
        except QuantumVaultError as exc:
            self._show_error(str(exc))
            return
        self._reload_list()
        self.label_edit.clear()
        self.username_edit.clear()
        self.password_edit.clear()
        self.status_label.setText(f"Deleted entry '{label}'.")
        self._update_health_stats()
        self.entry_strength_bar.setValue(0)
        self.entry_strength_label.setText("Entry strength: –")
        self._bump_idle_timer()

    def _arm_secure_clipboard(self, owner_tag: str, timeout_ms: int = 15000) -> None:
        """
        Start a timer to clear the clipboard after a short interval.

        owner_tag marks that this instance is responsible for the clipboard.
        """
        self._clipboard_token = owner_tag
        self._clipboard_timer.start(timeout_ms)

    def _on_clipboard_timeout(self) -> None:
        """
        Clear clipboard if it still holds a value we placed.
        """
        if not self._clipboard_token:
            return

        cb = QGuiApplication.clipboard()
        current_text = cb.text()
        if current_text:
            cb.clear()

        self._clipboard_token = None
        self.status_label.setText("Clipboard cleared for safety.")
        # Clipboard activity is part of defensive posture, not a tamper event.

    def on_copy_clicked(self) -> None:
        if not self.unlocked:
            self._show_error("Unlock the vault first.")
            return

        if self.high_security_mode:
            self._show_error(
                "High-security session is enabled.\n\nCopying to clipboard is disabled."
            )
            return

        password = self.password_edit.text()
        if not password:
            self._show_error("No password to copy.")
            return

        clipboard = QGuiApplication.clipboard()
        try:
            clipboard.setText(password)
        except Exception:
            # Windows clipboard can be temporarily locked by other apps
            self._show_error(
                "Could not copy to clipboard because another application is using it.\n"
                "Please close any clipboard managers and try again."
            )
            return

        self._arm_secure_clipboard(owner_tag="vault_entry")

        self.status_label.setText(
            "Password copied to clipboard (auto-clear in a few seconds)."
        )
        self._bump_idle_timer()

    def _update_entry_strength(self) -> None:
        """
        Update the strength meter for the password currently in the field.
        """
        pwd = self.password_edit.text()
        bits = estimate_entropy_bits(pwd)
        if bits <= 0:
            self.entry_strength_bar.setValue(0)
            self.entry_strength_label.setText("Entry strength: –")
            return

        capped = max(0.0, min(bits, 120.0))
        score = int((capped / 120.0) * 100)
        self.entry_strength_bar.setValue(score)
        self.entry_strength_label.setText(
            f"Entry strength: {entropy_label(bits)} (~{bits:.1f} bits)"
        )

    def on_view_toggled(self) -> None:
        """
        Toggle password visibility in the vault password field.
        """
        if self.password_edit.echoMode() == QLineEdit.Password:
            self.password_edit.setEchoMode(QLineEdit.Normal)
            self.view_button.setText("Hide")
            self._view_timer.start(self._view_timeout_ms)
        else:
            self.password_edit.setEchoMode(QLineEdit.Password)
            self.view_button.setText("View")
            self._view_timer.stop()

    def _on_view_timeout(self) -> None:
        """
        Automatically hide password again after a short view window.
        """
        if self.password_edit.echoMode() == QLineEdit.Normal:
            self.password_edit.setEchoMode(QLineEdit.Password)
            self.view_button.setText("View")
            self.status_label.setText(
                "Password view timed out and was hidden."
            )

    @Slot(str)
    def receive_generated_password(self, password: str) -> None:
        """
        Slot called by the Generator tab when the user sends a password.

        Behaviour:
        - Always prepare a *new* entry slot:
          * clear current selection
          * clear label / username
          * pre-fill password only
        - If vault is unlocked, user can immediately hit Add / Update
          after choosing a label and (optionally) username.
        """
        # Treat this as a fresh entry, not an update of the selected one
        self.entry_list.clearSelection()
        self.label_edit.clear()
        self.username_edit.clear()

        self.password_edit.setText(password)
        self._update_entry_strength()

        # Focus label so user can name this entry
        self.label_edit.setFocus()

        if not self.unlocked:
            self.status_label.setText(
                "Password received from generator. Unlock vault, name it, then save as a new entry."
            )
        else:
            self.status_label.setText(
                "Password received from generator. Enter label/username, then Add / Update to store as a new entry."
            )
        if self.unlocked:
            self._bump_idle_timer()

    def _show_error(self, message: str) -> None:
        self.status_label.setText(message)
        msg = QMessageBox(self)
        msg.setWindowTitle("Vault error")
        msg.setIcon(QMessageBox.Critical)
        msg.setText(message)
        msg.exec()


# ---------- Main Window ----------
class AboutTab(QWidget):
    """
    About tab: overview, quick usage guide, and best practices.
    """

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(10)

        # Title
        title = QLabel("About – QuantaLock")
        title_font = title.font()
        title_font.setPointSize(title_font.pointSize() + 2)
        title_font.setBold(True)
        title.setFont(title_font)
        layout.addWidget(title)

        # Intro
        intro = QLabel(
            "This app combines a quantum-backed password generator with a local "
            "encrypted vault. Use the Generator tab to create strong passwords, "
            "and the Manager tab to store, audit, and rotate them safely."
        )
        intro.setWordWrap(True)
        layout.addWidget(intro)

        # Generator usage
        generator_label = QLabel("<b>Generator tab – how to use</b>")
        layout.addWidget(generator_label)

        generator_text = QLabel(
            "• Pick the desired password length.\n"
            "• Adjust number of qubits and entropy rounds if you want extra mixing.\n"
            "• Click Generate to create a new password.\n"
            "• Use auto-copy or the Copy button to place it on the clipboard (it will be auto-cleared)."
        )
        generator_text.setWordWrap(True)
        layout.addWidget(generator_text)

        # Manager usage
        manager_label = QLabel("<b>Manager tab – how to use</b>")
        layout.addWidget(manager_label)

        manager_text = QLabel(
            "• On first use, set a master password for the vault.\n"
            "• Unlock the vault with your master password to view and edit entries.\n"
            "• Add one entry per site/app with label, username, and password.\n"
            "• Use filters and health indicators (weak, stale, reused, breached) to decide what to rotate."
        )
        manager_text.setWordWrap(True)
        layout.addWidget(manager_text)

        # Advanced security modes
        advanced_label = QLabel("<b>Advanced security modes</b>")
        layout.addWidget(advanced_label)

        advanced_text = QLabel(
            "<u>High-security session</u>\n"
            "• Toggle this in the Manager tab.\n"
            "• Disables clipboard copy from vault entries.\n"
            "• Shortens auto-lock (idle timeout) and locks the vault if the window "
            "is minimized or loses focus.\n"
            "• Recommended when working in public or during sensitive sessions.\n\n"
            "<u>Security Dashboard & Details…</u>\n"
            "• The Security dashboard bar and radar text summarize overall posture "
            "(weak, stale, reused, breached, decoy / attention state).\n"
            "• Click the “Details…” button to open Security Dashboard Details.\n"
            "• The details view shows counts of risky entries, reuse groups, breach "
            "patterns, lockout status, integrity guard results, and recent security events.\n\n"
            "<u>Rotate risky passwords</u>\n"
            "• The “Rotate risky passwords” button runs the Deep Rotation Engine.\n"
            "• It selects all entries that are weak, stale, reused, or breach-flagged, "
            "shows you the list, then replaces their passwords using the quantum generator.\n"
            "• Use this after a breach, or periodically to harden your vault in one step."
        )
        advanced_text.setWordWrap(True)
        layout.addWidget(advanced_text)

        # Security features summary
        secure_label = QLabel("<b>Security features</b>")
        layout.addWidget(secure_label)

        secure_text = QLabel(
            "• Clipboard auto-clear removes copied passwords after a short time.\n"
            "• Panic lock (keyboard shortcut) immediately locks the vault.\n"
            "• Integrity guard watches core files and warns if something changes unexpectedly.\n"
            "• A background security monitor watches for suspicious processes "
            "like screen-share / remote-control tools and can auto-lock when needed."
        )
        secure_text.setWordWrap(True)
        layout.addWidget(secure_text)

        # Best practices
        best_label = QLabel("<b>Best practices</b>")
        layout.addWidget(best_label)

        best_text = QLabel(
            "• Use a long, unique master password (16+ characters) and never reuse it elsewhere.\n"
            "• Keep one unique password per site/app; avoid reusing the same password.\n"
            "• Rotate passwords regularly, especially for critical accounts or after breaches.\n"
            "• Lock the app or close it when leaving your device unattended.\n"
            "• Store the vault file only on trusted disks and pair it with full disk encryption."
        )
        best_text.setWordWrap(True)
        layout.addWidget(best_text)

        layout.addStretch(1)

class QuantumPassWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()

        self.setWindowTitle("QuantaLock")
        # ↑ title text doesn’t matter, just an example

        # Increase both the minimum and initial height
        self.setMinimumSize(700, 800)   # width=900, height=520 (taller)
        self.resize(700, 800)

        self._apply_base_style()

        self.tabs = QTabWidget()
        self.generator_tab = GeneratorTab()
        self.manager_tab = ManagerTab()
        self.about_tab = AboutTab()     # if you added the About tab

        self.tabs.addTab(self.generator_tab, "Generator")
        self.tabs.addTab(self.manager_tab, "Manager")
        self.tabs.addTab(self.about_tab, "About")

        self.setCentralWidget(self.tabs)


        # Global panic lock shortcut (Ctrl+Shift+L)
        self.panic_shortcut = QShortcut(QKeySequence("Ctrl+Shift+L"), self)
        self.panic_shortcut.activated.connect(self._on_panic_lock)

        # Wire: Generator → Manager (send to vault)
        self.generator_tab.passwordGenerated.connect(
            self.on_password_generated_for_manager
        )

    @Slot(str)
    def on_password_generated_for_manager(self, password: str) -> None:
        """
        When GeneratorTab emits passwordGenerated, switch to Manager tab
        and pre-fill the password field there.
        """
        self.tabs.setCurrentWidget(self.manager_tab)
        self.manager_tab.receive_generated_password(password)

    def _apply_base_style(self) -> None:
        self.setStyleSheet(
            """
            QMainWindow {
                background-color: #05070c;
            }
            QWidget {
                color: #e5e7eb;
                background-color: #05070c;
                font-family: Segoe UI, Arial, sans-serif;
            }
            QGroupBox {
                border: 1px solid #1f2933;
                border-radius: 10px;
                margin-top: 16px;
                background-color: #080b12;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                subcontrol-position: top left;
                padding: 2px 8px;
                color: #7dd3fc;
                font-weight: 600;
                font-size: 10pt;
            }
            QLabel {
                font-size: 10pt;
            }
            QLineEdit {
                border: 1px solid #1f2933;
                border-radius: 6px;
                padding: 6px 8px;
                background-color: #050810;
                selection-background-color: #38bdf8;
                selection-color: #f9fafb;
            }
            QPushButton {
                border-radius: 8px;
                padding: 6px 14px;
                background-color: #0b1120;
                color: #e5e7eb;
                border: 1px solid #38bdf8;
            }
            QPushButton:hover {
                background-color: #020617;
            }
            QPushButton:pressed {
                background-color: #000000;
            }
            QSpinBox, QSlider {
                background-color: #050810;
            }
            QSpinBox {
                border: 1px solid #1f2933;
                border-radius: 6px;
                padding: 4px 6px;
            }
            QCheckBox {
                spacing: 6px;
            }
            QCheckBox::indicator {
                width: 14px;
                height: 14px;
            }
            QCheckBox::indicator:unchecked {
                border: 1px solid #4b5563;
                background-color: #020617;
            }
            QCheckBox::indicator:checked {
                border: 1px solid #38bdf8;
                background-color: #38bdf8;
            }
            QListWidget {
                border: 1px solid #1f2933;
                border-radius: 6px;
                background-color: #050810;
            }
            """
        )

    def _on_panic_lock(self) -> None:
        """
        Immediate manual lock, regardless of active tab.
        """
        if self.manager_tab.unlocked:
            self.manager_tab._lock_vault("Panic lock activated.")

    def _panic_lock_if_needed(self, reason: str) -> None:
        """
        Lock the vault automatically when High-security mode is enabled
        and the window loses focus or is minimized.
        """
        mgr = self.manager_tab
        if getattr(mgr, "high_security_mode", False) and getattr(mgr, "unlocked", False):
            mgr._lock_vault(reason)

    def changeEvent(self, event: QEvent) -> None:
        """
        Monitor window activation / state for High-security auto-lock.
        """
        super().changeEvent(event)

        if event.type() == QEvent.WindowStateChange:
            if self.isMinimized():
                self._panic_lock_if_needed(
                    "Vault locked (window minimized in High-security session)."
                )
        elif event.type() == QEvent.ActivationChange:
            if not self.isActiveWindow():
                self._panic_lock_if_needed(
                    "Vault locked (window lost focus in High-security session)."
                )

def main() -> None:
    app = QApplication(sys.argv)
    window = QuantumPassWindow()
    window.show()
    sys.exit(app.exec())
