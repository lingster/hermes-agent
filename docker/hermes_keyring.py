"""Encrypted file keyring backend for hermes.

Stores secrets in $HERMES_HOME/keyring/secrets.enc using Fernet symmetric
encryption (AES-128-CBC via cryptography package). Isolated per profile
since each profile has its own /opt/data volume mount.

Master password priority:
  1. KEYRING_MASTER_PASSWORD environment variable (provide at container start)
  2. Auto-generated token persisted to $HERMES_HOME/.keyring_master (chmod 600)

Usage from hermes/agents:
    import keyring
    keyring.set_password("my-service", "username", "secret")
    keyring.get_password("my-service", "username")
    keyring.delete_password("my-service", "username")
"""
import base64
import json
import os
import secrets
from pathlib import Path

import keyring.backend
import keyring.errors
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def _hermes_home() -> Path:
    return Path(os.environ.get("HERMES_HOME", "/opt/data"))


def _get_fernet() -> Fernet:
    keyring_dir = _hermes_home() / "keyring"
    keyring_dir.mkdir(parents=True, exist_ok=True)

    salt_file = keyring_dir / ".salt"
    master_key_file = _hermes_home() / ".keyring_master"

    # Salt — generated once, stored alongside the encrypted secrets file.
    if salt_file.exists():
        salt = base64.b64decode(salt_file.read_bytes())
    else:
        salt = os.urandom(16)
        salt_file.write_bytes(base64.b64encode(salt))
        salt_file.chmod(0o600)

    # Master password — from env var or auto-generated and persisted.
    password = os.environ.get("KEYRING_MASTER_PASSWORD")
    if not password:
        if master_key_file.exists():
            password = master_key_file.read_text().strip()
        else:
            password = secrets.token_hex(32)
            master_key_file.write_text(password)
            master_key_file.chmod(0o600)

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480_000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return Fernet(key)


class HermesKeyring(keyring.backend.KeyringBackend):
    """Encrypted keyring stored in $HERMES_HOME/keyring/secrets.enc."""

    priority = 10

    @property
    def _secrets_file(self) -> Path:
        return _hermes_home() / "keyring" / "secrets.enc"

    def _load(self) -> dict:
        if not self._secrets_file.exists():
            return {}
        data = _get_fernet().decrypt(self._secrets_file.read_bytes())
        return json.loads(data)

    def _save(self, data: dict) -> None:
        encrypted = _get_fernet().encrypt(json.dumps(data).encode())
        self._secrets_file.write_bytes(encrypted)
        self._secrets_file.chmod(0o600)

    def get_password(self, service: str, username: str) -> str | None:
        return self._load().get(f"{service}:{username}")

    def set_password(self, service: str, username: str, password: str) -> None:
        data = self._load()
        data[f"{service}:{username}"] = password
        self._save(data)

    def delete_password(self, service: str, username: str) -> None:
        data = self._load()
        key = f"{service}:{username}"
        if key not in data:
            raise keyring.errors.PasswordDeleteError(key)
        del data[key]
        self._save(data)
