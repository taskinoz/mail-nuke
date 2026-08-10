from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken


SCRYPT_N = 2**14
SCRYPT_R = 8
SCRYPT_P = 1
SALT_BYTES = 16
KEY_BYTES = 32
SESSION_BYTES = 32
SESSION_LIFETIME = timedelta(hours=12)


def hash_password(password: str) -> str:
    if len(password) < 12:
        raise ValueError("Administrator password must be at least 12 characters")
    salt = os.urandom(SALT_BYTES)
    key = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        dklen=KEY_BYTES,
    )
    return "$".join(
        [
            "scrypt",
            str(SCRYPT_N),
            str(SCRYPT_R),
            str(SCRYPT_P),
            base64.urlsafe_b64encode(salt).decode("ascii"),
            base64.urlsafe_b64encode(key).decode("ascii"),
        ]
    )


def verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, n, r, p, salt_value, expected_value = encoded.split("$", 5)
        if algorithm != "scrypt":
            return False
        salt = base64.urlsafe_b64decode(salt_value.encode("ascii"))
        expected = base64.urlsafe_b64decode(expected_value.encode("ascii"))
        actual = hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=int(n),
            r=int(r),
            p=int(p),
            dklen=len(expected),
        )
        return hmac.compare_digest(actual, expected)
    except (TypeError, ValueError):
        return False


def generate_session_token() -> str:
    return secrets.token_urlsafe(SESSION_BYTES)


def hash_session_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def session_expiry() -> str:
    return (datetime.now(timezone.utc) + SESSION_LIFETIME).isoformat()


class SecretCipher:
    def __init__(self, fernet: Fernet):
        self._fernet = fernet

    @classmethod
    def load(cls, configured_key: str | None, generated_key_path: Path) -> "SecretCipher":
        if configured_key:
            key = configured_key.encode("ascii")
        elif generated_key_path.exists():
            key = generated_key_path.read_bytes().strip()
        else:
            generated_key_path.parent.mkdir(parents=True, exist_ok=True)
            key = Fernet.generate_key()
            generated_key_path.write_bytes(key + b"\n")
            try:
                generated_key_path.chmod(0o600)
            except OSError:
                pass
        try:
            return cls(Fernet(key))
        except (TypeError, ValueError) as exc:
            raise RuntimeError("MAIL_NUKE_SECRET_KEY is not a valid Fernet key") from exc

    def encrypt(self, value: str) -> str:
        return self._fernet.encrypt(value.encode("utf-8")).decode("ascii")

    def decrypt(self, value: str) -> str:
        try:
            return self._fernet.decrypt(value.encode("ascii")).decode("utf-8")
        except (InvalidToken, ValueError) as exc:
            raise RuntimeError("Stored secret cannot be decrypted with the active key") from exc
