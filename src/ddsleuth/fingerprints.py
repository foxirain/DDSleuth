from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from dataclasses import dataclass


FINGERPRINT_ENVIRONMENT = "DDSLEUTH_FINGERPRINT_SECRET"
FINGERPRINT_SCHEME = "hmac-sha256-run-local-v1"
_DOMAIN_SEPARATOR = b"ddsleuth:key-fingerprint:v1\x00"


class FingerprintError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class RunLocalFingerprinter:
    _secret: bytes

    def __post_init__(self) -> None:
        if len(self._secret) != 32:
            raise FingerprintError("run-local fingerprint secret must be exactly 32 bytes")

    @classmethod
    def generate(cls) -> "RunLocalFingerprinter":
        return cls(secrets.token_bytes(32))

    @classmethod
    def from_hex(cls, encoded: str) -> "RunLocalFingerprinter":
        try:
            secret = bytes.fromhex(encoded)
        except ValueError as error:
            raise FingerprintError("run-local fingerprint secret must be hexadecimal") from error
        return cls(secret)

    @classmethod
    def from_environment(cls) -> "RunLocalFingerprinter":
        encoded = os.environ.get(FINGERPRINT_ENVIRONMENT)
        if encoded is None:
            raise FingerprintError(f"missing {FINGERPRINT_ENVIRONMENT}")
        return cls.from_hex(encoded)

    def environment_value(self) -> str:
        return self._secret.hex()

    def fingerprint(self, key_material: bytes) -> str:
        digest = hmac.new(
            self._secret,
            _DOMAIN_SEPARATOR + key_material,
            hashlib.sha256,
        ).hexdigest()
        return f"{FINGERPRINT_SCHEME}:{digest}"
