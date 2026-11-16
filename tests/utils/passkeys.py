"""A software WebAuthn authenticator, so tests can add and use passkeys without a browser.

It produces the same JSON a browser's `PublicKeyCredential.toJSON()` does, signed with a real P-256 key, so the
server's verification runs for real. Its knobs exist to produce the faulty responses an attacker or a broken
authenticator might send.
"""

import hashlib
import json
import secrets
import struct
from dataclasses import dataclass, field
from typing import Any

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url

FLAG_UP = 0x01
FLAG_UV = 0x04
FLAG_BE = 0x08
FLAG_BS = 0x10
FLAG_AT = 0x40


@dataclass
class SoftAuthenticator:
    rp_id: str
    origin: str
    user_verification: bool = True
    synced: bool = True
    credential_id: bytes = field(default_factory=lambda: secrets.token_bytes(32))
    sign_count: int = 0
    user_handle: bytes | None = None
    """Set when the passkey is created, from the options' `user.id`."""

    def __post_init__(self) -> None:
        self._key = ec.generate_private_key(ec.SECP256R1())

    def _flags(self, attested: bool = False) -> int:
        flags = FLAG_UP
        if self.user_verification:
            flags |= FLAG_UV
        if self.synced:
            flags |= FLAG_BE | FLAG_BS
        if attested:
            flags |= FLAG_AT
        return flags

    def _client_data(self, kind: str, challenge: str, origin: str | None) -> bytes:
        return json.dumps(
            {"type": kind, "challenge": challenge, "origin": origin or self.origin, "crossOrigin": False}
        ).encode()

    def _cose_public_key(self) -> bytes:
        numbers = self._key.public_key().public_numbers()
        return cbor2.dumps({1: 2, 3: -7, -1: 1, -2: numbers.x.to_bytes(32, "big"), -3: numbers.y.to_bytes(32, "big")})

    def create(self, options: dict[str, Any], *, origin: str | None = None) -> dict[str, Any]:
        """Answers registration options like `navigator.credentials.create()` would."""
        self.user_handle = base64url_to_bytes(options["user"]["id"])

        auth_data = (
            hashlib.sha256(self.rp_id.encode()).digest()
            + bytes([self._flags(attested=True)])
            + struct.pack(">I", self.sign_count)
            + bytes(16)  # aaguid: an authenticator that won't say what it is
            + struct.pack(">H", len(self.credential_id))
            + self.credential_id
            + self._cose_public_key()
        )
        attestation_object = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth_data})

        return {
            "id": bytes_to_base64url(self.credential_id),
            "rawId": bytes_to_base64url(self.credential_id),
            "type": "public-key",
            "response": {
                "clientDataJSON": bytes_to_base64url(
                    self._client_data("webauthn.create", options["challenge"], origin)
                ),
                "attestationObject": bytes_to_base64url(attestation_object),
                "transports": ["internal", "hybrid"],
            },
            "clientExtensionResults": {},
            "authenticatorAttachment": "platform",
        }

    def get(
        self,
        options: dict[str, Any],
        *,
        origin: str | None = None,
        user_handle: bytes | None = None,
        tamper_signature: bool = False,
    ) -> dict[str, Any]:
        """Answers authentication options like `navigator.credentials.get()` would."""
        if self.sign_count:
            self.sign_count += 1

        auth_data = (
            hashlib.sha256(self.rp_id.encode()).digest() + bytes([self._flags()]) + struct.pack(">I", self.sign_count)
        )
        client_data = self._client_data("webauthn.get", options["challenge"], origin)
        signature = self._key.sign(auth_data + hashlib.sha256(client_data).digest(), ec.ECDSA(hashes.SHA256()))
        if tamper_signature:
            signature = self._key.sign(b"something else entirely", ec.ECDSA(hashes.SHA256()))

        handle = user_handle if user_handle is not None else self.user_handle
        return {
            "id": bytes_to_base64url(self.credential_id),
            "rawId": bytes_to_base64url(self.credential_id),
            "type": "public-key",
            "response": {
                "clientDataJSON": bytes_to_base64url(client_data),
                "authenticatorData": bytes_to_base64url(auth_data),
                "signature": bytes_to_base64url(signature),
                "userHandle": bytes_to_base64url(handle) if handle else None,
            },
            "clientExtensionResults": {},
            "authenticatorAttachment": "platform",
        }
