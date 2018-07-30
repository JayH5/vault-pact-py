"""
A straight port of:
https://github.com/hashicorp/vault/blob/v0.10.4/helper/dhutil/dhutil.go
...using the cryptography library.
"""
from __future__ import unicode_literals

import base64
import json
import os
from json import JSONEncoder

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class PublicKeyInfo:
    def __init__(self, curve25519_public_key):
        self.curve25519_public_key = _maybe_bytes(curve25519_public_key)

    @classmethod
    def from_json(cls, s):
        json_obj = json.loads(s)
        return PublicKeyInfo(
            _unmarshal_bytes(json_obj["curve25519_public_key"])
        )

    def to_json(self):
        return json.dumps(self.__dict__, cls=_BytesEncoder)


class Envelope:
    def __init__(self, curve25519_public_key, nonce, encrypted_payload):
        self.curve25519_public_key = _maybe_bytes(curve25519_public_key)
        self.nonce = nonce
        self.encrypted_payload = encrypted_payload

    @classmethod
    def from_json(cls, s):
        json_obj = json.loads(s)
        return Envelope(
            _unmarshal_bytes(json_obj["curve25519_public_key"]),
            _unmarshal_bytes(json_obj["nonce"]),
            _unmarshal_bytes(json_obj["encrypted_payload"])
        )

    def to_json(self):
        return json.dumps(self.__dict__, cls=_BytesEncoder)


class _BytesEncoder(JSONEncoder):
    def default(self, obj):
        if isinstance(obj, bytes):
            return _marshal_bytes(obj)
        return super().default(obj)


def _marshal_bytes(b):
    return base64.b64encode(b).decode("utf-8")


def _unmarshal_bytes(s):
    return base64.b64decode(s.encode("utf-8"))


def _maybe_bytes(curve25519_public_key):
    if isinstance(curve25519_public_key, X25519PublicKey):
        curve25519_public_key = curve25519_public_key.public_bytes()
    return curve25519_public_key


def generate_public_private_key():
    """
    generate_public_private_key uses curve25519 to generate a public and
    private key pair
    """
    private_key = X25519PrivateKey.generate()
    return private_key.public_key(), private_key


def generate_shared_key(our_private, their_public):
    """
    generate_shared_key uses the private key and the other party's public key
    to generate the shared secret.
    """
    return our_private.exchange(their_public)


def encrypt_aes(key, plaintext, aad):
    """
    Use AES256-GCM to encrypt some plaintext with a provided key. The returned
    values are the ciphertext, the nonce, and error respectively.
    """
    # We enforce AES-256, so check explicitly for 32 bytes on the key
    if len(key) != 32:
        raise ValueError("invalid key length: {}".format(len(key)))

    if not plaintext:
        raise ValueError("empty plaintext provided")

    # Never use more than 2^32 random nonces with a given key because of the
    # risk of a repeat.
    nonce = os.urandom(12)

    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, aad)

    return ciphertext, nonce


def decrypt_aes(key, ciphertext, nonce, aad):
    """
    Use AES256-GCM to decrypt some ciphertext with a provided key and nonce.
    The returned values are the plaintext and error respectively.
    """
    # We enforce AES-256, so check explicitly for 32 bytes on the key
    if len(key) != 32:
        raise ValueError("invalid key length: {}".format(len(key)))

    if not ciphertext:
        raise ValueError("empty ciphertext provided")

    if not nonce:
        raise ValueError("empty nonce provided")

    aesgcm = AESGCM(key)

    return aesgcm.decrypt(nonce, ciphertext, aad)
