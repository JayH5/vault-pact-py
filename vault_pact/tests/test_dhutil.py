import os

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

import pytest

from vault_pact.dhutil import (
    Envelope, PublicKeyInfo, decrypt_aes, encrypt_aes,
    generate_public_private_key, generate_shared_key)


class TestPublicKeyInfo:
    def test_to_from_json(self):
        public_key = X25519PrivateKey.generate().public_key()

        pki = PublicKeyInfo(public_key)
        pki_json = pki.to_json()

        pki_deser = PublicKeyInfo.from_json(pki_json)
        assert pki.__dict__ == pki_deser.__dict__


class TestEnvelope:
    def test_to_from_json(self):
        public_key = X25519PrivateKey.generate().public_key()
        nonce = os.urandom(12)

        envelope = Envelope(public_key, nonce, b"foo")
        envelope_json = envelope.to_json()

        envelope_deser = Envelope.from_json(envelope_json)
        assert envelope.__dict__ == envelope_deser.__dict__


class TestGenerateKeyFuncs:
    def test_key_exchange(self):
        our_public, our_private = generate_public_private_key()
        their_public, their_private = generate_public_private_key()

        our_shared_key = generate_shared_key(our_private, their_public)
        their_shared_key = generate_shared_key(their_private, our_public)

        assert our_shared_key == their_shared_key
        assert len(our_shared_key) == 32


class TestDecryptEncryptFuncs:
    def test_encrypt_decrypt(self):
        key = os.urandom(32)
        plaintext = b"hello"
        aad = b"world"

        ciphertext, nonce = encrypt_aes(key, plaintext, aad)

        assert decrypt_aes(key, ciphertext, nonce, aad) == plaintext

    def test_encrypt_invalid_key_length(self):
        with pytest.raises(ValueError) as excinfo:
            encrypt_aes(b"foo", b"bar", b"baz")
        assert str(excinfo.value) == "invalid key length: 3"

    def test_encrypt_empty_plaintext(self):
        with pytest.raises(ValueError) as excinfo:
            encrypt_aes(os.urandom(32), b"", b"foo")
        assert str(excinfo.value) == "empty plaintext provided"

    def test_decrypt_invalid_key_length(self):
        with pytest.raises(ValueError) as excinfo:
            decrypt_aes(b"foo", b"bar", b"baz", b"baz")
        assert str(excinfo.value) == "invalid key length: 3"

    def test_decrypt_empty_ciphertext(self):
        with pytest.raises(ValueError) as excinfo:
            decrypt_aes(os.urandom(32), b"", b"foo", b"bar")
        assert str(excinfo.value) == "empty ciphertext provided"

    def test_decrypt_empty_nonce(self):
        with pytest.raises(ValueError) as excinfo:
            decrypt_aes(os.urandom(32), b"foo", b"", b"bar")
        assert str(excinfo.value) == "empty nonce provided"
