#!/usr/bin/env python3
"""Regenerate the envelope fixtures pinned in KyPasswordEnvelopeCryptoTest.

Derives with reference libargon2 (argon2-cffi) and encrypts with pyca/cryptography, so the
fixture is produced by implementations independent of KyAuth's. A fixture KyAuth generated
itself would only prove self-consistency, which is exactly the failure this guards against.

    pip install argon2-cffi cryptography && python3 tools/gen_argon2id_envelope_fixture.py
"""
import binascii
import json

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

PASSWORD = b"correct horse battery staple"
SALT = bytes.fromhex("030303030303030303030303030303030303030303030303030303030303030f")[:16]
IV = bytes.fromhex("0102030405060708090a0b0c")
VAULT_KEY = bytes(range(32))
MEMORY_KIB, ITERATIONS, PARALLELISM = 65536, 3, 1

key = hash_secret_raw(
    PASSWORD, SALT,
    time_cost=ITERATIONS, memory_cost=MEMORY_KIB, parallelism=PARALLELISM,
    hash_len=32, type=Type.ID,
)
ciphertext = AESGCM(key).encrypt(IV, VAULT_KEY, None)

print("derived key:", binascii.hexlify(key).decode())
print("vault key:  ", binascii.hexlify(VAULT_KEY).decode())
print(json.dumps({
    "kdf": "argon2id",
    "salt": binascii.hexlify(SALT).decode(),
    "iv": binascii.hexlify(IV).decode(),
    "ciphertext": binascii.hexlify(ciphertext).decode(),
    "memoryKiB": MEMORY_KIB,
    "iterations": ITERATIONS,
    "parallelism": PARALLELISM,
}))

# The legacy (no "kdf" key) PBKDF2-HMAC-SHA256 shape, pinned so the compatibility test survives
# the write path moving to Argon2id.
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

LEGACY_PASSWORD = b"legacy-secret"
LEGACY_SALT = bytes.fromhex("00112233445566778899aabbccddeeff")
LEGACY_IV = bytes.fromhex("0b0a090807060504030201ff")
LEGACY_VAULT_KEY = bytes((i * 5 + 1) & 0xFF for i in range(32))
LEGACY_ITERATIONS = 600_000

legacy_key = PBKDF2HMAC(
    algorithm=hashes.SHA256(), length=32, salt=LEGACY_SALT, iterations=LEGACY_ITERATIONS,
).derive(LEGACY_PASSWORD)

print()
print("legacy vault key:", binascii.hexlify(LEGACY_VAULT_KEY).decode())
print(json.dumps({
    "salt": LEGACY_SALT.hex(),
    "iv": LEGACY_IV.hex(),
    "ciphertext": AESGCM(legacy_key).encrypt(LEGACY_IV, LEGACY_VAULT_KEY, None).hex(),
    "iterations": LEGACY_ITERATIONS,
}))
