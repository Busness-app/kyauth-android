#!/usr/bin/env python3
"""Regenerate the Argon2id envelope fixture pinned in KyPasswordEnvelopeCryptoTest.

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

