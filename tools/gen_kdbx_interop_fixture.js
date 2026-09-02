#!/usr/bin/env node
/**
 * Regenerate app/src/test/resources/kypasswords-web-vault.kdbx.
 *
 * Writes the vault with kdbxweb -- the library the KyPasswords web client uses -- so the Kotlin
 * test proves kotpass can open a genuinely foreign file. A fixture written by kotpass would only
 * prove kotpass reads its own output, which is the direction that already worked.
 *
 * Mirrors the web client: credential is the vault key as lowercase hex text, Argon2d at
 * m=32 MiB / t=8 / p=2 to match kotpass's KdfParameters.Argon2.default(), KDBX 4 (kdbxweb's
 * setVersion takes a major version only, so it emits 4.0 where kotpass emits 4.1).
 *
 *   npm install kdbxweb && pip install argon2-cffi
 *   node tools/gen_kdbx_interop_fixture.js
 */
const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');
const kdbxweb = require('kdbxweb');

// Argon2 via reference libargon2 (argon2-cffi). kdbxweb deliberately ships no implementation.
kdbxweb.CryptoEngine.setArgon2Impl((password, salt, memoryKiB, iterations, length, parallelism, type) => {
  const script = `
import sys, binascii
from argon2.low_level import hash_secret_raw, Type
pw, salt, m, t, p, l, ty = sys.argv[1:8]
out = hash_secret_raw(
    binascii.unhexlify(pw), binascii.unhexlify(salt),
    time_cost=int(t), memory_cost=int(m), parallelism=int(p), hash_len=int(l),
    type=Type.D if int(ty) == 0 else Type.ID,
)
sys.stdout.write(binascii.hexlify(out).decode())
`;
  const hex = (buf) => Buffer.from(buf).toString('hex');
  const result = spawnSync('python3', [
    '-c', script,
    hex(password), hex(salt), String(memoryKiB), String(iterations), String(parallelism),
    String(length), String(type),
  ], { encoding: 'utf8' });
  if (result.status !== 0) throw new Error(`argon2 helper failed: ${result.stderr}`);
  return Promise.resolve(Buffer.from(result.stdout.trim(), 'hex'));
});

// Fixed so the fixture is reproducible; the Kotlin test hardcodes the same key.
const VAULT_KEY_HEX = '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff';

async function main() {
  const credentials = new kdbxweb.Credentials(kdbxweb.ProtectedValue.fromString(VAULT_KEY_HEX));
  const db = kdbxweb.Kdbx.create(credentials, 'KyAuth Passwords');
  db.setVersion(4);
  db.setKdf(kdbxweb.Consts.KdfId.Argon2d);

  const kdf = db.header.kdfParameters;
  kdf.set('M', kdbxweb.VarDictionary.ValueType.UInt64, kdbxweb.Int64.from(32 * 1024 * 1024));
  kdf.set('I', kdbxweb.VarDictionary.ValueType.UInt64, kdbxweb.Int64.from(8));
  kdf.set('P', kdbxweb.VarDictionary.ValueType.UInt32, 2);

  const entry = db.createEntry(db.getDefaultGroup());
  entry.fields.set('Title', 'Interop fixture');
  entry.fields.set('UserName', 'alice@example.test');
  entry.fields.set('Password', kdbxweb.ProtectedValue.fromString('web-written-secret'));
  entry.fields.set('URL', 'https://passwords.example.test');
  entry.fields.set('Notes', 'Written by kdbxweb');

  const out = path.join(__dirname, '..', 'app', 'src', 'test', 'resources', 'kypasswords-web-vault.kdbx');
  fs.mkdirSync(path.dirname(out), { recursive: true });
  fs.writeFileSync(out, Buffer.from(await db.save()));
  console.log(`wrote ${out} (${fs.statSync(out).size} bytes), vault key ${VAULT_KEY_HEX}`);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
