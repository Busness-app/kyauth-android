#!/usr/bin/env node
// Real web-library fixture generator and semantic verifier for Android output.
const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
const { kdbxweb: k, VAULT_KEY_HEX } = require('./gen_kdbx_interop_fixture');
const credentials = () => new k.Credentials(k.ProtectedValue.fromString(VAULT_KEY_HEX));
const resources = path.resolve(__dirname, '../app/src/test/resources');
const open = async file => k.Kdbx.load(new Uint8Array(fs.readFileSync(file)).buffer, credentials());
const text = value => value instanceof k.ProtectedValue ? value.getText() : value;

async function generate() {
  const db = k.Kdbx.create(credentials(), 'Preservation');
  db.setVersion(4);
  db.setKdf(k.Consts.KdfId.Argon2d);
  const root = db.getDefaultGroup();
  const nested = db.createGroup(db.createGroup(root, 'Live'), 'Nested');
  const add = (group, title, password) => {
    const e = db.createEntry(group);
    e.fields.set('Title', title);
    e.fields.set('Password', k.ProtectedValue.fromString(password));
    return e;
  };
  const edit = add(nested, 'Edit me', 'old secret');
  edit.fields.set('URL', 'https://example.test');
  edit.fields.set('TimeOtp-Secret-Base32', k.ProtectedValue.fromString('JBSWY3DPEHPK3PXP'));
  edit.fields.set('Foreign-Protected', k.ProtectedValue.fromString('keep me'));
  edit.fields.set('Foreign-Plain', 'also keep me');
  edit.tags = ['work', 'fixture'];
  edit.binaries.set('attachment.txt', await db.createBinary(new TextEncoder().encode('attachment contents').buffer));
  edit.pushHistory();
  edit.fields.set('Notes', 'current notes');
  const recycled = add(root, 'Recycled', 'bin secret');
  db.remove(recycled);
  const bin = db.getGroup(db.meta.recycleBinUuid);
  const child = db.createGroup(bin, 'Deleted folder');
  const deletedChild = add(child, 'Deleted child', 'old secret');
  deletedChild.fields.set('Passkey-RpId', 'example.test');
  deletedChild.fields.set('Passkey-CredentialId', 'AQ==');
  deletedChild.fields.set('Passkey-PrivateKey', 'Ag==');
  add(child, '', '');
  add(db.createGroup(root, 'Recycle Bin'), 'Live namesake', 'old secret');
  add(nested, 'TOTP only', '').fields.set('TimeOtp-Secret-Base32', 'JBSWY3DPEHPK3PXP');
  add(nested, '', 'hidden password');
  add(nested, 'Spaces one', '  ');
  add(nested, 'Spaces two', '  ');
  add(nested, 'Different case', 'Old secret');
  const removed = add(root, 'Permanently removed', 'gone');
  db.meta.recycleBinEnabled = false;
  db.remove(removed);
  db.meta.recycleBinEnabled = true;
  db.meta.description = 'Preserve database metadata';
  db.meta.customData.set('foreign-meta', { value: 'keep metadata' });
  fs.writeFileSync(path.join(resources, 'vault-preservation.kdbx'), Buffer.from(await db.save()));
  db.meta.recycleBinEnabled = false;
  fs.writeFileSync(path.join(resources, 'vault-recycling-disabled.kdbx'), Buffer.from(await db.save()));
}

function entry(e) {
  return {
    uuid: e.uuid.toString(),
    fields: [...e.fields].map(([key, value]) => [key, text(value), value instanceof k.ProtectedValue]).sort(),
    binaries: [...e.binaries].map(([key, value]) => [key, value.hash]).sort(),
    tags: e.tags, history: e.history.map(entry),
    times: { ...e.times }, icon: e.icon, customData: [...(e.customData || new Map())],
    autoType: { ...e.autoType, defaultSequence: e.autoType?.defaultSequence || '' }, overrideUrl: e.overrideUrl,
  };
}
function group(g) {
  return { uuid: g.uuid.toString(), name: g.name, notes: g.notes, times: { ...g.times },
    customData: [...(g.customData || new Map())], groups: g.groups.map(group), entries: g.entries.map(entry).sort((a,b) => a.uuid.localeCompare(b.uuid)) };
}
function summary(db) {
  return { groups: db.groups.map(group), bin: db.meta.recycleBinUuid.toString(),
    recycling: db.meta.recycleBinEnabled, description: db.meta.description,
    customData: [...db.meta.customData],
    deleted: db.deletedObjects.map(o => [o.uuid.toString(), o.deletionTime]),
    attachments: [...db.binaries.getAllWithHashes()].map(b => b.hash).sort() };
}
async function verify(directory) {
  const before = await open(path.join(resources, 'vault-preservation.kdbx'));
  const noop = await open(path.join(directory, 'noop.kdbx'));
  assert.deepEqual(summary(noop), summary(before), 'kotpass no-op round trip');
  const after = await open(path.join(directory, 'edited.kdbx'));
  const original = [...before.getDefaultGroup().allEntries()].find(e => text(e.fields.get('Title')) === 'Edit me');
  const changed = [...after.getDefaultGroup().allEntries()].find(e => e.uuid.equals(original.uuid));
  assert.equal(text(changed.fields.get('Password')), 'new secret');
  assert.equal(changed.history.length, original.history.length + 1);
  assert.deepEqual(entry(changed.history.at(-1)), { ...entry(original), history: [] });
  // Only the intended field, added history and modification/access times may differ.
  changed.fields.set('Password', original.fields.get('Password'));
  changed.history = original.history;
  changed.times = original.times;
  assert.deepEqual(summary(after), summary(before), 'Android edit preserves unrelated data');
  console.log('Verified kdbxweb → kotpass → kdbxweb: no-op and targeted edit.');
}
(process.argv[2] === 'generate' ? generate() : verify(process.argv[2])).catch(e => { console.error(e); process.exitCode = 1; });
