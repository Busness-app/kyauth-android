**Repo:** kyauth-android (paired with kypassword-server)
**PR:** #7 — https://github.com/Busness-app/kyauth-android/pull/7
**Worktree:** /home/yoshi/busness.app/kyauth-android (branch main)

# KDBX preservation and mobile feature parity plan

Implementation completed in merged PR #7. This plan records the original approach;
see `2026-09-05-vault-parity-verification.md` for results and physical-device limits.
Mobile CSV import was removed from scope at Yoshi's request on 2026-09-06.

Original planning baseline: inspected Android commit
`f0a6f1621bda4a7c20824b42c057c44a15e59380`. No runtime reproduction or Android
checks were run for this planning-only change.

Source handoff: https://myslop.urlxl.us/f/kyauth-kypassword-vault-parity (post 455).
The handoff's ordering is right: establish lossless persistence before adding views
and feature work. Deliver preservation as the first focused PR, followed by
separate feature changes.

## Findings confirmed in the checkout

- `passwords/KdbxPasswordVault.kt` flattens all groups, including the recycle bin,
  into a filtered `PasswordEntry` list, then creates a new database on save. The
  source flow discards structure and unrepresented data; runtime proof remains to
  be written.
- `MainActivity.kt:899` saves the UI's cached list directly. Add and delete call
  this helper, contrary to AGENTS.md's requirement that incremental writes use
  `update`. Autofill and vault-backed Credential Provider writes already use it.
- `MainActivity.kt:1573` handles HTTP 409 by downloading over the local file and
  combining remote entries with cached UI entries using `distinctBy(id)`. This is
  not a full-database merge and chooses the remote version of matching IDs. The
  ordinary newer-server download also replaces the local file.
- `KyPasswordClient.downloadVault` installs downloaded bytes directly, outside
  the vault object's monitor and before the UI decodes them. Atomic replacement
  alone cannot prevent a concurrent local change from being overwritten.
- `PasswordEntry` and the loader reject blank passwords, including space-only
  values. Exact reuse reporting must use all live KDBX records with nonempty
  passwords, not silently inherit this display filter.
- Existing tests cover basic web-to-Android opening, field names, simple round
  trips and concurrent additions. They do not prove preservation of a rich file
  after an Android mutation and reopening in the web library.
- Server [PR 33](https://github.com/Busness-app/kypassword-server/pull/33) is now
  MERGED, verified through GitHub during planning; its head is
  `84c296e13af94ea5ea2847bfaeb6f3608f4e3ca4`. The handoff's OPEN status is stale.

## 1. First PR: preserve the database across every mobile write

### Establish the regression and library capability first

Extend `tools/gen_kdbx_interop_fixture.js` and the existing test resources with a
fake-secret, kdbxweb-written fixture containing nested live groups, an actual bin
with descendants, a live group named Recycle Bin, protected custom fields, TOTP,
attachments, history, tags, timestamps and records excluded by the current display
model. Include recycle metadata and deletion records. Add a recycling-disabled
variant.

First test a decode/encode without mutation using installed kotpass 0.13.0, then
change one live entry through `KdbxPasswordVault.update`. Reopen the Android output
with kdbxweb and compare semantic contents, UUIDs, hierarchy and metadata against
the input. Encryption randomness means byte equality is inappropriate for a
successful save. Verify unchanged protected fields retain their protection.

This distinguishes library loss from our reconstruction bug. If kotpass itself
cannot preserve required content, resolve that specific limitation before enabling
writes to affected files; do not claim complete preservation from Kotlin-only
tests or add a second persistence framework preemptively.

### Mutate the decoded database

Keep one synchronized decode/mutate/atomic-write boundary. Retain `PasswordEntry`
as a UI projection, not the persisted source of truth. Apply changes by UUID to
the original entries in their original groups, patching only explicitly changed
owned fields. Preserve unknown fields, binaries, metadata and prior history;
record appropriate history/timestamps for intentional edits. New entries go into
the live root. Invalid or duplicate mutation IDs fail without writing.

Prefer retaining the current callback API with a before/after UUID comparison if
it can express these semantics safely. Do not infer deletion of records absent
from the display projection. Restrict fresh-database creation to initialization;
remove existing-file reconstruction paths. A corrupt or zero-length existing file
must not silently become an empty database. A no-op or failed mutation leaves
the original bytes unchanged.

Share UUID-based bin exclusion across live reads, including descendants. This
automatically covers Autofill and Credential Provider selection. Bin identity
must never depend on the displayed group name.

Route UI add/delete, Autofill saves, password/passkey creation and passkey counter
increments through the same boundary. Include recycle-aware deletion now: move
the original record to the actual bin, reuse that bin across saves, and preserve
the explicit recycling-disabled policy. In that disabled case, confirm permanent
removal from the current vault and preserve appropriate deletion metadata. Keep
the richer bin browsing/restore UI for the next PR.

### Close the sync overwrite path in the same preservation scope

Download to a separate bounded candidate and decode it before installation. Take
an encrypted local snapshot and version under the vault boundary; perform network
I/O outside it. Install a candidate only if local state still matches the captured
state and replacement is known safe. Pairing must retain its different-key guard.

Replace the cached-list 409 merge. The initial safe policy is to retain both
encrypted files and surface a recoverable conflict, without automatic upload or
discarding either side. Apply this to newer-server downloads when unsynced local
changes exist or their absence cannot be established. Track the last successfully
synced local state; unknown state is not proof of cleanliness. A full semantic
merge engine is outside this first PR. Keep `If-Match`, report background upload
failures, and update sync metadata only for the snapshot actually acknowledged.
Conflict artifacts remain app-private and are included in local wipe handling.

### First-PR acceptance gate

- kdbxweb → Android mutation → kdbxweb preserves every unrelated fixture item.
- Recycled passwords and passkeys never appear in live lists or provider results.
- Two deletions with save/reopen between them retain both entries in one bin;
  disabled recycling stays disabled and a same-named live folder stays live.
- UI/provider interleaving, passkey counter updates, download/local-write races,
  HTTP 409, invalid downloads and decode failures cannot destroy either version.
- Existing tests remain green; run
  `./gradlew test lintDebug assembleDebug compileDebugAndroidTestSources` plus the
  cross-library runner. Make the runner reproducible in CI using pinned test-tool
  dependencies. Update AGENTS.md to describe the implemented write/conflict rules.

## 2. Second PR: recycle-bin recovery UI

Add a separate read-only deleted-entry view and Restore to vault. Traverse the
metadata-identified bin and descendants, including records not representable as
ordinary password cards. Restore the original entry, with the same UUID, fields,
attachments and history, to the live root. Repeated deletion in the bin is a
no-op; add no purge action. Refresh live/provider results after restoration.
Test one restored entry becoming live while the others remain recycled, then
verify delete and restore in both directions with the web client.

## 3. Third PR: local reused-password report

Compare exact nonempty passwords across all live records; case and whitespace
remain significant, including space-only values. Return entry IDs/counts and keep
passwords out of logs, telemetry and network requests. Ensure the report can label
records excluded by today's password-card model without losing their identity.
Recompute after mutations, restore and sync.
Test empty, space-only, case-different and recycled values. Clear report state on
lock and retain existing authentication for reveal/copy.

## 4. Native lock review

Review idle behavior and dialogs without copying browser session machinery.
`onStop` already locks except during configuration changes; verify backgrounding,
rotation, process recreation, unsaved forms, revealed dialogs and in-flight work
cannot retain/display secrets after lock or repopulate unlocked state. Preserve
per-operation provider authentication and the separate KySignOn passkey path.
Define any foreground idle-timeout change against the merged web contract before
implementation; the handoff supplies no timeout value. Record actual device
observations separately from compiled device tests.

## References and boundaries

Use merged server PRs [32](https://github.com/Busness-app/kypassword-server/pull/32) and
[33](https://github.com/Busness-app/kypassword-server/pull/33) as behavior references.
The handoff identifies `frontend/src/lib/kdbx.ts`, `recycleBin.test.ts`,
`passwordReuse.ts` and `passwordReuse.test.ts`
in `/home/yoshi/busness.app/kypassword-server-recycle-bin`; read the current merged
versions before implementing each feature. Refresh repo state and instructions
before starting implementation.

Retain lowercase-hex vault credentials, existing Argon2id envelope validation,
size limits, authentication-bound keys and lock/wipe behavior. Do not bundle SCIM,
server backups, FCM work, passkey enrollment or provider API migrations.

Implementation and merge are complete. Physical-device verification remains the
next verification task; see the verification note for the outstanding limits.
