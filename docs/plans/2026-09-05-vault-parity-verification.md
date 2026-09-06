**Repo:** kyauth-android
**PR:** #7 — https://github.com/Busness-app/kyauth-android/pull/7
**Worktree:** /home/yoshi/busness.app/kyauth-android (branch feat/vault-preservation)

# Vault parity implementation and verification

Implementation is built and committed at `cbca78a9d987ffe0b47a5eb0f4a6d0f172256d88`.
PR #8 (recycle recovery) and #9 (reuse/locking) were merged into #7 externally
during implementation. PR #7 subsequently merged into `main` on 2026-09-06 at
02:44:17 UTC (2026-09-05 22:44:17 EDT), as merge commit
`a21dc3ad63ff6bd026621c70ee42e9c3aa40f1f8`. Implementation and merge are complete.
The local checkout remains on `feat/vault-preservation`; this status update did
not change branches or rebuild the APK. The original plan is historical context.

## Built

- Patch decoded KDBX records by UUID instead of reconstructing the database from
  the UI projection. Preserve unrelated groups, metadata, protected fields,
  attachments and bounded history. Corrupt/invalid files fail without writing.
- Snapshot and validate sync, guard concurrent changes, preserve both encrypted
  conflict copies, and offer explicit device/server resolution and encrypted
  export. A validated master-password key remains available after a sync conflict.
  Clean sync and unpair clear conflict copies.
- Identify the real recycle bin through metadata, exclude it from live/provider
  results, and restore original records intact from a separate deleted-entry view.
- Report exact nonempty password reuse locally, including whitespace-only values
  and entries outside the ordinary display projection, without showing passwords.
- Add configurable native idle locking (five-minute default), clear revealed and
  unsaved dialogs on lock, and reject stale asynchronous UI completions.
- Keep vault work off the UI thread. Add debug-only loopback network policy matching
  existing endpoint validation; other cleartext destinations remain denied.

Mobile CSV import was removed from the plan at Yoshi's request on 2026-09-06.

## Artifact and proof

Debug APK: `app/build/outputs/apk/debug/app-debug.apk`

SHA-256: `0aca496dc40ff5df703754a1f6dd40e6a563a4a9a67be904fd70beaa87181ec1`

Full local runs passed on API 36 at `9232f09` and API 35 at final code head
`cbca78a` (the latter also includes the unpair race regression):

```bash
ANDROID_SERIAL=<task-emulator> ./gradlew test lintDebug assembleDebug compileDebugAndroidTestSources connectedDebugAndroidTest
node tools/vault_preservation.js app/build/interop
```

137 unit tests passed. Each platform's instrumented XML reports 20 tests, zero
failures/errors, and four hardware-key assumptions skipped. Instrumented checks
cover StrictMode threading, real loopback HTTP master-password conflict recovery,
recycle restore, reuse refresh, and clearing revealed/unsaved forms on lock.
The kdbxweb verifier checks no-op/targeted-write preservation and delete/restore
interoperability. The added unpair check failed before the fix and passed after it.
Logs: `/tmp/kyauth-unpair-race-fixed.log` (final API 35 run) and
`/tmp/kyauth-final-verification.log` (API 36).

CI now uses the verified API 35 Google APIs/Pixel 6 profile, keeps the screen
awake, and retries temporary missing UI roots while waiting for the PIN field to
become ready. All CI checks are green at final head `cbca78a`, including both verify jobs,
both device jobs, and dependency submission. The unpair fix clears account/key/files in one transaction, so
a new device-only vault cannot race the old vault's asynchronous teardown.

## Remaining and cautions

- Review history: the reviewer marked the recovery findings RESOLVED and cleared
  `464f4d3`. At this update, no verdict for final head `cbca78a` is recorded.
  PR #7 was merged externally with all final-head CI checks green; merging must
  not be represented as a fresh autonomous security clearance. #8 had a clear
  review on an earlier head; #9 merged before its reviewer comment appeared.
- Physical-device hardware-backed key generation and full biometric/provider
  authentication flows remain unverified. Fake-unlocked UI fixtures prove lifecycle
  behavior, not biometric authentication or hardware key residency.
- Do not flatten a vault or automatically choose one side of a sync conflict.
  The four skipped tests must not be counted as positive hardware verification.
- The local verification note is a durable report artifact, intentionally separate
  from the already-pushed code commits so a status update does not reset CI/review.

Temporary worktrees, the implementation stash, and task-created emulators were
removed. The APK remains at the path above. Code changes are committed/pushed;
this local report is the only untracked artifact. The handoff is complete.
Any follow-up should start from merged `main`; physical-device verification
remains a separate outstanding item described above.
