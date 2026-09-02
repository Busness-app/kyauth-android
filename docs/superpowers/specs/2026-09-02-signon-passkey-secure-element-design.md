# KySignOn login passkeys in the secure element

Date: 2026-09-02
Status: approved, not yet implemented

## Problem

`kysignon-server` branch `feature/webauthn-passkeys` adds WebAuthn as a second factor. Once it
merges, KyAuth becomes a passkey provider for KySignOn login through the Android Credential
Manager with no code change here — and today that means the credential lands in
`passwords_vault.kdbx`, the vault that syncs to KyPasswords (`AGENTS.md:27`).

A KySignOn *login* passkey in that vault means a KyPasswords compromise plus the master password
yields a KySignOn authentication factor. That contradicts `kysignon-server/design.md:41`: "KySignOn
MFA must remain fully operational even if KyPassword is locked, compromised, or in recovery."

The server cannot prevent it. It records the WebAuthn BE/BS backup flags and badges credentials
`Synced` / `Device-bound`, but deliberately does not reject synced passkeys — that would break
iCloud Keychain and Windows Hello for every browser user. Those flags are also self-asserted by the
client, because attestation is not verified: the badge is a claim, not evidence. Enforcement has to
happen here, where the vault is chosen.

## Decision

A KySignOn login passkey is generated in, and never leaves, the device's secure element. Its
private key is a non-exportable `AndroidKeyStore` P-256 key, StrongBox-backed where the hardware
allows and TEE-backed otherwise. It is not stored in any KDBX vault and never syncs.

Device loss means the passkey is gone, and recovery falls to KySignOn recovery codes or an admin
MFA reset. That is the correct trade for an MFA factor and matches how `totp_vault.kdbx` already
behaves. Confirmed as a product decision, not an assumption.

### Rejected alternatives

**A third KDBX vault (`signon_vault.kdbx`).** Symmetric with `totp_vault.kdbx` and superficially
tidy, but a KDBX vault can only hold an exportable key, so it forfeits the secure element outright.
Its key would also be wrapped by the same `VaultKek` blob as the other two, so it would look like
isolation while delivering none.

**Keep it in `passwords_vault.kdbx`, tagged non-syncable.** Cheapest diff. Rejected: the private
key stays exportable and stays inside the blast radius of a KyPasswords compromise, and the
security property would depend on every future sync path continuing to honour a flag.

## Non-goals

- Key attestation. Now that the key is hardware-resident, `setAttestationChallenge` could give the
  server a verifiable chain and retire the "badge is a client claim" problem. It needs a matching
  verifier in `kysignon-server`, which is in its final fix wave. Tracked as a follow-up below.
- Any change to non-KySignOn passkeys. They keep syncing via `passwords_vault.kdbx`, deliberately,
  as other password managers do.
- Migrating existing keys in place. Not possible; see "Stranded passkeys".

## Design

Target is `minSdk 31`, so `setIsStrongBoxBacked` (API 28), `setUnlockedDeviceRequired` (API 28),
`setUserAuthenticationParameters` (API 30) and `AUTH_DEVICE_CREDENTIAL` (API 30) are all available
unconditionally. The Credential Provider itself remains `@RequiresApi(34)`.

### 1. Routing

One predicate, evaluated in one place: the already-validated `rpId` equals
`RpId.normalize(Uri.parse(PairingStore.account().serverUrl).host)`. Comparing normalized forms on
both sides keeps the match exact — no subdomain or parent-domain matching, matching the "Passkey
matching is exact on RP ID" rule in `AGENTS.md:48`.

`KyAuthCredentialProviderService` applies it in both `onBeginGetCredential` and
`onBeginCreateCredential`, choosing the local path or the vault path before any key material is
touched. When the device is not paired the predicate is false for every RP, the local path does not
exist, and behaviour is exactly as today.

The paired server URL is a locally-held fact, so a hostile relying party cannot opt itself into the
local store by asserting an RP ID. The predicate composes with — does not replace — the existing
`RpId.validate` and `DigitalAssetLinks` checks: a caller must still prove it is authorized for that
RP ID before anything is offered or minted.

### 2. `passkeys/SignOnPasskeyKey`

Generates and holds the P-256 key in `AndroidKeyStore` under alias `kyauth_signon_passkey_v1`:

- `setIsStrongBoxBacked(true)`, catching `StrongBoxUnavailableException` and regenerating without
  it. Which backing succeeded is recorded so the UI can state it truthfully rather than implying a
  secure element that is not there.
- `setUserAuthenticationRequired(true)` with
  `setUserAuthenticationParameters(0, AUTH_BIOMETRIC_STRONG or AUTH_DEVICE_CREDENTIAL)` — per-use
  authentication, the pattern `VaultKek` and `DeviceSigningKey` already use.
- `setUnlockedDeviceRequired(true)`.
- `setDigests(DIGEST_SHA256)`, `PURPOSE_SIGN`.

There is no fallback to a software or vault-held key. If the key cannot be created in hardware,
enrolment fails closed.

The `kyauth_` alias prefix is matched by the existing alias sweep in `SecurityWipe.wipe`, so local
wipe covers the key with no change to `SecurityWipe`. Unpairing must also delete the alias and the
metadata below: a passkey for a server we are no longer paired to is dead weight.

### 3. `passkeys/SignOnPasskeyStore`

The private key is non-exportable, so no secret remains to vault. What is left is rpId,
credentialId, userHandle, username, signCount and the backing type. This goes in an
`EncryptedSharedPreferences` store modelled directly on `PairingStore` — same dependency, same
pattern, no new crypto and no third KDBX vault.

`signCount` is incremented and persisted on every successful assertion.

### 4. Flows

**Create** — `ACTION_CREATE_SIGNON_PASSKEY` on `CredentialAuthActivity`. Generate the Keystore key,
then run `BiometricPrompt` with `CryptoObject(Signature)` over the fresh key. That satisfies
WebAuthn user verification and proves the key is usable before a public key is handed to the
server. The attestation object stays `fmt: none`, as today. Metadata is persisted only after the
response is successfully built, so a cancelled or failed creation leaves no orphan record.

**Get** — `ACTION_GET_SIGNON_PASSKEY`. The authenticated object differs between the two paths
(`Signature` here, `Cipher` for the vault), and the prompt must be constructed with the right one,
so the branch happens before the prompt. That is why these are distinct actions rather than a flag
inside `handleGetPasskey`.

`VaultUnlockPrompt` gains a signature variant alongside its existing cipher variant.
`WebAuthnEngine.signAssertion` gains a `Signature` overload, and the existing `ECPrivateKey` version
delegates to it, so there remains one signing path rather than two.

### 5. Enumeration while locked

`KyAuthCredentialProviderService.buildGetResponse` currently returns `lockedResponse()` whenever the
password vault key is absent. This changes: local passkey entries are built regardless of lock
state, and vault entries are added only when unlocked.

This is the load-bearing part of the design. If a KySignOn assertion required the user to tap
"Unlock KyAuth", the MFA factor would depend on a `VaultKek` unwrap of the password vault — the
exact dependency `design.md:41` forbids. As designed, the KySignOn path never calls
`AppLockManager.useVaultKeys` and never holds a vault key.

The deliberate cost: while KyAuth is locked, the existence of a KySignOn passkey is visible to the
enumeration path. The exposure is bounded — only a caller that has already proven authorization for
the paired KySignOn host reaches it — but it is a real departure from "locked reveals nothing" and
is recorded here rather than left implicit.

### 6. Stranded passkeys

Any passkey already in `passwords_vault.kdbx` whose rpId matches the paired host is refused by the
KDBX path and badged "Re-enroll on KySignOn" in the Passwords tab.

It is not deleted automatically. It may be a user's only MFA factor, and removal is a user action.
The key cannot be migrated in place either: a key that was ever exportable cannot become
secure-element-resident, so re-enrolment is the only honest path.

### 7. UI

The local passkey appears in **Settings**, next to pairing and Push MFA, as "KySignOn passkey —
device-bound (StrongBox)" or "(hardware-backed)" per the recorded backing type, with a remove
action. Not the Passwords tab: it is not a password and it does not sync, and the Passwords tab
would imply both.

Enrolment states plainly that the passkey stays on this device and that losing the device means
falling back to recovery codes or an admin reset.

## Security properties

Claimed, and to be demonstrated by the tests below:

- The KySignOn passkey private key is non-exportable and never enters a KDBX vault or any synced
  artifact.
- The KySignOn assertion path never calls `AppLockManager.useVaultKeys` and never obtains a vault
  key, so it is unaffected by the password vault being locked, compromised, or in recovery.
- Each use of the key requires fresh user authentication.
- A relying party other than the paired KySignOn host cannot reach the local store.

Explicitly **not** claimed:

- That the key is in a discrete secure element. On a device without StrongBox it is TEE-backed. The
  UI reports which, and nothing in the design assumes StrongBox.
- That the server can verify any of the above. Without attestation the server still has only the
  client's word. See the follow-up.

## Testing

Unit (`app/src/test`):

- The routing predicate: paired host matches, sibling and parent domains do not, unpaired matches
  nothing.
- `SignOnPasskeyStore` round-trip and `signCount` increment.
- The `WebAuthnEngine.signAssertion` `Signature` overload against a software key, asserting it
  produces the same bytes as the existing `ECPrivateKey` path.

Instrumented (`app/src/androidTest/DeviceSecurityTest`):

- Key generation succeeds, StrongBox-then-TEE, and the resulting key is non-exportable.
- A locked app still enumerates the local passkey while offering no vault entries.

Per-use biometric prompts still require manual device verification; this is added to the
`AGENTS.md` "Outstanding security work" list rather than claimed as covered.

Full gate: `./gradlew test lintDebug assembleDebug compileDebugAndroidTestSources`.

## Documentation to update

- `AGENTS.md:27` — passkey vault placement now has an exception.
- `AGENTS.md:106` — "Passkey private keys are exportable" currently documents the opposite decision
  for this case and must be rewritten to scope it to non-KySignOn passkeys.
- `AGENTS.md` project layout — the two new files in `passkeys/`.
- `prompt.md:22` — extend the existing "must not sync TOTP data" rule to cover the KySignOn passkey,
  rather than adding a parallel rule.

## Follow-ups

- **Key attestation.** `setAttestationChallenge` plus a verifier in `kysignon-server` would let the
  server prove hardware backing instead of trusting the client's BE/BS claim.
- Unrelated, from the originating hand-off: making `kypassword-server` OIDC-only, and consolidating
  the duplicated pairing/audit code into `ky_server_base`.
