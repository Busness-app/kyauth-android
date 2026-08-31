# KyAuth Android Client

KyAuth is the native Android authenticator for the KySecurity suite.

## Purpose

KyAuth pairs an Android device with KySignOn. It stores TOTP entries in an encrypted local KDBX v4 vault. It also provides a local biometric and optional PIN lock.

## Current product contract

- Pairing accepts a short-lived KySignOn QR payload or manual server details.
- Release builds require HTTPS. Debug builds permit loopback HTTP only.
- The optional registration URL must use the same origin as the pairing server.
- The app generates a hardware-backed P-256 device signing key.
- TOTP entries use KeePass `TimeOtp-*` fields in `totp_vault.kdbx`, along with standard KeePass title, URL, and notes.
- The TOTP vault uses an app-private file and an independent random vault key.
- Both vault keys are wrapped by `VaultKek`, an authentication-bound Keystore RSA-OAEP key
  (`setUserAuthenticationRequired(true)`, per-use). Wrapping needs no prompt; unwrapping requires a
  `BiometricPrompt.CryptoObject`. A device without a secure lock screen cannot use KyAuth.
- One authentication yields one unwrap, so both keys share a single wrapped blob.
- The app locks when it moves to the background. It clears in-memory TOTP data and its copied code,
  and zeroes the vault key arrays.
- The PIN is an optional second local factor. Failed PIN attempts use delays of 0, 5, 30, and 300 seconds. The fifth failure wipes local data.
- Release builds disable screenshots and Android backup.
- Push MFA receives KySignOn FCM data-message challenges, posts a local notification, and opens the Push MFA tab for approve/deny. A response is only ever sent to the paired server; a `serverUrl` in the push payload is ignored. Digits must be two-digit, decoys are capped at 3, and expiry is clamped to 10 minutes.
- An MFA response must carry an explicit decision. A 2xx with no `approved`/`success` field is a protocol error, not an approval.
- Passwords and Passkeys use `passwords_vault.kdbx`. The app can generate an independent random local vault key for device-only storage. Pairing with an empty KyPasswords account uploads that local vault with a client-created password envelope; pairing never replaces an existing server vault that uses another key.
- Passkeys use native ES256 / P-256 WebAuthn cryptography with COSE public key encoding and ECDSA assertion signing.
- KyAuth acts as an Android 14+ (API 34+) system Credential Provider for both Passkeys and Passwords via `KyAuthCredentialProviderService` (with `CredentialAuthActivity`) and an Android 12+ (API 31+) system Autofill Service via `KyAuthAutofillService`.
- While locked, neither provider touches vault material. Autofill returns a `FillResponse` with an
  authentication `IntentSender` (`AutofillUnlockActivity`); the Credential Provider returns an
  authentication `Action` (`CredentialUnlockActivity`). Both unwrap the keys for one operation via
  `AppLockManager.useVaultKeys` and erase them again, so a background request never unlocks the app.
- Passkey RP IDs are validated by `RpId`: syntactically valid, not a public suffix, and for browser
  callers equal to or a registrable parent of the caller's web origin. Native-app callers are bound
  to the RP by `DigitalAssetLinks`, which fetches `https://<rpId>/.well-known/assetlinks.json` and
  matches the caller's signing certificate. It fails closed: no statement, or an offline device with
  a cold cache, means no passkeys are offered to a native caller.
- A caller-supplied `clientDataHash` is honoured only from a caller that set a privileged web origin
  (`ClientData.privilegedClientDataHash`). Only a holder of `CREDENTIAL_MANAGER_SET_ORIGIN` can set
  that origin, so an ordinary app cannot choose the bytes KyAuth signs. For every other caller the
  `CollectedClientData` is built here, with the `android:apk-key-hash:` origin.
- Autofill believes a request's `webDomain` only from a known browser installed as a system app or
  by Google Play; any other
  caller is matched on its own package. `setWebDomain` is public API, so an unfiltered domain from an
  arbitrary app would hand one site's credential to another.
- Password fill matches an entry's domain or its subdomains, never a parent or sibling, and never
  across a public suffix. Passkey matching is exact on RP ID.
- Every incremental vault mutation goes through `KdbxPasswordVault.update`, one serialized
  read-modify-write. `loadEntries` throws on a vault it cannot decode; callers must never turn that
  into an empty list.
- The Passwords tab supports pairing with KyPasswords, syncing vaults, local add, generate, list, reveal, copy, and delete actions with distinct Passkey badging. Reveal and copy require a biometric or device-authentication prompt.
- Copied passwords are marked sensitive and clear after 30 seconds or when KyAuth locks.

## UI contract

- Use the `KyAuth` name in user-visible text.
- Keep the KySignOn mark and KyAuth wordmark in the header and lock screen.
- Use the five-part bottom pill: TOTP Vault, Push MFA, lock shield, Passwords, Settings.
- The TOTP Vault screen provides a + icon to scan QR or add accounts manually with optional Website and Notes fields.
- Use the 15 suite themes from `ThemeManager`. The default is Patina Ky.
- Use rounded, flat buttons. Do not add elevation shadows to custom controls.

## Project layout

- `app/src/main/java/org/kysecurity/authenticator/MainActivity.kt`: app UI and workflows.
- `pairing/`: QR parsing, endpoint validation, pairing network client, device key, and encrypted pairing store.
- `mfa/`: push challenge model, FCM receive service, signed payload, and response client.
- `security/`: lock state, PIN policy, `VaultKek` authentication-bound key wrapping, `VaultUnlockPrompt`, atomic file writes, and local wipe.
- `totp/`: TOTP parsing, generation, and KDBX persistence.
- `passwords/`: password/passkey entry models, domain matcher, password generator, autofill service, and KDBX persistence.
- `passkeys/`: FIDO2 WebAuthn crypto engine, `ClientData` (CollectedClientData), `RpId` validation, CredentialProviderService, entry builder, slice builder, unlock activity, and auth activity.
- `ThemeManager.kt`: the shared 15-theme palette and local theme preference.
- `UiComponents.kt`: reusable programmatic view styling and controls.
- `AboutDialog.kt`: MIT About dialog.

## Work guidance

- Use the smallest correct change.
- Reuse native Android APIs and existing project code before adding dependencies.
- Fix shared root causes, not one call site.
- Keep security checks fail-closed.
- Add a focused test for non-trivial logic.
- Update this file when a durable product contract, workflow, or file boundary changes.

## Verification

Run unit tests, lint, the debug build, and compile device tests:

```bash
./gradlew test lintDebug assembleDebug compileDebugAndroidTestSources
```

## Outstanding security work

Recorded so it is not mistaken for done:

- **Non-Play browser builds.** `TrustedBrowsers` accepts known browser packages only when installed
  by Google Play or as system apps. F-Droid and direct-download builds fail closed until explicit
  signing-certificate pins are maintained for them.
- **Vault size ceilings.** `KyPasswordClient` and `KdbxPasswordVault` cap a synced vault at 25 MB and
  a JSON body at 1 MB. Large legitimate vaults would need these raised.
- **Push MFA payload binding.** `MfaMessage.formatPayload` still signs only
  `prefix|challengeId|verb|digits`. Binding server origin, account, purpose and expiry needs a
  matching KySignOn server change.
- **Passkey private keys are exportable.** Deliberate: they live in the KDBX vault so they sync and
  restore, as other password managers do. Protection comes from the authentication-bound vault key.
  Non-exportable Keystore keys would make passkeys device-only.
- **Device verification.** Emulator tests cover secure-lock-backed `VaultKek` creation and backup
  flags. Full biometric prompts, `useVaultKeys`, and provider unlock flows still require manual
  device verification.
- **Deprecated platform APIs.** `Slice`, `EncryptedSharedPreferences`/`MasterKey`, and the
  `Dataset`/`FillResponse` builders are deprecated. Moving to `androidx.credentials` would remove
  most of the Slice usage.

## Child DOX Index

No child `AGENTS.md` files exist.
