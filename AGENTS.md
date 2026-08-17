# KyAuth Android Client

KyAuth is the native Android authenticator for the KySecurity suite.

## Purpose

KyAuth pairs an Android device with KySignOn. It stores TOTP entries in an encrypted local KDBX v4 vault. It also provides a local biometric and optional PIN lock.

## Current product contract

- Pairing accepts a short-lived KySignOn QR payload or manual server details.
- Release builds require HTTPS. Debug builds permit loopback HTTP only.
- The optional registration URL must use the same origin as the pairing server.
- The app generates a hardware-backed P-256 device signing key.
- TOTP entries use KeePass `TimeOtp-*` fields in `totp_vault.kdbx`.
- The TOTP vault uses an app-private file and an independent random vault key.
- The app locks when it moves to the background. It clears in-memory TOTP data and its copied code.
- The PIN is an optional second local factor. Failed PIN attempts use delays of 0, 5, 30, and 300 seconds. The fifth failure wipes local data.
- Release builds disable screenshots and Android backup.
- Push MFA receives KySignOn FCM data-message challenges, posts a local notification, and opens the Push MFA tab for approve/deny.
- Passwords and Passkeys use `passwords_vault.kdbx` and a separate random vault key. The password vault stores KeePass title, username, password, URL, notes, and FIDO2 Passkey custom fields (`Passkey-*`).
- Passkeys use native ES256 / P-256 WebAuthn cryptography with COSE public key encoding and ECDSA assertion signing.
- KyAuth acts as an Android 14+ (API 34+) system Credential Provider for both Passkeys and Passwords via `KyAuthCredentialProviderService` (with `CredentialAuthActivity`) and an Android 12+ (API 31+) system Autofill Service via `KyAuthAutofillService`.
- The Passwords tab supports local add, generate, list, reveal, copy, and delete actions with distinct Passkey badging. Reveal and copy require a biometric or device-authentication prompt.
- Copied passwords are marked sensitive and clear after 30 seconds or when KyAuth locks.
- KyPasswords remote sync is a later feature.

## UI contract

- Use the `KyAuth` name in user-visible text.
- Keep the KySignOn mark and KyAuth wordmark in the header and lock screen.
- Use the five-part bottom pill: TOTP Vault, Push MFA, lock shield, Passwords, Settings.
- Keep TOTP scan and manual-add actions in Settings.
- Use the 15 suite themes from `ThemeManager`. The default is Patina Ky.
- Use rounded, flat buttons. Do not add elevation shadows to custom controls.

## Project layout

- `app/src/main/java/org/kysecurity/authenticator/MainActivity.kt`: app UI and workflows.
- `pairing/`: QR parsing, endpoint validation, pairing network client, device key, and encrypted pairing store.
- `mfa/`: push challenge model, FCM receive service, signed payload, and response client.
- `security/`: lock state, PIN policy, key wrapping, and local wipe.
- `totp/`: TOTP parsing, generation, and KDBX persistence.
- `passwords/`: password/passkey entry models, domain matcher, password generator, autofill service, and KDBX persistence.
- `passkeys/`: FIDO2 WebAuthn crypto engine, CredentialProviderService, slice builder, and auth activity.
- `ThemeManager.kt`: the shared 15-theme palette and local theme preference.
- `AboutDialog.kt`: GPL-3.0-only About dialog.

## Work guidance

- Use the smallest correct change.
- Reuse native Android APIs and existing project code before adding dependencies.
- Fix shared root causes, not one call site.
- Keep security checks fail-closed.
- Add a focused test for non-trivial logic.
- Update this file when a durable product contract, workflow, or file boundary changes.

## Verification

Run the unit tests and build the debug APK:

```bash
./gradlew test assembleDebug
```

## Child DOX Index

No child `AGENTS.md` files exist.
