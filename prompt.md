# KyAuth Android Product Notes

KyAuth is an on-device authenticator for the KySecurity suite.

## Current scope

- Pair a device with KySignOn from a short-lived QR payload or manual server details.
- Store TOTP entries in an encrypted local KDBX v4 vault.
- Store password entries in a separate encrypted local KDBX v4 vault.
- Protect the app with biometric or device authentication and an optional PIN.
- Apply PIN delays and wipe local data after five failed PIN attempts.
- Show a Push MFA interface and send signed approve or deny responses.
- Offer 15 suite color themes and an MIT About dialog.

## Accepted decisions

- Biometric or device authentication is always required to unlock KyAuth.
- The PIN is an optional second local factor.
- TOTP entries use a dedicated KDBX vault.
- Passwords use a separate KDBX vault and a separate vault key.
- Password reveal and copy require a fresh biometric or device-authentication prompt.
- KyPasswords sync is a later feature. It must not sync TOTP data.
- Password sync must not send plaintext passwords or vault keys to KyPasswords.
- Release builds require HTTPS. Debug builds allow loopback HTTP only.
- The pairing registration endpoint must share the pairing server origin.

## Planned work

- Add a production Push MFA challenge-receive path.
- Define encrypted record sync, revisions, and conflict behavior before network sync work starts.
