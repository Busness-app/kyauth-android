# Contributing to KyAuth

Read [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) before you contribute.

## Setup

Use a supported Android SDK and JDK 17. The Gradle wrapper downloads the required Gradle version.

Run the test suite and build the debug APK before you submit a change:

```bash
./gradlew test assembleDebug
```

## Security rules

- Keep release pairing HTTPS-only.
- Do not weaken QR expiry, origin validation, or redirect blocking.
- Do not log secrets, PINs, pairing credentials, vault keys, OTPs, or passwords.
- Keep sensitive data in app-private storage.
- Preserve the background lock, clipboard clearing, screenshot protection, and wipe behavior.
- Document a new secret, network path, storage location, or security trade-off before review.

## Product rules

- Use `KyAuth` in user-visible text.
- Keep TOTP and password data in separate KDBX files with separate vault keys.
- Do not add KyPasswords sync or Android Autofill without a reviewed threat model and security tests.
- Keep the 15 suite themes numerically aligned with the source palette in `ThemeManager.kt`.

## Documentation

Read [AGENTS.md](AGENTS.md) before you edit the project. Update it when a durable contract or project boundary changes.

Update relevant Markdown files when a user-visible behavior, license, or contributor workflow changes.

## Pull requests

- Make one logical change per pull request.
- Explain the user effect and security effect.
- Add or update tests for non-trivial behavior.
- State which checks you ran.
- Add AI attribution when an AI tool materially contributed.

## License

KyAuth uses the MIT License. By contributing, you license your contribution under MIT.
