# KyAuth Visual Style Guide

## Brand

Use the KySignOn shield mark with the `KyAuth` wordmark. Do not use `KyAuthenticator` in user-visible text.

## Themes

`ThemeManager.kt` is the Android source of truth for these themes:

- Dark Matter
- Light Matter
- Tropics
- Tropic Night
- Ocean
- Coffee
- White Cliffs
- Cyber Punk
- Neon Purple
- Space
- Sky
- Forest
- Sun
- Patina Ky
- Polished Ky

Patina Ky is the default. Use `ThemeManager.color` for app colors. Do not use fixed Patina colors for a themed view.

Keep danger and success colors separate from the theme palette.

## Layout

- Keep 20dp content padding at the screen edge.
- Add a larger header above dashboard content.
- Keep the five-part navigation pill at the bottom of the dashboard.
- Use a centered card for an empty Push MFA screen.
- Group Settings content in padded cards.
- Require a fresh biometric or device-authentication prompt before Passwords reveals or copies a password.

## Shape and depth

- Use 14dp corners for inputs.
- Use 20dp corners for cards.
- Use 24dp corners for primary and secondary buttons.
- Use stadium corners for navigation pills and badges.
- Use flat custom controls. Do not use elevation shadows.

## Type and feedback

- Use system-scaled `sp` text sizes.
- Use monospace text only for codes, secrets, and technical values.
- Keep button labels readable at large system font sizes.
- Mark copied OTP codes as sensitive and clear the app-owned clipboard entry on lock or expiry.

## Native behavior

Use Android system dialogs for biometric prompts. Use `AlertDialog` for confirmation and the About dialog. Apply the active theme palette to custom dialog content.
