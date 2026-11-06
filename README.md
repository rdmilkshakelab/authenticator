# Catlow Authenticator

A private, installable web authenticator for time-based one-time passwords (TOTP).

## Features

- Generates standard 6- or 8-digit TOTP codes (30- or 60-second periods).
- Add accounts with a Base32 setup key or an `otpauth://` URI.
- QR scanning on browsers that support the native `BarcodeDetector` API.
- Encrypted local vault using AES-256-GCM with a key derived through PBKDF2-SHA-256.
- Encrypted backup export and import.
- Installable Progressive Web App with an offline service worker.
- No account, analytics, backend, or network requests for vault data.

## Deploy

This is a static site. Enable GitHub Pages for the repository and deploy from the `main` branch, root folder. Open the published Pages URL over HTTPS to install it as an app.

## First use

1. Open Catlow Authenticator.
2. Create a vault password (minimum 10 characters).
3. Add an account using its setup key or authenticator QR code.
4. Keep an encrypted backup somewhere safe.

## Security notes

- The vault is encrypted in browser storage. The password is not stored.
- Losing the vault password means the encrypted vault cannot be recovered.
- Exported backups are encrypted with the same vault key and require the same password to import.
- Lock the vault when finished. Catlow also locks when the page is hidden.
- QR scanning depends on browser support for `BarcodeDetector`; manual setup is always available.
- This initial version supports TOTP with HMAC-SHA1. HOTP and non-SHA1 algorithms are not supported.
- Use a trusted device, keep your browser updated, and do not share setup keys or exported backups.

## Local development

Serve this folder over localhost or HTTPS. Service workers and camera access require a secure context.
