# Chromium DPAPI Master Key Decryptor

A **single‑file Rust executable** that extracts the 32‑byte AES master key from Chromium‑based browsers (Chrome, Edge, Brave, …) **without injection, without COM, and without the browser running**.

It reads the `Local State` file, uses Windows’ built‑in DPAPI (`CryptUnprotectData`) to decrypt the key, and prints it as Base64.

> **Note:** This tool uses the classic `os_crypt.encrypted_key` field (DPAPI) – not the newer app‑bound encryption.  
> It works on all Chromium versions that still include that fallback (which is currently all of them).

---

## How it works

1. Locates the browser’s `Local State` JSON file (auto‑detects from `%LOCALAPPDATA%`, or you can provide a custom path).
2. Reads the `os_crypt.encrypted_key` value (Base64, prefixed with `DPAPI`).
3. Strips the `DPAPI` prefix and calls `CryptUnprotectData` (DPAPI) to decrypt the blob.
4. Prints the resulting **32‑byte AES master key** as a Base64 string.

Because DPAPI is tied to the current Windows user, you must run the tool **as the same user who owns the browser profile**.

---

## Supported Browsers

- Google Chrome
- Microsoft Edge
- Brave
- (any Chromium fork that stores `encrypted_key` under `os_crypt` in `Local State`)

You can easily add more by editing the `BROWSERS` array in `src/main.rs`.

---

## Build

```bash
cargo build --release