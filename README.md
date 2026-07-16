# KeyForge

A Bitwarden-style password manager that runs entirely on your machine.
One encrypted file, no network, no accounts. C++20, Dear ImGui.

## Window

KeyForge opens a three-pane window: a tag sidebar (click a tag to filter,
"All" resets), a searchable entry list, and a detail panel. Select an entry
to view it (copy buttons, password reveal, live TOTP); **+ Add** and **Edit**
open an inline form with a password generator and TOTP by secret, otpauth://
URI, or a QR image — you can also drag a QR image onto the window. The
sidebar's audit button flags weak/reused/old passwords; settings holds
CSV import/export. Every command below is still available via a **Ctrl+K**
(Cmd+K on macOS) palette overlay.

## Build

Needs CMake ≥ 3.24 and a C++20 compiler. All libraries are fetched
automatically on first configure (takes a few minutes).

    cmake -B build -DCMAKE_BUILD_TYPE=Release
    cmake --build build -j
    ./build/tests/core_tests        # run the test suite
    ./build/app/keyforge            # launch (add --vault <path> to override)

## Commands

Type into the palette. `help` shows this list in-app.

    add <name> --password P [--username U] [--url U] [--notes N] [--tags t1,t2]
               [--totp-secret S | --totp-uri URI | --totp-qr PATH]
    update <name> [same flags as add]
    delete <name> --yes
    show <name>                    field view, password masked
    retrieve <name> [--type password|username|url|notes|totp]   copies to clipboard
    totp <name>                    live 6-digit code
    list [--tag filter]
    gen [--len N] [--no-symbols] [--allow-ambiguous]
    audit                          weak / reused / old passwords
    export <path>                  encrypted vault backup
    import <path> [--format csv]   Chrome/Bitwarden CSV
    lock
    help

Typing anything else searches your entries live.

## Security model

- Vault file: `KFV1` header (Argon2id opslimit/memlimit, salt, nonce) +
  XChaCha20-Poly1305 ciphertext of a JSON payload. The header is
  authenticated data — any tampering, even with KDF params, fails decryption.
- Master password → Argon2id (libsodium MODERATE) → 256-bit key.
- Saves are atomic (tmp + fsync + rename); the previous version is kept
  as `vault.kfv.bak`.
- The key lives in `sodium_malloc` locked memory and is wiped on lock/exit;
  the master-password input buffer is zeroed after use. Decrypted entry
  data lives in ordinary process memory while unlocked — locking drops it.
  Full locked-memory entry storage is out of scope.
- Clipboard auto-clears (default 30 s) only if it still holds our value.
- Auto-lock after idle (default 5 min), manual `lock`, lock on exit.

Default vault location: `~/Library/Application Support/keyforge/vault.kfv`
(macOS), `%APPDATA%\keyforge` (Windows), `~/.local/share/keyforge` (Linux).
