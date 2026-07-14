# KeyForge — Local Password Manager (Design Spec)

**Date:** 2026-07-14
**Status:** Approved
**Location:** `~/Claude/keyforge`

## Purpose

A Bitwarden-style password manager written in C++ that runs entirely locally —
no network, no accounts, one encrypted vault file. Desktop GUI with a
command-palette interface (dark, green-on-black monospace theme, per reference
screenshots): a single input where the user types commands or searches entries.

## Decisions (locked during brainstorming)

| Decision | Choice |
|---|---|
| UI | Native GUI: Dear ImGui + GLFW (cross-platform: macOS/Windows/Linux) |
| Crypto | libsodium — Argon2id KDF + XChaCha20-Poly1305 AEAD |
| Architecture | `vaultcore` static library (all logic, no UI) + thin ImGui shell |
| Vault location | OS app-data dir by default; path override in settings (portable use OK) |
| Extras | Clipboard copy w/ auto-clear, auto-lock on inactivity, import/export, vault health audit |
| Language/build | C++20, CMake, all deps via FetchContent (builds anywhere with CMake + compiler) |
| Tests | doctest, core-only coverage, run via ctest |

## Project Layout

```
keyforge/
├── CMakeLists.txt
├── core/                 # vaultcore static library — zero UI code
│   ├── include/vaultcore/*.hpp
│   └── src/
│       ├── crypto.cpp      # libsodium wrapper: Argon2id KDF, seal/open
│       ├── vault.cpp       # in-memory vault: entries, CRUD, search, tags
│       ├── storage.cpp     # encrypted file format, atomic save + .bak
│       ├── generator.cpp   # password generation (CSPRNG)
│       ├── totp.cpp        # RFC 6238 TOTP, base32, otpauth:// parsing
│       ├── qr.cpp          # QR image → otpauth URI (quirc + stb_image)
│       ├── commands.cpp    # command parser + dispatcher → typed results
│       ├── audit.cpp       # weak/reused/old password checks
│       ├── porting.cpp     # CSV import, vault export
│       └── paths.cpp       # OS app-data dir resolution
├── app/                  # ImGui + GLFW shell: theme, palette, clipboard, timers
└── tests/                # doctest unit tests for core only
```

Dependencies (FetchContent): Dear ImGui, GLFW, libsodium (CMake wrapper),
quirc, stb_image, doctest.

## Security Model

**Vault file** — single file, default `<app-data>/keyforge/vault.kfv`
(`~/Library/Application Support` on macOS, `%APPDATA%` on Windows,
`~/.local/share` on Linux), path overridable in settings:

```
[magic "KFV1"][Argon2id opslimit+memlimit][16B salt][24B nonce][ciphertext]
```

- **KDF:** Argon2id via libsodium `crypto_pwhash`, MODERATE limits, from
  master password + salt → 256-bit key. Params stored in header so they can
  be raised later without breaking old vaults.
- **Encryption:** XChaCha20-Poly1305 AEAD over the JSON payload; the entire
  header is authenticated data (AAD). Tampering with anything — including KDF
  params — fails decryption. Wrong password and corruption are both detected
  cryptographically.
- **Memory hygiene:** derived key and decrypted payload in `sodium_mlock`ed
  buffers; `sodium_memzero` on lock/exit; master-password input buffer wiped
  after use.
- **Atomic saves:** write temp file → fsync → rename over vault; previous
  version kept as `vault.kfv.bak`. Crash mid-save never destroys the vault.
- **Locking:** `lock` command, auto-lock after N idle minutes (default 5),
  and lock-on-exit all wipe key + plaintext; app returns to unlock screen.
- **Clipboard:** `retrieve` copies via GLFW clipboard API; after N seconds
  (default 30) the clipboard is cleared *only if it still holds our value*.

**Entry model** (JSON payload, in memory only while unlocked):

```json
{
  "settings": { "auto_lock_min": 5, "clip_clear_sec": 30,
                "gen_len": 20, "gen_symbols": true },
  "entries": [ {
    "name": "GitHub",            // unique key
    "username": "", "password": "", "url": "", "notes": "",
    "tags": ["dev"],
    "totp_secret": "",           // base32, empty if none
    "created_at": 0, "updated_at": 0, "password_changed_at": 0
  } ]
}
```

## UI

Three screens, matching the reference screenshots:

1. **Unlock** — first run: create master password (entered twice, min 8
   chars); afterwards: single prompt. Failure shows error, wipes input.
2. **Main** — slim left sidebar (logo top; settings gear + exit at bottom),
   command input with placeholder "Type a command or search entries…",
   results area below. Dark theme, green accent, monospace font.
3. **Settings pane** (gear) — auto-lock minutes, clipboard clear seconds,
   generator defaults, vault path. Persisted inside the encrypted vault.

**Palette behavior:**
- Empty input → list all entries. Plain text → live substring filter over
  name/username/url/tags.
- Recognized command prefix → inline usage help while typing; Enter executes.
- Results below: entry lists, generated password, TOTP code with live
  countdown, errors in red.

## Commands

| Command | Behavior |
|---|---|
| `add <name> --password P [--username U] [--url U] [--notes N] [--tags t1,t2] [--totp-secret S \| --totp-uri URI \| --totp-qr PATH]` | Create entry; unique name; TOTP from base32 secret, otpauth:// URI, or QR image file |
| `update <name> [same flags as add]` | Change any subset of fields; each given flag replaces that field wholesale (`--tags` replaces the tag list, not merges); `--password` updates `password_changed_at` |
| `delete <name> --yes` | Delete; refuses without `--yes` |
| `show <name>` | Full entry; password masked with reveal toggle |
| `retrieve <name> [--type password\|username\|url\|notes\|totp]` | Copy field (default password) to clipboard with auto-clear |
| `totp <name>` | Current 6-digit code + seconds remaining, auto-refresh |
| `list [--tag filter]` | All entries or filtered by tag |
| `gen [--len N] [--no-symbols] [--allow-ambiguous]` | Default 20 chars, symbols on, ambiguous (`0O1lI`) excluded; guarantees ≥1 upper, digit, symbol (when enabled); CSPRNG only |
| `lock` | Wipe secrets, return to unlock screen |
| `audit` | Flag weak (short/low char variety), reused (identical across entries), old (>1 year unchanged) |
| `export <path>` | Copy of the encrypted vault file to path |
| `import <path> --format csv` | Import Bitwarden/Chrome-style CSV (name,url,username,password,notes) |
| `help` | Command reference listing |

## Error Handling

- Core returns `Result<T>` (value or typed error code + message). Core never
  prints or aborts; the shell renders errors in red.
- Wrong password / corrupt vault: "Invalid master password (or vault file is
  corrupted)" + hint about `vault.kfv.bak` on repeated failure.
- Typed errors for: duplicate name, entry not found, malformed flags, bad
  base32/otpauth/QR, unreadable/unwritable paths, CSV parse failures.
- Unknown command → closest-match suggestion ("did you mean `retrieve`?").
- Import: parse the whole file first; then apply all valid rows, skipping
  rows that are malformed or whose name already exists in the vault, and
  report counts (imported / skipped) plus the reason per skipped row.

## Testing (doctest, ctest)

- **Crypto:** roundtrip; wrong password fails; bit-flips anywhere in
  header/ciphertext fail authentication.
- **TOTP:** RFC 6238 test vectors; base32 edge cases; otpauth parsing.
- **Generator:** length, class guarantees, ambiguous exclusion.
- **Vault/commands:** CRUD, unique names, tag filter, search, parser
  (incl. quoted args with spaces).
- **Storage:** save/load roundtrip, .bak behavior, atomicity via temp file.
- **Audit/CSV:** detection rules; import/export roundtrip.

GUI shell is deliberately thin and verified manually.

## Verification

`cmake -B build && cmake --build build && ctest --test-dir build` on macOS
first; no platform-specific code outside `paths.cpp` and GLFW's abstractions.

## Out of Scope (YAGNI)

Sync/network features, browser extension, multiple vaults open at once,
password history, custom fields, attachments, CLI binary (add later — the
core/UI split makes it trivial), Argon2 param auto-tuning.
