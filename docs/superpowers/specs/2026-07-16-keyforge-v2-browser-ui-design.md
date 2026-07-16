# KeyForge v2 — Browser UI (Design Spec)

**Date:** 2026-07-16
**Status:** Approved
**Baseline:** v1 on `main` (commit dbc733d) — palette-only GUI, core fully tested (23 cases / 740 assertions)

## Purpose

Replace the palette-only main screen with a browsable three-pane window
(Bitwarden-style): see all entries, click to view, edit in place — while
keeping every v1 command available through a Ctrl+K palette overlay.

## Decisions (locked during brainstorming)

| Decision | Choice |
|---|---|
| Layout | Three-pane: tag sidebar / entry list / detail panel, toolbar above |
| Command palette | Survives as a Ctrl+K overlay reusing the v1 dispatcher verbatim |
| Editing | Inline: the detail pane flips into the form (no modal) |
| Secondary tools | Audit = sidebar shield icon; import/export = settings pane; all also via Ctrl+K |
| Architecture | Panel modules: App member functions split across `app/src/panels/*.cpp`; core untouched except tested `Vault::all_tags()` |
| Vault format / commands | Unchanged — v1 vaults open as-is |

## Core change (the only one)

`Vault::all_tags() const -> std::vector<std::string>` — all tags across
entries, case-insensitively deduplicated (first-seen casing wins), sorted
case-insensitively. Unit-tested in `tests/test_vault.cpp`.

## App layer structure

```
app/src/
├── main.cpp                  # + glfwSetDropCallback for QR drag-drop; 1000x680 window
├── theme.hpp/.cpp            # unchanged
├── app.hpp/.cpp              # screens, timers, toolbar, panel composition, shared actions
├── ui_state.hpp              # UiState struct (below)
└── panels/
    ├── sidebar.cpp           # App::draw_sidebar
    ├── entry_list.cpp        # App::draw_entry_list
    ├── detail.cpp            # App::draw_detail (view + edit form + delete confirm)
    └── palette.cpp           # App::draw_palette_overlay (Ctrl+K)
```

Panels are `App` member functions defined in separate translation units —
each file owns one pane; `app.cpp` keeps the state machine, timers
(clipboard auto-clear, auto-lock, lock-on-exit — all unchanged), unlock
screen, and shared helpers (`copy_secret`, `save_or_warn`).

### UiState (`ui_state.hpp`)

```cpp
struct EditBuffers {           // all wiped with sodium_memzero on save/cancel/lock
    char name[128], username[256], password[256], url[512];
    char notes[2048], tags[256];
    char totp_secret[256], totp_uri[1024], totp_qr_path[1024];
    std::string original_name; // empty => Add mode
};
enum class DetailMode { View, Edit, Audit };
struct UiState {
    char search[256] = {};
    std::string selected_tag;      // empty = All
    std::string selected_entry;    // entry name; empty = none
    DetailMode mode = DetailMode::View;
    EditBuffers edit;              // valid only in Edit mode
    bool show_palette = false;     // Ctrl+K overlay
    char palette_input[512] = {};
    vaultcore::CommandOutcome palette_result; bool palette_has_result = false;
    std::vector<vaultcore::AuditFinding> audit_findings;  // Audit mode cache
    std::string status;  bool status_is_error = false;  double status_until = 0;
    bool reveal_password = false;
    bool confirm_delete = false;   // delete-confirm popup open
};
```

## Behavior

**Toolbar (top, full width):** search input with hint "Search entries…" —
live filter via `Vault::search`; **+ Add** button → detail pane enters Edit
mode with empty buffers (Add).

**Sidebar (left, ~150 px):** "All (N)" then one row per `all_tags()` with
per-tag entry count; click filters the list; active row highlighted.
Bottom-pinned icon buttons: audit (shield), settings (gear), lock.

**Entry list (middle, ~260 px):** rows show name + dim username; contents =
`search(text)` ∩ tag filter, name-sorted (both already core behavior);
click selects and shows View mode. Empty vault shows "No entries yet —
press + Add". If the selected entry disappears (deleted/renamed), selection
clears.

**Detail — View mode:** name heading; rows username / url / notes / tags,
each non-empty row with a copy button (via the existing auto-clearing
`copy_secret`); password masked with reveal toggle + copy; if
`totp_secret` set: live 6-digit code, countdown bar, copy button
(recomputed per frame like v1). Buttons: Edit (fills EditBuffers from the
entry), Delete (opens confirm popup: "Delete '<name>'? This cannot be
undone." Cancel / Delete).

**Detail — Edit mode (also Add):** fields name, username, password
(masked input + show toggle + **gen** button that fills the field using the
vault's generator settings), url, notes (multiline), tags
(comma-separated), TOTP (three inputs: secret, otpauth:// URI, QR image
path — at most one may be non-empty, mirroring the v1 flag rule; hint text:
"or drag a QR image onto the window", which fills the path via the GLFW
drop callback). Save: builds `Entry` (Add: `Vault::add`) or `EntryPatch`
(Edit: `update_entry`; only changed fields set), resolves TOTP inputs
through the same `parse_otpauth_uri`/`decode_qr_image`/`base32_decode`
validations the dispatcher uses, then `session.save()`; on success return
to View with status "Saved."; on error stay in the form with the core's
message shown red. Cancel returns to View. Buffers wiped on save, cancel,
and lock.

**Detail — Audit mode:** shield icon runs `audit_vault` and lists findings
("name: issue") with a "Run again" button; clicking a finding selects that
entry in View mode. "No issues found" state when clean.

**Ctrl+K palette overlay:** centered ~600 px panel over a dimmed
background; same input semantics and result rendering as v1 (help, usage
hints, entry lists, gen, TOTP with countdown, errors in red); Esc or
clicking outside closes. Executes via `execute_command`; honors
`vault_changed` (save + panes refresh naturally since they read the vault
each frame), `copy_to_clipboard`, and `lock_requested`.

**Settings pane:** v1 sliders/checkbox plus a Tools section: import
(path input + "Import CSV" button, result summary shown) and export
(path input + "Export vault" button) — thin wrappers over the same core
calls the dispatcher uses.

**Status line (bottom of the detail pane):** transient messages
("Copied password — clears in 28s", "Saved.", "Imported 5 entries."),
errors red; clears after ~4 s (`status_until`).

**Unchanged:** unlock/create screen, clipboard auto-clear, idle auto-lock,
lock-on-exit, vault file format, all commands.

## Error handling

All mutations flow through the existing core validations; the GUI renders
`Status`/`Result` errors verbatim (red, inline in the form or in the
status line). Save failures show the same "WARNING: saving vault failed"
path as v1. The TOTP "at most one input" rule is enforced before calling
core, with the same wording as the dispatcher's error.

## Testing & verification

- Core: `all_tags()` unit tests (dedup casing, sorting, empty vault).
- GUI: panels are thin rendering over tested core calls — verified
  manually on the user's display with a checklist (add/edit/delete with
  confirm, tag filtering, search, copy + auto-clear, TOTP countdown,
  QR drag-drop, Ctrl+K commands, audit jump, import/export, lock paths).
- Full suite must stay green (23 cases / 740 assertions + new tag tests).

## Out of scope (YAGNI)

Menu bar, modal edit dialogs, multi-select, keyboard list navigation,
icons font (Tabler/FontAwesome) — sidebar icons stay text glyphs like v1,
password history, native file-picker dialogs (path input + drag-drop
instead), any vault-format change.
