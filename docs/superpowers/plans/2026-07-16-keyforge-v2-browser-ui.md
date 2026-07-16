# KeyForge v2 Browser UI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace KeyForge's palette-only main screen with a browsable three-pane window (tag sidebar / entry list / detail panel), inline add/edit/delete, a Ctrl+K command-palette overlay, audit view, import/export in settings, and QR drag-drop — reusing the v1 tested core unchanged except one new tested method.

**Architecture:** `vaultcore` gains only `Vault::all_tags()` (unit-tested). The app layer splits `App`'s drawing across focused panel files (`app/src/panels/*.cpp`) with shared UI state in `ui_state.hpp`; `app.cpp` keeps the state machine, timers, unlock screen, and shared actions. All mutations go through existing core methods followed by the same auto-save v1 uses. The GUI is verified by building + a manual checklist (no unit tests for ImGui code).

**Tech Stack:** C++20, Dear ImGui v1.90.9, GLFW 3.4, libsodium, existing `vaultcore`. CMake via the existing build.

**Spec:** `docs/superpowers/specs/2026-07-16-keyforge-v2-browser-ui-design.md`

**Conventions & environment (every task):**
- Work from `/Users/naramalawar36/Claude/keyforge`, branch `feature/keyforge-v2` (Task 1 Step 0 creates it).
- CMake is pip-installed: prefix cmake commands with `PATH="/Users/naramalawar36/Library/Python/3.9/bin:$PATH"`. `cmake --build build -j` auto-reconfigures when CMakeLists changes. A fresh configure needs `-DCMAKE_POLICY_VERSION_MINIMUM=3.5`.
- FOREGROUND commands only (timeout up to 600000 ms). NEVER launch `build/app/keyforge` — no display is available; it hangs. GUI verification for each task = it builds cleanly, the binary links (`ls -la build/app/keyforge`), and the core suite stays green (`./build/tests/core_tests` → 23 cases pre-existing + the new tag tests). A human runs the manual checklist later.
- Name-key entries are matched case-insensitively (core behavior). Renaming an existing entry is NOT supported (the core patches fields, name is the key) — the edit form shows the name read-only when editing.

**File structure after this plan:**
```
core/include/vaultcore/vault.hpp   # + all_tags() decl
core/src/vault.cpp                 # + all_tags() impl
tests/test_vault.cpp               # + all_tags tests
app/src/
├── main.cpp        # + drop callback + window user pointer; 1000x680
├── theme.hpp/.cpp  # unchanged
├── app.hpp         # rewritten: UiState member, new method decls
├── app.cpp         # state machine, timers, unlock, shared actions
├── ui_state.hpp    # UiState + EditBuffers + DetailMode
└── panels/
    ├── sidebar.cpp     # App::draw_sidebar
    ├── entry_list.cpp  # App::draw_toolbar, App::draw_entry_list
    ├── detail.cpp      # App::draw_detail (+ view/edit/audit) , draw_settings
    └── palette.cpp     # App::draw_palette_overlay
app/CMakeLists.txt   # + the 4 panel sources
```

---

### Task 1: Core — `Vault::all_tags()`

**Files:**
- Modify: `core/include/vaultcore/vault.hpp`, `core/src/vault.cpp`
- Test: `tests/test_vault.cpp`

- [ ] **Step 0: Create the branch**

```bash
git checkout -b feature/keyforge-v2
```

- [ ] **Step 1: Write the failing test — append to `tests/test_vault.cpp`**

```cpp
TEST_CASE("all_tags: sorted, case-insensitively deduplicated") {
    Vault v;
    Entry a = make("A", "1"); a.tags = {"Dev", "work"};
    Entry b = make("B", "2"); b.tags = {"dev", "School"};
    Entry c = make("C", "3");  // no tags
    REQUIRE(v.add(a, 1).ok());
    REQUIRE(v.add(b, 1).ok());
    REQUIRE(v.add(c, 1).ok());

    auto tags = v.all_tags();
    // "Dev"/"dev" collapse to one (first-seen casing kept); sorted case-insensitively.
    REQUIRE(tags.size() == 3);
    CHECK(tags[0] == "Dev");
    CHECK(tags[1] == "School");
    CHECK(tags[2] == "work");
}

TEST_CASE("all_tags: empty vault yields no tags") {
    Vault v;
    CHECK(v.all_tags().empty());
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `PATH="/Users/naramalawar36/Library/Python/3.9/bin:$PATH" cmake --build build -j 2>&1 | tail -5`
Expected: compile FAILURE — no member named `all_tags` in `Vault`.

- [ ] **Step 3: Declare — in `core/include/vaultcore/vault.hpp`, add after the `search` declaration**

```cpp
    std::vector<std::string> all_tags() const;  // dedup (case-insensitive), sorted
```

- [ ] **Step 4: Implement — in `core/src/vault.cpp`, add after `Vault::search`**

```cpp
std::vector<std::string> Vault::all_tags() const {
    std::vector<std::string> out;
    for (const auto& e : entries_) {
        for (const auto& t : e.tags) {
            bool seen = false;
            for (const auto& kept : out)
                if (iequals(kept, t)) { seen = true; break; }
            if (!seen) out.push_back(t);
        }
    }
    std::sort(out.begin(), out.end(), [](const std::string& a, const std::string& b) {
        return to_lower(a) < to_lower(b);
    });
    return out;
}
```

- [ ] **Step 5: Run to verify it passes**

Run: `PATH="/Users/naramalawar36/Library/Python/3.9/bin:$PATH" cmake --build build -j && ./build/tests/core_tests`
Expected: SUCCESS — 25 test cases (23 prior + 2 new).

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "feat(core): Vault::all_tags for the tag sidebar"
```

---

### Task 2: Three-pane read-only shell (state, headers, CMake, sidebar/list/detail-view)

This task swaps the palette main-screen for a working browsable window: toolbar (search + Add button — Add wired in Task 3), tag sidebar with counts, filtered entry list with selection, and a read-only detail view (copy, reveal, live TOTP). Edit/Add/Delete, palette overlay, audit, import/export, drag-drop come in later tasks.

**Files:**
- Create: `app/src/ui_state.hpp`, `app/src/panels/sidebar.cpp`, `app/src/panels/entry_list.cpp`, `app/src/panels/detail.cpp`
- Rewrite: `app/src/app.hpp`, `app/src/app.cpp`
- Modify: `app/CMakeLists.txt`

- [ ] **Step 1: Create `app/src/ui_state.hpp`**

```cpp
#pragma once
#include <string>
#include <vector>
#include <vaultcore/commands.hpp>
#include <vaultcore/audit.hpp>

namespace keyforge {

// All char buffers here are wiped with sodium_memzero on save/cancel/lock.
struct EditBuffers {
    char name[128] = {};
    char username[256] = {};
    char password[256] = {};
    char url[512] = {};
    char notes[2048] = {};
    char tags[256] = {};
    char totp_secret[256] = {};
    char totp_uri[1024] = {};
    char totp_qr_path[1024] = {};
    bool remove_totp = false;
    std::string original_name;  // empty => Add mode
    std::string original_password;
    std::string error;          // inline form error (red)
};

enum class DetailMode { View, Edit, Audit };

struct UiState {
    char search[256] = {};
    std::string selected_tag;    // empty = All
    std::string selected_entry;  // entry name; empty = none
    DetailMode mode = DetailMode::View;
    EditBuffers edit;

    bool show_palette = false;
    bool palette_focus = false;
    char palette_input[512] = {};
    vaultcore::CommandOutcome palette_result;
    bool palette_has_result = false;

    std::vector<vaultcore::AuditFinding> audit_findings;

    std::string status;
    bool status_is_error = false;
    double status_until = 0.0;

    bool reveal_password = false;  // detail view reveal
    bool edit_reveal = false;      // edit form reveal
    bool confirm_delete = false;
};

}  // namespace keyforge
```

- [ ] **Step 2: Rewrite `app/src/app.hpp`**

```cpp
#pragma once
#include <filesystem>
#include <optional>
#include <string>
#include <vaultcore/storage.hpp>
#include "ui_state.hpp"

struct GLFWwindow;

namespace keyforge {

class App {
public:
    App(GLFWwindow* window, std::filesystem::path vault_path);
    void frame();                                  // once per ImGui frame
    void shutdown();                               // lock-on-exit
    void on_drop(int count, const char** paths);   // GLFW drag-drop

private:
    enum class Screen { Unlock, Main };

    // screens / panels
    void draw_unlock();
    void draw_main();
    void draw_toolbar();       // entry_list.cpp
    void draw_sidebar();       // sidebar.cpp
    void draw_entry_list();    // entry_list.cpp
    void draw_detail();        // detail.cpp
    void draw_detail_view(const vaultcore::Entry& e);  // detail.cpp
    void draw_detail_edit();   // detail.cpp (Task 3)
    void draw_detail_audit();  // detail.cpp (Task 5)
    void draw_palette_overlay();  // palette.cpp (Task 4)
    void draw_settings();      // detail.cpp

    // actions
    void begin_add();                          // Task 3
    void begin_edit(const vaultcore::Entry& e);// Task 3
    void save_edit();                          // Task 3
    void delete_selected();                    // Task 3
    void run_audit();                          // Task 5
    void run_palette(const std::string& line); // Task 4
    void set_status(const std::string& msg, bool is_error);
    void copy_field(const std::string& value, const std::string& label);
    void copy_secret(const std::string& value);

    // lifecycle
    void tick_timers();
    void lock();

    GLFWwindow* window_;
    std::filesystem::path vault_path_;
    Screen screen_ = Screen::Unlock;
    std::optional<vaultcore::Session> session_;

    char master_buf_[256] = {};
    char master_confirm_buf_[256] = {};
    std::string unlock_error_;

    UiState ui_;
    bool show_settings_ = false;

    std::string clip_value_;
    double clip_deadline_ = 0.0;
    double last_activity_ = 0.0;
    bool want_lock_ = false;
};

}  // namespace keyforge
```

- [ ] **Step 3: Rewrite `app/src/app.cpp`** (keeps unlock/timers/lock/copy from v1; new draw_main composition; shared helpers. Panel bodies live in panels/*.cpp. Task-3/4/5 methods are defined in their own files, so this file must NOT define them.)

```cpp
#include "app.hpp"
#include "theme.hpp"
#include <GLFW/glfw3.h>
#include <imgui.h>
#include <sodium.h>
#include <cstring>
#include <ctime>

namespace keyforge {

using vaultcore::Session;

App::App(GLFWwindow* window, std::filesystem::path vault_path)
    : window_(window), vault_path_(std::move(vault_path)) {}

void App::frame() {
    tick_timers();
    const ImGuiViewport* vp = ImGui::GetMainViewport();
    ImGui::SetNextWindowPos(vp->WorkPos);
    ImGui::SetNextWindowSize(vp->WorkSize);
    ImGui::Begin("##root", nullptr,
                 ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove |
                     ImGuiWindowFlags_NoBringToFrontOnFocus |
                     ImGuiWindowFlags_NoSavedSettings);
    if (screen_ == Screen::Unlock) draw_unlock();
    else draw_main();
    ImGui::End();
}

void App::draw_unlock() {
    const bool first_run = !std::filesystem::exists(vault_path_);
    const float w = 380.0f;
    ImGui::SetCursorPosX((ImGui::GetWindowWidth() - w) * 0.5f);
    ImGui::SetCursorPosY(ImGui::GetWindowHeight() * 0.28f);
    ImGui::BeginGroup();
    ImGui::PushItemWidth(w);
    ImGui::Text("KeyForge");
    ImGui::TextDisabled("%s", vault_path_.string().c_str());
    ImGui::Spacing();
    if (first_run)
        ImGui::TextDisabled("No vault yet — choose a master password (8+ chars).");

    bool submit = ImGui::InputTextWithHint("##master", "master password", master_buf_,
                                           sizeof master_buf_,
                                           ImGuiInputTextFlags_Password |
                                               ImGuiInputTextFlags_EnterReturnsTrue);
    if (first_run)
        submit |= ImGui::InputTextWithHint("##confirm", "confirm master password",
                                           master_confirm_buf_, sizeof master_confirm_buf_,
                                           ImGuiInputTextFlags_Password |
                                               ImGuiInputTextFlags_EnterReturnsTrue);
    submit |= ImGui::Button(first_run ? "Create Vault" : "Unlock", ImVec2(w, 0));

    if (submit) {
        std::string pw(master_buf_);
        std::string confirm(master_confirm_buf_);
        if (first_run && pw != confirm) {
            unlock_error_ = "passwords do not match";
        } else {
            auto r = first_run ? Session::create(vault_path_, pw)
                               : Session::open(vault_path_, pw);
            if (r.ok()) {
                session_.emplace(std::move(*r.value));
                screen_ = Screen::Main;
                unlock_error_.clear();
                ui_ = UiState{};
                last_activity_ = glfwGetTime();
            } else {
                unlock_error_ = r.error.message;
            }
        }
        sodium_memzero(pw.data(), pw.size());
        sodium_memzero(confirm.data(), confirm.size());
        sodium_memzero(master_buf_, sizeof master_buf_);
        sodium_memzero(master_confirm_buf_, sizeof master_confirm_buf_);
    }
    if (!unlock_error_.empty()) {
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(kErrRed[0], kErrRed[1], kErrRed[2], 1));
        ImGui::TextWrapped("%s", unlock_error_.c_str());
        ImGui::PopStyleColor();
    }
    ImGui::PopItemWidth();
    ImGui::EndGroup();
}

void App::draw_main() {
    ImGuiIO& io = ImGui::GetIO();
    if ((io.KeyCtrl || io.KeySuper) && ImGui::IsKeyPressed(ImGuiKey_K)) {
        ui_.show_palette = true;
        ui_.palette_focus = true;
    }
    draw_toolbar();
    draw_sidebar();
    ImGui::SameLine();
    draw_entry_list();
    ImGui::SameLine();
    draw_detail();
    draw_palette_overlay();
    if (show_settings_) draw_settings();
}

void App::set_status(const std::string& msg, bool is_error) {
    ui_.status = msg;
    ui_.status_is_error = is_error;
    ui_.status_until = glfwGetTime() + 4.0;
}

void App::copy_secret(const std::string& value) {
    glfwSetClipboardString(window_, value.c_str());
    clip_value_ = value;
    clip_deadline_ = glfwGetTime() +
                     (session_ ? session_->vault().settings().clip_clear_sec : 30);
}

void App::copy_field(const std::string& value, const std::string& label) {
    if (value.empty()) { set_status(label + " is empty", true); return; }
    copy_secret(value);
    int secs = session_ ? session_->vault().settings().clip_clear_sec : 30;
    set_status("Copied " + label + " — clears in " + std::to_string(secs) + "s", false);
}

void App::tick_timers() {
    const double now = glfwGetTime();
    if (want_lock_) { want_lock_ = false; lock(); }
    if (!clip_value_.empty() && now > clip_deadline_) {
        const char* cur = glfwGetClipboardString(window_);
        if (cur && clip_value_ == cur) glfwSetClipboardString(window_, "");
        clip_value_.clear();
    }
    ImGuiIO& io = ImGui::GetIO();
    if (io.MouseDelta.x != 0.0f || io.MouseDelta.y != 0.0f ||
        ImGui::IsMouseClicked(0) || io.MouseWheel != 0.0f ||
        io.InputQueueCharacters.Size > 0)
        last_activity_ = now;
    if (session_ && session_->vault().settings().auto_lock_min > 0 &&
        now - last_activity_ > session_->vault().settings().auto_lock_min * 60.0)
        lock();
}

void App::shutdown() { lock(); }

void App::lock() {
    session_.reset();
    screen_ = Screen::Unlock;
    show_settings_ = false;
    // Wipe the char buffers that hold secrets before dropping ui_ state.
    // (Only the char arrays — never memzero a struct containing std::string.)
    sodium_memzero(ui_.edit.password, sizeof ui_.edit.password);
    sodium_memzero(ui_.edit.totp_secret, sizeof ui_.edit.totp_secret);
    sodium_memzero(ui_.edit.notes, sizeof ui_.edit.notes);
    sodium_memzero(ui_.palette_input, sizeof ui_.palette_input);
    sodium_memzero(ui_.search, sizeof ui_.search);
    ui_ = UiState{};
    unlock_error_.clear();
    if (!clip_value_.empty()) {
        const char* cur = glfwGetClipboardString(window_);
        if (cur && clip_value_ == cur) glfwSetClipboardString(window_, "");
        clip_value_.clear();
    }
}

}  // namespace keyforge
```

- [ ] **Step 4: Create `app/src/panels/sidebar.cpp`**

```cpp
#include "app.hpp"
#include <imgui.h>
#include <vaultcore/util.hpp>

namespace keyforge {

void App::draw_sidebar() {
    ImGui::BeginChild("##side", ImVec2(150, 0), true);
    auto& v = session_->vault();

    int total = int(v.entries().size());
    if (ImGui::Selectable((std::string("All (") + std::to_string(total) + ")").c_str(),
                          ui_.selected_tag.empty()))
        ui_.selected_tag.clear();

    for (const auto& tag : v.all_tags()) {
        int count = 0;
        for (const auto& e : v.entries())
            for (const auto& t : e.tags)
                if (vaultcore::iequals(t, tag)) { ++count; break; }
        std::string label = tag + " (" + std::to_string(count) + ")";
        bool active = vaultcore::iequals(ui_.selected_tag, tag);
        if (ImGui::Selectable(label.c_str(), active)) ui_.selected_tag = tag;
    }

    // Bottom-pinned tool icons.
    float btn_h = 30.0f;
    ImGui::SetCursorPosY(ImGui::GetWindowHeight() - (btn_h + 6) * 3);
    if (ImGui::Button("audit", ImVec2(-1, btn_h))) run_audit();
    if (ImGui::Button("settings", ImVec2(-1, btn_h))) show_settings_ = !show_settings_;
    if (ImGui::Button("lock", ImVec2(-1, btn_h))) want_lock_ = true;

    ImGui::EndChild();
}

}  // namespace keyforge
```

- [ ] **Step 5: Create `app/src/panels/entry_list.cpp`**

```cpp
#include "app.hpp"
#include <imgui.h>
#include <vaultcore/util.hpp>
#include <vector>

namespace keyforge {

void App::draw_toolbar() {
    ImGui::SetNextItemWidth(-120);
    ImGui::InputTextWithHint("##search", "Search entries…", ui_.search, sizeof ui_.search);
    ImGui::SameLine();
    if (ImGui::Button("+ Add", ImVec2(-1, 0))) begin_add();
    ImGui::Separator();
}

void App::draw_entry_list() {
    ImGui::BeginChild("##list", ImVec2(260, 0), true);
    auto& v = session_->vault();

    std::string q(ui_.search);
    std::vector<const vaultcore::Entry*> rows =
        q.empty() ? v.list() : v.search(q);

    bool still_present = false;
    for (const auto* e : rows) {
        if (!ui_.selected_tag.empty()) {
            bool has = false;
            for (const auto& t : e->tags)
                if (vaultcore::iequals(t, ui_.selected_tag)) { has = true; break; }
            if (!has) continue;
        }
        bool selected = vaultcore::iequals(ui_.selected_entry, e->name);
        if (selected) still_present = true;
        ImGui::PushID(e->name.c_str());
        if (ImGui::Selectable(e->name.c_str(), selected)) {
            ui_.selected_entry = e->name;
            ui_.mode = DetailMode::View;
            ui_.reveal_password = false;
        }
        if (!e->username.empty()) {
            ImGui::SameLine();
            ImGui::TextDisabled("%s", e->username.c_str());
        }
        ImGui::PopID();
    }

    if (rows.empty() && q.empty() && ui_.selected_tag.empty())
        ImGui::TextDisabled("No entries yet — press + Add");
    if (!still_present && ui_.mode == DetailMode::View)
        ui_.selected_entry.clear();

    ImGui::EndChild();
}

}  // namespace keyforge
```

- [ ] **Step 6: Create `app/src/panels/detail.cpp`** (view mode + settings now; edit/audit stubs are filled in Tasks 3 & 5 — provide stubs here so the file links)

```cpp
#include "app.hpp"
#include <GLFW/glfw3.h>
#include <imgui.h>
#include <ctime>
#include <vaultcore/totp.hpp>

namespace keyforge {

static void field_row(const char* label, const std::string& value) {
    ImGui::TextDisabled("%-10s", label);
    ImGui::SameLine();
    ImGui::TextWrapped("%s", value.empty() ? "-" : value.c_str());
}

void App::draw_detail() {
    ImGui::BeginChild("##detail", ImVec2(0, 0), true);

    if (ui_.mode == DetailMode::Edit) {
        draw_detail_edit();
    } else if (ui_.mode == DetailMode::Audit) {
        draw_detail_audit();
    } else {
        const vaultcore::Entry* e = ui_.selected_entry.empty()
            ? nullptr : session_->vault().find(ui_.selected_entry);
        if (!e) ImGui::TextDisabled("Select an entry, or press + Add.");
        else draw_detail_view(*e);
    }

    // Transient status line, bottom of the pane.
    if (!ui_.status.empty() && glfwGetTime() < ui_.status_until) {
        ImGui::SetCursorPosY(ImGui::GetWindowHeight() - 26);
        if (ui_.status_is_error)
            ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(kErrRed[0], kErrRed[1], kErrRed[2], 1));
        else
            ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.36f, 0.62f, 0.43f, 1));
        ImGui::TextWrapped("%s", ui_.status.c_str());
        ImGui::PopStyleColor();
    }

    ImGui::EndChild();
}

void App::draw_detail_view(const vaultcore::Entry& e) {
    ImGui::Text("%s", e.name.c_str());
    ImGui::Separator();

    field_row("username", e.username);
    if (!e.username.empty()) {
        ImGui::SameLine();
        if (ImGui::SmallButton("copy##u")) copy_field(e.username, "username");
    }

    ImGui::TextDisabled("%-10s", "password");
    ImGui::SameLine();
    ImGui::TextUnformatted(ui_.reveal_password ? e.password.c_str() : "************");
    ImGui::SameLine();
    if (ImGui::SmallButton(ui_.reveal_password ? "hide" : "reveal"))
        ui_.reveal_password = !ui_.reveal_password;
    ImGui::SameLine();
    if (ImGui::SmallButton("copy##p")) copy_field(e.password, "password");

    field_row("url", e.url);
    if (!e.url.empty()) { ImGui::SameLine(); if (ImGui::SmallButton("copy##url")) copy_field(e.url, "url"); }
    field_row("notes", e.notes);

    std::string tags;
    for (size_t i = 0; i < e.tags.size(); ++i) tags += (i ? ", " : "") + e.tags[i];
    field_row("tags", tags);

    if (!e.totp_secret.empty()) {
        int64_t t = int64_t(std::time(nullptr));
        auto code = vaultcore::totp_code(e.totp_secret, t);
        int rem = vaultcore::totp_seconds_remaining(t);
        ImGui::TextDisabled("%-10s", "totp");
        ImGui::SameLine();
        ImGui::TextUnformatted(code.ok() ? code.value->c_str() : "error");
        ImGui::SameLine();
        ImGui::TextDisabled("(%ds)", rem);
        ImGui::SameLine();
        if (code.ok() && ImGui::SmallButton("copy##t")) copy_field(*code.value, "TOTP");
        ImGui::ProgressBar(float(rem) / 30.0f, ImVec2(220, 6), "");
    } else {
        field_row("totp", "");
    }

    ImGui::Separator();
    if (ImGui::Button("Edit")) begin_edit(e);
    ImGui::SameLine();
    if (ImGui::Button("Delete")) ui_.confirm_delete = true;

    if (ui_.confirm_delete) {
        ImGui::OpenPopup("Delete entry?");
        ui_.confirm_delete = false;
    }
    if (ImGui::BeginPopupModal("Delete entry?", nullptr,
                               ImGuiWindowFlags_AlwaysAutoResize)) {
        ImGui::Text("Delete '%s'? This cannot be undone.", e.name.c_str());
        if (ImGui::Button("Delete")) { delete_selected(); ImGui::CloseCurrentPopup(); }
        ImGui::SameLine();
        if (ImGui::Button("Cancel")) ImGui::CloseCurrentPopup();
        ImGui::EndPopup();
    }
}

// Stubs replaced in later tasks so the panel links now.
void App::draw_detail_edit() { ImGui::TextDisabled("edit — implemented in Task 3"); }
void App::draw_detail_audit() { ImGui::TextDisabled("audit — implemented in Task 5"); }
void App::begin_add() {}
void App::begin_edit(const vaultcore::Entry&) {}
void App::save_edit() {}
void App::delete_selected() {}
void App::run_audit() {}
void App::draw_palette_overlay() {}
void App::run_palette(const std::string&) {}

void App::draw_settings() {
    ImGui::SetNextWindowSize(ImVec2(460, 0), ImGuiCond_Appearing);
    if (ImGui::Begin("Settings", &show_settings_, ImGuiWindowFlags_NoCollapse)) {
        auto& s = session_->vault().settings();
        ImGui::SliderInt("Auto-lock (min)", &s.auto_lock_min, 1, 60);
        ImGui::SliderInt("Clipboard clear (sec)", &s.clip_clear_sec, 5, 120);
        ImGui::SliderInt("Generator length", &s.gen_len, 8, 64);
        ImGui::Checkbox("Generator symbols", &s.gen_symbols);
        ImGui::Separator();
        ImGui::TextDisabled("Vault: %s", vault_path_.string().c_str());
        if (ImGui::Button("Save settings")) {
            auto st = session_->save();
            set_status(st.ok() ? "Settings saved." : st.error.message, !st.ok());
        }
    }
    ImGui::End();
}

}  // namespace keyforge
```

- [ ] **Step 7: Update `app/CMakeLists.txt`**

```cmake
find_package(OpenGL REQUIRED)
add_executable(keyforge
  src/main.cpp
  src/app.cpp
  src/theme.cpp
  src/panels/sidebar.cpp
  src/panels/entry_list.cpp
  src/panels/detail.cpp
  src/panels/palette.cpp)
target_link_libraries(keyforge PRIVATE vaultcore imgui glfw OpenGL::GL)
target_compile_definitions(keyforge PRIVATE GL_SILENCE_DEPRECATION)
```

- [ ] **Step 8: Create a placeholder `app/src/panels/palette.cpp`** (real overlay in Task 4; must exist now because CMake lists it — but `draw_palette_overlay`/`run_palette` are already defined as stubs in detail.cpp, so this file must NOT redefine them)

```cpp
#include "app.hpp"
// Palette overlay is implemented in Task 4. This translation unit is
// intentionally empty until then (draw_palette_overlay/run_palette are
// temporarily stubbed in detail.cpp).
```

- [ ] **Step 9: Widen the window — in `app/src/main.cpp`, change the `glfwCreateWindow` line**

```cpp
    GLFWwindow* window = glfwCreateWindow(1000, 680, "KeyForge", nullptr, nullptr);
```

- [ ] **Step 10: Build, verify link, core suite green**

Run: `PATH="/Users/naramalawar36/Library/Python/3.9/bin:$PATH" cmake --build build -j 2>&1 | tail -4 && ls -la build/app/keyforge && ./build/tests/core_tests 2>&1 | tail -3`
Expected: clean build; `build/app/keyforge` exists; core suite SUCCESS (25 cases). If ImGui API mismatches appear (e.g. `ImGuiKey_K`, `IsKeyPressed`), fix minimally and note the fix.

- [ ] **Step 11: Manual verification (pending — human at a display)**

Note in the commit/report that the following need a screen: three panes render; typing in search filters the list; clicking a tag filters; "All (N)" resets; clicking an entry shows read-only detail with reveal/copy and live TOTP; settings/lock buttons work.

- [ ] **Step 12: Commit**

```bash
git add -A
git commit -m "feat(ui): three-pane browsable shell (sidebar, list, read-only detail)"
```

---

### Task 3: Inline add / edit / delete

Replaces the Task-2 stubs `begin_add`/`begin_edit`/`save_edit`/`delete_selected`/`draw_detail_edit` with the real inline form and actions.

**Files:**
- Create: `app/src/panels/actions.cpp` (form-backing actions + helpers)
- Modify: `app/src/panels/detail.cpp` (replace `draw_detail_edit` stub; delete the `begin_add/begin_edit/save_edit/delete_selected` stubs — they move to actions.cpp), `app/CMakeLists.txt`

- [ ] **Step 1: Remove the four action stubs from `app/src/panels/detail.cpp`**

Delete these exact stub lines (leave `draw_detail_audit`, `draw_palette_overlay`, `run_palette`, `run_audit` stubs in place — those belong to Tasks 4 & 5):

```cpp
void App::begin_add() {}
void App::begin_edit(const vaultcore::Entry&) {}
void App::save_edit() {}
void App::delete_selected() {}
```

Also replace the `draw_detail_edit` stub:

```cpp
void App::draw_detail_edit() { ImGui::TextDisabled("edit — implemented in Task 3"); }
```

with the real form:

```cpp
void App::draw_detail_edit() {
    bool adding = ui_.edit.original_name.empty();
    ImGui::Text("%s", adding ? "Add entry" : ("Edit: " + ui_.edit.original_name).c_str());
    ImGui::Separator();

    ImGui::PushItemWidth(-1);
    ImGui::TextDisabled("name");
    ImGui::InputText("##name", ui_.edit.name, sizeof ui_.edit.name,
                     adding ? 0 : ImGuiInputTextFlags_ReadOnly);
    ImGui::TextDisabled("username");
    ImGui::InputText("##user", ui_.edit.username, sizeof ui_.edit.username);

    ImGui::TextDisabled("password");
    ImGuiInputTextFlags pf = ui_.edit_reveal ? 0 : ImGuiInputTextFlags_Password;
    ImGui::InputText("##pass", ui_.edit.password, sizeof ui_.edit.password, pf);
    ImGui::PopItemWidth();
    if (ImGui::SmallButton(ui_.edit_reveal ? "hide" : "show"))
        ui_.edit_reveal = !ui_.edit_reveal;
    ImGui::SameLine();
    if (ImGui::SmallButton("gen")) {
        auto& st = session_->vault().settings();
        vaultcore::GenOptions o;
        o.length = st.gen_len;
        o.symbols = st.gen_symbols;
        auto r = vaultcore::generate_password(o);
        if (r.ok()) {
            std::snprintf(ui_.edit.password, sizeof ui_.edit.password, "%s", r.value->c_str());
            ui_.edit_reveal = true;
        }
    }

    ImGui::PushItemWidth(-1);
    ImGui::TextDisabled("url");
    ImGui::InputText("##url", ui_.edit.url, sizeof ui_.edit.url);
    ImGui::TextDisabled("notes");
    ImGui::InputTextMultiline("##notes", ui_.edit.notes, sizeof ui_.edit.notes,
                              ImVec2(-1, 60));
    ImGui::TextDisabled("tags (comma-separated)");
    ImGui::InputText("##tags", ui_.edit.tags, sizeof ui_.edit.tags);

    ImGui::Separator();
    ImGui::TextDisabled("TOTP — set at most one (or drag a QR image onto the window)");
    ImGui::InputTextWithHint("##tsecret", "base32 secret", ui_.edit.totp_secret,
                             sizeof ui_.edit.totp_secret);
    ImGui::InputTextWithHint("##turi", "otpauth:// URI", ui_.edit.totp_uri,
                             sizeof ui_.edit.totp_uri);
    ImGui::InputTextWithHint("##tqr", "QR image path", ui_.edit.totp_qr_path,
                             sizeof ui_.edit.totp_qr_path);
    ImGui::PopItemWidth();
    if (!adding) ImGui::Checkbox("Remove existing TOTP", &ui_.edit.remove_totp);

    if (!ui_.edit.error.empty()) {
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(kErrRed[0], kErrRed[1], kErrRed[2], 1));
        ImGui::TextWrapped("%s", ui_.edit.error.c_str());
        ImGui::PopStyleColor();
    }

    ImGui::Separator();
    if (ImGui::Button("Save")) save_edit();
    ImGui::SameLine();
    if (ImGui::Button("Cancel")) {
        sodium_memzero(ui_.edit.password, sizeof ui_.edit.password);
        sodium_memzero(ui_.edit.totp_secret, sizeof ui_.edit.totp_secret);
        ui_.edit = EditBuffers{};
        ui_.mode = DetailMode::View;
        ui_.edit_reveal = false;
    }
}
```

Add `#include <sodium.h>`, `#include <cstdio>`, and `#include <vaultcore/generator.hpp>` to the top of `detail.cpp`.

- [ ] **Step 2: Create `app/src/panels/actions.cpp`**

```cpp
#include "app.hpp"
#include <GLFW/glfw3.h>
#include <sodium.h>
#include <cstdio>
#include <sstream>
#include <vector>
#include <vaultcore/generator.hpp>
#include <vaultcore/qr.hpp>
#include <vaultcore/totp.hpp>

namespace keyforge {

namespace {
std::vector<std::string> split_tags(const char* s) {
    std::vector<std::string> out;
    std::stringstream ss(s);
    std::string cur;
    while (std::getline(ss, cur, ',')) {
        size_t b = cur.find_first_not_of(" \t");
        size_t e = cur.find_last_not_of(" \t");
        if (b != std::string::npos) out.push_back(cur.substr(b, e - b + 1));
    }
    return out;
}

// Resolves the three TOTP inputs to a validated base32 secret.
// Returns {ok, secret, error}. secret empty with ok=true means "no TOTP given".
struct TotpResolve { bool ok; std::string secret; std::string error; };
TotpResolve resolve_totp(const EditBuffers& b) {
    int given = (b.totp_secret[0] != '\0') + (b.totp_uri[0] != '\0') +
                (b.totp_qr_path[0] != '\0');
    if (given == 0) return {true, "", ""};
    if (given > 1) return {false, "", "set at most one of secret / URI / QR path"};
    std::string secret;
    if (b.totp_secret[0]) {
        secret = b.totp_secret;
    } else if (b.totp_uri[0]) {
        auto info = vaultcore::parse_otpauth_uri(b.totp_uri);
        if (!info.ok()) return {false, "", info.error.message};
        secret = info.value->secret;
    } else {
        auto payload = vaultcore::decode_qr_image(b.totp_qr_path);
        if (!payload.ok()) return {false, "", payload.error.message};
        auto info = vaultcore::parse_otpauth_uri(*payload.value);
        if (!info.ok()) return {false, "", info.error.message};
        secret = info.value->secret;
    }
    if (!vaultcore::base32_decode(secret).ok())
        return {false, "", "TOTP secret is not valid base32"};
    return {true, secret, ""};
}
}  // namespace

void App::begin_add() {
    sodium_memzero(ui_.edit.password, sizeof ui_.edit.password);
    ui_.edit = EditBuffers{};
    ui_.mode = DetailMode::Edit;
    ui_.edit_reveal = false;
}

void App::begin_edit(const vaultcore::Entry& e) {
    ui_.edit = EditBuffers{};
    std::snprintf(ui_.edit.name, sizeof ui_.edit.name, "%s", e.name.c_str());
    std::snprintf(ui_.edit.username, sizeof ui_.edit.username, "%s", e.username.c_str());
    std::snprintf(ui_.edit.password, sizeof ui_.edit.password, "%s", e.password.c_str());
    std::snprintf(ui_.edit.url, sizeof ui_.edit.url, "%s", e.url.c_str());
    std::snprintf(ui_.edit.notes, sizeof ui_.edit.notes, "%s", e.notes.c_str());
    std::string tags;
    for (size_t i = 0; i < e.tags.size(); ++i) tags += (i ? "," : "") + e.tags[i];
    std::snprintf(ui_.edit.tags, sizeof ui_.edit.tags, "%s", tags.c_str());
    ui_.edit.original_name = e.name;
    ui_.edit.original_password = e.password;
    ui_.mode = DetailMode::Edit;
    ui_.edit_reveal = false;
}

void App::save_edit() {
    auto& v = session_->vault();
    int64_t now = int64_t(std::time(nullptr));
    auto totp = resolve_totp(ui_.edit);
    if (!totp.ok) { ui_.edit.error = totp.error; return; }

    vaultcore::Status st = vaultcore::Status::success();
    if (ui_.edit.original_name.empty()) {  // Add
        vaultcore::Entry e;
        e.name = ui_.edit.name;
        e.username = ui_.edit.username;
        e.password = ui_.edit.password;
        e.url = ui_.edit.url;
        e.notes = ui_.edit.notes;
        e.tags = split_tags(ui_.edit.tags);
        e.totp_secret = totp.secret;
        st = v.add(std::move(e), now);
    } else {  // Edit
        vaultcore::EntryPatch p;
        p.username = std::string(ui_.edit.username);
        p.url = std::string(ui_.edit.url);
        p.notes = std::string(ui_.edit.notes);
        p.tags = split_tags(ui_.edit.tags);
        if (std::string(ui_.edit.password) != ui_.edit.original_password)
            p.password = std::string(ui_.edit.password);
        if (ui_.edit.remove_totp) p.totp_secret = std::string("");
        else if (!totp.secret.empty()) p.totp_secret = totp.secret;
        st = v.update_entry(ui_.edit.original_name, p, now);
    }
    if (!st.ok()) { ui_.edit.error = st.error.message; return; }

    auto save = session_->save();
    if (!save.ok()) { ui_.edit.error = "saving vault failed: " + save.error.message; return; }

    ui_.selected_entry = ui_.edit.name[0] ? ui_.edit.name : ui_.edit.original_name;
    sodium_memzero(ui_.edit.password, sizeof ui_.edit.password);
    sodium_memzero(ui_.edit.totp_secret, sizeof ui_.edit.totp_secret);
    ui_.edit = EditBuffers{};
    ui_.mode = DetailMode::View;
    ui_.edit_reveal = false;
    set_status("Saved.", false);
}

void App::delete_selected() {
    if (ui_.selected_entry.empty()) return;
    auto st = session_->vault().remove(ui_.selected_entry);
    if (!st.ok()) { set_status(st.error.message, true); return; }
    auto save = session_->save();
    if (!save.ok()) { set_status("saving vault failed: " + save.error.message, true); return; }
    set_status("Deleted '" + ui_.selected_entry + "'.", false);
    ui_.selected_entry.clear();
    ui_.mode = DetailMode::View;
}

}  // namespace keyforge
```

- [ ] **Step 3: Add `actions.cpp` to `app/CMakeLists.txt`** (in the `add_executable(keyforge ...)` list, after `src/panels/detail.cpp`):

```cmake
  src/panels/actions.cpp
```

- [ ] **Step 4: Build, verify link, core green**

Run: `PATH="/Users/naramalawar36/Library/Python/3.9/bin:$PATH" cmake --build build -j 2>&1 | tail -4 && ls -la build/app/keyforge && ./build/tests/core_tests 2>&1 | tail -3`
Expected: clean build; binary links; core SUCCESS (25 cases). Fix any ImGui/enum mismatch minimally and report.

- [ ] **Step 5: Manual verification (pending — human)**

Note for the checklist: + Add opens an empty form; gen fills the password; Save adds and selects it; Edit prefills (name read-only), changing a field + Save persists; unchanged password doesn't rebump; Delete → confirm dialog → removed; duplicate/empty name shows a red inline error.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "feat(ui): inline add/edit/delete with generator and TOTP inputs"
```

---

### Task 4: Ctrl+K command palette overlay

Replaces the `draw_palette_overlay`/`run_palette` stubs (currently in detail.cpp) with the real overlay in palette.cpp, reusing the v1 dispatcher and result rendering.

**Files:**
- Modify: `app/src/panels/detail.cpp` (delete the two palette stubs), `app/src/panels/palette.cpp` (implement)

- [ ] **Step 1: Delete the palette stubs from `app/src/panels/detail.cpp`**

Remove exactly:

```cpp
void App::draw_palette_overlay() {}
void App::run_palette(const std::string&) {}
```

- [ ] **Step 2: Implement `app/src/panels/palette.cpp`** (replace the placeholder file contents)

```cpp
#include "app.hpp"
#include <GLFW/glfw3.h>
#include <imgui.h>
#include <ctime>
#include <cstring>
#include <sodium.h>
#include <vaultcore/totp.hpp>

namespace keyforge {

void App::run_palette(const std::string& line) {
    auto out = vaultcore::execute_command(*session_, line, int64_t(std::time(nullptr)));
    if (out.vault_changed) {
        auto st = session_->save();
        if (!st.ok()) {
            out.ok = false;
            out.message += "\nWARNING: saving vault failed: " + st.error.message;
        }
    }
    if (out.copy_to_clipboard) copy_secret(out.secret);
    if (out.lock_requested) want_lock_ = true;
    ui_.palette_result = std::move(out);
    ui_.palette_has_result = true;
}

void App::draw_palette_overlay() {
    if (!ui_.show_palette) return;

    ImGuiIO& io = ImGui::GetIO();
    if (ImGui::IsKeyPressed(ImGuiKey_Escape)) {
        ui_.show_palette = false;
        ui_.palette_has_result = false;
        sodium_memzero(ui_.palette_input, sizeof ui_.palette_input);
        return;
    }

    const ImGuiViewport* vp = ImGui::GetMainViewport();
    ImGui::SetNextWindowPos(ImVec2(vp->WorkPos.x + vp->WorkSize.x * 0.5f,
                                   vp->WorkPos.y + vp->WorkSize.y * 0.28f),
                            ImGuiCond_Always, ImVec2(0.5f, 0.0f));
    ImGui::SetNextWindowSize(ImVec2(600, 0));
    ImGui::Begin("##palette", nullptr,
                 ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
                     ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoSavedSettings);

    if (ui_.palette_focus) { ImGui::SetKeyboardFocusHere(); ui_.palette_focus = false; }
    ImGui::SetNextItemWidth(-1);
    bool entered = ImGui::InputTextWithHint(
        "##palinput", "Type a command — 'help' for the list", ui_.palette_input,
        sizeof ui_.palette_input, ImGuiInputTextFlags_EnterReturnsTrue);
    if (entered && ui_.palette_input[0] != '\0') {
        run_palette(ui_.palette_input);
        sodium_memzero(ui_.palette_input, sizeof ui_.palette_input);
        ui_.palette_focus = true;
    }

    const std::string typed(ui_.palette_input);
    if (!typed.empty()) {
        std::string first = typed.substr(0, typed.find(' '));
        std::string usage = vaultcore::usage_for(first);
        if (!usage.empty()) ImGui::TextDisabled("%s", usage.c_str());
    }

    if (ui_.palette_has_result) {
        ImGui::Separator();
        using Kind = vaultcore::CommandOutcome::Kind;
        const auto& r = ui_.palette_result;
        if (!r.ok) {
            ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(kErrRed[0], kErrRed[1], kErrRed[2], 1));
            ImGui::TextWrapped("%s", r.message.c_str());
            ImGui::PopStyleColor();
        } else if (r.kind == Kind::EntryList) {
            ImGui::TextDisabled("%s", r.message.c_str());
            for (const auto& e : r.entries) ImGui::TextUnformatted(e.name.c_str());
        } else if (r.kind == Kind::Totp) {
            const auto* e = session_->vault().find(r.totp_entry);
            if (e && !e->totp_secret.empty()) {
                int64_t t = int64_t(std::time(nullptr));
                auto code = vaultcore::totp_code(e->totp_secret, t);
                ImGui::Text("TOTP %s (%ds)", code.ok() ? code.value->c_str() : "error",
                            vaultcore::totp_seconds_remaining(t));
            }
        } else if (r.kind == Kind::Secret) {
            ImGui::TextWrapped("%s", r.message.c_str());
            if (!r.copy_to_clipboard) {
                ImGui::TextUnformatted(r.secret.c_str());
                if (ImGui::SmallButton("copy")) copy_secret(r.secret);
            }
        } else {
            ImGui::TextWrapped("%s", r.message.c_str());
        }
    }

    ImGui::TextDisabled("Esc to close");
    ImGui::End();
}

}  // namespace keyforge
```

- [ ] **Step 3: Build, verify link, core green**

Run: `PATH="/Users/naramalawar36/Library/Python/3.9/bin:$PATH" cmake --build build -j 2>&1 | tail -4 && ls -la build/app/keyforge && ./build/tests/core_tests 2>&1 | tail -3`
Expected: clean build; binary links; core SUCCESS (25 cases).

- [ ] **Step 4: Manual verification (pending — human)**

Checklist note: Ctrl+K (Cmd+K on macOS) opens the overlay; `help` lists commands; `gen --len 32` shows a password; `add`/`delete` refresh the panes behind it; a vault-changing command persists; Esc closes.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat(ui): Ctrl+K command palette overlay reusing the dispatcher"
```

---

### Task 5: Audit view + import/export tools + status polish

Replaces the `run_audit`/`draw_detail_audit` stubs and adds import/export to settings.

**Files:**
- Modify: `app/src/panels/detail.cpp` (replace `run_audit` and `draw_detail_audit` stubs; extend `draw_settings`)

- [ ] **Step 1: In `app/src/panels/detail.cpp`, replace the two stubs**

Replace:

```cpp
void App::draw_detail_audit() { ImGui::TextDisabled("audit — implemented in Task 5"); }
```

and

```cpp
void App::run_audit() {}
```

with:

```cpp
void App::run_audit() {
    ui_.audit_findings = vaultcore::audit_vault(session_->vault(), int64_t(std::time(nullptr)));
    ui_.mode = DetailMode::Audit;
    ui_.selected_entry.clear();
}

void App::draw_detail_audit() {
    ImGui::Text("Vault audit");
    ImGui::SameLine();
    if (ImGui::SmallButton("run again")) run_audit();
    ImGui::SameLine();
    if (ImGui::SmallButton("close")) ui_.mode = DetailMode::View;
    ImGui::Separator();
    if (ui_.audit_findings.empty()) {
        ImGui::TextDisabled("No issues found — vault is healthy.");
        return;
    }
    for (const auto& f : ui_.audit_findings) {
        ImGui::PushID(&f);
        if (ImGui::SmallButton("view")) {
            ui_.selected_entry = f.name;
            ui_.mode = DetailMode::View;
        }
        ImGui::SameLine();
        ImGui::TextWrapped("%s: %s", f.name.c_str(), f.issue.c_str());
        ImGui::PopID();
    }
}
```

Add `#include <vaultcore/audit.hpp>` and (if not already present) `<ctime>` to the top of `detail.cpp`.

- [ ] **Step 2: Extend `draw_settings` in `detail.cpp` with import/export** — insert before the final `if (ImGui::Button("Save settings"))`:

```cpp
        ImGui::Separator();
        ImGui::TextDisabled("Tools");
        static char import_path[1024] = {};
        static char export_path[1024] = {};
        ImGui::PushItemWidth(-90);
        ImGui::InputTextWithHint("##imp", "CSV path to import", import_path, sizeof import_path);
        ImGui::PopItemWidth();
        ImGui::SameLine();
        if (ImGui::Button("Import CSV")) {
            auto out = vaultcore::execute_command(
                *session_, std::string("import \"") + import_path + "\"",
                int64_t(std::time(nullptr)));
            if (out.vault_changed) session_->save();
            set_status(out.message, !out.ok);
        }
        ImGui::PushItemWidth(-90);
        ImGui::InputTextWithHint("##exp", "path to export vault", export_path, sizeof export_path);
        ImGui::PopItemWidth();
        ImGui::SameLine();
        if (ImGui::Button("Export vault")) {
            auto out = vaultcore::execute_command(
                *session_, std::string("export \"") + export_path + "\"",
                int64_t(std::time(nullptr)));
            set_status(out.message, !out.ok);
        }
```

Add `#include <vaultcore/commands.hpp>` to `detail.cpp` if not already present (it is via app.hpp → commands.hpp, but include explicitly for clarity).

- [ ] **Step 3: Build, verify link, core green**

Run: `PATH="/Users/naramalawar36/Library/Python/3.9/bin:$PATH" cmake --build build -j 2>&1 | tail -4 && ls -la build/app/keyforge && ./build/tests/core_tests 2>&1 | tail -3`
Expected: clean build; binary links; core SUCCESS (25 cases).

- [ ] **Step 4: Manual verification (pending — human)**

Checklist note: audit button lists weak/reused/old findings; "view" jumps to that entry; clean vault shows the healthy message; settings Import CSV reports counts and the new entries appear; Export writes the file.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat(ui): audit view and CSV import/export in settings"
```

---

### Task 6: QR drag-drop + README + final verification

**Files:**
- Modify: `app/src/main.cpp` (drop callback + window user pointer), `app/src/panels/actions.cpp` (`on_drop`), `README.md`

- [ ] **Step 1: Implement `App::on_drop` — append to `app/src/panels/actions.cpp`** (inside `namespace keyforge`)

```cpp
void App::on_drop(int count, const char** paths) {
    if (count < 1 || screen_ != Screen::Main) return;
    if (ui_.mode != DetailMode::Edit) begin_add();  // dropping starts a new entry
    std::snprintf(ui_.edit.totp_qr_path, sizeof ui_.edit.totp_qr_path, "%s", paths[0]);
    ui_.edit.totp_secret[0] = '\0';
    ui_.edit.totp_uri[0] = '\0';
    set_status("QR image attached — Save to enroll TOTP", false);
}
```

- [ ] **Step 2: Wire the GLFW drop callback — in `app/src/main.cpp`**

Add this function above `main`:

```cpp
static void drop_callback(GLFWwindow* w, int count, const char** paths) {
    auto* app = static_cast<keyforge::App*>(glfwGetWindowUserPointer(w));
    if (app) app->on_drop(count, paths);
}
```

Then, immediately after `keyforge::App app(window, vault_path);`, add:

```cpp
    glfwSetWindowUserPointer(window, &app);
    glfwSetDropCallback(window, drop_callback);
```

- [ ] **Step 3: Update `README.md`** — replace the "## Commands" heading paragraph's intro with a note about the window, by inserting this section immediately after the first paragraph (the one ending "C++20, Dear ImGui."):

```markdown

## Window

KeyForge opens a three-pane window: a tag sidebar (click a tag to filter,
"All" resets), a searchable entry list, and a detail panel. Select an entry
to view it (copy buttons, password reveal, live TOTP); **+ Add** and **Edit**
open an inline form with a password generator and TOTP by secret, otpauth://
URI, or a QR image — you can also drag a QR image onto the window. The
sidebar's audit button flags weak/reused/old passwords; settings holds
CSV import/export. Every command below is still available via a **Ctrl+K**
(Cmd+K on macOS) palette overlay.
```

- [ ] **Step 4: Build, verify link, core green**

Run: `PATH="/Users/naramalawar36/Library/Python/3.9/bin:$PATH" cmake --build build -j 2>&1 | tail -4 && ls -la build/app/keyforge && ./build/tests/core_tests 2>&1 | tail -3`
Expected: clean build; binary links; core SUCCESS (25 cases).

- [ ] **Step 5: Clean-from-scratch build (proves the whole v2 tree compiles fresh)**

Run: `rm -rf build && PATH="/Users/naramalawar36/Library/Python/3.9/bin:$PATH" cmake -B build -DCMAKE_BUILD_TYPE=Release -DCMAKE_POLICY_VERSION_MINIMUM=3.5 >/tmp/kf2_cfg.log 2>&1 && PATH="/Users/naramalawar36/Library/Python/3.9/bin:$PATH" cmake --build build -j >/tmp/kf2_build.log 2>&1 && echo OK && ./build/tests/core_tests 2>&1 | tail -3 && ls -la build/app/keyforge`
Expected: `OK`, core SUCCESS (25 cases), binary present. (Downloads deps; allow several minutes.)

- [ ] **Step 6: Manual verification checklist (pending — human at a display)**

Document in the report that a human must run `./build/app/keyforge --vault /tmp/kf-v2.kfv` and confirm: three panes; search + tag filter; add/edit/delete with confirm; gen; reveal/copy with auto-clear; live TOTP; drag a QR image onto the window fills the path; Ctrl+K commands; audit jump; import/export; lock and auto-lock.

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "feat(ui): QR drag-drop enrollment; document the v2 window"
```

---

## Requirement → Task Traceability

| Spec requirement | Task |
|---|---|
| `Vault::all_tags()` (tested) | 1 |
| Panel-module restructure, ui_state.hpp | 2 |
| Toolbar search + Add | 2 (Add action wired in 3) |
| Tag sidebar with counts + tool icons | 2 |
| Entry list (search ∩ tag, selection, empty state) | 2 |
| Detail view (copy, reveal, live TOTP) | 2 |
| Inline edit/add form (gen, TOTP inputs, name read-only on edit) | 3 |
| Delete with confirm dialog | 3 |
| Ctrl+K palette overlay (reuses dispatcher) | 4 |
| Audit view with jump-to-entry | 5 |
| Import/export in settings | 5 |
| Status line | 2 (helper), 3–5 (uses) |
| QR drag-drop | 6 |
| 1000×680 window | 2 |
| Unlock/timers/lock/clipboard unchanged | 2 (carried from v1) |
| README/window docs | 6 |
| Core untouched except all_tags; v1 vaults open as-is | all (no format/command change) |
