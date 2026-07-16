#include "app.hpp"
#include "theme.hpp"
#include <GLFW/glfw3.h>
#include <imgui.h>
#include <sodium.h>
#include <cstring>
#include <ctime>
#include <sstream>
#include <vaultcore/totp.hpp>

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
        if (first_run && pw != std::string(master_confirm_buf_)) {
            unlock_error_ = "passwords do not match";
        } else {
            auto r = first_run ? Session::create(vault_path_, pw)
                               : Session::open(vault_path_, pw);
            if (r.ok()) {
                session_.emplace(std::move(*r.value));
                screen_ = Screen::Main;
                unlock_error_.clear();
                has_result_ = false;
                input_buf_[0] = '\0';
                focus_input_ = true;
                last_activity_ = glfwGetTime();
            } else {
                unlock_error_ = r.error.message;
            }
        }
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

namespace {
void entry_row(const vaultcore::Entry& e) {
    ImGui::TextUnformatted(e.name.c_str());
    if (!e.username.empty()) {
        ImGui::SameLine();
        ImGui::TextDisabled("%s", e.username.c_str());
    }
    if (!e.tags.empty()) {
        std::string t = "[";
        for (size_t i = 0; i < e.tags.size(); ++i)
            t += (i ? ", " : "") + e.tags[i];
        t += "]";
        ImGui::SameLine();
        ImGui::TextDisabled("%s", t.c_str());
    }
}

void field_row(const char* label, const std::string& value) {
    ImGui::TextDisabled("%-10s", label);
    ImGui::SameLine();
    ImGui::TextWrapped("%s", value.empty() ? "-" : value.c_str());
}
}  // namespace

void App::draw_main() {
    draw_sidebar();
    ImGui::SameLine();
    ImGui::BeginGroup();
    draw_palette();
    draw_results();
    ImGui::EndGroup();
    if (show_settings_) draw_settings();
}

void App::draw_sidebar() {
    ImGui::BeginChild("##side", ImVec2(52, 0));
    ImGui::TextDisabled("</>");
    ImGui::SetCursorPosY(ImGui::GetWindowHeight() - 76);
    if (ImGui::Button("cfg", ImVec2(38, 30))) show_settings_ = !show_settings_;
    if (ImGui::Button("lk", ImVec2(38, 30))) want_lock_ = true;
    ImGui::EndChild();
}

void App::draw_palette() {
    if (focus_input_) {
        ImGui::SetKeyboardFocusHere();
        focus_input_ = false;
    }
    ImGui::SetNextItemWidth(-1);
    bool entered = ImGui::InputTextWithHint(
        "##cmd", "Type a command or search entries…", input_buf_, sizeof input_buf_,
        ImGuiInputTextFlags_EnterReturnsTrue);
    if (entered && input_buf_[0] != '\0') {
        run_command(input_buf_);
        input_buf_[0] = '\0';
        focus_input_ = true;
    }
}

void App::draw_results() {
    ImGui::BeginChild("##results", ImVec2(0, 0));
    const std::string typed(input_buf_);

    if (!typed.empty()) {
        std::istringstream is(typed);
        std::string first;
        is >> first;
        std::string usage = vaultcore::usage_for(first);
        if (!usage.empty()) {
            ImGui::TextDisabled("%s", usage.c_str());  // live usage hint while typing
        } else {
            for (const auto* e : session_->vault().search(typed)) entry_row(*e);
        }
        ImGui::EndChild();
        return;
    }

    if (!has_result_) {  // idle: show the whole vault
        for (const auto* e : session_->vault().list()) entry_row(*e);
        ImGui::EndChild();
        return;
    }

    using Kind = vaultcore::CommandOutcome::Kind;
    if (!last_.ok) {
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(kErrRed[0], kErrRed[1], kErrRed[2], 1));
        ImGui::TextWrapped("%s", last_.message.c_str());
        ImGui::PopStyleColor();
        ImGui::EndChild();
        return;
    }

    switch (last_.kind) {
        case Kind::Text:
        case Kind::Help:
            ImGui::TextWrapped("%s", last_.message.c_str());
            break;
        case Kind::EntryList:
            ImGui::TextDisabled("%s", last_.message.c_str());
            ImGui::Separator();
            for (const auto& e : last_.entries) entry_row(e);
            break;
        case Kind::EntryDetail: {
            const auto& e = last_.entries[0];
            field_row("name", e.name);
            field_row("username", e.username);
            ImGui::TextDisabled("%-10s", "password");
            ImGui::SameLine();
            ImGui::TextUnformatted(reveal_password_ ? e.password.c_str() : "************");
            ImGui::SameLine();
            if (ImGui::SmallButton(reveal_password_ ? "hide" : "reveal"))
                reveal_password_ = !reveal_password_;
            field_row("url", e.url);
            field_row("notes", e.notes);
            std::string tags;
            for (size_t i = 0; i < e.tags.size(); ++i) tags += (i ? ", " : "") + e.tags[i];
            field_row("tags", tags);
            field_row("totp", e.totp_secret.empty() ? "-" : "configured");
            break;
        }
        case Kind::Secret:
            ImGui::TextWrapped("%s", last_.message.c_str());
            if (!last_.copy_to_clipboard) {  // gen: show value + copy button
                ImGui::TextUnformatted(last_.secret.c_str());
                if (ImGui::SmallButton("copy")) copy_secret(last_.secret);
            } else if (!clip_value_.empty()) {
                ImGui::TextDisabled("clipboard clears in %ds",
                                    int(clip_deadline_ - glfwGetTime()) + 1);
            }
            break;
        case Kind::Totp: {
            const auto* e = session_->vault().find(last_.totp_entry);
            if (!e || e->totp_secret.empty()) {
                ImGui::TextDisabled("entry no longer has TOTP");
                break;
            }
            int64_t t = int64_t(std::time(nullptr));
            auto code = vaultcore::totp_code(e->totp_secret, t);
            int rem = vaultcore::totp_seconds_remaining(t);
            ImGui::TextDisabled("TOTP for '%s'", e->name.c_str());
            ImGui::SetWindowFontScale(1.8f);
            ImGui::TextUnformatted(code.ok() ? code.value->c_str() : "error");
            ImGui::SetWindowFontScale(1.0f);
            ImGui::ProgressBar(float(rem) / 30.0f, ImVec2(220, 8), "");
            ImGui::SameLine();
            ImGui::TextDisabled("%ds", rem);
            if (code.ok() && ImGui::SmallButton("copy")) copy_secret(*code.value);
            break;
        }
    }
    ImGui::EndChild();
}

void App::draw_settings() {
    ImGui::SetNextWindowSize(ImVec2(440, 0), ImGuiCond_Appearing);
    if (ImGui::Begin("Settings", &show_settings_, ImGuiWindowFlags_NoCollapse)) {
        auto& s = session_->vault().settings();
        ImGui::SliderInt("Auto-lock (min)", &s.auto_lock_min, 1, 60);
        ImGui::SliderInt("Clipboard clear (sec)", &s.clip_clear_sec, 5, 120);
        ImGui::SliderInt("Generator length", &s.gen_len, 8, 64);
        ImGui::Checkbox("Generator symbols", &s.gen_symbols);
        ImGui::Separator();
        ImGui::TextDisabled("Vault: %s", vault_path_.string().c_str());
        ImGui::TextDisabled("Launch with --vault <path> to use another vault file.");
        if (ImGui::Button("Save settings")) {
            auto st = session_->save();
            if (!st.ok()) unlock_error_ = st.error.message;  // shown after next lock
        }
    }
    ImGui::End();
}

void App::run_command(const std::string& line) {
    reveal_password_ = false;
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
    last_ = std::move(out);
    has_result_ = true;
}

void App::copy_secret(const std::string& value) {
    glfwSetClipboardString(window_, value.c_str());
    clip_value_ = value;
    clip_deadline_ = glfwGetTime() +
                     (session_ ? session_->vault().settings().clip_clear_sec : 30);
}

void App::tick_timers() {
    if (want_lock_) {
        want_lock_ = false;
        lock();
    }
}

void App::lock() {
    session_.reset();  // SecureBuffer destructor wipes the key
    screen_ = Screen::Unlock;
    last_ = {};
    has_result_ = false;
    reveal_password_ = false;
    show_settings_ = false;
    input_buf_[0] = '\0';
    unlock_error_.clear();
    if (!clip_value_.empty()) {
        const char* cur = glfwGetClipboardString(window_);
        if (cur && clip_value_ == cur) glfwSetClipboardString(window_, "");
        clip_value_.clear();
    }
}

}  // namespace keyforge
