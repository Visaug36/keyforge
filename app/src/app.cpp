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
