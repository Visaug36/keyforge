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

// ---- Placeholders replaced in Task 14 ----
void App::draw_main() {
    ImGui::Text("Unlocked. %zu entries.", session_->vault().entries().size());
    if (ImGui::Button("lock")) want_lock_ = true;
}
void App::draw_sidebar() {}
void App::draw_palette() {}
void App::draw_results() {}
void App::draw_settings() {}
void App::run_command(const std::string&) {}
void App::copy_secret(const std::string& value) {
    glfwSetClipboardString(window_, value.c_str());
    clip_value_ = value;
    clip_deadline_ = glfwGetTime() +
                     (session_ ? session_->vault().settings().clip_clear_sec : 30);
}
// ------------------------------------------

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
