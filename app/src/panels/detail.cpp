#include "app.hpp"
#include "theme.hpp"
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
