#include "app.hpp"
#include "theme.hpp"
#include <GLFW/glfw3.h>
#include <imgui.h>
#include <sodium.h>
#include <cstdio>
#include <ctime>
#include <vaultcore/audit.hpp>
#include <vaultcore/commands.hpp>
#include <vaultcore/generator.hpp>
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
        if (ImGui::Button("Save settings")) {
            auto st = session_->save();
            set_status(st.ok() ? "Settings saved." : st.error.message, !st.ok());
        }
    }
    ImGui::End();
}

}  // namespace keyforge
