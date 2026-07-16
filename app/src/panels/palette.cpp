#include "app.hpp"
#include "theme.hpp"
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
        ui_.palette_result = vaultcore::CommandOutcome{};  // drop any secrets it held
        sodium_memzero(ui_.palette_input, sizeof ui_.palette_input);
        return;
    }

    const ImGuiViewport* vp = ImGui::GetMainViewport();
    ImGui::GetBackgroundDrawList()->AddRectFilled(
        vp->WorkPos,
        ImVec2(vp->WorkPos.x + vp->WorkSize.x, vp->WorkPos.y + vp->WorkSize.y),
        IM_COL32(0, 0, 0, 120));  // dim the panes behind the overlay
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
