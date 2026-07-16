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
