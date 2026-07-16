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
