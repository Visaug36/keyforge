#include "theme.hpp"
#include <imgui.h>

namespace keyforge {

void apply_theme() {
    ImGuiStyle& st = ImGui::GetStyle();
    st.WindowRounding = 0.0f;
    st.FrameRounding = 3.0f;
    st.FrameBorderSize = 1.0f;
    st.WindowBorderSize = 0.0f;
    st.FramePadding = ImVec2(10, 8);
    st.ItemSpacing = ImVec2(10, 10);
    st.WindowPadding = ImVec2(16, 16);
    st.ScrollbarSize = 10.0f;

    const ImVec4 bg{0.043f, 0.055f, 0.047f, 1.0f};
    const ImVec4 panel{0.075f, 0.095f, 0.080f, 1.0f};
    const ImVec4 frame{0.030f, 0.042f, 0.034f, 1.0f};
    const ImVec4 text{0.60f, 0.80f, 0.63f, 1.0f};
    const ImVec4 dim{0.38f, 0.52f, 0.41f, 1.0f};
    const ImVec4 border{0.29f, 0.50f, 0.35f, 1.0f};
    const ImVec4 accent{0.36f, 0.62f, 0.43f, 1.0f};

    ImVec4* c = st.Colors;
    c[ImGuiCol_WindowBg] = bg;
    c[ImGuiCol_ChildBg] = ImVec4(0, 0, 0, 0);
    c[ImGuiCol_PopupBg] = panel;
    c[ImGuiCol_Text] = text;
    c[ImGuiCol_TextDisabled] = dim;
    c[ImGuiCol_FrameBg] = frame;
    c[ImGuiCol_FrameBgHovered] = panel;
    c[ImGuiCol_FrameBgActive] = panel;
    c[ImGuiCol_Border] = border;
    c[ImGuiCol_Button] = frame;
    c[ImGuiCol_ButtonHovered] = panel;
    c[ImGuiCol_ButtonActive] = accent;
    c[ImGuiCol_TitleBg] = bg;
    c[ImGuiCol_TitleBgActive] = bg;
    c[ImGuiCol_TitleBgCollapsed] = bg;
    c[ImGuiCol_ScrollbarBg] = bg;
    c[ImGuiCol_ScrollbarGrab] = border;
    c[ImGuiCol_ScrollbarGrabHovered] = accent;
    c[ImGuiCol_ScrollbarGrabActive] = accent;
    c[ImGuiCol_Separator] = border;
    c[ImGuiCol_CheckMark] = accent;
    c[ImGuiCol_SliderGrab] = border;
    c[ImGuiCol_SliderGrabActive] = accent;
    c[ImGuiCol_PlotHistogram] = accent;
    c[ImGuiCol_TextSelectedBg] = ImVec4(0.36f, 0.62f, 0.43f, 0.35f);
    c[ImGuiCol_NavHighlight] = accent;
    c[ImGuiCol_HeaderHovered] = panel;
    c[ImGuiCol_HeaderActive] = panel;
    c[ImGuiCol_Header] = panel;
}

}  // namespace keyforge
