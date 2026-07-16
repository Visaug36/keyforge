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
