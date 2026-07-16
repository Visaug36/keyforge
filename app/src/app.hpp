#pragma once
#include <filesystem>
#include <optional>
#include <string>
#include <vaultcore/commands.hpp>
#include <vaultcore/storage.hpp>

struct GLFWwindow;

namespace keyforge {

class App {
public:
    App(GLFWwindow* window, std::filesystem::path vault_path);
    void frame();     // call once per ImGui frame
    void shutdown();  // call once on app exit: wipes key, clears our clipboard

private:
    enum class Screen { Unlock, Main };

    void draw_unlock();
    void draw_main();
    void draw_sidebar();
    void draw_palette();
    void draw_results();
    void draw_settings();
    void run_command(const std::string& line);
    void copy_secret(const std::string& value);
    void tick_timers();
    void lock();

    GLFWwindow* window_;
    std::filesystem::path vault_path_;
    Screen screen_ = Screen::Unlock;
    std::optional<vaultcore::Session> session_;

    char master_buf_[256] = {};
    char master_confirm_buf_[256] = {};
    char input_buf_[512] = {};
    std::string unlock_error_;

    vaultcore::CommandOutcome last_;
    bool has_result_ = false;
    bool reveal_password_ = false;
    bool show_settings_ = false;
    bool focus_input_ = true;
    bool want_lock_ = false;

    std::string clip_value_;      // last value we put on the clipboard
    double clip_deadline_ = 0.0;  // glfwGetTime() when it must be cleared
    double last_activity_ = 0.0;  // for auto-lock
};

}  // namespace keyforge
