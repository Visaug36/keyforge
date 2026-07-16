#include "app.hpp"
#include <GLFW/glfw3.h>
#include <sodium.h>
#include <cstdio>
#include <sstream>
#include <vector>
#include <vaultcore/generator.hpp>
#include <vaultcore/qr.hpp>
#include <vaultcore/totp.hpp>

namespace keyforge {

namespace {
std::vector<std::string> split_tags(const char* s) {
    std::vector<std::string> out;
    std::stringstream ss(s);
    std::string cur;
    while (std::getline(ss, cur, ',')) {
        size_t b = cur.find_first_not_of(" \t");
        size_t e = cur.find_last_not_of(" \t");
        if (b != std::string::npos) out.push_back(cur.substr(b, e - b + 1));
    }
    return out;
}

// Resolves the three TOTP inputs to a validated base32 secret.
// Returns {ok, secret, error}. secret empty with ok=true means "no TOTP given".
struct TotpResolve { bool ok; std::string secret; std::string error; };
TotpResolve resolve_totp(const EditBuffers& b) {
    int given = (b.totp_secret[0] != '\0') + (b.totp_uri[0] != '\0') +
                (b.totp_qr_path[0] != '\0');
    if (given == 0) return {true, "", ""};
    if (given > 1) return {false, "", "set at most one of secret / URI / QR path"};
    std::string secret;
    if (b.totp_secret[0]) {
        secret = b.totp_secret;
    } else if (b.totp_uri[0]) {
        auto info = vaultcore::parse_otpauth_uri(b.totp_uri);
        if (!info.ok()) return {false, "", info.error.message};
        secret = info.value->secret;
    } else {
        auto payload = vaultcore::decode_qr_image(b.totp_qr_path);
        if (!payload.ok()) return {false, "", payload.error.message};
        auto info = vaultcore::parse_otpauth_uri(*payload.value);
        if (!info.ok()) return {false, "", info.error.message};
        secret = info.value->secret;
    }
    if (!vaultcore::base32_decode(secret).ok())
        return {false, "", "TOTP secret is not valid base32"};
    return {true, secret, ""};
}
}  // namespace

void App::begin_add() {
    sodium_memzero(ui_.edit.password, sizeof ui_.edit.password);
    ui_.edit = EditBuffers{};
    ui_.mode = DetailMode::Edit;
    ui_.edit_reveal = false;
}

void App::begin_edit(const vaultcore::Entry& e) {
    ui_.edit = EditBuffers{};
    std::snprintf(ui_.edit.name, sizeof ui_.edit.name, "%s", e.name.c_str());
    std::snprintf(ui_.edit.username, sizeof ui_.edit.username, "%s", e.username.c_str());
    std::snprintf(ui_.edit.password, sizeof ui_.edit.password, "%s", e.password.c_str());
    std::snprintf(ui_.edit.url, sizeof ui_.edit.url, "%s", e.url.c_str());
    std::snprintf(ui_.edit.notes, sizeof ui_.edit.notes, "%s", e.notes.c_str());
    std::string tags;
    for (size_t i = 0; i < e.tags.size(); ++i) tags += (i ? "," : "") + e.tags[i];
    std::snprintf(ui_.edit.tags, sizeof ui_.edit.tags, "%s", tags.c_str());
    ui_.edit.original_name = e.name;
    ui_.edit.original_password = e.password;
    ui_.mode = DetailMode::Edit;
    ui_.edit_reveal = false;
}

void App::save_edit() {
    auto& v = session_->vault();
    int64_t now = int64_t(std::time(nullptr));
    auto totp = resolve_totp(ui_.edit);
    if (!totp.ok) { ui_.edit.error = totp.error; return; }

    vaultcore::Status st = vaultcore::Status::success();
    if (ui_.edit.original_name.empty()) {  // Add
        vaultcore::Entry e;
        e.name = ui_.edit.name;
        e.username = ui_.edit.username;
        e.password = ui_.edit.password;
        e.url = ui_.edit.url;
        e.notes = ui_.edit.notes;
        e.tags = split_tags(ui_.edit.tags);
        e.totp_secret = totp.secret;
        st = v.add(std::move(e), now);
    } else {  // Edit
        vaultcore::EntryPatch p;
        p.username = std::string(ui_.edit.username);
        p.url = std::string(ui_.edit.url);
        p.notes = std::string(ui_.edit.notes);
        p.tags = split_tags(ui_.edit.tags);
        if (std::string(ui_.edit.password) != ui_.edit.original_password)
            p.password = std::string(ui_.edit.password);
        if (ui_.edit.remove_totp) p.totp_secret = std::string("");
        else if (!totp.secret.empty()) p.totp_secret = totp.secret;
        st = v.update_entry(ui_.edit.original_name, p, now);
    }
    if (!st.ok()) { ui_.edit.error = st.error.message; return; }

    auto save = session_->save();
    if (!save.ok()) { ui_.edit.error = "saving vault failed: " + save.error.message; return; }

    ui_.selected_entry = ui_.edit.name[0] ? ui_.edit.name : ui_.edit.original_name;
    sodium_memzero(ui_.edit.password, sizeof ui_.edit.password);
    sodium_memzero(ui_.edit.totp_secret, sizeof ui_.edit.totp_secret);
    ui_.edit = EditBuffers{};
    ui_.mode = DetailMode::View;
    ui_.edit_reveal = false;
    set_status("Saved.", false);
}

void App::delete_selected() {
    if (ui_.selected_entry.empty()) return;
    auto st = session_->vault().remove(ui_.selected_entry);
    if (!st.ok()) { set_status(st.error.message, true); return; }
    auto save = session_->save();
    if (!save.ok()) { set_status("saving vault failed: " + save.error.message, true); return; }
    set_status("Deleted '" + ui_.selected_entry + "'.", false);
    ui_.selected_entry.clear();
    ui_.mode = DetailMode::View;
}

void App::on_drop(int count, const char** paths) {
    if (count < 1 || screen_ != Screen::Main) return;
    if (ui_.mode != DetailMode::Edit) begin_add();  // dropping starts a new entry
    std::snprintf(ui_.edit.totp_qr_path, sizeof ui_.edit.totp_qr_path, "%s", paths[0]);
    ui_.edit.totp_secret[0] = '\0';
    ui_.edit.totp_uri[0] = '\0';
    set_status("QR image attached — Save to enroll TOTP", false);
}

}  // namespace keyforge
