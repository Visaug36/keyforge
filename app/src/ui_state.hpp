#pragma once
#include <string>
#include <vector>
#include <vaultcore/commands.hpp>
#include <vaultcore/audit.hpp>

namespace keyforge {

// All char buffers here are wiped with sodium_memzero on save/cancel/lock.
struct EditBuffers {
    char name[128] = {};
    char username[256] = {};
    char password[256] = {};
    char url[512] = {};
    char notes[2048] = {};
    char tags[256] = {};
    char totp_secret[256] = {};
    char totp_uri[1024] = {};
    char totp_qr_path[1024] = {};
    bool remove_totp = false;
    std::string original_name;  // empty => Add mode
    std::string original_password;
    std::string error;          // inline form error (red)
};

enum class DetailMode { View, Edit, Audit };

struct UiState {
    char search[256] = {};
    std::string selected_tag;    // empty = All
    std::string selected_entry;  // entry name; empty = none
    DetailMode mode = DetailMode::View;
    EditBuffers edit;

    bool show_palette = false;
    bool palette_focus = false;
    char palette_input[512] = {};
    vaultcore::CommandOutcome palette_result;
    bool palette_has_result = false;

    std::vector<vaultcore::AuditFinding> audit_findings;

    std::string status;
    bool status_is_error = false;
    double status_until = 0.0;

    bool reveal_password = false;  // detail view reveal
    bool edit_reveal = false;      // edit form reveal
    bool confirm_delete = false;
};

}  // namespace keyforge
