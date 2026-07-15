#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include "result.hpp"
#include "storage.hpp"
#include "vault.hpp"

namespace vaultcore {

struct CommandOutcome {
    enum class Kind { Text, EntryList, EntryDetail, Secret, Totp, Help };
    Kind kind = Kind::Text;
    bool ok = true;
    std::string message;           // status/error text (render red when !ok)
    std::vector<Entry> entries;    // EntryList rows / EntryDetail single entry
    std::string secret;            // Secret: generated/retrieved value; Totp: code
    std::string secret_label;      // e.g. "password for 'GitHub'"
    std::string totp_entry;        // Totp: entry name, for live refresh in the UI
    bool copy_to_clipboard = false;
    bool vault_changed = false;    // caller must Session::save() when true
    bool lock_requested = false;
};

// Splits a palette line into tokens; double quotes group words.
Result<std::vector<std::string>> tokenize(const std::string& line);

bool is_command_word(const std::string& word);
std::string usage_for(const std::string& command);  // "" if unknown
std::string help_text();

// Parses and runs one palette line against the unlocked session.
CommandOutcome execute_command(Session& session, const std::string& line, int64_t now);

}  // namespace vaultcore
