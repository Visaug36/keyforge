#pragma once
#include <cstdint>
#include <optional>
#include <string>
#include <vector>
#include "result.hpp"

namespace vaultcore {

struct Entry {
    std::string name;  // unique key, matched case-insensitively
    std::string username, password, url, notes;
    std::vector<std::string> tags;
    std::string totp_secret;  // base32; empty = no TOTP
    int64_t created_at = 0, updated_at = 0, password_changed_at = 0;
};

// Fields set here overwrite the entry's fields wholesale.
struct EntryPatch {
    std::optional<std::string> username, password, url, notes, totp_secret;
    std::optional<std::vector<std::string>> tags;
    bool empty() const {
        return !username && !password && !url && !notes && !totp_secret && !tags;
    }
};

struct Settings {
    int auto_lock_min = 5;
    int clip_clear_sec = 30;
    int gen_len = 20;
    bool gen_symbols = true;
};

class Vault {
public:
    Status add(Entry e, int64_t now);
    Status update_entry(const std::string& name, const EntryPatch& p, int64_t now);
    Status remove(const std::string& name);
    const Entry* find(const std::string& name) const;
    std::vector<const Entry*> list(const std::string& tag = "") const;   // name-sorted
    std::vector<const Entry*> search(const std::string& query) const;    // name-sorted
    std::vector<std::string> all_tags() const;  // dedup (case-insensitive), sorted
    const std::vector<Entry>& entries() const { return entries_; }
    Settings& settings() { return settings_; }
    const Settings& settings() const { return settings_; }
    std::string to_json() const;
    static Result<Vault> from_json(const std::string& text);

private:
    Entry* find_mutable(const std::string& name);
    std::vector<Entry> entries_;
    Settings settings_;
};

}  // namespace vaultcore
