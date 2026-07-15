#include "vaultcore/vault.hpp"
#include "vaultcore/util.hpp"
#include <nlohmann/json.hpp>
#include <algorithm>

namespace vaultcore {

namespace {
void sort_by_name(std::vector<const Entry*>& v) {
    std::sort(v.begin(), v.end(), [](const Entry* a, const Entry* b) {
        return to_lower(a->name) < to_lower(b->name);
    });
}
}  // namespace

Status Vault::add(Entry e, int64_t now) {
    if (e.name.empty()) return Status::failure(Err::BadArgs, "entry name is required");
    if (find(e.name))
        return Status::failure(Err::Duplicate, "an entry named '" + e.name + "' already exists");
    e.created_at = e.updated_at = now;
    e.password_changed_at = e.password.empty() ? 0 : now;
    entries_.push_back(std::move(e));
    return Status::success();
}

Status Vault::update_entry(const std::string& name, const EntryPatch& p, int64_t now) {
    Entry* e = find_mutable(name);
    if (!e) return Status::failure(Err::NotFound, "no entry named '" + name + "'");
    if (p.empty()) return Status::failure(Err::BadArgs, "nothing to update");
    if (p.username) e->username = *p.username;
    if (p.password) { e->password = *p.password; e->password_changed_at = now; }
    if (p.url) e->url = *p.url;
    if (p.notes) e->notes = *p.notes;
    if (p.totp_secret) e->totp_secret = *p.totp_secret;
    if (p.tags) e->tags = *p.tags;
    e->updated_at = now;
    return Status::success();
}

Status Vault::remove(const std::string& name) {
    auto it = std::find_if(entries_.begin(), entries_.end(),
                           [&](const Entry& e) { return iequals(e.name, name); });
    if (it == entries_.end())
        return Status::failure(Err::NotFound, "no entry named '" + name + "'");
    entries_.erase(it);
    return Status::success();
}

const Entry* Vault::find(const std::string& name) const {
    for (const auto& e : entries_)
        if (iequals(e.name, name)) return &e;
    return nullptr;
}

Entry* Vault::find_mutable(const std::string& name) {
    for (auto& e : entries_)
        if (iequals(e.name, name)) return &e;
    return nullptr;
}

std::vector<const Entry*> Vault::list(const std::string& tag) const {
    std::vector<const Entry*> out;
    for (const auto& e : entries_) {
        if (tag.empty()) { out.push_back(&e); continue; }
        for (const auto& t : e.tags)
            if (iequals(t, tag)) { out.push_back(&e); break; }
    }
    sort_by_name(out);
    return out;
}

std::vector<const Entry*> Vault::search(const std::string& query) const {
    std::string q = to_lower(query);
    std::vector<const Entry*> out;
    for (const auto& e : entries_) {
        std::string hay = to_lower(e.name) + " " + to_lower(e.username) + " " + to_lower(e.url);
        for (const auto& t : e.tags) hay += " " + to_lower(t);
        if (hay.find(q) != std::string::npos) out.push_back(&e);
    }
    sort_by_name(out);
    return out;
}

std::string Vault::to_json() const {
    nlohmann::json j;
    j["settings"] = {{"auto_lock_min", settings_.auto_lock_min},
                     {"clip_clear_sec", settings_.clip_clear_sec},
                     {"gen_len", settings_.gen_len},
                     {"gen_symbols", settings_.gen_symbols}};
    j["entries"] = nlohmann::json::array();
    for (const auto& e : entries_) {
        j["entries"].push_back({{"name", e.name},
                                {"username", e.username},
                                {"password", e.password},
                                {"url", e.url},
                                {"notes", e.notes},
                                {"tags", e.tags},
                                {"totp_secret", e.totp_secret},
                                {"created_at", e.created_at},
                                {"updated_at", e.updated_at},
                                {"password_changed_at", e.password_changed_at}});
    }
    return j.dump();
}

Result<Vault> Vault::from_json(const std::string& text) {
    auto j = nlohmann::json::parse(text, nullptr, /*allow_exceptions=*/false);
    if (j.is_discarded() || !j.is_object())
        return Result<Vault>::failure(Err::Corrupt, "vault payload is not valid JSON");
    Vault v;
    const auto s = j.value("settings", nlohmann::json::object());
    v.settings_.auto_lock_min = s.value("auto_lock_min", 5);
    v.settings_.clip_clear_sec = s.value("clip_clear_sec", 30);
    v.settings_.gen_len = s.value("gen_len", 20);
    v.settings_.gen_symbols = s.value("gen_symbols", true);
    for (const auto& je : j.value("entries", nlohmann::json::array())) {
        if (!je.is_object()) continue;
        Entry e;
        e.name = je.value("name", "");
        e.username = je.value("username", "");
        e.password = je.value("password", "");
        e.url = je.value("url", "");
        e.notes = je.value("notes", "");
        e.tags = je.value("tags", std::vector<std::string>{});
        e.totp_secret = je.value("totp_secret", "");
        e.created_at = je.value("created_at", int64_t{0});
        e.updated_at = je.value("updated_at", int64_t{0});
        e.password_changed_at = je.value("password_changed_at", int64_t{0});
        if (!e.name.empty()) v.entries_.push_back(std::move(e));
    }
    return Result<Vault>::success(std::move(v));
}

}  // namespace vaultcore
