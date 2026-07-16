#include "vaultcore/audit.hpp"
#include <cctype>
#include <map>

namespace vaultcore {

std::vector<AuditFinding> audit_vault(const Vault& v, int64_t now) {
    std::vector<AuditFinding> out;

    for (const auto& e : v.entries()) {
        bool lo = false, up = false, di = false, sy = false;
        for (unsigned char c : e.password) {
            if (std::islower(c)) lo = true;
            else if (std::isupper(c)) up = true;
            else if (std::isdigit(c)) di = true;
            else sy = true;
        }
        int classes = int(lo) + int(up) + int(di) + int(sy);
        if (e.password.size() < 12 || classes < 3)
            out.push_back({e.name, "weak password (" + std::to_string(e.password.size()) +
                                       " chars, " + std::to_string(classes) +
                                       " character classes)"});
    }

    std::map<std::string, std::vector<std::string>> by_pw;
    for (const auto& e : v.entries())
        if (!e.password.empty()) by_pw[e.password].push_back(e.name);
    for (const auto& [pw, names] : by_pw)
        if (names.size() > 1)
            for (const auto& n : names)
                out.push_back({n, "password reused across " +
                                      std::to_string(names.size()) + " entries"});

    constexpr int64_t kYear = 365LL * 24 * 3600;
    for (const auto& e : v.entries()) {
        int64_t ref = e.password_changed_at ? e.password_changed_at : e.created_at;
        if (ref && now - ref > kYear)
            out.push_back({e.name, "password older than 1 year"});
    }
    return out;
}

}  // namespace vaultcore
