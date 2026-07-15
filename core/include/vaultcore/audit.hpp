#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include "vault.hpp"

namespace vaultcore {

struct AuditFinding {
    std::string name;   // entry name
    std::string issue;  // human-readable description
};

// Flags weak (<12 chars or <3 character classes), reused (identical password
// across entries), and old (password unchanged for >1 year) passwords.
std::vector<AuditFinding> audit_vault(const Vault& v, int64_t now);

}  // namespace vaultcore
