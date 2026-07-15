#pragma once
#include <string>
#include "result.hpp"

namespace vaultcore {

struct GenOptions {
    int length = 20;
    bool symbols = true;
    bool allow_ambiguous = false;  // when false, 0 O 1 l I are excluded
};

// CSPRNG-only generation; guarantees at least one char from every enabled class.
Result<std::string> generate_password(const GenOptions& opt);

}  // namespace vaultcore
