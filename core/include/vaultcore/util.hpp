#pragma once
#include <algorithm>
#include <cctype>
#include <string>

namespace vaultcore {

inline std::string to_lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return char(std::tolower(c)); });
    return s;
}

inline bool iequals(const std::string& a, const std::string& b) {
    return to_lower(a) == to_lower(b);
}

}  // namespace vaultcore
