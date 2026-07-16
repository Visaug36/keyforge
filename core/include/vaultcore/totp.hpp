#pragma once
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include "result.hpp"

namespace vaultcore {

// RFC 4648 base32; case-insensitive; spaces, dashes and '=' padding ignored.
Result<std::vector<uint8_t>> base32_decode(std::string_view s);

// RFC 6238 TOTP with HMAC-SHA1 (the authenticator-app standard).
Result<std::string> totp_code(std::string_view base32_secret, int64_t unix_time,
                              int digits = 6, int period = 30);
int totp_seconds_remaining(int64_t unix_time, int period = 30);

struct OtpauthInfo {
    std::string secret;  // base32, validated
    int digits = 6;
    int period = 30;
    std::string label;
};
Result<OtpauthInfo> parse_otpauth_uri(const std::string& uri);  // implemented in Task 7

}  // namespace vaultcore
