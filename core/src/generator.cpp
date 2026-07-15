#include "vaultcore/generator.hpp"
#include <sodium.h>
#include <utility>
#include <vector>

namespace vaultcore {
namespace {
constexpr const char* kLowerSafe = "abcdefghijkmnopqrstuvwxyz";
constexpr const char* kLowerAll = "abcdefghijklmnopqrstuvwxyz";
constexpr const char* kUpperSafe = "ABCDEFGHJKLMNPQRSTUVWXYZ";
constexpr const char* kUpperAll = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
constexpr const char* kDigitSafe = "23456789";
constexpr const char* kDigitAll = "0123456789";
constexpr const char* kSymbols = "!@#$%^&*()-_=+[]{};:,.?";
}  // namespace

Result<std::string> generate_password(const GenOptions& opt) {
    if (opt.length < 4 || opt.length > 128)
        return Result<std::string>::failure(Err::BadArgs, "length must be between 4 and 128");
    std::vector<std::string> classes = {
        opt.allow_ambiguous ? kLowerAll : kLowerSafe,
        opt.allow_ambiguous ? kUpperAll : kUpperSafe,
        opt.allow_ambiguous ? kDigitAll : kDigitSafe};
    if (opt.symbols) classes.push_back(kSymbols);

    std::string all;
    for (const auto& c : classes) all += c;

    std::string out;
    for (const auto& c : classes)
        out += c[randombytes_uniform(uint32_t(c.size()))];
    while (int(out.size()) < opt.length)
        out += all[randombytes_uniform(uint32_t(all.size()))];
    // Fisher-Yates so the guaranteed class chars aren't stuck at the front.
    for (size_t i = out.size() - 1; i > 0; --i)
        std::swap(out[i], out[randombytes_uniform(uint32_t(i + 1))]);
    return Result<std::string>::success(std::move(out));
}

}  // namespace vaultcore
