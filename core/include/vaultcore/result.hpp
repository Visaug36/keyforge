#pragma once
#include <optional>
#include <string>
#include <utility>

namespace vaultcore {

enum class Err {
    None, Io, WrongPassword, Corrupt, NotFound, Duplicate,
    BadArgs, BadBase32, BadUri, BadQr, BadCsv, UnknownCommand
};

struct Error {
    Err code = Err::None;
    std::string message;
};

// For operations with no return value.
struct Status {
    Error error;
    bool ok() const { return error.code == Err::None; }
    static Status success() { return {}; }
    static Status failure(Err c, std::string m) { return {{c, std::move(m)}}; }
};

// For operations that return a value. Check ok() before dereferencing value.
template <typename T>
struct Result {
    std::optional<T> value;
    Error error;
    bool ok() const { return value.has_value(); }
    static Result success(T v) { Result r; r.value = std::move(v); return r; }
    static Result failure(Err c, std::string m) { Result r; r.error = {c, std::move(m)}; return r; }
};

}  // namespace vaultcore
