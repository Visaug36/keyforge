#include <doctest/doctest.h>
#include <vaultcore/paths.hpp>

TEST_CASE("default vault dir is non-empty and ends with keyforge") {
    auto p = vaultcore::default_vault_dir();
    CHECK(!p.empty());
    CHECK(p.filename() == "keyforge");
}
