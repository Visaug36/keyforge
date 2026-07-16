#include <doctest/doctest.h>
#include <vaultcore/qr.hpp>
#include <string>

using namespace vaultcore;

TEST_CASE("qr decoding") {
    SUBCASE("decodes an otpauth QR png") {
        auto r = decode_qr_image(std::string(TEST_FIXTURES_DIR) + "/totp_qr.png");
        REQUIRE(r.ok());
        CHECK(*r.value ==
              "otpauth://totp/KeyForge:demo?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
              "&issuer=KeyForge");
    }
    SUBCASE("image without a QR code fails with BadQr") {
        auto r = decode_qr_image(std::string(TEST_FIXTURES_DIR) + "/not_a_qr.png");
        REQUIRE_FALSE(r.ok());
        CHECK(r.error.code == Err::BadQr);
    }
    SUBCASE("missing file fails with Io") {
        auto r = decode_qr_image("/nonexistent/nope.png");
        REQUIRE_FALSE(r.ok());
        CHECK(r.error.code == Err::Io);
    }
}
