#include "vaultcore/qr.hpp"
#include <quirc.h>
#include <cstring>

#define STB_IMAGE_IMPLEMENTATION
#define STBI_ONLY_PNG
#define STBI_ONLY_JPEG
#define STBI_ONLY_BMP
#include <stb_image.h>

namespace vaultcore {

Result<std::string> decode_qr_image(const std::filesystem::path& image_path) {
    int w = 0, h = 0, ch = 0;
    unsigned char* img = stbi_load(image_path.string().c_str(), &w, &h, &ch, 1);
    if (!img)
        return Result<std::string>::failure(Err::Io,
                                            "cannot read image: " + image_path.string());
    struct quirc* q = quirc_new();
    if (!q || quirc_resize(q, w, h) < 0) {
        stbi_image_free(img);
        if (q) quirc_destroy(q);
        return Result<std::string>::failure(Err::Io, "out of memory decoding QR");
    }
    uint8_t* buf = quirc_begin(q, nullptr, nullptr);
    std::memcpy(buf, img, size_t(w) * size_t(h));
    stbi_image_free(img);
    quirc_end(q);

    int n = quirc_count(q);
    for (int i = 0; i < n; ++i) {
        struct quirc_code code;
        struct quirc_data data;
        quirc_extract(q, i, &code);
        if (quirc_decode(&code, &data) == QUIRC_SUCCESS) {
            std::string payload(reinterpret_cast<char*>(data.payload),
                                size_t(data.payload_len));
            quirc_destroy(q);
            return Result<std::string>::success(std::move(payload));
        }
    }
    quirc_destroy(q);
    return Result<std::string>::failure(Err::BadQr, "no readable QR code found in image");
}

}  // namespace vaultcore
