#pragma once
#include <filesystem>
#include <string>
#include "result.hpp"

namespace vaultcore {

// Reads a PNG/JPG/etc image and returns the text payload of the first
// decodable QR code in it.
Result<std::string> decode_qr_image(const std::filesystem::path& image_path);

}  // namespace vaultcore
