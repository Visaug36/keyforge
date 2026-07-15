add_library(vaultcore STATIC
  src/paths.cpp
  src/crypto.cpp
  src/vault.cpp
  src/storage.cpp
  src/generator.cpp
  src/totp.cpp
  src/qr.cpp
  src/audit.cpp
  src/porting.cpp)
target_include_directories(vaultcore PUBLIC include PRIVATE ${stb_SOURCE_DIR})
target_link_libraries(vaultcore PUBLIC sodium nlohmann_json::nlohmann_json PRIVATE quirc)
