add_executable(core_tests
  main.cpp
  test_paths.cpp
  test_crypto.cpp
  test_vault.cpp
  test_storage.cpp
  test_generator.cpp
  test_totp.cpp
  test_otpauth.cpp
  test_qr.cpp
  test_audit.cpp
  test_porting.cpp)
target_link_libraries(core_tests PRIVATE vaultcore doctest::doctest)
target_compile_definitions(core_tests PRIVATE TEST_FIXTURES_DIR="${CMAKE_CURRENT_SOURCE_DIR}/fixtures")  # used by fixture-based tests in later tasks
add_test(NAME core_tests COMMAND core_tests)
