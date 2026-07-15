add_executable(core_tests
  main.cpp
  test_paths.cpp)
target_link_libraries(core_tests PRIVATE vaultcore doctest::doctest)
target_compile_definitions(core_tests PRIVATE TEST_FIXTURES_DIR="${CMAKE_CURRENT_SOURCE_DIR}/fixtures")
add_test(NAME core_tests COMMAND core_tests)
