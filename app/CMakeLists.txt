find_package(OpenGL REQUIRED)
add_executable(keyforge
  src/main.cpp
  src/app.cpp
  src/theme.cpp
  src/panels/sidebar.cpp
  src/panels/entry_list.cpp
  src/panels/detail.cpp
  src/panels/palette.cpp)
target_include_directories(keyforge PRIVATE src)
target_link_libraries(keyforge PRIVATE vaultcore imgui glfw OpenGL::GL)
target_compile_definitions(keyforge PRIVATE GL_SILENCE_DEPRECATION)
