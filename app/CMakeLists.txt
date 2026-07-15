find_package(OpenGL REQUIRED)
add_executable(keyforge
  src/main.cpp
  src/app.cpp
  src/theme.cpp)
target_link_libraries(keyforge PRIVATE vaultcore imgui glfw OpenGL::GL)
target_compile_definitions(keyforge PRIVATE GL_SILENCE_DEPRECATION)
