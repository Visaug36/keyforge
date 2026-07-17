find_package(OpenGL REQUIRED)

set(KEYFORGE_ICON ${CMAKE_CURRENT_SOURCE_DIR}/assets/keyforge.icns)

add_executable(keyforge MACOSX_BUNDLE
  src/main.cpp
  src/app.cpp
  src/theme.cpp
  src/panels/sidebar.cpp
  src/panels/entry_list.cpp
  src/panels/detail.cpp
  src/panels/actions.cpp
  src/panels/palette.cpp
  ${KEYFORGE_ICON})

target_include_directories(keyforge PRIVATE src)
target_link_libraries(keyforge PRIVATE vaultcore imgui glfw OpenGL::GL)
target_compile_definitions(keyforge PRIVATE GL_SILENCE_DEPRECATION)

# Nice product name for the window/binary/bundle (KeyForge.app, KeyForge.exe).
set_target_properties(keyforge PROPERTIES OUTPUT_NAME "KeyForge")

# macOS: bundle it into KeyForge.app with the icon in Resources.
set_source_files_properties(${KEYFORGE_ICON} PROPERTIES
  MACOSX_PACKAGE_LOCATION "Resources")
set_target_properties(keyforge PROPERTIES
  MACOSX_BUNDLE_BUNDLE_NAME "KeyForge"
  MACOSX_BUNDLE_GUI_IDENTIFIER "com.naramalawar.keyforge"
  MACOSX_BUNDLE_BUNDLE_VERSION "2.0.0"
  MACOSX_BUNDLE_SHORT_VERSION_STRING "2.0.0"
  MACOSX_BUNDLE_ICON_FILE "keyforge.icns"
  MACOSX_BUNDLE_INFO_PLIST ${CMAKE_CURRENT_SOURCE_DIR}/Info.plist.in)

# Windows: build as a GUI app (no console window) while keeping standard main().
if(MSVC)
  set_target_properties(keyforge PROPERTIES
    WIN32_EXECUTABLE TRUE
    LINK_FLAGS "/ENTRY:mainCRTStartup")
endif()
