link_directories(${PROJECT_BINARY_DIR}/common ${PROJECT_BINARY_DIR}/xpwn)

include_directories(.)

add_executable(fwstitcher fwstitcher.c base64.c)

target_link_libraries (fwstitcher curl xpwn common)

install(TARGETS fwstitcher DESTINATION .)

