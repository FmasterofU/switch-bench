cmake_minimum_required(VERSION 3.12)

project(switch-bench)

add_executable("${PROJECT_NAME}" switch-bench.cpp)

find_package(PcapPlusPlus 23.09 REQUIRED)

# We want to have the binary compiled in the same folder as the code
set_target_properties("${PROJECT_NAME}" PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}")

target_link_libraries("${PROJECT_NAME}" PUBLIC PcapPlusPlus::Pcap++)