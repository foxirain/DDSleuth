cmake_minimum_required(VERSION 3.16)

project(ddsleuth_fastdds_probe LANGUAGES CXX)

find_package(fastcdr 2 REQUIRED)
find_package(fastdds 3 REQUIRED)

add_executable(ddsleuth_fastdds_probe main.cpp)
target_compile_features(ddsleuth_fastdds_probe PRIVATE cxx_std_17)
target_compile_options(ddsleuth_fastdds_probe PRIVATE
    $<$<CXX_COMPILER_ID:GNU,Clang>:-Wall;-Wextra;-Wpedantic>)
target_include_directories(ddsleuth_fastdds_probe PRIVATE ../common)
target_link_libraries(ddsleuth_fastdds_probe PRIVATE fastdds fastcdr)
