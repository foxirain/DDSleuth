cmake_minimum_required(VERSION 3.16)

project(ddsleuth_transport_fault LANGUAGES CXX)

add_library(ddsleuth_transport_fault SHARED transport_fault.cpp)
target_compile_features(ddsleuth_transport_fault PRIVATE cxx_std_17)
target_compile_options(ddsleuth_transport_fault PRIVATE
    $<$<CXX_COMPILER_ID:GNU,Clang>:-Wall;-Wextra;-Wpedantic>)
target_link_libraries(ddsleuth_transport_fault PRIVATE dl pthread)
set_target_properties(ddsleuth_transport_fault PROPERTIES
    OUTPUT_NAME ddsleuth_transport_fault)
