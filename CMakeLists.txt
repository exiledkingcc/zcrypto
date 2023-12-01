cmake_minimum_required(VERSION 3.0.0)
project(zcrypto VERSION 0.1.0)

include(CTest)
enable_testing()

set(CMAKE_C_STANDARD 17)
set(CMAKE_CXX_STANDARD 17)

if (${CMAKE_CXX_COMPILER_ID} STREQUAL "MSVC")

    # add_compile_options(/Wall /WX)
    add_compile_options(/bigobj /utf-8)
    add_definitions(/D_WIN32_WINNT=0x0A00)  # Windows 10
    add_definitions(/D__ZCRYPO_BYTE_ORDER__=1)

else ()

    if (${CMAKE_CXX_COMPILER_ID} STREQUAL "GNU")
        add_compile_options (-fdiagnostics-color=always)
    elseif (${CMAKE_CXX_COMPILER_ID} STREQUAL "Clang")
        add_compile_options (-fcolor-diagnostics)
    endif ()

endif()

include_directories(include)
add_subdirectory(src)
add_subdirectory(tests)
