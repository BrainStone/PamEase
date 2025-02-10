cmake_minimum_required(VERSION 3.16)
project(PamEase CXX)

option(ENABLE_PEDANTIC_WARNINGS "Enable strict warnings" ON)
option(TREAT_WARNINGS_AS_ERRORS "Treat all warnings as errors" ON)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_INTERPROCEDURAL_OPTIMIZATION TRUE)
set(CMAKE_VERBOSE_MAKEFILE ON CACHE BOOL "ON" FORCE)

set(SRC_DIR "${CMAKE_SOURCE_DIR}/src")
set(MODULES_DIR "${SRC_DIR}/modules")

file(GLOB UTILITY_SOURCES "${SRC_DIR}/*.cpp")
file(GLOB MODULE_SOURCES "${MODULES_DIR}/*.cpp")

# Allow setting installation prefix
if (NOT DEFINED CMAKE_INSTALL_PREFIX)
    set(CMAKE_INSTALL_PREFIX "/usr")
endif ()
# And the arch dir
if (NOT DEFINED CMAKE_LIBRARY_ARCHITECTURE)
    set(CMAKE_LIBRARY_ARCHITECTURE "x86_64-linux-gnu")
endif ()
set(PAM_MODULE_DIR "${CMAKE_INSTALL_PREFIX}/lib/${CMAKE_LIBRARY_ARCHITECTURE}/security")

# Ensure src directory is included for module compilation
include_directories(${SRC_DIR})

if (ENABLE_PEDANTIC_WARNINGS)
    if (CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang|AppleClang")
        add_compile_options(-Wall -Wextra -Wpedantic)
    elseif (CMAKE_CXX_COMPILER_ID MATCHES "MSVC")
        add_compile_options(/W4)
    endif ()
endif ()

if (TREAT_WARNINGS_AS_ERRORS)
    if (CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang|AppleClang")
        add_compile_options(-Werror)
    elseif (CMAKE_CXX_COMPILER_ID MATCHES "MSVC")
        add_compile_options(/WX)
    endif ()
endif ()

# Remove unused objects
if (CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang|AppleClang")
    add_compile_options(-ffunction-sections -fdata-sections)
    add_link_options(-Wl,--gc-sections)
elseif (CMAKE_CXX_COMPILER_ID MATCHES "MSVC")
    add_compile_options(/Gy)
    add_link_options(/OPT:REF /OPT:ICF)
endif ()

# Create a shared library for each module
foreach (SOURCE_FILE ${MODULE_SOURCES})
    get_filename_component(MODULE_NAME ${SOURCE_FILE} NAME_WE)
    add_library(${MODULE_NAME}_objs OBJECT ${UTILITY_SOURCES})
    add_library(${MODULE_NAME} SHARED ${SOURCE_FILE} $<TARGET_OBJECTS:${MODULE_NAME}_objs>)

    set_target_properties(${MODULE_NAME} PROPERTIES
            PREFIX "pam_" # No "lib" prefix, and ensure pam_ prefix
            SUFFIX ".so"  # Ensure .so suffix
    )

    target_link_libraries(${MODULE_NAME} PRIVATE pam)

    # Install directive
    install(TARGETS ${MODULE_NAME} DESTINATION "${PAM_MODULE_DIR}" COMPONENT Runtime)
endforeach ()
