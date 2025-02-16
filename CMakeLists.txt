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
set(RESOURCES_DIR "${CMAKE_SOURCE_DIR}/resources")
# PAU = pam-auth-update
set(PAU_PROFILES_DIR "${RESOURCES_DIR}/pam-auth-update")

file(GLOB UTILITY_SOURCES "${SRC_DIR}/*.cpp" "${SRC_DIR}/*.hpp" "${SRC_DIR}/*.inc")
file(GLOB MODULE_SOURCES "${MODULES_DIR}/*.cpp" "${MODULES_DIR}/*.hpp" "${MODULES_DIR}/*.inc")
file(GLOB PAU_PROFILE_SOURCES "${PAU_PROFILES_DIR}/*.conf")

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
    add_compile_options(-Wall -Wextra -Wpedantic)
endif ()

if (TREAT_WARNINGS_AS_ERRORS)
    add_compile_options(-Werror)
endif ()

# Remove unused objects
add_compile_options(-ffunction-sections -fdata-sections -fvisibility=hidden)
add_link_options(-Wl,--gc-sections)

add_library(utility_objs OBJECT ${UTILITY_SOURCES})
target_link_libraries(utility_objs PRIVATE pam dl)

# Create a shared library for each module
foreach (SOURCE_FILE ${MODULE_SOURCES})
    get_filename_component(MODULE_NAME ${SOURCE_FILE} NAME_WE)
    add_library(${MODULE_NAME} SHARED ${SOURCE_FILE} $<TARGET_OBJECTS:utility_objs>)

    set_target_properties(${MODULE_NAME} PROPERTIES
            PREFIX "pam_" # No "lib" prefix, and ensure pam_ prefix
            SUFFIX ".so"  # Ensure .so suffix
    )

    target_link_libraries(${MODULE_NAME} PRIVATE pam)

    # Install directive
    install(TARGETS ${MODULE_NAME} DESTINATION "${PAM_MODULE_DIR}" COMPONENT pam_fuzzy)
endforeach ()

# Create pam-auth-update profile file for each PAM module
foreach (PAU_PROFILE ${PAU_PROFILE_SOURCES})
    get_filename_component(PROFILE_NAME "${PAU_PROFILE}" NAME_WE)

    install(FILES "${PAU_PROFILE}" DESTINATION /usr/share/pam-configs RENAME "${PROFILE_NAME}" COMPONENT "pam_${PROFILE_NAME}")
endforeach ()

# Extra dependencies
target_link_libraries(fuzzy PRIVATE crypt)
