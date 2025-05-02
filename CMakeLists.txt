cmake_minimum_required(VERSION 3.16)
project(PlanetLLM)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Add include directories
include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/deps/llama.cpp/include)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/deps/llama.cpp/ggml/include)

# Find packages
find_package(OpenMP REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(ZMQ REQUIRED libzmq)
find_package(OpenSSL REQUIRED)
find_package(CURL REQUIRED)
find_package(Boost REQUIRED COMPONENTS system filesystem)

find_package(nlohmann_json QUIET)
if(NOT nlohmann_json_FOUND)
    include(FetchContent)
    FetchContent_Declare(
        nlohmann_json
        URL https://github.com/nlohmann/json/releases/download/v3.11.2/json.tar.xz
    )
    FetchContent_MakeAvailable(nlohmann_json)
endif()

# Find Catch2 for testing
find_package(Catch2 QUIET)
if(NOT Catch2_FOUND)
    # Download and configure Catch2
    include(FetchContent)
    FetchContent_Declare(
        Catch2
        GIT_REPOSITORY https://github.com/catchorg/Catch2.git
        GIT_TAG v2.13.9
    )
    FetchContent_MakeAvailable(Catch2)
endif()

# Find llama.cpp library
set(LLAMA_LIBRARY "")
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/deps/llama.cpp/build/bin/libllama.so")
    set(LLAMA_LIBRARY "${CMAKE_CURRENT_SOURCE_DIR}/deps/llama.cpp/build/bin/libllama.so")
elseif(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/deps/llama.cpp/build/lib/libllama.so")
    set(LLAMA_LIBRARY "${CMAKE_CURRENT_SOURCE_DIR}/deps/llama.cpp/build/lib/libllama.so")
elseif(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/deps/llama.cpp/build/libllama.so")
    set(LLAMA_LIBRARY "${CMAKE_CURRENT_SOURCE_DIR}/deps/llama.cpp/build/libllama.so")
else()
    message(WARNING "Could not find pre-compiled libllama.so. Make sure to build llama.cpp first.")
endif()

# Library sources
set(LIBRARY_SOURCES
    src/llm/llama_wrapper.cpp
    src/node/model_node.cpp
    src/node/user_node.cpp
    src/node/verification_node.cpp
)

# Create library
add_library(planet_llm_library ${LIBRARY_SOURCES})
target_include_directories(planet_llm_library PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_include_directories(planet_llm_library PUBLIC ${Boost_INCLUDE_DIRS})
target_include_directories(planet_llm_library PUBLIC ${CURL_INCLUDE_DIRS})
target_include_directories(planet_llm_library PUBLIC ${OPENSSL_INCLUDE_DIR})

target_link_libraries(planet_llm_library PUBLIC 
    OpenMP::OpenMP_CXX 
    ${ZMQ_LIBRARIES} 
    ${LLAMA_LIBRARY}
    ${OPENSSL_SSL_LIBRARY}
    ${OPENSSL_CRYPTO_LIBRARY}
    ${CURL_LIBRARIES}
    ${Boost_LIBRARIES}
    pthread
)

# Add nlohmann_json dependency
if(TARGET nlohmann_json::nlohmann_json)
    target_link_libraries(planet_llm_library PUBLIC nlohmann_json::nlohmann_json)
endif()

# Create a specific library for verification node
add_library(verification_node_lib STATIC
    src/node/verification_node.cpp
)
target_link_libraries(verification_node_lib PUBLIC planet_llm_library)

# Update the verification_node executable to use the library
add_executable(verification_node src/node/main_verification_node.cpp)
target_link_libraries(verification_node verification_node_lib)

# Test executables
add_executable(test_node_local 
    tests/test_node_local.cpp 
    src/llm/llama_wrapper.cpp
    src/node/model_node.cpp
    src/node/user_node.cpp
)
target_link_libraries(test_node_local planet_llm_library)

add_executable(test_direct_comm tests/test_direct_node_communication.cpp)
target_link_libraries(test_direct_comm planet_llm_library)

add_executable(test_sida tests/test_sida.cpp)
target_link_libraries(test_sida planet_llm_library)

# Add new test for verification node
add_executable(test_verification tests/test_verification_node.cpp)
target_link_libraries(test_verification PRIVATE
  verification_node_lib
  planet_llm_library
  Catch2::Catch2
)

# Make sure the test has the right includes
target_include_directories(test_verification PRIVATE
  ${CMAKE_SOURCE_DIR}/src
  ${CMAKE_SOURCE_DIR}/tests
  ${Catch2_INCLUDE_DIRS}
)

# Find the necessary CMakeLists.txt file and add the TESTING flag for test builds
# Search for test-related targets and add the definition

# Add this line near the beginning, after the project declaration
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_compile_definitions(TESTING)
endif()

# Find the test_verification target and add the TESTING definition specifically for it
target_compile_definitions(test_verification PRIVATE TESTING)

