cmake_minimum_required(VERSION 3.28)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)
project(FlowTuner VERSION 1.0.0)

include(FetchContent)
FetchContent_Declare(
  ARGUMENT_PARSER
  GIT_REPOSITORY https://github.com/jarro2783/cxxopts.git
  GIT_TAG v3.2.0
)
FetchContent_Declare(
  CAPSTONE
  GIT_REPOSITORY https://github.com/capstone-engine/capstone.git
  GIT_TAG 5.0.3
)
FetchContent_MakeAvailable(ARGUMENT_PARSER CAPSTONE)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
SET(CMAKE_CXX_FLAGS "-Wall -Wextra -Wconversion -Werror -Wshadow -O3")
file(GLOB_RECURSE sources src/*.cpp)
add_executable(${PROJECT_NAME} ${sources})

set_property(TARGET ${PROJECT_NAME} PROPERTY INTERPROCEDURAL_OPTIMIZATION)

target_link_libraries(${PROJECT_NAME}
  PRIVATE cxxopts
  PRIVATE capstone
)

include_directories(include)
