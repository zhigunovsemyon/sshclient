# CMakeList.txt : Top-level CMake project file, do global configuration
# and include sub-projects here.
#
cmake_minimum_required (VERSION 3.10)

# Enable Hot Reload for MSVC compilers if supported.
if (POLICY CMP0141)
  cmake_policy(SET CMP0141 NEW)
  set(CMAKE_MSVC_DEBUG_INFORMATION_FORMAT "$<IF:$<AND:$<C_COMPILER_ID:MSVC>,$<CXX_COMPILER_ID:MSVC>>,$<$<CONFIG:Debug,RelWithDebInfo>:EditAndContinue>,$<$<CONFIG:Debug,RelWithDebInfo>:ProgramDatabase>>")
endif()

project ("myssh" LANGUAGES C)
set(CMAKE_C_STANDARD 23)
file(GLOB C_FILES "src/*.c")

if (WIN32)
	add_definitions("/W4 /WX") 
	add_compile_options(-D _CRT_SECURE_NO_WARNINGS) 
else()
	add_definitions("-Wall -Wextra -Werror -Wconversion -Wsign-conversion")
endif(WIN32)

add_executable (${PROJECT_NAME} ${C_FILES}) 

find_package(libssh2 REQUIRED CONFIG)
target_link_libraries(${PROJECT_NAME} libssh2::libssh2)
