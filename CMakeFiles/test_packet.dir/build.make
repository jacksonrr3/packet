# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.12

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/local/cmake-3.12.4/bin/cmake

# The command to remove a file.
RM = /usr/local/cmake-3.12.4/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/travis/build/jacksonrr3/packet

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/travis/build/jacksonrr3/packet

# Include any dependencies generated for this target.
include CMakeFiles/test_packet.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/test_packet.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/test_packet.dir/flags.make

CMakeFiles/test_packet.dir/src/test_packet.cpp.o: CMakeFiles/test_packet.dir/flags.make
CMakeFiles/test_packet.dir/src/test_packet.cpp.o: src/test_packet.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/travis/build/jacksonrr3/packet/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/test_packet.dir/src/test_packet.cpp.o"
	/usr/local/clang-7.0.0/bin/clang++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/test_packet.dir/src/test_packet.cpp.o -c /home/travis/build/jacksonrr3/packet/src/test_packet.cpp

CMakeFiles/test_packet.dir/src/test_packet.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/test_packet.dir/src/test_packet.cpp.i"
	/usr/local/clang-7.0.0/bin/clang++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/travis/build/jacksonrr3/packet/src/test_packet.cpp > CMakeFiles/test_packet.dir/src/test_packet.cpp.i

CMakeFiles/test_packet.dir/src/test_packet.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/test_packet.dir/src/test_packet.cpp.s"
	/usr/local/clang-7.0.0/bin/clang++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/travis/build/jacksonrr3/packet/src/test_packet.cpp -o CMakeFiles/test_packet.dir/src/test_packet.cpp.s

# Object files for target test_packet
test_packet_OBJECTS = \
"CMakeFiles/test_packet.dir/src/test_packet.cpp.o"

# External object files for target test_packet
test_packet_EXTERNAL_OBJECTS =

test_packet: CMakeFiles/test_packet.dir/src/test_packet.cpp.o
test_packet: CMakeFiles/test_packet.dir/build.make
test_packet: /usr/lib/x86_64-linux-gnu/libboost_unit_test_framework.so
test_packet: libpacket_lib.so
test_packet: CMakeFiles/test_packet.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/travis/build/jacksonrr3/packet/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable test_packet"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/test_packet.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/test_packet.dir/build: test_packet

.PHONY : CMakeFiles/test_packet.dir/build

CMakeFiles/test_packet.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/test_packet.dir/cmake_clean.cmake
.PHONY : CMakeFiles/test_packet.dir/clean

CMakeFiles/test_packet.dir/depend:
	cd /home/travis/build/jacksonrr3/packet && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/travis/build/jacksonrr3/packet /home/travis/build/jacksonrr3/packet /home/travis/build/jacksonrr3/packet /home/travis/build/jacksonrr3/packet /home/travis/build/jacksonrr3/packet/CMakeFiles/test_packet.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/test_packet.dir/depend
