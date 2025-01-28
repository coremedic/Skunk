cmake_minimum_required(VERSION 3.30)
project(Skunk)

set(CMAKE_CXX_STANDARD 17)
#set(CMAKE_CXX_COMPILER x86_64-w64-mingw32-g++)

set(CMAKE_VERBOSE_MAKEFILE ON)

include_directories(include)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_definitions(-DDEBUG)
endif()

add_compile_options(
        -Os -fno-asynchronous-unwind-tables -nostdlib
        -fno-ident -fpack-struct=8 -falign-functions=1
        -s -ffunction-sections -falign-jumps=1 -w
        -falign-labels=1 -fPIC -Iinclude -masm=intel -fpermissive
)

add_link_options(
        -Wl,-T${CMAKE_SOURCE_DIR}/scripts/Linker.ld
        -Wl,-s,--no-seh,--enable-stdcall-fixup
        -Wl,--as-needed,--no-whole-archive
)

file(GLOB_RECURSE ALL_CXX_FILES "${PROJECT_SOURCE_DIR}/src/*.cpp")
file(GLOB_RECURSE ALL_C_FILES "${PROJECT_SOURCE_DIR}/src/*.c")
file(GLOB_RECURSE ALL_CXX_HEADER_FILES "${PROJECT_SOURCE_DIR}/include/*.hpp")
file(GLOB_RECURSE ALL_C_HEADER_FILES "${PROJECT_SOURCE_DIR}/include/*.h")

set_source_files_properties(${ALL_C_FILES} PROPERTIES LANGUAGE CXX)

add_executable(
        Skunk
        src/Skunk.c
        src/Ldr.c
        include/Ntdll.h
        include/Macros.h
        include/Ldr.h
        include/Constexpr.h
        include/Skunk.h
)

target_link_libraries(Skunk -nostdlib -nodefaultlibs)

set(ASM_SOURCE_FILES
        asm/x64/Loader.asm
        asm/x64/ProxyCaller.asm
)

foreach(ASM_SRC IN LISTS ASM_SOURCE_FILES)
    get_filename_component(ASM_OBJ ${ASM_SRC} NAME_WE)
    set(ASM_OBJ ${CMAKE_CURRENT_BINARY_DIR}/${ASM_OBJ}.obj)
    add_custom_command(OUTPUT ${ASM_OBJ}
            COMMAND jwasm -win64 -coff -Fo${ASM_OBJ} ${CMAKE_CURRENT_SOURCE_DIR}/${ASM_SRC}
            DEPENDS ${ASM_SRC}
            COMMENT "Assembling ${ASM_SRC}"
    )
    target_sources(Skunk PRIVATE ${ASM_OBJ})
endforeach()

add_custom_command(TARGET Skunk POST_BUILD
        COMMAND python3 scripts/extract.py -f $<TARGET_FILE:Skunk> -o ${CMAKE_CURRENT_SOURCE_DIR}/Skunk.bin
        COMMENT "Building UDRL: Skunk.bin"
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
)
