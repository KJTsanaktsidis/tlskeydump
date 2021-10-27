cmake_minimum_required(VERSION 3.21)
project(tlskeydump VERSION 0.1)

set(CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake")
include(CheckSymbolExists)
include(CTest)
include(ExternalProject)

add_executable(tlskeydump)
set(TLSKEYDUMP_SOURCES
    "include/compat/sigabbrev_np.h"
    "include/debuginfo_search/debuginfo_search.h"
    "include/dwarf_util/dwarf_defs.h"
    "include/dwarf_util/dwarf_die_cache.h"
    "include/dwarf_util/dwarf_helpers.h"
    "include/dwarf_util/dwarf_iterators.h"
    "include/probes/openssl_probe.h"
    "include/ptrace/dwfl_handle.h"
    "include/ptrace/ptrace_arch.h"
    "include/ptrace/ptrace_breakpoint_handler.h"
    "include/ptrace/ptrace_exceptions.h"
    "include/ptrace/ptrace_mem.h"
    "include/ptrace/ptrace_process_monitor.h"
    "include/ptrace/ptrace_process.h"
    "include/cleanup_pointers.h"
    "include/cli_args.h"
    "include/comma_separated_opts.h"
    "include/log.h"
    "include/lru_set.h"
    "include/parse_util.h"
    "include/tls_key_collector.h"
    "src/compat/sigabbrev_np.c"
    "src/debuginfo_search/debuginfo_search.cxx"
    "src/dwarf_util/dwarf_die_cache.cxx"
    "src/dwarf_util/dwarf_helpers.cxx"
    "src/dwarf_util/dwarf_iterators.cxx"
    "src/probes/openssl_probe.cxx"
    "src/ptrace/dwfl_handle.cxx"
    "src/ptrace/ptrace_process_monitor.cxx"
    "src/ptrace/ptrace_process.cxx"
    "src/cli_args.cxx"
    "src/log.cxx"
    "src/main.cxx"
    "src/parse_util.cxx"
    "src/tls_key_collector.cxx"
)
target_sources(tlskeydump PRIVATE ${TLSKEYDUMP_SOURCES})
set_property(TARGET tlskeydump PROPERTY CXX_STANDARD 20)
set_property(TARGET tlskeydump PROPERTY CXX_EXTENSIONS ON)
target_compile_options(tlskeydump PRIVATE "-g")

set(Boost_USE_STATIC_LIBS OFF)
set(Boost_USE_MULTITHREADED ON)
set(Boost_USE_STATIC_RUNTIME OFF)
find_package(Boost REQUIRED COMPONENTS log thread iostreams program_options)
target_include_directories(tlskeydump PRIVATE ${Boost_INCLUDE_DIR})
target_link_libraries(tlskeydump PRIVATE ${Boost_LIBRARIES})
find_package(Libdw REQUIRED)
target_include_directories(tlskeydump PRIVATE ${Libdw_INCLUDE_DIR})
target_link_libraries(tlskeydump PRIVATE ${Libdw_LIBRARIES})
find_package(Libelf REQUIRED)
target_include_directories(tlskeydump PRIVATE ${Libelf_INCLUDE_DIR})
target_link_libraries(tlskeydump PRIVATE ${Libelf_LIBRARIES})
find_package(Libdebuginfod REQUIRED)
target_include_directories(tlskeydump PRIVATE ${Libdebuginfod_INCLUDE_DIR})
target_link_libraries(tlskeydump PRIVATE ${Libdebuginfod_LIBRARIES})
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)
target_link_libraries(tlskeydump PRIVATE Threads::Threads)
find_package(OpenSSL REQUIRED)
target_include_directories(tlskeydump PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(tlskeydump PRIVATE ${OPENSSL_LIBRARIES})

check_symbol_exists(SYS_pidfd_open "sys/syscall.h" HAVE_PIDFD_OPEN)
check_symbol_exists(SYS_pidfd_send_signal "sys/syscall.h" HAVE_PIDFD_SEND_SIGNAL)
check_symbol_exists(sigabbrev_np "string.h" HAVE_SIGABBREV_NP)
configure_file(include/config.h.in config.h)
target_include_directories(tlskeydump PRIVATE include/)
target_include_directories(tlskeydump PRIVATE "${PROJECT_BINARY_DIR}")

# This block is for the tests. The test build setup is pretty complicated because
# it builds OpenSSL several times in various different configurations.
if(CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME AND BUILD_TESTING)

    # Programs needed by the test suite
    find_program(RUBY ruby REQUIRED)
    find_program(BUNDLE bundle REQUIRED)
    find_program(STRIP strip REQUIRED)
    find_program(READELF readelf REQUIRED)
    find_program(ENVPROG env REQUIRED)

    # This sets up a target bundle_install that will run bundle install.
    # The gems are installed to tests/bundle_vendor, and we also touch a file
    # tests/bundle_vendor/bundled_at so that the target is not considered out-of-date
    # unless the Gemfile/Gemfile.lock changes.
    # This doesn't just stop pointless bundle install invocations, it also makes sure
    # that the OpenSSL targets (which depend on this) don't think they're out of date
    # either.
    set(BUNDLE_PATH "${PROJECT_BINARY_DIR}/tests/bundle_vendor")
    add_custom_command(
        OUTPUT "${BUNDLE_PATH}/bundled_at"
        COMMAND
            "sh" "-ec" "BUNDLE_PATH=${BUNDLE_PATH} ${BUNDLE} install && ${CMAKE_COMMAND} -E touch ${BUNDLE_PATH}/bundled_at"
        WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/test"
        DEPENDS "test/Gemfile" "test/Gemfile.lock"
        VERBATIM
    )
    add_custom_target(bundle_install DEPENDS "${BUNDLE_PATH}/bundled_at")

    # This function builds OpenSSL. It takes:
    #   -> A version, which needs to be a valid git tag in the OpenSSL repository
    #   -> A "sym_type", which is one of the values that openssl_build_command.rb
    #      understands (so "dbg", "strip", "buildid", "dir", or "dwz").
    #        - A "dbg" build has debug symbols in the .so/.a files themselves.
    #        - A "strip" build has no debug symbols at all
    #        - A "buildid" build has debug symbols at $PREFIX/debug/.build-id/xx/xxxxxx.debug
    #        - A "debuglink" build has debug symbols specified at a filename in the
    #          .gnu_debuglink ELF section
    #        - A "dwz" build has main and aux debug info separated with the dwz tool
    #      openssl_build_command.rb is responsible for setting up the debug syms as
    #      requested.
    # It returns the target name it created & the prefix it was installed to.
    function(Build_OpenSSL_For_Test OPENSSL_VERSION OPENSSL_SYM_TYPE OUT_TARGET OUT_PREFIX)
        set(OPENSSL_PREFIX "${PROJECT_BINARY_DIR}/tests/openssl_vendor/${OPENSSL_VERSION}_${OPENSSL_SYM_TYPE}")
        set(OPENSSL_TARGET "${OPENSSL_VERSION}_${OPENSSL_SYM_TYPE}")
        set(OPENSSL_SRCDIR "${PROJECT_BINARY_DIR}/tests/openssl_vendor_src/${OPENSSL_VERSION}_${OPENSSL_SYM_TYPE}")

        ExternalProject_Add(
            ${OPENSSL_TARGET}
            URL "https://github.com/openssl/openssl/archive/refs/tags/${OPENSSL_VERSION}.tar.gz"
            UPDATE_DISCONNECTED ON
            SOURCE_DIR ${OPENSSL_SRCDIR}
            # Set CONFIGURE and INSTALL commands to "" since we just drive the whole thing
            # with a Ruby script.
            CONFIGURE_COMMAND ""
            BUILD_COMMAND
                ${ENVPROG} "BUNDLE_PATH=${BUNDLE_PATH}" ${RUBY}
                "${PROJECT_SOURCE_DIR}/test/openssl_build_command.rb"
                "--prefix" ${OPENSSL_PREFIX}
                "--srcdir" ${OPENSSL_SRCDIR}
                "--symtype" ${OPENSSL_SYM_TYPE}
            INSTALL_COMMAND ""
        )
        # The OpenSSL target needs to depend on the bundle_install target because the
        # openssl_build_command.rb script needs gems.
        add_dependencies(${OPENSSL_TARGET} bundle_install)

        set(${OUT_TARGET} ${OPENSSL_TARGET} PARENT_SCOPE)
        set(${OUT_PREFIX} ${OPENSSL_PREFIX} PARENT_SCOPE)
    endfunction()

    Build_OpenSSL_For_Test("OpenSSL_1_1_1l" "dbg" OPENSSL_1_1_1_DBG_TARGET OPENSSL_1_1_1_DBG_PREFIX)
    Build_OpenSSL_For_Test("OpenSSL_1_1_1l" "buildid" OPENSSL_1_1_1_BUILDID_TARGET OPENSSL_1_1_1_BUILDID_PREFIX)
    Build_OpenSSL_For_Test("OpenSSL_1_1_1l" "debuglink" OPENSSL_1_1_1_DEBUGLINK_TARGET OPENSSL_1_1_1_DEBUGLINK_PREFIX)

    # Each individual testprog actually specifies its own sources, but this array is so
    # that we have a list of all of them for use in the format target.
    set(
        TESTPROG_SOURCES
        "test/testprogs/openssl_111_client_testprog.cxx"
        "test/testprogs/test_shared/openssl_111.cxx"
        "test/testprogs/test_shared/openssl_111.h"
    )

    # This function will build the testprogs/openssl_111_client_testprog.cxx test
    # program, linked againsg the OpenSSL specified by OPENSSL_TARGET/OPENSSL_PREFIX
    function(Build_Dyn_Client_Testprog OPENSSL_TARGET OPENSSL_PREFIX OUT_TARGET)
        set(TESTPROG_TARGET "${OPENSSL_TARGET}_testprog_dyn")
        add_executable(${TESTPROG_TARGET})
        target_sources(
            ${TESTPROG_TARGET}
            PRIVATE test/testprogs/openssl_111_client_testprog.cxx
            PRIVATE test/testprogs/test_shared/openssl_111.cxx
            PRIVATE test/testprogs/test_shared/openssl_111.h
        )
        target_include_directories(${TESTPROG_TARGET} PRIVATE test/testprogs)
        # Testprogs depend on boost
        target_include_directories(${TESTPROG_TARGET} PRIVATE ${Boost_INCLUDE_DIR})
        target_link_libraries(${TESTPROG_TARGET} PRIVATE ${Boost_LIBRARIES})

        # Link against the specified OpenSSL we compiled
        add_dependencies(${TESTPROG_TARGET} ${OPENSSL_TARGET})
        target_include_directories(${TESTPROG_TARGET} PRIVATE "${OPENSSL_PREFIX}/include")
        target_link_libraries(${TESTPROG_TARGET} PRIVATE "${OPENSSL_PREFIX}/lib/libssl.so")
        target_link_libraries(${TESTPROG_TARGET} PRIVATE "${OPENSSL_PREFIX}/lib/libcrypto.so")

        set(${OUT_TARGET} ${TESTPROG_TARGET} PARENT_SCOPE)
    endfunction()

    Build_Dyn_Client_Testprog(${OPENSSL_1_1_1_DBG_TARGET} ${OPENSSL_1_1_1_DBG_PREFIX} openssl_1_1_1_dyn_dbg_client_exe)
    Build_Dyn_Client_Testprog(${OPENSSL_1_1_1_BUILDID_TARGET} ${OPENSSL_1_1_1_BUILDID_PREFIX} openssl_1_1_1_dyn_buildid_client_exe)
    Build_Dyn_Client_Testprog(${OPENSSL_1_1_1_DEBUGLINK_TARGET} ${OPENSSL_1_1_1_DEBUGLINK_PREFIX} openssl_1_1_1_dyn_debuglink_client_exe)

    # This huge set of environment variables gets passed as /usr/bin/env ${TEST_PROGRAMS} ruby test.rb
    # so that the tests can find out how to execute the test programs.
    # Since they use $<TARGET_FILE:>, it also has the effect of making the tests depend on the
    # test programs.
    set(TEST_PROGRAMS
        "TLSKEYDUMP_TESTS__TLSKEYDUMP_EXE=$<TARGET_FILE:tlskeydump>"
        "TLSKEYDUMP_TESTS__OPENSSL_1_1_1_DBG_PREFIX=${OPENSSL_1_1_1_DBG_PREFIX}"
        "TLSKEYDUMP_TESTS__OPENSSL_1_1_1_BUILDID_PREFIX=${OPENSSL_1_1_1_BUILDID_PREFIX}"
        "TLSKEYDUMP_TESTS__OPENSSL_1_1_1_DEBUGLINK_PREFIX=${OPENSSL_1_1_1_DEBUGLINK_PREFIX}"
        "TLSKEYDUMP_TESTS__OPENSSL_1_1_1_TESTPROG_DYN_DBG_CLIENT_EXE=$<TARGET_FILE:${openssl_1_1_1_dyn_dbg_client_exe}>"
        "TLSKEYDUMP_TESTS__OPENSSL_1_1_1_TESTPROG_DYN_BUILDID_CLIENT_EXE=$<TARGET_FILE:${openssl_1_1_1_dyn_buildid_client_exe}>"
        "TLSKEYDUMP_TESTS__OPENSSL_1_1_1_TESTPROG_DYN_DEBUGLINK_CLIENT_EXE=$<TARGET_FILE:${openssl_1_1_1_dyn_debuglink_client_exe}>"
    )

    add_test(
        NAME find_debuginfo_test
        COMMAND
            "${ENVPROG}"
            "BUNDLE_PATH=${BUNDLE_PATH}"
            ${TEST_PROGRAMS}
            "${RUBY}" "${PROJECT_SOURCE_DIR}/test/find_debuginfo_test.rb"
        WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/test"
    )

    # Ripped off how to make a clang-format target from here: http://mariobadr.com/using-clang-format-to-enforce-style.html
    function(prepend var prefix)
        set(listVar "")
        foreach(f ${ARGN})
            list(APPEND listVar "${prefix}/${f}")
        endforeach()
        set(${var} "${listVar}" PARENT_SCOPE)
    endfunction()
    find_program(CLANG_FORMAT_EXE NAMES "clang-format" DOC "Path to clang-format executable")
    if(NOT CLANG_FORMAT_EXE)
        message(STATUS "clang-format not found.")
    else()
        message(STATUS "clang-format found: ${CLANG_FORMAT_EXE}")
        set(DO_CLANG_FORMAT "${CLANG_FORMAT_EXE}" "-i -style=file")
        set(SOURCES_TO_FORMAT ${TLSKEYDUMP_SOURCES} ${TESTPROG_SOURCES})
        prepend(FILES_TO_FORMAT ${CMAKE_CURRENT_SOURCE_DIR} ${TLSKEYDUMP_SOURCES})
        add_custom_target(format COMMAND ${CLANG_FORMAT_EXE} -i -style=file ${FILES_TO_FORMAT} )
    endif()
endif()
