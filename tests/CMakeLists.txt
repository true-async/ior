# Test utilities
add_library(test_utils STATIC
    test_utils.c
)

# Fix include paths for tests
target_include_directories(test_utils 
    PUBLIC 
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_BINARY_DIR}
)
target_link_libraries(test_utils PUBLIC ior cmocka::cmocka)
# Windows: the loopback socketpair helper needs Winsock.
if(WIN32)
    target_link_libraries(test_utils PUBLIC ws2_32)
endif()
apply_sanitizers(test_utils)

# Test executables - common tests
set(TESTS
    test_basic
    test_read_write
    test_timeout
    test_edge
    test_socket
    test_poll
    test_concurrency
    test_link_timeout
    test_slow_op
    test_sq_reuse
    test_capacity
    test_work
    test_cancel
    test_notify
    test_accept_connect
    test_waitpid
    test_sigwait
    test_dir_changes
)

# Add test for splice only on Linux with splice support
if(IOR_HAVE_SPLICE)
    list(APPEND TESTS test_splice)
endif()

foreach(test ${TESTS})
    add_executable(${test} ${test}.c)
    target_include_directories(${test} PRIVATE 
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_BINARY_DIR}
    )
    target_link_libraries(${test} PRIVATE test_utils ior cmocka::cmocka)
    apply_sanitizers(${test})

    # Add to CTest
    add_test(NAME ${test} COMMAND ${test})

    # Set timeout for tests
    set_tests_properties(${test} PROPERTIES TIMEOUT 30)

    # With both backends in one library, run the same binary on the thread
    # backend too, selected through the environment.
    if(IOR_HAVE_URING AND IOR_HAVE_THREADS)
        add_test(NAME ${test}_threads COMMAND ${test})
        set_tests_properties(${test}_threads PROPERTIES
            TIMEOUT 30
            ENVIRONMENT "IOR_BACKEND=threads"
        )
    endif()
endforeach()

# POSIX only: signal delivery (every ior thread must block signals),
# descriptor blocking mode (the checks read O_NONBLOCK) and fork
if(NOT WIN32)
    foreach(test test_signals test_fd_mode test_fork)
        add_executable(${test} ${test}.c)
        target_include_directories(${test} PRIVATE
            ${CMAKE_SOURCE_DIR}/include
            ${CMAKE_BINARY_DIR}
        )
        target_link_libraries(${test} PRIVATE test_utils ior cmocka::cmocka)
        apply_sanitizers(${test})
        add_test(NAME ${test} COMMAND ${test})
        set_tests_properties(${test} PROPERTIES TIMEOUT 30)
        if(IOR_HAVE_URING AND IOR_HAVE_THREADS)
            add_test(NAME ${test}_threads COMMAND ${test})
            set_tests_properties(${test}_threads PROPERTIES
                TIMEOUT 30
                ENVIRONMENT "IOR_BACKEND=threads"
            )
        endif()
    endforeach()

    # Forking a multi-threaded process is slow under TSan: test_fork forks a
    # hundred times while ior's threads run, which takes about 30 s there.
    # Each child has an alarm of its own, so a hang still fails it.
    if(IOR_ENABLE_TSAN)
        set_tests_properties(test_fork PROPERTIES TIMEOUT 120)
        if(IOR_HAVE_URING AND IOR_HAVE_THREADS)
            set_tests_properties(test_fork_threads PROPERTIES TIMEOUT 120)
        endif()
    endif()
endif()

# Thread backend tests (only if thread backend is compiled)
if(IOR_HAVE_THREADS)
    # Thread-specific unit tests
    set(THREAD_TESTS
        test_threads_ring
        test_threads_event
    )

    foreach(test ${THREAD_TESTS})
        add_executable(${test} ${test}.c)
        target_include_directories(${test} PRIVATE 
            ${CMAKE_SOURCE_DIR}/include
            ${CMAKE_BINARY_DIR}
            ${CMAKE_SOURCE_DIR}/src
        )
        target_link_libraries(${test} PRIVATE test_utils ior cmocka::cmocka)
        apply_sanitizers(${test})
        add_test(NAME ${test} COMMAND ${test})
        set_tests_properties(${test} PROPERTIES TIMEOUT 30)
    endforeach()

    # Thread backend integration test
    add_executable(test_threads_backend test_threads_backend.c)
    target_include_directories(test_threads_backend PRIVATE 
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_BINARY_DIR}
    )
    target_link_libraries(test_threads_backend PRIVATE test_utils ior cmocka::cmocka)
    apply_sanitizers(test_threads_backend)
    add_test(NAME test_threads_backend COMMAND test_threads_backend)
    set_tests_properties(test_threads_backend PROPERTIES TIMEOUT 30)
endif()

# io_uring backend tests (only if available)
if(IOR_HAVE_URING)
    add_executable(test_uring_backend test_uring_backend.c)
    target_include_directories(test_uring_backend PRIVATE 
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_BINARY_DIR}
    )
    target_link_libraries(test_uring_backend PRIVATE test_utils ior cmocka::cmocka)
    apply_sanitizers(test_uring_backend)
    add_test(NAME test_uring_backend COMMAND test_uring_backend)
    set_tests_properties(test_uring_backend PROPERTIES TIMEOUT 30)
endif()

# AUTO falling back to the thread backend (both Linux backends built)
if(IOR_HAVE_URING AND IOR_HAVE_THREADS)
    add_executable(test_backend_fallback test_backend_fallback.c)
    target_include_directories(test_backend_fallback PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_BINARY_DIR}
    )
    target_link_libraries(test_backend_fallback PRIVATE test_utils ior cmocka::cmocka)
    apply_sanitizers(test_backend_fallback)
    add_test(NAME test_backend_fallback COMMAND test_backend_fallback)
    set_tests_properties(test_backend_fallback PROPERTIES TIMEOUT 30)
endif()

# IOCP backend tests (only if available, Windows)
if(IOR_HAVE_IOCP)
    add_executable(test_iocp_backend test_iocp_backend.c)
    target_include_directories(test_iocp_backend PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_BINARY_DIR}
    )
    target_link_libraries(test_iocp_backend PRIVATE test_utils ior cmocka::cmocka)
    apply_sanitizers(test_iocp_backend)
    add_test(NAME test_iocp_backend COMMAND test_iocp_backend)
    set_tests_properties(test_iocp_backend PROPERTIES TIMEOUT 30)

    # The same programs on a library whose port refuses completion packets
    # (see iocp_fault.c), so the path that keeps them is exercised. Each
    # links its own copy of test_utils.c: test_utils brings the real ior.
    add_library(ior_iocp_fault STATIC
        ${CMAKE_SOURCE_DIR}/src/ior.c
        ${CMAKE_SOURCE_DIR}/src/ior_log.c
        iocp_fault.c
    )
    target_include_directories(ior_iocp_fault PUBLIC
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_BINARY_DIR}
    )
    target_link_libraries(ior_iocp_fault PUBLIC ws2_32)
    apply_sanitizers(ior_iocp_fault)

    foreach(test test_basic test_timeout test_link_timeout test_work test_poll
            test_notify test_waitpid test_iocp_backend)
        add_executable(${test}_pqcs_fault ${test}.c test_utils.c)
        target_include_directories(${test}_pqcs_fault PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}
            ${CMAKE_SOURCE_DIR}/include
            ${CMAKE_BINARY_DIR}
        )
        target_link_libraries(${test}_pqcs_fault PRIVATE ior_iocp_fault cmocka::cmocka)
        apply_sanitizers(${test}_pqcs_fault)
        add_test(NAME ${test}_pqcs_fault COMMAND ${test}_pqcs_fault)
        set_tests_properties(${test}_pqcs_fault PROPERTIES
            TIMEOUT 30
            ENVIRONMENT "IOR_FAULT_PQCS_RATE=100"
        )
    endforeach()
endif()