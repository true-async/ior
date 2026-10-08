/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * test_iocp_backend.c - IOCP-specific edge cases (Windows only, no sockets).
 *
 * These exercise behaviour that is specific to the IOCP backend's emulation
 * of io_uring semantics on Windows:
 *   - the synthetic-completion path (immediate ReadFile/WriteFile failure)
 *   - LINK cancellation when the head op fails
 *   - DRAIN ordering against real file I/O
 *   - timer completion via the dedicated timer thread
 *   - synchronous-completion accounting (cached reads)
 *   - teardown while operations are still in flight
 *   - a handle moving between rings (one completion port per handle), with
 *     recycled handle values, requests pending elsewhere and racing rings
 *   - the errno of a closed or empty pipe
 *
 * The whole file compiles to an empty (passing) cmocka group on non-IOCP
 * builds, so it is harmless to register unconditionally in CMake - but the
 * CMakeLists gates it on IOR_HAVE_IOCP anyway.
 */
#include "test_utils.h"

#ifdef IOR_HAVE_IOCP

/* A small temp-file fixture independent of the read/write fixture so we can
 * open handles with custom access modes. Stores the ctx + a temp path. */
typedef struct iocp_state {
	ior_ctx *ctx;
	char *path;
} iocp_state;

static int iocp_setup(void **state)
{
	iocp_state *s = calloc(1, sizeof(*s));
	assert_non_null(s);

	int ret = ior_queue_init(32, &s->ctx);
	assert_return_code(ret, 0);
	assert_non_null(s->ctx);

	const char *content = "IOCP edge-case fixture payload.\n";
	s->path = create_temp_file(content, strlen(content));
	assert_non_null(s->path);

	*state = s;
	return 0;
}

static int iocp_teardown(void **state)
{
	iocp_state *s = (iocp_state *) *state;
	if (s) {
		if (s->ctx) {
			ior_queue_exit(s->ctx);
		}
		if (s->path) {
			remove_temp_file(s->path);
			free(s->path);
		}
		free(s);
	}
	return 0;
}

/* ===================================================================== */
/* Synthetic completion: immediate I/O failure                           */
/* ===================================================================== */

/*
 * Writing to a GENERIC_READ-only overlapped handle fails immediately with
 * ERROR_ACCESS_DENIED (not ERROR_IO_PENDING). The backend must detect this
 * and post a SYNTHETIC completion so the op still surfaces as a CQE with a
 * negative res, rather than hanging waiting for a packet that never comes.
 */
static void test_synthetic_write_eacces(void **state)
{
	iocp_state *s = (iocp_state *) *state;

	ior_fd_t ro = test_open_fd_readonly(s->path);
	assert_true(test_fd_is_valid(ro));

	const char *data = "should fail";
	ior_sqe *sqe = ior_get_sqe(s->ctx);
	assert_non_null(sqe);
	ior_prep_write(s->ctx, sqe, ro, data, (unsigned) strlen(data), 0);
	ior_sqe_set_data(s->ctx, sqe, (void *) 0xE1);

	int ret = ior_submit_and_wait(s->ctx, 1);
	assert_true(ret >= 0);

	ior_cqe *cqe = NULL;
	ret = ior_wait_cqe(s->ctx, &cqe);
	assert_return_code(ret, 0);
	assert_int_equal((uintptr_t) ior_cqe_get_data(s->ctx, cqe), 0xE1);

	/* Must be a negative errno; ACCESS_DENIED maps to -EACCES. */
	int32_t res = ior_cqe_get_res(s->ctx, cqe);
	assert_true(res < 0);
	assert_int_equal(res, -EACCES);

	ior_cqe_seen(s->ctx, cqe);
	test_close_fd(ro);
}

/* Symmetric: reading from a write-only handle fails immediately. */
static void test_synthetic_read_eacces(void **state)
{
	iocp_state *s = (iocp_state *) *state;

	ior_fd_t wo = test_open_fd_writeonly(s->path);
	assert_true(test_fd_is_valid(wo));

	char buf[16];
	ior_sqe *sqe = ior_get_sqe(s->ctx);
	assert_non_null(sqe);
	ior_prep_read(s->ctx, sqe, wo, buf, sizeof(buf), 0);
	ior_sqe_set_data(s->ctx, sqe, (void *) 0xE2);

	int ret = ior_submit_and_wait(s->ctx, 1);
	assert_true(ret >= 0);

	ior_cqe *cqe = NULL;
	ret = ior_wait_cqe(s->ctx, &cqe);
	assert_return_code(ret, 0);
	assert_int_equal(ior_cqe_get_res(s->ctx, cqe), -EACCES);

	ior_cqe_seen(s->ctx, cqe);
	test_close_fd(wo);
}

/* ===================================================================== */
/* LINK cancellation when the head fails                                 */
/* ===================================================================== */

/*
 * Head op fails immediately (write to read-only handle, -EACCES). The
 * linked successor must be cancelled with -ECANCELED and must NOT execute.
 * This deterministically exercises cancel_link_chain() via the failure
 * branch in dequeue_one_completion().
 */
static void test_link_head_failure_cancels(void **state)
{
	iocp_state *s = (iocp_state *) *state;

	ior_fd_t ro = test_open_fd_readonly(s->path);
	assert_true(test_fd_is_valid(ro));

	/* Head: failing write, with LINK set. */
	ior_sqe *head = ior_get_sqe(s->ctx);
	assert_non_null(head);
	ior_prep_write(s->ctx, head, ro, "x", 1, 0);
	ior_sqe_set_data(s->ctx, head, (void *) 0x1);
	ior_sqe_set_flags(s->ctx, head, IOR_SQE_IO_LINK);

	/* Successor: a NOP that should be cancelled, never run. */
	ior_sqe *next = ior_get_sqe(s->ctx);
	assert_non_null(next);
	ior_prep_nop(s->ctx, next);
	ior_sqe_set_data(s->ctx, next, (void *) 0x2);

	int ret = ior_submit_and_wait(s->ctx, 2);
	assert_true(ret >= 0);

	int head_res = 0xDEAD, next_res = 0xDEAD;
	for (int i = 0; i < 2; i++) {
		ior_cqe *cqe = NULL;
		ret = ior_wait_cqe(s->ctx, &cqe);
		assert_return_code(ret, 0);
		uintptr_t d = (uintptr_t) ior_cqe_get_data(s->ctx, cqe);
		if (d == 0x1) {
			head_res = ior_cqe_get_res(s->ctx, cqe);
		} else if (d == 0x2) {
			next_res = ior_cqe_get_res(s->ctx, cqe);
		}
		ior_cqe_seen(s->ctx, cqe);
	}

	assert_int_equal(head_res, -EACCES);
	assert_int_equal(next_res, -ECANCELED);

	test_close_fd(ro);
}

/* ===================================================================== */
/* DRAIN ordering against real file I/O                                  */
/* ===================================================================== */

/*
 * Two writes followed by a DRAIN-flagged NOP. The drained op must not
 * complete until both writes have been dequeued (completed_cnt caught up).
 * We can't observe internal counters, but we CAN assert the drained op is
 * the last completion reaped, which is the externally visible contract.
 */
static void test_drain_is_last(void **state)
{
	iocp_state *s = (iocp_state *) *state;

	ior_fd_t fd = test_open_fd(s->path); /* RW overlapped handle */
	assert_true(test_fd_is_valid(fd));

	ior_sqe *w1 = ior_get_sqe(s->ctx);
	assert_non_null(w1);
	ior_prep_write(s->ctx, w1, fd, "AAAA", 4, 0);
	ior_sqe_set_data(s->ctx, w1, (void *) 0x1);

	ior_sqe *w2 = ior_get_sqe(s->ctx);
	assert_non_null(w2);
	ior_prep_write(s->ctx, w2, fd, "BBBB", 4, 64);
	ior_sqe_set_data(s->ctx, w2, (void *) 0x2);

	ior_sqe *d = ior_get_sqe(s->ctx);
	assert_non_null(d);
	ior_prep_nop(s->ctx, d);
	ior_sqe_set_data(s->ctx, d, (void *) 0x3);
	ior_sqe_set_flags(s->ctx, d, IOR_SQE_IO_DRAIN);

	int ret = ior_submit_and_wait(s->ctx, 3);
	assert_true(ret >= 0);

	int reaped = 0;
	int drain_position = -1;
	for (int i = 0; i < 3; i++) {
		ior_cqe *cqe = NULL;
		ret = ior_wait_cqe(s->ctx, &cqe);
		assert_return_code(ret, 0);
		uintptr_t tag = (uintptr_t) ior_cqe_get_data(s->ctx, cqe);
		if (tag == 0x3) {
			drain_position = reaped;
		}
		reaped++;
		ior_cqe_seen(s->ctx, cqe);
	}

	/* The DRAIN op must be the final completion. */
	assert_int_equal(drain_position, 2);

	test_close_fd(fd);
}

/* ===================================================================== */
/* Timer via the timer thread                                            */
/* ===================================================================== */

/* A short relative timer must fire and surface as -ETIME (mapped from
 * ERROR_TIMEOUT). Confirms the timer thread + heap + PQCS path. */
static void test_timer_fires(void **state)
{
	iocp_state *s = (iocp_state *) *state;

	ior_timespec ts = { .tv_sec = 0, .tv_nsec = 50 * 1000 * 1000 }; /* 50ms */

	ior_sqe *sqe = ior_get_sqe(s->ctx);
	assert_non_null(sqe);
	ior_prep_timeout(s->ctx, sqe, &ts, 0, 0);
	ior_sqe_set_data(s->ctx, sqe, (void *) 0x7);

	int ret = ior_submit_and_wait(s->ctx, 1);
	assert_true(ret >= 0);

	ior_cqe *cqe = NULL;
	ret = ior_wait_cqe(s->ctx, &cqe);
	assert_return_code(ret, 0);

	int32_t res = ior_cqe_get_res(s->ctx, cqe);
	assert_true(res == -ETIME || res == -ETIMEDOUT);

	ior_cqe_seen(s->ctx, cqe);
}

/*
 * Two timers armed out of deadline order must fire in DEADLINE order
 * (min-heap correctness): arm a 150ms timer, then a 30ms timer; the 30ms
 * one must complete first.
 */
static void test_timer_heap_order(void **state)
{
	iocp_state *s = (iocp_state *) *state;

	ior_timespec slow = { .tv_sec = 0, .tv_nsec = 150 * 1000 * 1000 };
	ior_timespec fast = { .tv_sec = 0, .tv_nsec = 30 * 1000 * 1000 };

	ior_sqe *a = ior_get_sqe(s->ctx);
	assert_non_null(a);
	ior_prep_timeout(s->ctx, a, &slow, 0, 0);
	ior_sqe_set_data(s->ctx, a, (void *) 0x5107); /* "slow" */

	ior_sqe *b = ior_get_sqe(s->ctx);
	assert_non_null(b);
	ior_prep_timeout(s->ctx, b, &fast, 0, 0);
	ior_sqe_set_data(s->ctx, b, (void *) 0xFA57); /* "fast" */

	int ret = ior_submit(s->ctx);
	assert_true(ret >= 0);

	ior_cqe *cqe = NULL;
	ret = ior_wait_cqe(s->ctx, &cqe);
	assert_return_code(ret, 0);
	/* First to fire must be the 30ms timer. */
	assert_int_equal((uintptr_t) ior_cqe_get_data(s->ctx, cqe), 0xFA57);
	ior_cqe_seen(s->ctx, cqe);

	ret = ior_wait_cqe(s->ctx, &cqe);
	assert_return_code(ret, 0);
	assert_int_equal((uintptr_t) ior_cqe_get_data(s->ctx, cqe), 0x5107);
	ior_cqe_seen(s->ctx, cqe);
}

/* ===================================================================== */
/* Synchronous completion accounting (cached read)                       */
/* ===================================================================== */

/*
 * A small read from a freshly written file usually completes synchronously
 * (ReadFile returns TRUE) because the data is in cache. The backend must
 * STILL deliver exactly one completion (default IOCP behaviour posts a
 * packet even on synchronous success). Issue several such reads and verify
 * the completion count matches the submission count exactly - i.e. no
 * double-delivery and no lost completion.
 */
static void test_sync_completion_accounting(void **state)
{
	iocp_state *s = (iocp_state *) *state;

	ior_fd_t fd = test_open_fd(s->path);
	assert_true(test_fd_is_valid(fd));

	const unsigned N = 8;
	char bufs[8][32];

	for (unsigned i = 0; i < N; i++) {
		ior_sqe *sqe = ior_get_sqe(s->ctx);
		assert_non_null(sqe);
		ior_prep_read(s->ctx, sqe, fd, bufs[i], 8, 0);
		ior_sqe_set_data(s->ctx, sqe, (void *) (uintptr_t) (0x200u + i));
	}

	int ret = ior_submit_and_wait(s->ctx, N);
	assert_true(ret >= 0);

	unsigned seen = 0;
	unsigned mask = 0;
	for (unsigned i = 0; i < N; i++) {
		ior_cqe *cqe = NULL;
		ret = ior_wait_cqe(s->ctx, &cqe);
		assert_return_code(ret, 0);
		uintptr_t d = (uintptr_t) ior_cqe_get_data(s->ctx, cqe);
		assert_true(d >= 0x200u && d < 0x200u + N);
		mask |= (1u << (d - 0x200u));
		assert_true(ior_cqe_get_res(s->ctx, cqe) >= 0);
		seen++;
		ior_cqe_seen(s->ctx, cqe);
	}

	assert_int_equal(seen, N);
	assert_int_equal(mask, (1u << N) - 1u); /* each op exactly once */

	test_close_fd(fd);
}

/* ===================================================================== */
/* One completion port per handle                                        */
/* ===================================================================== */

// Read a few bytes of fd through ctx and return the result.
static int32_t read_once(ior_ctx *ctx, ior_fd_t fd)
{
	char buf[8];
	ior_sqe *sqe = ior_get_sqe(ctx);
	assert_non_null(sqe);
	ior_prep_read(ctx, sqe, fd, buf, sizeof(buf), 0);
	ior_sqe_set_data(ctx, sqe, (void *) 0x300);
	assert_true(ior_submit(ctx) >= 0);
	ior_cqe *cqe = NULL;
	assert_return_code(ior_wait_cqe(ctx, &cqe), 0);
	assert_ptr_equal(ior_cqe_get_data(ctx, cqe), (void *) 0x300);
	int32_t res = ior_cqe_get_res(ctx, cqe);
	ior_cqe_seen(ctx, cqe);
	return res;
}

/*
 * A handle stays tied to the port of the first ring that used it; once that
 * ring is destroyed, the next ring to use it takes it over.
 */
static void test_handle_moves_after_destroy(void **state)
{
	iocp_state *s = (iocp_state *) *state;
	ior_fd_t fd = test_open_fd(s->path);
	assert_true(test_fd_is_valid(fd));

	ior_ctx *other = NULL;
	assert_return_code(ior_queue_init(32, &other), 0);
	assert_true(read_once(other, fd) >= 0);
	ior_queue_exit(other);

	assert_true(read_once(s->ctx, fd) >= 0);
	assert_true(read_once(s->ctx, fd) >= 0);
	test_close_fd(fd);
}

/*
 * While the first ring lives, it may still have requests on the handle, so
 * another ring is refused with -EBUSY; it gets the handle once the first is
 * destroyed.
 */
static void test_handle_busy_in_live_ring(void **state)
{
	iocp_state *s = (iocp_state *) *state;
	ior_fd_t fd = test_open_fd(s->path);
	assert_true(test_fd_is_valid(fd));

	ior_ctx *other = NULL;
	assert_return_code(ior_queue_init(32, &other), 0);
	assert_true(read_once(other, fd) >= 0);

	assert_int_equal(read_once(s->ctx, fd), -EBUSY);
	assert_true(read_once(other, fd) >= 0); // still the first ring's

	ior_queue_exit(other);
	assert_true(read_once(s->ctx, fd) >= 0);
	test_close_fd(fd);
}

// A handle tied to a completion port that is not ior's is taken over.
static void test_handle_from_foreign_port(void **state)
{
	iocp_state *s = (iocp_state *) *state;
	ior_fd_t fd = test_open_fd(s->path);
	assert_true(test_fd_is_valid(fd));

	HANDLE port = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
	assert_non_null(port);
	assert_non_null(CreateIoCompletionPort((HANDLE) fd, port, 0, 0));

	assert_true(read_once(s->ctx, fd) >= 0);
	CloseHandle(port);
	test_close_fd(fd);
}

#define READ_NO_COMPLETION INT32_MIN

/*
 * Read a few bytes of fd through ctx, READ_NO_COMPLETION if nothing arrives
 * within 2s (the completion went to another port). No asserts: also run on
 * threads of their own.
 */
static int32_t read_timed(ior_ctx *ctx, ior_fd_t fd)
{
	char buf[8];
	ior_sqe *sqe = ior_get_sqe(ctx);
	if (!sqe) {
		return -ENOBUFS;
	}
	ior_prep_read(ctx, sqe, fd, buf, sizeof(buf), 0);
	if (ior_submit(ctx) < 0) {
		return -EIO;
	}
	ior_cqe *cqe = NULL;
	ior_timespec ts = { .tv_sec = 2, .tv_nsec = 0 };
	if (ior_wait_cqe_timeout(ctx, &cqe, &ts) < 0) {
		return READ_NO_COMPLETION;
	}
	int32_t res = ior_cqe_get_res(ctx, cqe);
	ior_cqe_seen(ctx, cqe);
	return res;
}

// Close fd and open the file again, for the same handle value if it comes back.
static ior_fd_t reopen(const char *path, ior_fd_t fd)
{
	test_close_fd(fd);
	ior_fd_t again = test_open_fd(path);
	assert_true(test_fd_is_valid(again));
	return again;
}

/*
 * A live ring that used a handle value whose object was closed since does not
 * hold the object under it now: once that one's ring is gone, a third ring
 * takes it over instead of being refused.
 */
static void test_handle_recycled_value_not_busy(void **state)
{
	iocp_state *s = (iocp_state *) *state;
	ior_ctx *first = NULL, *second = NULL;
	assert_return_code(ior_queue_init(32, &first), 0);
	assert_return_code(ior_queue_init(32, &second), 0);

	ior_fd_t fd = test_open_fd(s->path);
	assert_true(read_once(first, fd) >= 0);
	ior_fd_t again = reopen(s->path, fd);
	if (again != fd) {
		test_close_fd(again);
		ior_queue_exit(second);
		ior_queue_exit(first);
		skip(); // the value did not come back
	}
	assert_true(read_once(second, again) >= 0);
	ior_queue_exit(second);

	int32_t res = read_timed(s->ctx, again);
	ior_queue_exit(first);
	assert_true(res >= 0);
	test_close_fd(again);
}

/*
 * A ring that used a handle value before, and meets it again naming an object
 * another ring (destroyed since) had, takes the object over rather than
 * taking it for its own: its request would complete on the other port.
 */
static void test_handle_recycled_value_retaken(void **state)
{
	iocp_state *s = (iocp_state *) *state;
	ior_ctx *other = NULL;
	assert_return_code(ior_queue_init(32, &other), 0);

	ior_fd_t fd = test_open_fd(s->path);
	assert_true(read_once(s->ctx, fd) >= 0);
	ior_fd_t again = reopen(s->path, fd);
	if (again != fd) {
		test_close_fd(again);
		ior_queue_exit(other);
		skip();
	}
	assert_true(read_once(other, again) >= 0);
	ior_queue_exit(other);

	int32_t res = read_timed(s->ctx, again);
	if (res == READ_NO_COMPLETION) {
		s->ctx = NULL; // its teardown would wait for the lost completion
	}
	assert_true(res >= 0 && res != READ_NO_COMPLETION);
	test_close_fd(again);
}

/*
 * A handle with a request pending on a port that is not ior's stays there:
 * the kernel does not move it, as that request's completion would follow it.
 * The ring gets -EBUSY and the other port its completion.
 */
static void test_handle_foreign_pending_busy(void **state)
{
	iocp_state *s = (iocp_state *) *state;
	ior_fd_t fds[2];
	assert_return_code(test_make_socketpair(fds), 0);
	HANDLE port = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
	assert_non_null(port);
	assert_non_null(CreateIoCompletionPort((HANDLE) fds[0], port, 7, 0));

	char fbuf[4];
	OVERLAPPED fov;
	memset(&fov, 0, sizeof(fov));
	WSABUF wb = { sizeof(fbuf), fbuf };
	DWORD flags = 0;
	int rc = WSARecv((SOCKET) fds[0], &wb, 1, NULL, &flags, &fov, NULL);
	assert_true(rc == SOCKET_ERROR && WSAGetLastError() == WSA_IO_PENDING);

	char ibuf[4];
	ior_sqe *sqe = ior_get_sqe(s->ctx);
	assert_non_null(sqe);
	ior_prep_recv(s->ctx, sqe, fds[0], ibuf, sizeof(ibuf), 0);
	assert_true(ior_submit(s->ctx) >= 0);
	ior_cqe *cqe = NULL;
	assert_return_code(ior_wait_cqe(s->ctx, &cqe), 0);
	assert_int_equal(ior_cqe_get_res(s->ctx, cqe), -EBUSY);
	ior_cqe_seen(s->ctx, cqe);

	assert_int_equal(send((SOCKET) fds[1], "abcd", 4, 0), 4);
	DWORD n = 0;
	ULONG_PTR key = 0;
	LPOVERLAPPED ov = NULL;
	assert_true(GetQueuedCompletionStatus(port, &n, &key, &ov, 2000));
	assert_ptr_equal(ov, &fov);
	assert_int_equal(key, 7);

	test_close_fd(fds[0]);
	test_close_fd(fds[1]);
	CloseHandle(port);
}

// Sockets move as files do: from a port that is not ior's, from a ring gone.
static void test_handle_socket_moves(void **state)
{
	iocp_state *s = (iocp_state *) *state;
	ior_fd_t fds[2];
	assert_return_code(test_make_socketpair(fds), 0);
	HANDLE port = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
	assert_non_null(port);
	assert_non_null(CreateIoCompletionPort((HANDLE) fds[0], port, 0, 0));

	ior_ctx *other = NULL;
	assert_return_code(ior_queue_init(32, &other), 0);
	char buf[4];
	ior_ctx *rings[2] = { other, s->ctx };
	for (int i = 0; i < 2; i++) {
		// Through `other` first (from the foreign port), then this ring.
		assert_int_equal(send((SOCKET) fds[1], "abcd", 4, 0), 4);
		ior_sqe *sqe = ior_get_sqe(rings[i]);
		assert_non_null(sqe);
		ior_prep_recv(rings[i], sqe, fds[0], buf, sizeof(buf), 0);
		assert_true(ior_submit(rings[i]) >= 0);
		ior_cqe *cqe = NULL;
		assert_return_code(ior_wait_cqe(rings[i], &cqe), 0);
		assert_int_equal(ior_cqe_get_res(rings[i], cqe), 4);
		ior_cqe_seen(rings[i], cqe);
		if (i == 0) {
			ior_queue_exit(other);
		}
	}
	test_close_fd(fds[0]);
	test_close_fd(fds[1]);
	CloseHandle(port);
}

typedef struct race_arg {
	ior_ctx *ctx;
	ior_fd_t fd;
	HANDLE go;
	int32_t res;
} race_arg;

static DWORD WINAPI race_read(LPVOID p)
{
	race_arg *a = p;
	WaitForSingleObject(a->go, INFINITE);
	a->res = read_timed(a->ctx, a->fd);
	return 0;
}

/*
 * Two rings reaching for a handle no live ring owns at once: one takes it
 * over, the other finds it owned and gets -EBUSY. Never both.
 */
static void test_handle_takeover_race(void **state)
{
	iocp_state *s = (iocp_state *) *state;
	for (int round = 0; round < 50; round++) {
		ior_fd_t fd = test_open_fd(s->path);
		ior_ctx *gone = NULL;
		assert_return_code(ior_queue_init(32, &gone), 0);
		assert_true(read_once(gone, fd) >= 0);
		ior_queue_exit(gone);

		HANDLE go = CreateEventW(NULL, TRUE, FALSE, NULL);
		assert_non_null(go);
		race_arg args[2];
		HANDLE threads[2];
		for (int i = 0; i < 2; i++) {
			args[i].ctx = NULL;
			assert_return_code(ior_queue_init(32, &args[i].ctx), 0);
			args[i].fd = fd;
			args[i].go = go;
			args[i].res = 0;
			threads[i] = CreateThread(NULL, 0, race_read, &args[i], 0, NULL);
			assert_non_null(threads[i]);
		}
		SetEvent(go);
		WaitForMultipleObjects(2, threads, TRUE, INFINITE);
		for (int i = 0; i < 2; i++) {
			CloseHandle(threads[i]);
		}
		CloseHandle(go);

		int won = (args[0].res >= 0) + (args[1].res >= 0);
		int busy = (args[0].res == -EBUSY) + (args[1].res == -EBUSY);
		for (int i = 0; i < 2; i++) {
			if (args[i].res != READ_NO_COMPLETION) {
				ior_queue_exit(args[i].ctx);
			}
		}
		assert_int_equal(won, 1);
		assert_int_equal(busy, 1);
		test_close_fd(fd);
	}
}

/* ===================================================================== */
/* Pipes                                                                 */
/* ===================================================================== */

// An overlapped duplex named pipe: *server for the ring, *client synchronous.
static void make_pipe_pair(HANDLE *server, HANDLE *client)
{
	static unsigned pairs = 0;
	char name[64];
	snprintf(name, sizeof(name), "\\\\.\\pipe\\ior-test-%lu-%u", GetCurrentProcessId(), pairs++);
	*server = CreateNamedPipeA(name,
			PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
			PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT, 1, 4096, 4096, 0, NULL);
	assert_true(*server != INVALID_HANDLE_VALUE);
	*client = CreateFileA(name, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
	assert_true(*client != INVALID_HANDLE_VALUE);
}

static int32_t pipe_op_once(ior_ctx *ctx, HANDLE h, void *buf, unsigned len, int write)
{
	ior_sqe *const sqe = ior_get_sqe(ctx);
	assert_non_null(sqe);
	if (write) {
		ior_prep_write(ctx, sqe, h, buf, len, IOR_OFF_NONE);
	} else {
		ior_prep_read(ctx, sqe, h, buf, len, IOR_OFF_NONE);
	}
	assert_true(ior_submit(ctx) >= 0);
	ior_cqe *cqe = NULL;
	assert_return_code(ior_wait_cqe(ctx, &cqe), 0);
	const int32_t res = ior_cqe_get_res(ctx, cqe);
	ior_cqe_seen(ctx, cqe);
	return res;
}

// A write to a pipe whose other end is closed fails with EPIPE, as on POSIX.
static void test_write_to_closed_pipe_epipe(void **state)
{
	iocp_state *s = (iocp_state *) *state;
	HANDLE server, client;
	make_pipe_pair(&server, &client);
	CloseHandle(client);

	char byte = 'x';
	assert_int_equal(pipe_op_once(s->ctx, server, &byte, 1, 1), -EPIPE);
	CloseHandle(server);
}

// A read of an empty PIPE_NOWAIT pipe fails with EAGAIN, as on POSIX.
static void test_read_empty_nowait_pipe_eagain(void **state)
{
	iocp_state *s = (iocp_state *) *state;
	HANDLE server, client;
	make_pipe_pair(&server, &client);
	DWORD mode = PIPE_READMODE_BYTE | PIPE_NOWAIT;
	assert_true(SetNamedPipeHandleState(server, &mode, NULL, NULL));

	char byte;
	assert_int_equal(pipe_op_once(s->ctx, server, &byte, 1, 0), -EAGAIN);
	CloseHandle(client);
	CloseHandle(server);
}

/* ===================================================================== */
/* Teardown with operations still in flight                              */
/* ===================================================================== */

/*
 * Arm a long timer and a NOP, submit, then tear down WITHOUT reaping. The
 * destroy path must drain active_count (timer thread stop + heap drain +
 * GQCS drain loop) without hanging or leaking. cmocka's leak checker and
 * the 30s CTest timeout are the assertions here.
 */
static void test_teardown_inflight(void **state)
{
	(void) state; /* uses its own ctx to control teardown timing */

	ior_ctx *ctx = NULL;
	int ret = ior_queue_init(32, &ctx);
	assert_return_code(ret, 0);

	ior_timespec longt = { .tv_sec = 30, .tv_nsec = 0 };
	ior_sqe *t = ior_get_sqe(ctx);
	assert_non_null(t);
	ior_prep_timeout(ctx, t, &longt, 0, 0);
	ior_sqe_set_data(ctx, t, (void *) 0x1);

	ior_sqe *n = ior_get_sqe(ctx);
	assert_non_null(n);
	ior_prep_nop(ctx, n);
	ior_sqe_set_data(ctx, n, (void *) 0x2);

	ret = ior_submit(ctx);
	assert_true(ret >= 0);

	/* Do NOT reap. Tearing down must cancel the in-flight timer cleanly. */
	ior_queue_exit(ctx);
}

#endif /* IOR_HAVE_IOCP */

int main(void)
{
#ifdef IOR_HAVE_IOCP
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup_teardown(test_synthetic_write_eacces, iocp_setup, iocp_teardown),
		cmocka_unit_test_setup_teardown(test_synthetic_read_eacces, iocp_setup, iocp_teardown),
		cmocka_unit_test_setup_teardown(test_link_head_failure_cancels, iocp_setup, iocp_teardown),
		cmocka_unit_test_setup_teardown(test_drain_is_last, iocp_setup, iocp_teardown),
		cmocka_unit_test_setup_teardown(test_timer_fires, iocp_setup, iocp_teardown),
		cmocka_unit_test_setup_teardown(test_timer_heap_order, iocp_setup, iocp_teardown),
		cmocka_unit_test_setup_teardown(test_sync_completion_accounting, iocp_setup, iocp_teardown),
		cmocka_unit_test(test_teardown_inflight),
		cmocka_unit_test_setup_teardown(test_handle_moves_after_destroy, iocp_setup, iocp_teardown),
		cmocka_unit_test_setup_teardown(test_handle_busy_in_live_ring, iocp_setup, iocp_teardown),
		cmocka_unit_test_setup_teardown(test_handle_from_foreign_port, iocp_setup, iocp_teardown),
		cmocka_unit_test_setup_teardown(
				test_handle_recycled_value_not_busy, iocp_setup, iocp_teardown),
		cmocka_unit_test_setup_teardown(
				test_handle_recycled_value_retaken, iocp_setup, iocp_teardown),
		cmocka_unit_test_setup_teardown(test_handle_foreign_pending_busy, iocp_setup, iocp_teardown),
		cmocka_unit_test_setup_teardown(test_handle_socket_moves, iocp_setup, iocp_teardown),
		cmocka_unit_test_setup_teardown(test_handle_takeover_race, iocp_setup, iocp_teardown),
		cmocka_unit_test_setup_teardown(test_write_to_closed_pipe_epipe, iocp_setup, iocp_teardown),
		cmocka_unit_test_setup_teardown(
				test_read_empty_nowait_pipe_eagain, iocp_setup, iocp_teardown),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
#else
	/* Not an IOCP build - nothing to test, report success. */
	return 0;
#endif
}
