/* SPDX-License-Identifier: BSD-3-Clause */
/**
 * @file ior.h
 * @brief Public API for ior, a cross-platform io_uring-like asynchronous I/O
 *        library.
 *
 * ior exposes a submission/completion queue model inspired by io_uring and maps
 * it onto the best available backend for the platform: io_uring on Linux, a
 * portable thread pool elsewhere, and I/O completion ports on Windows. The API
 * and its semantics are identical across all backends.
 *
 * Signals: every thread ior creates on POSIX (the thread backend's workers,
 * poller and timer, the worker pool behind ior_prep_work() on io_uring) runs
 * with all signals blocked, so a signal sent to the process is delivered to
 * one of the caller's threads and EINTR is only ever seen there; work
 * callbacks inherit that mask. The caller's own signal mask is never changed.
 *
 * Typical flow:
 *   1. ior_queue_init() / ior_queue_init_params() to create a context.
 *   2. ior_get_sqe(), then an ior_prep_*() helper to describe an operation.
 *   3. ior_submit() / ior_submit_and_wait() to submit.
 *   4. ior_wait_cqe() / ior_peek_cqe() to reap completions, then ior_cqe_seen().
 *   5. ior_queue_exit() to tear down.
 */
#ifndef IOR_H
#define IOR_H

#include <stdint.h>
#include <signal.h>
#include <sys/types.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Platform-specific file descriptor type */
#ifdef _WIN32
/*
 * Define WIN32_LEAN_AND_MEAN before windows.h so it does not implicitly
 * include the legacy winsock.h (Winsock 1.1). That header conflicts with
 * winsock2.h, so without this guard any consumer that uses ior.h together
 * with winsock2.h would get a flood of struct/function redefinition errors
 * unless they carefully control include order. With this guard, including
 * ior.h before or after winsock2.h both work.
 */
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
/* winsock2.h (for struct sockaddr / socklen_t in the accept and connect
 * helpers) must precede windows.h; it includes it in the right order. */
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
/** Platform descriptor type used by all operations (HANDLE on Windows). */
typedef HANDLE ior_fd_t;
/** Invalid-descriptor sentinel for ::ior_fd_t. */
#define IOR_INVALID_FD INVALID_HANDLE_VALUE
/** Process identifier for ior_prep_waitpid() (a process id on Windows). */
typedef DWORD ior_pid_t;
/**
 * Signal set for ior_prep_sigwait(). Windows has no sigset_t: this is a bit
 * per CRT signal number, built with ior_sigemptyset()/ior_sigaddset().
 */
typedef struct ior_sigset {
	uint32_t bits;
} ior_sigset_t;
/**
 * What ior_prep_sigwait() reports about the signal it collected. Windows has
 * no siginfo_t: the signal, and the console control event that raised it.
 */
typedef struct ior_siginfo {
	/** The signal: SIGINT or SIGBREAK. */
	int si_signo;
	/** The CTRL_*_EVENT the console delivered (CTRL_C_EVENT for SIGINT;
	 *  CTRL_BREAK_EVENT, CTRL_CLOSE_EVENT, CTRL_LOGOFF_EVENT or
	 *  CTRL_SHUTDOWN_EVENT for SIGBREAK, as the CRT maps them). */
	int si_code;
} ior_siginfo_t;
#else
#include <sys/types.h>
#include <sys/socket.h>
/** Platform descriptor type used by all operations (int on POSIX). */
typedef int ior_fd_t;
/** Invalid-descriptor sentinel for ::ior_fd_t. */
#define IOR_INVALID_FD (-1)
/** Process identifier for ior_prep_waitpid() (pid_t on POSIX). */
typedef pid_t ior_pid_t;
/** Signal set for ior_prep_sigwait() (sigset_t on POSIX). */
typedef sigset_t ior_sigset_t;
/** Signal information filled by ior_prep_sigwait() (siginfo_t on POSIX). */
typedef siginfo_t ior_siginfo_t;
#endif

/**
 * @brief Platform-independent timespec for async I/O operations.
 *
 * Matches the layout of Linux's __kernel_timespec (required by io_uring) and
 * uses 64-bit fields on all platforms.
 */
typedef struct ior_timespec {
	/** Seconds. */
	int64_t tv_sec;
	/** Nanoseconds. */
	long long tv_nsec;
} ior_timespec;

/**
 * @name Operation codes
 * Identify the type of operation an SQE carries; set by the ior_prep_*()
 * helpers. LISTEN and BIND are reserved and not yet wired to prep helpers;
 * everything else is implemented on every backend.
 * @{
 */
/** No-op; completes immediately with result 0. */
#define IOR_OP_NOP 0
/** Read into a buffer (ior_prep_read). */
#define IOR_OP_READ 1
/** Write from a buffer (ior_prep_write). */
#define IOR_OP_WRITE 2
/** Timeout (ior_prep_timeout); completes with -ETIME. */
#define IOR_OP_TIMER 3
/** Move data between descriptors (ior_prep_splice). */
#define IOR_OP_SPLICE 4
/** Accept a connection (ior_prep_accept, ior_prep_accept_multishot);
 *  completes with the new socket. */
#define IOR_OP_ACCEPT 5
/** Connect a socket (ior_prep_connect). */
#define IOR_OP_CONNECT 6
/** Reserved: listen on a socket (not yet implemented). */
#define IOR_OP_LISTEN 7
/** Reserved: bind a socket (not yet implemented). */
#define IOR_OP_BIND 8
/** Send on a socket (ior_prep_send). */
#define IOR_OP_SEND 9
/** Receive from a socket (ior_prep_recv). */
#define IOR_OP_RECV 10
/** Timeout that cancels the preceding linked op (ior_prep_link_timeout). */
#define IOR_OP_LINK_TIMEOUT 11
/** Run a user callback on the backend's thread pool (ior_prep_work). */
#define IOR_OP_WORK 12
/** Wait for fd readiness (ior_prep_poll_add, ior_prep_poll_multishot);
 *  completes with an IOR_POLL_* mask in res. */
#define IOR_OP_POLL 13
/** Cancel a submitted operation (ior_prep_cancel, ior_prep_cancel_fd). */
#define IOR_OP_ASYNC_CANCEL 14
/** Wait for a process state change (ior_prep_waitpid); completes with its
 *  pid, the process left for the caller to collect. */
#define IOR_OP_WAITPID 15
/** Wait for a signal (ior_prep_sigwait); completes with its number. */
#define IOR_OP_SIGWAIT 16
/** Wait for changes in a directory (ior_prep_dir_changes); completes with
 *  the bytes of change records written. Windows only. */
#define IOR_OP_DIR_CHANGES 17
/** @} */

/**
 * @name Setup flags
 * Bits for ior_params::flags. These primarily affect the io_uring backend;
 * other backends ignore flags they do not support.
 * @{
 */
/** Use a kernel submission-polling thread. */
#define IOR_SETUP_SQPOLL (1U << 0)
/** Use busy-polling for I/O completions. */
#define IOR_SETUP_IOPOLL (1U << 1)
/** Defer task work until the next submit. */
#define IOR_SETUP_DEFER (1U << 2)
/**
 * Every descriptor submitted to this context is already in non-blocking mode.
 *
 * The thread backend otherwise takes a blocking descriptor's mode over for an
 * operation that has no per-call non-blocking form (accept, connect, and a
 * read or write at the current position where RWF_NOWAIT is unavailable),
 * one fcntl and one ioctl to switch it and one ioctl to restore it once the
 * last such operation on it completes; this flag says the caller keeps its
 * descriptors non-blocking and all of that can be skipped. Set it only if
 * that holds for every descriptor you submit: an operation on a descriptor
 * that does block occupies a worker thread until it completes, and cannot be
 * cancelled meanwhile. Ignored by the io_uring and IOCP backends, which never
 * change descriptor state.
 */
#define IOR_SETUP_FD_NONBLOCK (1U << 3)
/** @} */

/**
 * @name Submission queue entry flags
 * Bits for ior_sqe_set_flags().
 * @{
 */
/**
 * fd refers to a registered (fixed) file. ior has no way to register files
 * yet, so on every backend an op that takes a descriptor fails with -EBADF
 * when it runs, as io_uring does with an empty file table; others ignore it.
 */
#define IOR_SQE_FIXED_FILE (1U << 0)
/** Wait for all prior SQEs to complete before this one. */
#define IOR_SQE_IO_DRAIN (1U << 1)
/** Link to the next SQE; it starts only if this one succeeds. */
#define IOR_SQE_IO_LINK (1U << 2)
/** Hint to perform the operation asynchronously. */
#define IOR_SQE_ASYNC (1U << 3)
/** @} */

/**
 * @name Timeout flags
 * Bits for the flags argument of ior_prep_timeout() and ior_prep_link_timeout().
 *
 * An absolute deadline is read on the monotonic clock unless a clock flag
 * names another: CLOCK_MONOTONIC on POSIX, QueryPerformanceCounter on Windows
 * (as nanoseconds: counter * 1e9 / frequency). A relative timeout is a
 * duration: io_uring counts it on the flagged clock, which matters across a
 * suspend (IOR_TIMEOUT_BOOTTIME keeps counting, the default does not); the
 * thread and IOCP backends count every relative timeout on their monotonic
 * clock, and convert an absolute deadline on another clock into one at arm
 * time, so a suspend between submit and expiry is not seen by them.
 * @{
 */
/** Interpret the timespec as an absolute deadline rather than a relative
 *  duration. */
#define IOR_TIMEOUT_ABS (1U << 0)
/** The deadline (or duration, on io_uring) is on the boot-time clock, which
 *  keeps counting while the system is suspended: CLOCK_BOOTTIME on Linux and
 *  FreeBSD, CLOCK_MONOTONIC on macOS (where it already counts sleep),
 *  GetTickCount64 on Windows (milliseconds since boot). io_uring's
 *  IORING_TIMEOUT_BOOTTIME. */
#define IOR_TIMEOUT_BOOTTIME (1U << 1)
/** The deadline is on the wall clock, as nanoseconds since the Unix epoch:
 *  CLOCK_REALTIME on POSIX, the system time on Windows. A deadline in the
 *  past fires at once. io_uring's IORING_TIMEOUT_REALTIME. */
#define IOR_TIMEOUT_REALTIME (1U << 2)
/** @} */

/**
 * @name Accept flags
 * Bits for the flags argument of ior_prep_accept(), applied to the accepted
 * socket. Equal to SOCK_NONBLOCK / SOCK_CLOEXEC where the platform defines
 * them (accept4 semantics), emulated elsewhere; ignored on Windows, where an
 * accepted socket is an overlapped socket like any other.
 * @{
 */
#ifdef SOCK_NONBLOCK
#define IOR_ACCEPT_NONBLOCK SOCK_NONBLOCK
#else
/** Put the accepted socket in non-blocking mode. */
#define IOR_ACCEPT_NONBLOCK (1U << 0)
#endif
#ifdef SOCK_CLOEXEC
#define IOR_ACCEPT_CLOEXEC SOCK_CLOEXEC
#else
/** Mark the accepted socket close-on-exec. */
#define IOR_ACCEPT_CLOEXEC (1U << 1)
#endif
/** @} */

/**
 * @name Poll event masks
 * Bits for the mask argument of ior_prep_poll_add() and for the resulting CQE
 * res. Values match Linux poll(2) event bits. IOR_POLL_ERR, IOR_POLL_HUP and
 * IOR_POLL_NVAL are output-only: always reported in res when they apply,
 * regardless of the requested mask (standard poll semantics).
 * @{
 */
/** Data available to read. */
#define IOR_POLL_IN 0x001
/** Ready for writing. */
#define IOR_POLL_OUT 0x004
/** Error condition (output only). */
#define IOR_POLL_ERR 0x008
/** Peer hung up (output only). */
#define IOR_POLL_HUP 0x010
/** Invalid descriptor (output only). */
#define IOR_POLL_NVAL 0x020
/** @} */

/**
 * @name Completion flags
 * Bits of ior_cqe_get_flags(). Values match io_uring's IORING_CQE_F_* bits.
 * @{
 */
/** More completions follow from the same operation: a multishot poll
 *  (ior_prep_poll_multishot) posts one per readiness edge, a multishot
 *  accept (ior_prep_accept_multishot) one per connection, and stays armed.
 *  A completion without this bit is the operation's last. */
#define IOR_CQE_F_MORE (1U << 1)
/** The socket has more waiting after this completion: another connection
 *  queued on the listener behind an accept (ior_prep_accept(),
 *  ior_prep_accept_multishot()), more data to read behind a receive
 *  (ior_prep_recv()). A hint, never a promise: it is set where the backend
 *  can tell at no great cost, and a completion without it says nothing.
 *  Accept: io_uring from Linux 6.10, the thread backend (a zero-timeout
 *  poll of the listener after each accept), IOCP for a one-shot accept
 *  (WSAPoll, likewise); a multishot accept's connections on IOCP never
 *  carry it, its outstanding AcceptEx taking what is queued. Receive:
 *  io_uring only (IORING_CQE_F_SOCK_NONEMPTY, Linux 5.19). Lets a caller
 *  accept or read again at once instead of waiting for -EAGAIN. */
#define IOR_CQE_F_SOCK_NONEMPTY (1U << 2)
/** @} */

/** Asynchronous I/O backend implementation. */
typedef enum {
	/** Auto-select the best backend for the platform. */
	IOR_BACKEND_AUTO = 0,
	/** Linux io_uring. */
	IOR_BACKEND_IOURING,
	/** Portable thread-pool fallback. */
	IOR_BACKEND_THREADS,
	/** Windows I/O completion ports. */
	IOR_BACKEND_IOCP,
} ior_backend_type;

/**
 * @name Feature flags
 * Reported in ior_params::features and by ior_get_features().
 * @{
 */
/** Backend performs I/O without a thread pool. */
#define IOR_FEAT_NATIVE_ASYNC (1U << 0)
/** Zero-copy splice is supported. */
#define IOR_FEAT_SPLICE (1U << 1)
/** Registered/fixed files are supported. */
#define IOR_FEAT_FIXED_FILE (1U << 2)
/** IOR_OP_POLL readiness ops are supported (ior_prep_poll_add,
 *  ior_prep_poll_multishot). */
#define IOR_FEAT_POLL_ADD (1U << 3)
/** Kernel submission polling is supported. */
#define IOR_FEAT_SQPOLL (1U << 4)
/** User work callbacks are supported (ior_prep_work). Set by every backend:
 *  the io_uring backend requires liburing 2.2+ and kernel 5.19+
 *  (IORING_OP_MSG_RING, cancel by descriptor) and is only selected when they
 *  are available;
 *  otherwise the threads backend is used. */
#define IOR_FEAT_WORK (1U << 5)
/** Directory change ops are supported (ior_prep_dir_changes): IOCP only. */
#define IOR_FEAT_DIR_CHANGES (1U << 6)
/** @} */

/**
 * @brief Sentinel offset meaning "no offset / use the file description's current
 *        position."
 *
 * For read/write this selects read()/write() semantics over the positioned
 * pread()/pwrite() (required for non-seekable fds such as sockets and pipes).
 * For splice it marks an unused in/out offset. Equal to (uint64_t)-1, matching
 * io_uring's convention for an absent offset. An overlapped handle on IOCP
 * keeps no current position: a socket or pipe ignores the offset either way,
 * a file is read from 0 and written at its end.
 */
#define IOR_OFF_NONE ((uint64_t) -1)

/* Forward declarations - OPAQUE TYPES */
/** Opaque I/O context: one submission/completion queue pair plus backend state. */
typedef struct ior_ctx ior_ctx;
/** Opaque submission queue entry; fill via ior_prep_*() and ior_sqe_set_*(). */
typedef struct ior_sqe ior_sqe;
/** Opaque completion queue entry; inspect via ior_cqe_get_*(). */
typedef struct ior_cqe ior_cqe;

typedef struct ior_params ior_params;

/** Setup parameters for ior_queue_init_params(). */
struct ior_params {
	/** [in,out] Submission queue size; 0 uses the `entries` argument to init.
	 *  On success, the size actually used (see ior_sq_entries()). */
	uint32_t sq_entries;
	/**
	 * [in,out] Completion queue size; 0 lets the backend choose (2x SQ). On
	 * success, the size actually used (see ior_cq_entries()). It bounds
	 * neither the operations in flight nor what may be submitted: a
	 * completion that finds it full waits until reaping makes room.
	 */
	uint32_t cq_entries;
	/** IOR_SETUP_* setup flags. */
	uint32_t flags;
	/** CPU to pin the SQPOLL thread to (io_uring + IOR_SETUP_SQPOLL). */
	uint32_t sq_thread_cpu;
	/** SQPOLL idle timeout in ms before the poll thread sleeps. */
	uint32_t sq_thread_idle;
	/** [out] IOR_FEAT_* flags the chosen backend provides. */
	uint32_t features;
	/** Desired backend, or IOR_BACKEND_AUTO: the best one built in, unless
	 *  the IOR_BACKEND environment variable names one ("io_uring",
	 *  "threads" or "iocp"); a name that is unknown or not built in makes
	 *  init fail with -ENOSYS. A build carries one backend unless
	 *  IOR_WITH_THREADS added the thread backend next to io_uring. */
	ior_backend_type backend;
};

/* Core API */

/**
 * Create an I/O context with explicit parameters.
 *
 * Every backend rounds the queue sizes up to a power of two. The thread and
 * IOCP backends raise the submission queue to at least 32, and the thread
 * backend the completion queue too; the completion queue must not be smaller
 * than the submission queue on io_uring. The sizes used are written back to
 * @p params and readable later with ior_sq_entries() and ior_cq_entries(), so
 * reset params->sq_entries and params->cq_entries before reusing @p params
 * for another context. @p params is left untouched on failure.
 *
 * @param entries  Default submission queue size, used when params->sq_entries is 0.
 * @param ctx_out  [out] Receives the new context on success.
 * @param params   Setup parameters; params->sq_entries, params->cq_entries and
 *                 params->features are filled in on success.
 * @return 0 on success, or a negative errno (-EINVAL for bad arguments, -ENOSYS
 *         if the requested backend is unavailable, -ENOMEM, ...).
 */
int ior_queue_init_params(unsigned entries, ior_ctx **ctx_out, ior_params *params);

/**
 * Create an I/O context with default parameters and the auto-selected backend.
 *
 * @param entries  Submission queue size.
 * @param ctx_out  [out] Receives the new context on success.
 * @return 0 on success, or a negative errno.
 */
int ior_queue_init(unsigned entries, ior_ctx **ctx_out);

/**
 * Destroy an I/O context and release its resources.
 *
 * Waits for any backend worker threads to finish. Safe to call with NULL.
 *
 * @param ctx  Context to destroy (may be NULL).
 */
void ior_queue_exit(ior_ctx *ctx);

/**
 * Drop an I/O context inherited through fork(2), in the child.
 *
 * A child gets a copy of every descriptor the parent's context holds (the
 * io_uring rings, the notification descriptor, the thread backend's poller,
 * the pidfds and signalfds of waits in flight) but none of its threads, and
 * the ring itself stays the parent's. This closes the child's copies of those
 * descriptors and unmaps its rings without touching what the parent still
 * uses: nothing is submitted, cancelled or unregistered, no operation
 * completes, and the parent's operations go on in the parent. It never
 * blocks on a lock one of the parent's threads may have held at the fork,
 * ior's own threads included, and leaves open the descriptors such a thread
 * was creating or changing at that moment: on the thread backend the
 * multishot polls' and accepts' dup(2)s when the fork lands while the poller
 * thread reports readiness (and a socket a multishot accept was accepting
 * right then), and the poller's own descriptors when it lands while
 * a worker is still creating the poller for the first poll; on io_uring
 * the pidfds and signalfds of pending waits when it lands while a worker or
 * timer thread retires a work job. Memory is released as far as the child
 * can do so safely; what ior's threads were using is left, the child's own
 * copy, which the parent does not see.
 *
 * Call it in the child before any other ior call on @p ctx, which is invalid
 * afterwards; ior_queue_exit() would wait for threads that do not exist
 * there. No other thread of the parent should be inside an ior call on
 * @p ctx during the fork.
 *
 * @param ctx  Context inherited from the parent.
 * @return 0, -EINVAL for a NULL @p ctx, or -ENOTSUP where there is no fork
 *         (IOCP), @p ctx then left as it is.
 */
int ior_queue_forget(ior_ctx *ctx);

/**
 * Untie a descriptor from the context before another process gets it.
 *
 * On IOCP a handle the context did I/O on stays associated with its
 * completion port, and the association belongs to the file object, which a
 * duplicate shares: a process given the handle (inherited, or through
 * DuplicateHandle) posts the packets of its own overlapped I/O on it to this
 * port. This takes the handle off the port; the next operation on it here
 * associates it again. A request another process has pending on the handle
 * is untied with it: its completion reaches no port. Call it on the thread
 * that submits. On other backends nothing ties a descriptor to a context,
 * and it returns 0.
 *
 * @param ctx  I/O context.
 * @param fd   Descriptor about to be handed out.
 *
 * @return 0 when nothing of this context ties @p fd to its port any more,
 *         as far as ior records (a handle it never associated is left as it
 *         is); -EINVAL for a NULL @p ctx, or when the kernel refuses (a
 *         closed handle); -EBADF for a NULL or INVALID_HANDLE_VALUE @p fd;
 *         -EBUSY while an operation of the context on @p fd is queued or its
 *         completion not yet dequeued; -ENOTSUP where the system cannot
 *         (before Windows 8.1). The handle stays associated on any error.
 */
int ior_release_handle(ior_ctx *ctx, ior_fd_t fd);

/* Submission */

/**
 * Obtain the next free submission queue entry.
 *
 * Describe the operation with an ior_prep_*() helper, optionally attach
 * ior_sqe_set_data()/ior_sqe_set_flags(), then publish it with ior_submit().
 *
 * An entry is refused only when the submission queue is full of entries not
 * yet submitted (ior_submit() makes room), as io_uring_get_sqe() is. Nothing
 * else bounds the operations in flight but memory, on every backend: a
 * completion that finds the completion queue full waits, in the order it was
 * posted, until reaping makes room (io_uring's IORING_FEAT_NODROP), so a
 * caller that submits without reaping holds that memory.
 *
 * @param ctx  I/O context.
 * @return A pointer to an SQE, or NULL if no entry is available.
 */
ior_sqe *ior_get_sqe(ior_ctx *ctx);

/**
 * Obtain the next free submission queue entry, or learn why none is available.
 *
 * Same as ior_get_sqe(), with the reason for a refusal as the return value.
 *
 * @param ctx      I/O context.
 * @param sqe_out  [out] Receives the SQE on success, NULL otherwise.
 * @return 0 on success; -ENOSPC if the submission queue is full (call
 *         ior_submit(), then retry); -ENOMEM if no memory could be had for
 *         the entry (IOCP, whose entry is its operation); -EINVAL for bad
 *         arguments.
 */
int ior_get_sqe_ex(ior_ctx *ctx, ior_sqe **sqe_out);

/**
 * Submit all prepared submission queue entries.
 *
 * Follows io_uring on every backend. An entry io_uring refuses to take (a
 * timeout with no timespec (-EFAULT), a negative field or two clocks
 * (-EINVAL), a link timeout with no linked entry before it in the same submit
 * (-EINVAL), an accept with flags other than IOR_ACCEPT_* (-EINVAL)) fails
 * its whole chain: it completes with its own error and the rest of the chain
 * with -ECANCELED. Submission stops right after it unless it links on, and
 * the count includes it. The entries not taken stay staged,
 * in order, and the next submit sends them; they need no new prep. An error
 * found while an op runs, such as a bad descriptor, is its completion only.
 *
 * Without memory for the operations a submit also takes fewer entries, or
 * none: io_uring when the kernel cannot allocate a request (-EAGAIN,
 * -ENOMEM), the thread backend when it cannot grow its work items (-EAGAIN,
 * taking none). What is left stays staged the same way.
 *
 * Only ior_submit() and ior_submit_and_wait() submit: waiting or peeking for
 * completions never sends staged entries, so waiting on an op that is still
 * staged blocks.
 *
 * @param ctx  I/O context.
 * @return The number of entries submitted (>= 0), or a negative errno.
 */
int ior_submit(ior_ctx *ctx);

/**
 * Submit all prepared entries and wait for completions.
 *
 * Submits as ior_submit() does. When entries are left staged it returns
 * without waiting, as io_uring does.
 *
 * @param ctx      I/O context.
 * @param wait_nr  Minimum number of completions to wait for (0 = do not wait).
 * @return The number of entries submitted (>= 0), or a negative errno.
 */
int ior_submit_and_wait(ior_ctx *ctx, unsigned wait_nr);

/* Completion
 *
 * All backends honor the same completion-queue contract, modeled on io_uring.
 * A completion (CQE) returned by peek or wait is NOT consumed by those calls:
 * it stays valid and stable - repeated peeks/waits return the same CQE - until
 * it is consumed with ior_cqe_seen or ior_cq_advance.
 */

/**
 * Non-blocking check for a ready completion.
 *
 * Does not submit staged entries (see ior_submit()) and does not consume the
 * completion; a subsequent peek or wait returns the same CQE until it is
 * consumed with ior_cqe_seen() or ior_cq_advance().
 *
 * @param ctx      I/O context.
 * @param cqe_out  On success, set to the completion at the head of the queue.
 * @return 0 if a completion was available, -EAGAIN if none is ready, or
 *         -EINVAL if ctx or cqe_out is NULL.
 */
int ior_peek_cqe(ior_ctx *ctx, ior_cqe **cqe_out);

/**
 * Block until a completion is ready.
 *
 * Waits indefinitely for the next completion. Does not submit staged entries
 * (see ior_submit()), does not return -EAGAIN spuriously and does not consume
 * the completion (the returned CQE is identical to what ior_peek_cqe() would
 * return).
 *
 * @param ctx      I/O context.
 * @param cqe_out  On success, set to the completion at the head of the queue.
 * @return 0 on success, or a negative errno on failure (e.g. -EINVAL if ctx or
 *         cqe_out is NULL, -EINTR if interrupted).
 */
int ior_wait_cqe(ior_ctx *ctx, ior_cqe **cqe_out);

/**
 * Block until a completion is ready or the timeout elapses.
 *
 * Like ior_wait_cqe() but bounded by @p timeout. Does not submit staged
 * entries and does not consume the completion.
 *
 * @param ctx      I/O context.
 * @param cqe_out  On success, set to the completion at the head of the queue.
 * @param timeout  Maximum time to wait, or NULL to wait indefinitely. Read as
 *                 io_uring does: a negative one has already expired, and a
 *                 tv_nsec of a second or more adds up.
 * @return 0 on success, -ETIME if the timeout elapsed before a completion
 *         arrived, or a negative errno on failure (e.g. -EINVAL for NULL ctx /
 *         cqe_out).
 */
int ior_wait_cqe_timeout(ior_ctx *ctx, ior_cqe **cqe_out, ior_timespec *timeout);

/**
 * Consume a single completion.
 *
 * Marks the completion at the head of the queue as seen, advancing the queue by
 * one. Equivalent to ior_cq_advance(ctx, 1). After this call the CQE pointer
 * must not be used.
 *
 * @param ctx  I/O context.
 * @param cqe  The completion previously obtained from peek/wait.
 */
void ior_cqe_seen(ior_ctx *ctx, ior_cqe *cqe);

/**
 * Peek at a batch of ready completions without consuming them.
 *
 * Fills @p cqes with up to @p max completions currently ready. The completions
 * are not consumed; release them afterwards with ior_cq_advance().
 *
 * @param ctx   I/O context.
 * @param cqes  Array receiving pointers to ready completions.
 * @param max   Capacity of @p cqes.
 * @return The number of completions written to @p cqes (0 if none are ready).
 */
unsigned ior_peek_batch_cqe(ior_ctx *ctx, ior_cqe **cqes, unsigned max);

/**
 * Consume @p nr completions from the head of the queue.
 *
 * Typically used to release a batch obtained via ior_peek_batch_cqe().
 *
 * @param ctx  I/O context.
 * @param nr   Number of completions to consume; 0 is a no-op.
 */
void ior_cq_advance(ior_ctx *ctx, unsigned nr);

/* SQE preparation helpers - describe an operation on an entry from ior_get_sqe(). */

/**
 * Prepare a no-op that completes immediately with result 0.
 *
 * @param ctx  I/O context.
 * @param sqe  Entry from ior_get_sqe().
 */
void ior_prep_nop(ior_ctx *ctx, ior_sqe *sqe);

/**
 * Prepare a read into @p buf.
 *
 * @param ctx     I/O context.
 * @param sqe     Entry from ior_get_sqe().
 * @param fd      Source file or socket descriptor.
 * @param buf     Destination buffer.
 * @param nbytes  Maximum number of bytes to read.
 * @param offset  File offset, or IOR_OFF_NONE to read at the current position.
 *                A non-seekable fd (socket, pipe) ignores the offset.
 */
void ior_prep_read(
		ior_ctx *ctx, ior_sqe *sqe, ior_fd_t fd, void *buf, unsigned nbytes, uint64_t offset);

/**
 * Prepare a write from @p buf.
 *
 * @param ctx     I/O context.
 * @param sqe     Entry from ior_get_sqe().
 * @param fd      Destination file or socket descriptor.
 * @param buf     Source buffer.
 * @param nbytes  Number of bytes to write.
 * @param offset  File offset, or IOR_OFF_NONE to write at the current position.
 *                A non-seekable fd (socket, pipe) ignores the offset.
 */
void ior_prep_write(
		ior_ctx *ctx, ior_sqe *sqe, ior_fd_t fd, const void *buf, unsigned nbytes, uint64_t offset);

/**
 * Prepare a splice (zero-copy move of data between two descriptors).
 *
 * Requires IOR_FEAT_SPLICE; backends without it emulate the move with a
 * read/write loop.
 *
 * @param ctx      I/O context.
 * @param sqe      Entry from ior_get_sqe().
 * @param fd_in    Source descriptor.
 * @param off_in   Source offset, or IOR_OFF_NONE for the current position.
 * @param fd_out   Destination descriptor.
 * @param off_out  Destination offset, or IOR_OFF_NONE for the current position.
 * @param nbytes   Number of bytes to move.
 * @param flags    Splice flags (SPLICE_F_*).
 */
void ior_prep_splice(ior_ctx *ctx, ior_sqe *sqe, ior_fd_t fd_in, uint64_t off_in, ior_fd_t fd_out,
		uint64_t off_out, unsigned nbytes, unsigned flags);

/**
 * Prepare a timeout that completes with -ETIME after @p ts elapses.
 *
 * @p ts is read and copied by the submit that takes the entry, as io_uring
 * does, so it may live on the caller's stack until that submit returns. An
 * entry left staged (see ior_submit()) has it read by a later submit, so keep
 * it valid until a submit has taken the entry. A tv_nsec of a second or more
 * is a longer timeout, as on io_uring.
 *
 * @param ctx    I/O context.
 * @param sqe    Entry from ior_get_sqe().
 * @param ts     Timeout value: a relative duration, or an absolute deadline
 *               if IOR_TIMEOUT_ABS is set in @p flags, on the clock the
 *               other IOR_TIMEOUT_* flags select (see there).
 * @param count  Number of completions to wait for before the timeout fires
 *               (io_uring semantics; 0 = a pure time-based timeout). Ignored by
 *               backends that do not support it.
 * @param flags  IOR_TIMEOUT_ABS to treat @p ts as an absolute deadline,
 *               IOR_TIMEOUT_BOOTTIME / IOR_TIMEOUT_REALTIME to pick its clock,
 *               else 0.
 */
void ior_prep_timeout(ior_ctx *ctx, ior_sqe *sqe, ior_timespec *ts, unsigned count, unsigned flags);

/**
 * Prepare a timeout linked to the preceding operation.
 *
 * Acts as a deadline/watchdog on a single operation. To use it, submit the
 * guarded operation with the IOR_SQE_IO_LINK flag and make this link timeout the
 * immediately following submission entry. Both entries always produce a CQE:
 *   - if @p ts elapses first, the guarded op is cancelled (its CQE has
 *     res == -ECANCELED) and this link timeout completes with res == -ETIME;
 *   - if the guarded op finishes first, it reports its normal result and this
 *     link timeout completes with res == -ECANCELED;
 *   - if @p ts elapses while the guarded op runs and cannot be stopped (a
 *     work callback, a read or write of a regular file on a worker, a signal
 *     wait blocked in sigwait(3) where there is no sigtimedwait), this link
 *     timeout completes at the deadline with res == -EALREADY, as io_uring's
 *     does for a running request, and the guarded op completes with its own
 *     result once it ends. Its memory stays in use until then.
 *
 * An entry linked behind this link timeout (IOR_SQE_IO_LINK on it) follows
 * the guarded op, not the timeout: it runs once that op succeeds and is
 * cancelled when that op fails, is cancelled or times out.
 *
 * The deadline runs from submit. On the thread backend a work callback, a
 * signal wait or a process wait heading its chain is ended at the deadline
 * even while it still waits for a free worker, and a one-shot poll heading
 * its chain is answered at submit if its descriptor is ready then (see
 * ior_prep_poll_add()), so this link timeout never arms and completes with
 * -ECANCELED. Any other op (a read, a write, a send or a receive) only
 * learns whether it can wait without its worker once one takes it, so one
 * still waiting for a worker at its deadline is ended then, late: it never
 * starts, completing with -ECANCELED and this link timeout with -ETIME.
 *
 * A read or write of a pollable descriptor (a socket, a pipe) waiting for
 * readiness is cancelled at the deadline; one of a regular file runs to
 * completion, as on io_uring, where a cached read even completes at submit,
 * before its link timeout is armed. io_uring from 6.16 arms the link timeout
 * around the issue instead, so a zero one can fire while such a completion is
 * still being flushed and report -ENOENT, its cancel having found nothing
 * left, or -ETIME, the completion having disarmed it just as it fired; the
 * guarded op reports its result either way. If the guarded op is cancelled
 * with ior_prep_cancel() instead, both it and this link timeout complete with
 * -ECANCELED.
 *
 * @p ts is read by the submit that takes the entry, as for ior_prep_timeout().
 *
 * @param ctx    I/O context.
 * @param sqe    Entry from ior_get_sqe(), submitted right after the guarded op.
 * @param ts     Deadline after which the guarded op is cancelled: a relative
 *               duration, or an absolute deadline if IOR_TIMEOUT_ABS is set in
 *               @p flags, on the clock the other IOR_TIMEOUT_* flags select.
 * @param flags  IOR_TIMEOUT_ABS to treat @p ts as an absolute deadline,
 *               IOR_TIMEOUT_BOOTTIME / IOR_TIMEOUT_REALTIME to pick its clock,
 *               else 0.
 */
void ior_prep_link_timeout(ior_ctx *ctx, ior_sqe *sqe, ior_timespec *ts, unsigned flags);

/**
 * Prepare a send on a connected socket.
 *
 * @param ctx     I/O context.
 * @param sqe     Entry from ior_get_sqe().
 * @param sockfd  Connected socket descriptor.
 * @param buf     Data to send.
 * @param nbytes  Number of bytes to send.
 * @param flags   Send flags (MSG_*).
 */
void ior_prep_send(
		ior_ctx *ctx, ior_sqe *sqe, ior_fd_t sockfd, const void *buf, unsigned nbytes, int flags);

/**
 * Prepare a receive from a connected socket.
 *
 * @param ctx     I/O context.
 * @param sqe     Entry from ior_get_sqe().
 * @param sockfd  Connected socket descriptor.
 * @param buf     Destination buffer.
 * @param nbytes  Maximum number of bytes to receive.
 * @param flags   Receive flags (MSG_*).
 */
void ior_prep_recv(
		ior_ctx *ctx, ior_sqe *sqe, ior_fd_t sockfd, void *buf, unsigned nbytes, int flags);

/**
 * Prepare an accept on a listening socket (like io_uring's ACCEPT).
 *
 * Completes with the accepted socket as res (>= 0), or a negative errno. On
 * Windows res is the accepted SOCKET cast to int32 (handles fit); the socket
 * is overlapped, associated with the context's port and ready for
 * ior_prep_send()/ior_prep_recv(). @p addr and @p addrlen, if non-NULL, are
 * filled with the peer address as accept(2) does; @p addrlen must be
 * initialised to the buffer size and stays valid until completion.
 *
 * The thread backend takes a blocking listener's mode over while the op
 * waits for readiness on its poller (see IOR_SETUP_FD_NONBLOCK), so the op is
 * cancellable and never occupies a worker, and restores it once the last
 * op on the listener completes; the accepted socket gets exactly the state
 * @p flags asks for, whatever the listener's mode.
 *
 * Under IOR_SETUP_FD_NONBLOCK, pass IOR_ACCEPT_NONBLOCK. That promise covers
 * the accepted socket as soon as you submit an operation on it, and nothing
 * else puts it in non-blocking mode: accepted without the flag, it is a
 * blocking descriptor the backend will take at its word.
 *
 * IOR_CQE_F_SOCK_NONEMPTY among the completion's flags says another
 * connection is queued already (a hint; see the flag).
 *
 * @param ctx      I/O context.
 * @param sqe      Entry from ior_get_sqe().
 * @param fd       Listening socket.
 * @param addr     Buffer for the peer address, or NULL.
 * @param addrlen  In/out size of @p addr, or NULL.
 * @param flags    IOR_ACCEPT_NONBLOCK, IOR_ACCEPT_CLOEXEC, or 0; any other bit
 *                 fails the entry at submit with -EINVAL (see ior_submit()).
 */
void ior_prep_accept(ior_ctx *ctx, ior_sqe *sqe, ior_fd_t fd, struct sockaddr *addr,
		socklen_t *addrlen, unsigned flags);

/**
 * Prepare a persistent accept on a listening socket (like io_uring's
 * multishot ACCEPT, IORING_ACCEPT_MULTISHOT).
 *
 * Like ior_prep_accept(), but the operation stays armed: it posts a
 * completion for every connection it accepts, with the accepted socket as
 * res (as ior_prep_accept() reports it, @p flags applied to each) and
 * IOR_CQE_F_MORE among its flags, until it is cancelled (ior_prep_cancel(),
 * ior_prep_cancel_fd(), a fired link timeout, ior_queue_exit()) or fails;
 * that posts its last completion, without IOR_CQE_F_MORE, carrying
 * -ECANCELED or the error (-EMFILE, say). Every completion carries the
 * operation's user data. No peer address is reported, since one buffer
 * would be overwritten per connection; ask the accepted socket
 * (getpeername(2)).
 *
 * Connections accepted before the last completion still arrive, with
 * IOR_CQE_F_MORE, ahead of it: reap until the completion without the flag,
 * and close what you do not want; one may carry IOR_CQE_F_SOCK_NONEMPTY,
 * another connection being queued behind it (a hint; see the flag). On
 * io_uring and the thread backend the
 * operation also ends on its own when a connection finds the completion
 * queue full: that connection is its last completion, with the socket as
 * res (>= 0) and no IOR_CQE_F_MORE, as io_uring ends a multishot accept.
 * IOCP keeps a few accepts outstanding, and ends only when no memory is
 * left. Re-arm by submitting a new operation. A connection the peer resets
 * while it is still queued is dropped, not reported and not the end of the
 * operation, where the system reports the reset to the accept at all
 * (FreeBSD, Windows); Linux and macOS hand the dead socket over as any
 * other.
 *
 * io_uring uses IORING_ACCEPT_MULTISHOT (Linux 5.19). The thread backend
 * accepts what is queued at submit on a worker, then watches the listener
 * edge-triggered on its poller, as a multishot poll, taking a blocking
 * listener's mode over meanwhile (see ior_prep_accept()), and accepts on
 * the poller thread until the backlog is empty at every edge. IOCP keeps
 * four AcceptEx outstanding, each with a socket created ahead of the
 * listener's family and protocol, and issues another after each
 * completion. A link timeout bounds the whole operation as it does a
 * multishot poll; do not link another entry behind it.
 *
 * @param ctx    I/O context.
 * @param sqe    Entry from ior_get_sqe().
 * @param fd     Listening socket.
 * @param flags  IOR_ACCEPT_NONBLOCK, IOR_ACCEPT_CLOEXEC, or 0, applied to
 *               every accepted socket; any other bit fails the entry at
 *               submit with -EINVAL (see ior_submit()).
 */
void ior_prep_accept_multishot(ior_ctx *ctx, ior_sqe *sqe, ior_fd_t fd, unsigned flags);

/**
 * Prepare a connect (like io_uring's CONNECT).
 *
 * Completes with 0 once the connection is established, or a negative errno
 * (-ECONNREFUSED, -ETIMEDOUT, ...). @p addr must stay valid until completion.
 *
 * The thread backend takes a blocking socket's mode over (see
 * IOR_SETUP_FD_NONBLOCK), starts the connection and waits for writability on
 * its poller, so the op is cancellable and never occupies a worker, and
 * restores the mode once the op completes. On
 * Windows an unbound socket is bound to the wildcard address first, as
 * ConnectEx requires. A connect that fails or is cancelled leaves the socket
 * unusable for another connect on every backend, as connect(2) and
 * ConnectEx do; create a fresh socket to retry.
 *
 * @param ctx      I/O context.
 * @param sqe      Entry from ior_get_sqe().
 * @param fd       Socket to connect.
 * @param addr     Address to connect to.
 * @param addrlen  Size of @p addr.
 */
void ior_prep_connect(
		ior_ctx *ctx, ior_sqe *sqe, ior_fd_t fd, const struct sockaddr *addr, socklen_t addrlen);

/**
 * Prepare a wait for a process state change (like waitpid(2) with WNOWAIT).
 *
 * Completes with the pid of the process whose state changed as res (> 0),
 * its wait status stored in @p status (if non-NULL) as waitpid(2) stores it,
 * or a negative errno: -ECHILD when @p pid is not a child of the caller (or
 * was collected already), -ECANCELED when cancelled. With WNOHANG in
 * @p options the op never waits and completes with 0 when nothing has
 * changed.
 *
 * ior never collects the process: the completion reports a child that is
 * waitable, and it stays so until the caller collects it, with
 * waitpid(WNOHANG) for the reported pid and the options it asked with, or
 * a wait of its own. Until then every wait that covers the child reports
 * it again, so two waits on it both complete, and a caller whose collect
 * finds it gone (-ECHILD or 0: another waiter took it) resubmits. A
 * completion nobody acts on, a cancelled or timed out op, and
 * ior_queue_exit() all leave the child as it is, and no pid is freed for
 * reuse until the caller collects it.
 *
 * No wait occupies a thread, whatever it asks for: a cancel takes it back
 * (0, the op -ECANCELED), a link timeout ends it at its deadline the same
 * way, and ior_queue_exit() does not wait for the child. io_uring asks the
 * kernel (IORING_OP_WAITID with WNOWAIT, Linux 6.7). Elsewhere a wait for
 * one child (@p pid > 0, no options) is watched: a pidfd poll on io_uring,
 * the thread backend's poller (a pidfd on Linux, EVFILT_PROC on kqueue), a
 * wait on the process handle on IOCP. Every other request (-1 for any
 * child, a process group, WUNTRACED or WCONTINUED, or a platform without a
 * process watch) is probed with waitid(WNOHANG | WNOWAIT) from a timer,
 * first at once and then at intervals doubling from 1 ms to 20 ms, so it
 * sees a change up to that much later than waitpid(2) would. A stop or
 * continue report is pending the same way until a wait with WUNTRACED or
 * WCONTINUED collects it.
 *
 * Windows accepts only @p pid > 0 (-ENOTSUP otherwise), ignores @p options
 * and stores the exit code in @p status. Any process can be waited for
 * there, not only a child; -ECHILD means no such process. There is nothing
 * to collect: the op opens the process by id when submitted, so keep a
 * handle to it open until the completion arrives, since once a process has
 * exited and its last handle is closed, its id may be given to another
 * process.
 *
 * @param ctx      I/O context.
 * @param sqe      Entry from ior_get_sqe().
 * @param pid      Process to wait for, with waitpid(2) meaning on POSIX.
 * @param status   Where to store the wait status, or NULL.
 * @param options  waitpid(2) options (WNOHANG, WUNTRACED, ...); 0 on Windows.
 * @return 0 on success, -EINVAL for bad arguments, or -ENOMEM.
 */
int ior_prep_waitpid(ior_ctx *ctx, ior_sqe *sqe, ior_pid_t pid, int *status, int options);

/**
 * Prepare a wait for one of a set of signals (like sigwaitinfo(2)).
 *
 * Completes with the number of the signal taken as res (> 0), its details
 * stored in @p info (if non-NULL) as sigwaitinfo(2) stores them, or a
 * negative errno: -ECANCELED when cancelled, -EAGAIN when the signal was
 * consumed elsewhere between its arrival and ior collecting it (see below).
 * The signal is consumed: it is not delivered to a handler and not seen by
 * any other wait. Every signal in @p set must be blocked in every thread of
 * the process before it can arrive, as sigwaitinfo(2) requires; the
 * caller's own threads are the caller's to mask (ior's threads block
 * everything already). A signal sent to the process as a whole is what the
 * op waits for; one directed at a particular thread with pthread_kill(3) is
 * seen only if that thread is the one calling ior, and not at all on the
 * thread backend, whose worker is the waiting thread.
 *
 * On io_uring the op is a poll on a signalfd, which occupies no thread and
 * is cancellable, and a link timeout bounds it. When the poll fires, the
 * signal is collected on the reaping thread; if it is gone by then (another
 * op in this context waiting for the same signal collected it, or a wait
 * of the caller's own), the op completes with -EAGAIN and can be submitted
 * again. On the thread backend a worker waits in sigtimedwait(2) in short
 * slices, so a cancel reports -EALREADY and the op completes with -ECANCELED
 * within a slice, as it does for a fired link timeout and at
 * ior_queue_exit(); every pending op occupies a worker for as long as it
 * waits. Where the platform has no sigtimedwait (macOS) the worker blocks in
 * sigwait(3) until a signal from the set arrives, uncancellable, filling
 * only si_signo in @p info, and ior_queue_exit() waits for it: a cancel then
 * reports -EALREADY, as does a link timeout at its deadline, and the op
 * completes with the signal (see ior_prep_link_timeout()).
 *
 * Windows knows console control events only: @p set may name SIGINT
 * (Ctrl+C) and SIGBREAK (Ctrl+Break, and the close, logoff and shutdown
 * events, as the CRT maps them); any other signal makes this call return
 * -ENOTSUP. The event is claimed by the op ahead of the CRT's signal()
 * handlers and the default action, and @p info carries the CTRL_*_EVENT in
 * si_code. The system ends the process once the handler returns from a
 * close, logoff or shutdown event, so a completion for those may never be
 * seen. An op is cancellable and bounded by a link timeout.
 *
 * @p set and @p info must stay valid until the completion arrives.
 *
 * A completion that reports a signal took it: one the caller discards (a
 * cancel that came too late, a caller gone) should put it back with
 * ior_sigrequeue(), or the process never sees that signal.
 *
 * @param ctx   I/O context.
 * @param sqe   Entry from ior_get_sqe().
 * @param set   Signals to wait for; built with ior_sigemptyset() and
 *              ior_sigaddset() (sigemptyset(3)/sigaddset(3) on POSIX).
 * @param info  Where to store the signal's details, or NULL.
 * @return 0 on success, -EINVAL for a NULL or empty set, -ENOTSUP for a
 *         signal the platform cannot wait for, -ENOMEM, or the error of
 *         signalfd(2) on io_uring.
 */
int ior_prep_sigwait(ior_ctx *ctx, ior_sqe *sqe, const ior_sigset_t *set, ior_siginfo_t *info);

/**
 * @name Signal sets
 * Portable construction of the ::ior_sigset_t given to ior_prep_sigwait():
 * sigemptyset(3), sigaddset(3) and sigismember(3) on POSIX, bit operations on
 * Windows, where the set holds CRT signal numbers.
 * @{
 */
/** Empty @p set. Returns 0. */
int ior_sigemptyset(ior_sigset_t *set);
/** Add @p signo to @p set. Returns 0, or -EINVAL for an invalid signal. */
int ior_sigaddset(ior_sigset_t *set, int signo);
/** Test @p set for @p signo. Returns 1 if present, 0 if not, -EINVAL for an
 *  invalid signal. */
int ior_sigismember(const ior_sigset_t *set, int signo);
/** @} */

/**
 * Put back a signal an ior_prep_sigwait() op took, as if it had never been
 * taken: for a completion the caller discards (its op was cancelled too late,
 * or nobody waits for it any more), so the next wait for the signal still
 * gets it rather than the process losing it.
 *
 * On POSIX the signal is queued to the process again and stays pending while
 * it is blocked, as a SigWait needs it to be. On Linux @p info goes back as
 * it is (rt_sigqueueinfo(2)); the kernel accepts a kernel's or kill()'s
 * si_code only from the main thread, so from any other one it goes back as
 * SI_QUEUE, keeping si_pid, si_uid and si_value. Elsewhere a queued signal
 * goes back with its value (sigqueue(3)), and any other with kill(2). A
 * real-time signal requeued queues behind any of its number that arrived
 * since; a standard one that is pending again merges with it, as the kernel
 * merges them.
 *
 * On Windows the console control event in si_code is offered to the pending
 * sigwait ops of every context, as on its arrival; with no taker, raise()
 * hands the signal to the CRT's signal() handler, or its default action.
 *
 * @param info  What the op reported (si_signo and, on Windows, si_code).
 * @return 0, -EINVAL for a NULL @p info or an invalid signal, or the error of
 *         queueing it (-EAGAIN when the process has too many pending).
 */
int ior_sigrequeue(const ior_siginfo_t *info);

/** @p flags of ior_prep_dir_changes(): watch the whole subtree. */
#define IOR_DIR_CHANGES_SUBTREE (1U << 0)

/**
 * Prepare a wait for changes in a directory (like ReadDirectoryChangesW()).
 *
 * Completes with the number of bytes written to @p buf as res: a chain of
 * FILE_NOTIFY_INFORMATION records, linked by NextEntryOffset, for the names
 * created, removed or renamed and the entries whose attributes, size, write,
 * access or creation time or security changed. Changes of the directory
 * itself are not reported. 0 means the records did not fit, the system's
 * buffer or @p buf: changes were lost, and the caller enumerates the
 * directory. -ECANCELED when cancelled.
 *
 * The first op on a handle starts the watch, and the system keeps the
 * changes that come between ops in a buffer the size of that op's @p buf,
 * for the handle's life. So every op on a handle uses the same @p flags and
 * @p nbytes, and the next one follows each completion at once. The handle is a
 * directory opened with FILE_LIST_DIRECTORY and FILE_FLAG_BACKUP_SEMANTICS |
 * FILE_FLAG_OVERLAPPED; the op associates it with the context's completion
 * port, as a read does (see ior_release_handle()).
 *
 * Windows only: other backends return -ENOTSUP, and report no
 * IOR_FEAT_DIR_CHANGES.
 *
 * @param ctx     I/O context.
 * @param sqe     Entry from ior_get_sqe().
 * @param dir     The directory's handle.
 * @param buf     Must be DWORD-aligned; valid until the completion arrives.
 * @param nbytes  Size of @p buf, at most 64 KiB for a directory on a share.
 * @param flags   IOR_DIR_CHANGES_SUBTREE or 0.
 * @return 0 on success, -EINVAL for a NULL or unaligned @p buf, a zero
 *         @p nbytes or an unknown flag, or -ENOTSUP.
 */
int ior_prep_dir_changes(
		ior_ctx *ctx, ior_sqe *sqe, ior_fd_t dir, void *buf, unsigned nbytes, uint32_t flags);

/**
 * Prepare a one-shot wait for fd readiness (like io_uring's POLL_ADD).
 *
 * Completes when the descriptor becomes ready for any requested event: the CQE
 * res is the mask of ready IOR_POLL_* events (> 0), or a negative errno. The
 * operation is one-shot; re-arm by submitting a new poll. Requires
 * IOR_FEAT_POLL_ADD. For a bounded wait, guard it with ior_prep_link_timeout()
 * (poll completes with -ECANCELED, the timeout with -ETIME).
 *
 * On the threads and IOCP backends all pending polls are multiplexed on a
 * single poller thread. On the IOCP backend only sockets are pollable; other
 * handles complete with -ENOTSOCK.
 *
 * A descriptor ready at submit completes the poll there, on every backend:
 * before anything submitted after it runs, so a cancel in the same submit
 * finds it gone (-ENOENT), and before its link timeout is armed, so a zero
 * link timeout (a liveness check that must not wait) finds the poll done and
 * completes with -ECANCELED (on io_uring possibly -ENOENT, see
 * ior_prep_link_timeout()). A regular file is always ready.
 *
 * @param ctx        I/O context.
 * @param sqe        Entry from ior_get_sqe().
 * @param fd         Descriptor to watch.
 * @param poll_mask  Events to wait for (IOR_POLL_IN, IOR_POLL_OUT, ...).
 */
void ior_prep_poll_add(ior_ctx *ctx, ior_sqe *sqe, ior_fd_t fd, uint32_t poll_mask);

/**
 * Prepare a persistent wait for fd readiness (like io_uring's multishot
 * POLL_ADD, IORING_POLL_ADD_MULTI).
 *
 * Like ior_prep_poll_add(), but the operation stays armed: it posts a
 * completion for every readiness edge, with the ready IOR_POLL_* mask as res
 * and IOR_CQE_F_MORE among its flags, until it is cancelled (ior_prep_cancel(),
 * ior_prep_cancel_fd(), a fired link timeout, ior_queue_exit()) or fails; that
 * posts its last completion, without IOR_CQE_F_MORE, carrying -ECANCELED or
 * the error. Every completion carries the operation's user data.
 *
 * Readiness is reported when it appears, not while it lasts, as with EPOLLET:
 * a descriptor that stays readable because nothing reads it produces no
 * further completions, and one more arrives when new data comes in. Consume
 * readiness fully after each completion (read until -EAGAIN) before waiting
 * for the next. A peer hang-up is one edge (IOR_POLL_HUP, with
 * IOR_CQE_F_MORE still set: the operation cannot tell it is the last event);
 * cancel the poll once it has been seen. A regular file is always ready and
 * completes at once with its mask as the last completion.
 *
 * The operation may also end on its own, with a positive res and no
 * IOR_CQE_F_MORE, when an edge finds the completion queue full: io_uring and
 * the thread backend end it then. IOCP holds the poll out of its wait until
 * the consumer has seen the previous edge, so its edges cannot pile up, and
 * it ends only when no memory is left.
 * Re-arm by submitting a new poll.
 *
 * io_uring uses IORING_POLL_ADD_MULTI. The thread backend watches the
 * descriptor edge-triggered on its poller (EPOLLET on epoll, EV_CLEAR on
 * kqueue). The thread backend's poll(2) poller and the IOCP backend's WSAPoll
 * poller cannot observe edges: they report readiness that persists again, the
 * poll(2) poller after about a millisecond and the IOCP one once the previous
 * completion has been marked seen (ior_cqe_seen(), ior_cq_advance()), so no
 * edge is missed, but an undrained descriptor (or one at hang-up) keeps
 * completing until the poll is cancelled.
 *
 * A link timeout bounds the whole operation: when it fires, the poll completes
 * with -ECANCELED and the timeout with -ETIME; when the poll ends first, the
 * timeout completes with -ECANCELED. Do not link another entry behind a
 * multishot poll: the chain continues only at the poll's last completion.
 *
 * @param ctx        I/O context.
 * @param sqe        Entry from ior_get_sqe().
 * @param fd         Descriptor to watch.
 * @param poll_mask  Events to wait for (IOR_POLL_IN, IOR_POLL_OUT, ...).
 */
void ior_prep_poll_multishot(ior_ctx *ctx, ior_sqe *sqe, ior_fd_t fd, uint32_t poll_mask);

/**
 * Prepare a cancellation of a submitted operation, matched by user data.
 *
 * Cancellation follows io_uring: the cancel is itself an operation with its
 * own completion, and the target completes separately with -ECANCELED. The
 * cancel's res is:
 *   - 0: the target was found and cancelled; its CQE (res == -ECANCELED)
 *     follows, as does the CQE of a link timeout attached to it (also
 *     -ECANCELED) and of every later entry in its link chain;
 *   - -ENOENT: no matching operation is in flight (it already completed, or
 *     was never submitted);
 *   - -EALREADY: the target was found but is executing and cannot be
 *     interrupted (a work callback, a syscall on a regular file, or a
 *     socket op in its non-blocking attempt); it completes on its own,
 *     with its real result or with -ECANCELED if it was about to wait for
 *     readiness. A running work callback sees ior_work_cancelled() return
 *     non-zero so it can return early.
 * If several in-flight operations share the user data, one of them is
 * cancelled per call.
 *
 * Both CQEs must be reaped: the target's buffers stay in use until its own
 * completion arrives, whatever the cancel reported. A link timeout cannot be
 * targeted directly (-ENOENT); cancel its guarded operation instead. Entries
 * that were prepared but not yet submitted cannot be cancelled.
 *
 * @param ctx        I/O context.
 * @param sqe        Entry from ior_get_sqe().
 * @param user_data  The pointer set with ior_sqe_set_data() on the target.
 */
void ior_prep_cancel(ior_ctx *ctx, ior_sqe *sqe, void *user_data);

/**
 * Prepare a cancellation of one operation submitted on a descriptor.
 *
 * Like ior_prep_cancel() but matches by descriptor (read, write, send, recv,
 * poll, splice); operations without one (timeouts, work, no-ops) never match.
 * One operation is cancelled per call, so to tear down everything on a
 * descriptor submit cancels until one completes with -ENOENT. An invalid
 * descriptor completes with -EBADF.
 *
 * Cancel before closing a descriptor. What happens to operations still in
 * flight when it is closed is not portable: io_uring keeps the file open
 * until they complete, IOCP fails them with the error the driver reports
 * for a closed object (-ECONNABORTED on a socket, -EPIPE on a pipe). On IOCP
 * the value of a closed handle may be reused by the next open at once; the
 * backend tolerates that, but only operations that were submitted after the
 * reopen belong to the new object.
 *
 * @param ctx  I/O context.
 * @param sqe  Entry from ior_get_sqe().
 * @param fd   Descriptor whose operation to cancel.
 */
void ior_prep_cancel_fd(ior_ctx *ctx, ior_sqe *sqe, ior_fd_t fd);

/**
 * @brief Opaque per-operation handle passed to a work callback.
 *
 * Lets a running callback observe cancellation (a fired link timeout or
 * context teardown) via ior_work_cancelled(). Valid only for the duration of
 * the callback invocation.
 */
typedef struct ior_work_token ior_work_token;

/**
 * @brief User work callback executed on the backend's thread pool.
 *
 * The returned value becomes the operation's CQE result (use a negative errno
 * to report failure, e.g. -ECANCELED after observing cancellation).
 *
 * @param token  Cancellation handle; poll ior_work_cancelled(token) from
 *               long-running callbacks to support link timeouts and fast
 *               teardown. Valid only during this invocation.
 * @param arg    The pointer given to ior_prep_work().
 */
typedef int32_t (*ior_work_fn)(ior_work_token *token, void *arg);

/**
 * Prepare a work operation: run @p fn on the backend's worker thread pool and
 * post a CQE with its return value once it finishes.
 *
 * Execution starts at ior_submit(). Every successfully submitted work op
 * invokes its callback exactly once - including during ior_queue_exit(), which
 * waits for queued callbacks to run - unless a linked timeout fires before the
 * callback has started, in which case the callback never runs and the op
 * completes with -ECANCELED.
 *
 * Attach ior_sqe_set_data() as with any other op to correlate the completion;
 * @p arg is independent of the CQE user data.
 *
 * A work op may be guarded by ior_prep_link_timeout() (submit the work op with
 * IOR_SQE_IO_LINK, the link timeout as the next entry). Both entries always
 * produce a CQE:
 *   - callback finishes first: work CQE = callback's return value, link
 *     timeout CQE = -ECANCELED;
 *   - timeout fires before the callback started, queued behind busy workers
 *     included: work CQE = -ECANCELED (the callback never runs), link timeout
 *     CQE = -ETIME;
 *   - timeout fires while the callback runs: the callback cannot be killed;
 *     the token is flagged so it can return early, the link timeout CQE =
 *     -EALREADY is posted at the deadline, and the work CQE carries the
 *     callback's return value once it returns. @p arg stays in use until
 *     then, and the callback keeps its worker thread busy.
 * Other IOR_SQE_IO_LINK / IOR_SQE_IO_DRAIN combinations involving work ops are
 * not supported on the io_uring backend (the kernel cannot order around a
 * userspace callback).
 *
 * @param ctx  I/O context.
 * @param sqe  Entry from ior_get_sqe().
 * @param fn   Callback to run; its return value becomes the CQE result.
 * @param arg  Opaque pointer passed to @p fn.
 * @return 0 on success, -EINVAL for bad arguments, or -ENOMEM.
 */
int ior_prep_work(ior_ctx *ctx, ior_sqe *sqe, ior_work_fn fn, void *arg);

/**
 * Check whether a running work callback has been cancelled.
 *
 * Returns non-zero once the guarding link timeout has fired or the context is
 * being torn down. Callable only from within the work callback that received
 * @p token.
 *
 * @param token  The token passed to the running callback.
 * @return Non-zero if cancelled, 0 otherwise.
 */
int ior_work_cancelled(const ior_work_token *token);

/**
 * Attach an opaque user-data pointer to an entry.
 *
 * The same pointer is returned by ior_cqe_get_data() on the operation's
 * completion, letting the caller correlate completions with their requests.
 *
 * @param ctx   I/O context.
 * @param sqe   Entry from ior_get_sqe().
 * @param data  Arbitrary user pointer.
 */
void ior_sqe_set_data(ior_ctx *ctx, ior_sqe *sqe, void *data);

/**
 * Set IOR_SQE_* flags on an entry (e.g. IOR_SQE_IO_LINK, IOR_SQE_IO_DRAIN).
 *
 * @param ctx    I/O context.
 * @param sqe    Entry from ior_get_sqe().
 * @param flags  Bitwise OR of IOR_SQE_* flags.
 */
void ior_sqe_set_flags(ior_ctx *ctx, ior_sqe *sqe, uint8_t flags);

/**
 * Retrieve the user data attached to a completion.
 *
 * @param ctx  I/O context.
 * @param cqe  A completion from peek/wait.
 * @return The user-data pointer set with ior_sqe_set_data() on the originating
 *         submission entry.
 */
void *ior_cqe_get_data(ior_ctx *ctx, ior_cqe *cqe);

/**
 * Retrieve the result of a completed operation.
 *
 * @param ctx  I/O context.
 * @param cqe  A completion from peek/wait.
 * @return A byte count (>= 0) for read/write/send/recv, 0 for a no-op, or a
 *         negative errno on failure (e.g. -ETIME for a timeout).
 */
int32_t ior_cqe_get_res(ior_ctx *ctx, ior_cqe *cqe);

/**
 * Retrieve the operation/backend-specific flags of a completion.
 *
 * @param ctx  I/O context.
 * @param cqe  A completion from peek/wait.
 * @return The completion flags (0 if none apply).
 */
uint32_t ior_cqe_get_flags(ior_ctx *ctx, ior_cqe *cqe);

/* Completion notification */

/**
 * Descriptor that becomes readable when completions are posted, for a loop
 * that embeds a context without making ior its blocking wait.
 *
 * Behaves like io_uring's registered eventfd on every backend: it is signalled
 * for each completion posted to the queue and is never cleared by ior, so a
 * loop waits for it to be readable, clears it with ior_notify_clear(), and
 * then reaps with ior_peek_cqe() until nothing is pending:
 *
 *     wait for readability
 *     ior_notify_clear(ctx);
 *     while (ior_peek_cqe(ctx, &cqe) == 0) { ... ior_cqe_seen(ctx, cqe); }
 *
 * Clear before reaping, not after. A completion is posted to the queue before
 * its signal, so one posted before the clear is already visible to the peeks
 * that follow, and one posted after it signals again. Clearing after reaping
 * instead drains the signal of any completion that landed in between, and
 * that completion then waits unreaped until unrelated traffic wakes the
 * descriptor again. A spurious wakeup that finds nothing is harmless. Mixing
 * this with ior_wait_cqe() is fine (the wait clears the descriptor as part of
 * its own blocking).
 *
 * Reap until the queue is empty. A clear consumes every pending signal at
 * once, so whatever is left unreaped is not announced again and waits for the
 * next completion; bounding the work per iteration strands it. This is the
 * registered eventfd's own behaviour, whose counter tracks completions posted
 * rather than entries still in the queue.
 *
 * Completions already pending when the descriptor is first requested are
 * announced by that call, so a loop may create the descriptor after
 * submitting.
 *
 * On the io_uring backend this is an eventfd registered with the ring (created
 * on first call); on the threads backend the eventfd or pipe workers already
 * signal; on Windows the readable end of a loopback socket pair fed by a
 * thread that pumps the completion port (started on first call), so that
 * WSAPoll() can wait on it. The descriptor is owned by the context and closed
 * by ior_queue_exit(); never close it.
 *
 * @param ctx  I/O context.
 * @return The descriptor (a SOCKET cast to ior_fd_t on Windows), or
 *         IOR_INVALID_FD if it could not be created.
 */
ior_fd_t ior_notify_fd(ior_ctx *ctx);

/**
 * Consume the pending signals of ior_notify_fd(), making it not readable until
 * the next completion is posted. Call it after waking and before reaping, and
 * reap the queue empty afterwards: this consumes every pending signal, not one
 * per completion. See ior_notify_fd(). Never blocks.
 *
 * @param ctx  I/O context.
 * @return 0 on success, -EINVAL if ior_notify_fd() has not been called, or a
 *         negative errno.
 */
int ior_notify_clear(ior_ctx *ctx);

/* Backend info */

/**
 * Query which backend a context is using.
 *
 * @param ctx  I/O context.
 * @return The backend selected for @p ctx.
 */
ior_backend_type ior_get_backend_type(ior_ctx *ctx);

/**
 * Get the human-readable name of the context's backend.
 *
 * @param ctx  I/O context.
 * @return A static backend name string (e.g. "io_uring", "threads", "iocp").
 */
const char *ior_get_backend_name(ior_ctx *ctx);

/**
 * Query the feature flags supported by the context's backend.
 *
 * @param ctx  I/O context.
 * @return A bitwise OR of the IOR_FEAT_* flags the active backend provides.
 */
uint32_t ior_get_features(ior_ctx *ctx);

/* Queue capacity */

/**
 * Size of the submission queue: how many entries ior_get_sqe() hands out
 * between two calls to ior_submit(). The size the backend settled on, which
 * may exceed the one requested (see ior_queue_init_params()).
 *
 * @param ctx  I/O context.
 * @return The number of submission queue entries, or 0 for a NULL context.
 */
unsigned ior_sq_entries(ior_ctx *ctx);

/**
 * Size of the completion queue, as the backend settled on it: how many
 * completions wait for the reaper in it. It bounds nothing else; completions
 * beyond it wait outside it, in order.
 *
 * @param ctx  I/O context.
 * @return The number of completion queue entries, or 0 for a NULL context.
 */
unsigned ior_cq_entries(ior_ctx *ctx);

/**
 * Submission queue entries still free: the number of ior_get_sqe() calls that
 * will succeed before ior_submit() is needed.
 *
 * @param ctx  I/O context.
 * @return The free entry count, or 0 for a NULL context.
 */
unsigned ior_sq_space_left(ior_ctx *ctx);

/**
 * Completion queue entries free: how many more completions fit before one
 * has to wait outside the queue for a reap, as io_uring's CQ ring reports it.
 * 0 while completions are waiting outside. Informational: it refuses nothing,
 * and operations in flight do not count.
 *
 * @param ctx  I/O context.
 * @return The free entry count, or 0 for a NULL context.
 */
unsigned ior_cq_space_left(ior_ctx *ctx);

#ifdef __cplusplus
}
#endif

#endif /* IOR_H */
