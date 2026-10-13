/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef IOR_BACKEND_H
#define IOR_BACKEND_H

#include "ior.h"
#include "ior_log.h"
#include <stdatomic.h>
#include <errno.h>

/*
 * Work-op cancellation token, shared by all backends. Embedded in the
 * backend's per-op state; `cancelled` is set by whichever thread arbitrates a
 * fired link timeout, `shutdown` points at the backend's teardown flag so a
 * running callback can also bail out during ior_queue_exit().
 */
struct ior_work_token {
	_Atomic int cancelled;
	const _Atomic int *shutdown; /* may be NULL */
};

/* Set in a cancel op's flags by prep_cancel_fd: match by fd, not user data. */
#define IOR_CANCEL_BY_FD (1U << 0)

/*
 * IOR_SQE_FIXED_FILE on an op that takes a descriptor: io_uring looks it up
 * in the registered file table, which ior never fills, so the op fails with
 * -EBADF when it is issued. Ops without a descriptor ignore the flag.
 */
static inline int ior_fixed_file_bad(uint8_t opcode, uint8_t sqe_flags, uint32_t cancel_flags)
{
	if (!(sqe_flags & IOR_SQE_FIXED_FILE)) {
		return 0;
	}
	switch (opcode) {
		case IOR_OP_READ:
		case IOR_OP_WRITE:
		case IOR_OP_SPLICE:
		case IOR_OP_ACCEPT:
		case IOR_OP_CONNECT:
		case IOR_OP_SEND:
		case IOR_OP_RECV:
		case IOR_OP_POLL:
		case IOR_OP_DIR_CHANGES:
			return 1;
		case IOR_OP_ASYNC_CANCEL:
			return (cancel_flags & IOR_CANCEL_BY_FD) != 0;
		default:
			return 0;
	}
}

/* Set in a poll op's len by prep_poll_multishot (io_uring's own encoding):
 * the poll persists, one completion per readiness edge. */
#define IOR_POLL_ADD_MULTI (1U << 0)

/* Set in an accept op's ioprio by prep_accept_multishot (io_uring's own
 * encoding): the accept persists, one completion per connection. */
#define IOR_ACCEPT_MULTISHOT (1U << 0)

/* Backend-specific SQE structures */
#ifdef IOR_HAVE_URING
#include <liburing.h>

typedef struct ior_sqe_uring {
	struct io_uring_sqe sqe;
} ior_sqe_uring;

typedef struct ior_cqe_uring {
	__u64 user_data;
	__s32 res;
	__u32 flags;
	/* Reserve space for IORING_SETUP_CQE32 extension (16 bytes) */
	__u64 big_cqe[2];
} ior_cqe_uring;
#endif

#ifdef IOR_HAVE_THREADS
/* Threads backend SQE/CQE */
typedef struct ior_sqe_threads {
	uint8_t opcode;
	uint8_t flags;
	uint16_t ioprio;
	ior_fd_t fd;
	uint64_t off;
	uint64_t addr;
	uint32_t len;
	union {
		uint32_t rw_flags;
		uint32_t splice_flags;
		uint32_t timeout_flags;
		uint32_t poll_events;
		uint32_t cancel_flags;
	};
	uint64_t user_data;
	union {
		ior_fd_t splice_fd_in;
		uint32_t file_index;
	};
	uint64_t splice_off_in;
	/* TIMER / LINK_TIMEOUT: the caller's timespec (addr points at it until
	 * submit), copied here by submit so the caller's may go out of scope. */
	ior_timespec ts;
} ior_sqe_threads;

typedef struct ior_cqe_threads {
	uint64_t user_data;
	int32_t res;
	uint32_t flags;
} ior_cqe_threads;
#endif

/* IOCP backend SQE/CQE */
#ifdef IOR_HAVE_IOCP
typedef struct ior_sqe_iocp {
	uint8_t opcode;
	uint8_t flags;
	uint16_t ioprio;
	ior_fd_t fd;
	uint64_t off;
	uint64_t addr;
	uint32_t len;
	union {
		uint32_t rw_flags;
		uint32_t timeout_flags;
	};
	uint64_t user_data;
	uint32_t file_index;
	uint64_t __pad[3];
} ior_sqe_iocp;

typedef struct ior_cqe_iocp {
	uint64_t user_data;
	int32_t res;
	uint32_t flags;
} ior_cqe_iocp;
#endif

/* Actual opaque type definitions - unions of all backend types */
struct ior_sqe {
#ifdef IOR_HAVE_URING
	ior_sqe_uring uring;
#endif
#ifdef IOR_HAVE_THREADS
	ior_sqe_threads threads;
#endif
#ifdef IOR_HAVE_IOCP
	ior_sqe_iocp iocp;
#endif
};

struct ior_cqe {
#ifdef IOR_HAVE_URING
	ior_cqe_uring uring;
#endif
#ifdef IOR_HAVE_THREADS
	ior_cqe_threads threads;
#endif
#ifdef IOR_HAVE_IOCP
	ior_cqe_iocp iocp;
#endif
};

/* Backend operations vtable */
typedef struct ior_backend_ops {
	/* Initialization and cleanup */
	int (*init)(void **backend_ctx, ior_params *params);
	void (*destroy)(void *backend_ctx);
	/* Optional (NULL = no fork): ior_queue_forget() in a forked child. */
	void (*forget)(void *backend_ctx);
	/* Optional (NULL = nothing ties a descriptor to the context): ior_release_handle(). */
	int (*release_handle)(void *backend_ctx, ior_fd_t fd);

	/* Submission queue operations. get_sqe: 0, -ENOSPC (submission queue
	 * full), -ENOMEM (no memory for the entry, IOCP). */
	int (*get_sqe)(void *backend_ctx, ior_sqe **sqe_out);
	int (*submit)(void *backend_ctx);
	int (*submit_and_wait)(void *backend_ctx, unsigned wait_nr);

	/* Completion queue operations */
	int (*peek_cqe)(void *backend_ctx, ior_cqe **cqe_out);
	int (*wait_cqe)(void *backend_ctx, ior_cqe **cqe_out);
	int (*wait_cqe_timeout)(void *backend_ctx, ior_cqe **cqe_out, ior_timespec *timeout);
	void (*cqe_seen)(void *backend_ctx, ior_cqe *cqe);
	unsigned (*peek_batch_cqe)(void *backend_ctx, ior_cqe **cqes, unsigned max);
	void (*cq_advance)(void *backend_ctx, unsigned nr);

	/* SQE preparation helpers */
	void (*prep_nop)(ior_sqe *sqe);
	void (*prep_read)(ior_sqe *sqe, ior_fd_t fd, void *buf, unsigned nbytes, uint64_t offset);
	void (*prep_write)(
			ior_sqe *sqe, ior_fd_t fd, const void *buf, unsigned nbytes, uint64_t offset);
	void (*prep_splice)(ior_sqe *sqe, ior_fd_t fd_in, uint64_t off_in, ior_fd_t fd_out,
			uint64_t off_out, unsigned nbytes, unsigned flags);
	void (*prep_timeout)(ior_sqe *sqe, ior_timespec *ts, unsigned count, unsigned flags);
	void (*prep_link_timeout)(ior_sqe *sqe, ior_timespec *ts, unsigned flags);
	void (*prep_send)(ior_sqe *sqe, ior_fd_t sockfd, const void *buf, unsigned nbytes, int flags);
	void (*prep_recv)(ior_sqe *sqe, ior_fd_t sockfd, void *buf, unsigned nbytes, int flags);
	void (*prep_poll_add)(ior_sqe *sqe, ior_fd_t fd, uint32_t poll_mask);
	void (*prep_poll_multishot)(ior_sqe *sqe, ior_fd_t fd, uint32_t poll_mask);
	void (*prep_accept)(
			ior_sqe *sqe, ior_fd_t fd, struct sockaddr *addr, socklen_t *addrlen, unsigned flags);
	void (*prep_accept_multishot)(ior_sqe *sqe, ior_fd_t fd, unsigned flags);
	void (*prep_connect)(ior_sqe *sqe, ior_fd_t fd, const struct sockaddr *addr, socklen_t addrlen);
	void (*prep_cancel)(ior_sqe *sqe, uint64_t user_data);
	void (*prep_cancel_fd)(ior_sqe *sqe, ior_fd_t fd);
	/* Takes backend_ctx: io_uring keeps a record per pidfd poll. */
	int (*prep_waitpid)(void *backend_ctx, ior_sqe *sqe, ior_pid_t pid, int *status, int options);
	/* Takes backend_ctx: io_uring keeps a record per signalfd poll. The set
	 * has been validated as non-empty. */
	int (*prep_sigwait)(
			void *backend_ctx, ior_sqe *sqe, const ior_sigset_t *set, ior_siginfo_t *info);
	/* Optional (NULL = directory change ops unsupported). Arguments checked. */
	void (*prep_dir_changes)(
			ior_sqe *sqe, ior_fd_t dir, void *buf, unsigned nbytes, uint32_t flags);
	/* Optional (NULL = work ops unsupported). Takes backend_ctx because some
	 * backends record per-op state beyond the SQE (e.g. io_uring's job list). */
	int (*prep_work)(void *backend_ctx, ior_sqe *sqe, ior_work_fn fn, void *arg);
	/* Optional: an entry of a kind submit checks (timeout, link timeout,
	 * accept) was prepped. Lets io_uring skip its scan when none was. */
	void (*prep_checked)(void *backend_ctx);
	void (*sqe_set_data)(ior_sqe *sqe, void *data);
	void (*sqe_set_flags)(ior_sqe *sqe, uint8_t flags);

	/* CQE accessors */
	void *(*cqe_get_data)(ior_cqe *cqe);
	int32_t (*cqe_get_res)(ior_cqe *cqe);
	uint32_t (*cqe_get_flags)(ior_cqe *cqe);

	/* Completion notification descriptor */
	ior_fd_t (*notify_fd)(void *backend_ctx);
	int (*notify_clear)(void *backend_ctx);

	/* Backend info */
	const char *(*backend_name)(void);
	uint32_t (*get_features)(void *backend_ctx);

	/* Queue capacity (see the public accessors of the same names) */
	unsigned (*sq_entries)(void *backend_ctx);
	unsigned (*cq_entries)(void *backend_ctx);
	unsigned (*sq_space_left)(void *backend_ctx);
	unsigned (*cq_space_left)(void *backend_ctx);
} ior_backend_ops;

/* Main context structure */
/*
 * A relative timespec in ns, read as io_uring reads it: a tv_nsec of a second
 * or more adds up, a negative total is already expired (0), and a huge one
 * saturates (at about 146 years) instead of wrapping.
 */
static inline uint64_t ior_timespec_ns(const ior_timespec *ts)
{
	const int64_t half = INT64_MAX / 2;
	const int64_t max_sec = half / 1000000000LL;
	if (ts->tv_sec > max_sec) {
		return (uint64_t) half;
	}
	if (ts->tv_sec < -max_sec) {
		return 0;
	}
	int64_t ns = ts->tv_sec * 1000000000LL;
	long long nsec = ts->tv_nsec;
	if (nsec > half) {
		nsec = half;
	} else if (nsec < -half) {
		nsec = -half;
	}
	ns += nsec;
	if (ns > half) {
		return (uint64_t) half;
	}
	return ns > 0 ? (uint64_t) ns : 0;
}

/*
 * The accept flags io_uring takes; any other bit fails the entry (-EINVAL).
 */
static inline int ior_accept_check(unsigned flags)
{
	return (flags & ~(unsigned) (IOR_ACCEPT_NONBLOCK | IOR_ACCEPT_CLOEXEC)) ? -EINVAL : 0;
}

/*
 * What io_uring checks when it takes a timeout entry: two clocks, then no
 * timespec (-EFAULT), then a negative field. A tv_nsec past a second is fine.
 */
static inline int ior_timeout_check(const ior_timespec *ts, unsigned flags)
{
	if ((flags & IOR_TIMEOUT_BOOTTIME) && (flags & IOR_TIMEOUT_REALTIME)) {
		return -EINVAL;
	}
	if (!ts) {
		return -EFAULT;
	}
	if (ts->tv_sec < 0 || ts->tv_nsec < 0) {
		return -EINVAL;
	}
	return 0;
}

/*
 * The same for a link timeout, which also needs a linked entry before it in
 * the same submit, one that is not a link timeout itself.
 */
static inline int ior_link_timeout_check(
		const ior_timespec *ts, unsigned flags, int in_chain, int prev_lt)
{
	int ret = ior_timeout_check(ts, flags);
	if (ret == 0 && (!in_chain || prev_lt)) {
		ret = -EINVAL;
	}
	return ret;
}

struct ior_ctx {
	const ior_backend_ops *ops;
	void *backend_ctx;
	ior_backend_type backend;
};

/* Backend registration */
#ifdef IOR_HAVE_URING
extern const ior_backend_ops ior_uring_ops;
#endif

#ifdef IOR_HAVE_THREADS
extern const ior_backend_ops ior_threads_ops;
#endif

#ifdef IOR_HAVE_IOCP
extern const ior_backend_ops ior_iocp_ops;
/* ior_sigrequeue(): console control events are the IOCP backend's. */
int ior_iocp_sigrequeue(const ior_siginfo_t *info);
#endif

#endif /* IOR_BACKEND_H */
