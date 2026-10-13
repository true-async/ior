#include "config.h"
#include "ior.h"
#include "ior_backend.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#ifndef _WIN32
#include <signal.h>
#include <unistd.h>
#ifdef __linux__
#include <sys/syscall.h>
#endif
#endif

/*
 * The backend for IOR_BACKEND_AUTO: the one IOR_BACKEND names in the
 * environment, if set (a name that is unknown or not built in fails init
 * with -ENOSYS rather than being ignored), else the best one built in.
 * Only the latter may fall back (see ior_queue_init_params).
 */
static ior_backend_type detect_backend(int *may_fall_back)
{
	const char *env = getenv("IOR_BACKEND");
	*may_fall_back = 0;
	if (env && *env) {
		if (strcmp(env, "io_uring") == 0 || strcmp(env, "uring") == 0) {
			return IOR_BACKEND_IOURING;
		}
		if (strcmp(env, "threads") == 0) {
			return IOR_BACKEND_THREADS;
		}
		if (strcmp(env, "iocp") == 0) {
			return IOR_BACKEND_IOCP;
		}
		return IOR_BACKEND_AUTO;
	}
	*may_fall_back = 1;
#ifdef IOR_HAVE_URING
	return IOR_BACKEND_IOURING;
#elif defined(IOR_HAVE_IOCP)
	return IOR_BACKEND_IOCP;
#elif defined(IOR_HAVE_THREADS)
	return IOR_BACKEND_THREADS;
#else
	/* Should never happen */
	return IOR_BACKEND_AUTO;
#endif
}

static const ior_backend_ops *get_backend_ops(ior_backend_type backend)
{
	switch (backend) {
#ifdef IOR_HAVE_URING
		case IOR_BACKEND_IOURING:
			return &ior_uring_ops;
#endif
#ifdef IOR_HAVE_THREADS
		case IOR_BACKEND_THREADS:
			return &ior_threads_ops;
#endif
#ifdef IOR_HAVE_IOCP
		case IOR_BACKEND_IOCP:
			return &ior_iocp_ops;
#endif
		default:
			return NULL;
	}
}

int ior_queue_init_params(unsigned entries, ior_ctx **ctx_out, ior_params *params)
{
	if (!ctx_out || !params || entries == 0) {
		return -EINVAL;
	}

	/* The backend writes the sizes it settles on into a copy, so the caller's
	 * params change only on success. */
	ior_params used = *params;
	if (used.sq_entries == 0) {
		used.sq_entries = entries;
	}

	ior_backend_type backend = used.backend;
	int may_fall_back = 0;
	if (backend == IOR_BACKEND_AUTO) {
		backend = detect_backend(&may_fall_back);
	}

	const ior_backend_ops *ops = get_backend_ops(backend);
	if (!ops) {
		return -ENOSYS;
	}

	ior_ctx *ctx = calloc(1, sizeof(*ctx));
	if (!ctx) {
		return -ENOMEM;
	}

	ctx->backend = backend;
	ctx->ops = ops;

	int ret = ops->init(&ctx->backend_ctx, &used);
#if defined(IOR_HAVE_URING) && defined(IOR_HAVE_THREADS)
	/*
	 * io_uring unusable here: kernel too old or without it (-ENOSYS),
	 * disabled by sysctl or seccomp (-EPERM), or memlock limit (-ENOMEM).
	 */
	if (may_fall_back && backend == IOR_BACKEND_IOURING
			&& (ret == -ENOSYS || ret == -EPERM || ret == -ENOMEM)) {
		ctx->backend = IOR_BACKEND_THREADS;
		ctx->ops = &ior_threads_ops;
		ret = ctx->ops->init(&ctx->backend_ctx, &used);
	}
#else
	(void) may_fall_back;
#endif
	if (ret < 0) {
		free(ctx);
		return ret;
	}

	params->sq_entries = used.sq_entries;
	params->cq_entries = used.cq_entries;
	params->features = used.features;
	*ctx_out = ctx;
	return 0;
}

int ior_queue_init(unsigned entries, ior_ctx **ctx_out)
{
	ior_params params = {
		.sq_entries = entries,
		.cq_entries = 0,
		.flags = 0,
		.backend = IOR_BACKEND_AUTO,
	};
	return ior_queue_init_params(entries, ctx_out, &params);
}

void ior_queue_exit(ior_ctx *ctx)
{
	if (!ctx) {
		return;
	}
	ctx->ops->destroy(ctx->backend_ctx);
	free(ctx);
}

int ior_queue_forget(ior_ctx *ctx)
{
	if (!ctx) {
		return -EINVAL;
	}
	if (!ctx->ops->forget) {
		return -ENOTSUP;
	}
	ctx->ops->forget(ctx->backend_ctx);
	free(ctx);
	return 0;
}

int ior_release_handle(ior_ctx *ctx, ior_fd_t fd)
{
	if (!ctx) {
		return -EINVAL;
	}

	if (!ctx->ops->release_handle) {
		return 0;
	}

	return ctx->ops->release_handle(ctx->backend_ctx, fd);
}

/* Submission operations - just call through vtable */
ior_sqe *ior_get_sqe(ior_ctx *ctx)
{
	ior_sqe *sqe = NULL;
	if (ctx) {
		ctx->ops->get_sqe(ctx->backend_ctx, &sqe);
	}
	return sqe;
}

int ior_get_sqe_ex(ior_ctx *ctx, ior_sqe **sqe_out)
{
	if (!sqe_out) {
		return -EINVAL;
	}
	*sqe_out = NULL;
	return ctx ? ctx->ops->get_sqe(ctx->backend_ctx, sqe_out) : -EINVAL;
}

int ior_submit(ior_ctx *ctx)
{
	return ctx ? ctx->ops->submit(ctx->backend_ctx) : -EINVAL;
}

int ior_submit_and_wait(ior_ctx *ctx, unsigned wait_nr)
{
	return ctx ? ctx->ops->submit_and_wait(ctx->backend_ctx, wait_nr) : -EINVAL;
}

/* Completion operations */
int ior_peek_cqe(ior_ctx *ctx, ior_cqe **cqe_out)
{
	return (ctx && cqe_out) ? ctx->ops->peek_cqe(ctx->backend_ctx, cqe_out) : -EINVAL;
}

int ior_wait_cqe(ior_ctx *ctx, ior_cqe **cqe_out)
{
	return (ctx && cqe_out) ? ctx->ops->wait_cqe(ctx->backend_ctx, cqe_out) : -EINVAL;
}

int ior_wait_cqe_timeout(ior_ctx *ctx, ior_cqe **cqe_out, ior_timespec *timeout)
{
	return (ctx && cqe_out) ? ctx->ops->wait_cqe_timeout(ctx->backend_ctx, cqe_out, timeout)
							: -EINVAL;
}

void ior_cqe_seen(ior_ctx *ctx, ior_cqe *cqe)
{
	if (ctx) {
		ctx->ops->cqe_seen(ctx->backend_ctx, cqe);
	}
}

unsigned ior_peek_batch_cqe(ior_ctx *ctx, ior_cqe **cqes, unsigned max)
{
	return (ctx && cqes) ? ctx->ops->peek_batch_cqe(ctx->backend_ctx, cqes, max) : 0;
}

void ior_cq_advance(ior_ctx *ctx, unsigned nr)
{
	if (ctx) {
		ctx->ops->cq_advance(ctx->backend_ctx, nr);
	}
}

/* Helper functions - work on opaque types via callbacks */
void ior_prep_nop(ior_ctx *ctx, ior_sqe *sqe)
{
	if (ctx && sqe) {
		ctx->ops->prep_nop(sqe);
	}
}

void ior_prep_read(
		ior_ctx *ctx, ior_sqe *sqe, ior_fd_t fd, void *buf, unsigned nbytes, uint64_t offset)
{
	if (ctx && sqe) {
		ctx->ops->prep_read(sqe, fd, buf, nbytes, offset);
	}
}

void ior_prep_write(
		ior_ctx *ctx, ior_sqe *sqe, ior_fd_t fd, const void *buf, unsigned nbytes, uint64_t offset)
{
	if (ctx && sqe) {
		ctx->ops->prep_write(sqe, fd, buf, nbytes, offset);
	}
}

void ior_prep_splice(ior_ctx *ctx, ior_sqe *sqe, ior_fd_t fd_in, uint64_t off_in, ior_fd_t fd_out,
		uint64_t off_out, unsigned nbytes, unsigned flags)
{
	if (ctx && sqe) {
		ctx->ops->prep_splice(sqe, fd_in, off_in, fd_out, off_out, nbytes, flags);
	}
}

void ior_prep_timeout(ior_ctx *ctx, ior_sqe *sqe, ior_timespec *ts, unsigned count, unsigned flags)
{
	if (ctx && sqe) {
		ctx->ops->prep_timeout(sqe, ts, count, flags);
		if (ctx->ops->prep_checked) {
			ctx->ops->prep_checked(ctx->backend_ctx);
		}
	}
}

void ior_prep_link_timeout(ior_ctx *ctx, ior_sqe *sqe, ior_timespec *ts, unsigned flags)
{
	if (ctx && sqe) {
		ctx->ops->prep_link_timeout(sqe, ts, flags);
		if (ctx->ops->prep_checked) {
			ctx->ops->prep_checked(ctx->backend_ctx);
		}
	}
}

void ior_prep_send(
		ior_ctx *ctx, ior_sqe *sqe, ior_fd_t sockfd, const void *buf, unsigned nbytes, int flags)
{
	if (ctx && sqe) {
		ctx->ops->prep_send(sqe, sockfd, buf, nbytes, flags);
	}
}

void ior_prep_recv(
		ior_ctx *ctx, ior_sqe *sqe, ior_fd_t sockfd, void *buf, unsigned nbytes, int flags)
{
	if (ctx && sqe) {
		ctx->ops->prep_recv(sqe, sockfd, buf, nbytes, flags);
	}
}

void ior_prep_poll_add(ior_ctx *ctx, ior_sqe *sqe, ior_fd_t fd, uint32_t poll_mask)
{
	if (ctx && sqe) {
		ctx->ops->prep_poll_add(sqe, fd, poll_mask);
	}
}

void ior_prep_poll_multishot(ior_ctx *ctx, ior_sqe *sqe, ior_fd_t fd, uint32_t poll_mask)
{
	if (ctx && sqe) {
		ctx->ops->prep_poll_multishot(sqe, fd, poll_mask);
	}
}

void ior_prep_accept(ior_ctx *ctx, ior_sqe *sqe, ior_fd_t fd, struct sockaddr *addr,
		socklen_t *addrlen, unsigned flags)
{
	if (ctx && sqe) {
		ctx->ops->prep_accept(sqe, fd, addr, addrlen, flags);
		if (ctx->ops->prep_checked) {
			ctx->ops->prep_checked(ctx->backend_ctx);
		}
	}
}

void ior_prep_accept_multishot(ior_ctx *ctx, ior_sqe *sqe, ior_fd_t fd, unsigned flags)
{
	if (ctx && sqe) {
		ctx->ops->prep_accept_multishot(sqe, fd, flags);
		if (ctx->ops->prep_checked) {
			ctx->ops->prep_checked(ctx->backend_ctx);
		}
	}
}

void ior_prep_connect(
		ior_ctx *ctx, ior_sqe *sqe, ior_fd_t fd, const struct sockaddr *addr, socklen_t addrlen)
{
	if (ctx && sqe) {
		ctx->ops->prep_connect(sqe, fd, addr, addrlen);
	}
}

int ior_prep_waitpid(ior_ctx *ctx, ior_sqe *sqe, ior_pid_t pid, int *status, int options)
{
	if (!ctx || !sqe) {
		return -EINVAL;
	}
	return ctx->ops->prep_waitpid(ctx->backend_ctx, sqe, pid, status, options);
}

#if !defined(_WIN32) && !defined(NSIG)
/* Strict-standard headers hide NSIG; sigismember rejects what is past it. */
#define NSIG 65
#endif

int ior_sigemptyset(ior_sigset_t *set)
{
	if (!set) {
		return -EINVAL;
	}
#ifdef _WIN32
	set->bits = 0;
	return 0;
#else
	return sigemptyset(set) == 0 ? 0 : -EINVAL;
#endif
}

int ior_sigaddset(ior_sigset_t *set, int signo)
{
	if (!set) {
		return -EINVAL;
	}
#ifdef _WIN32
	if (signo <= 0 || signo >= 32) {
		return -EINVAL;
	}
	set->bits |= 1U << signo;
	return 0;
#else
	/* BSD-derived libcs define sigaddset as a macro that range-checks
	 * nothing and always reports success, so check here: signo - 1 would
	 * otherwise be shifted by a negative count. */
	if (signo <= 0 || signo >= NSIG) {
		return -EINVAL;
	}
	return sigaddset(set, signo) == 0 ? 0 : -EINVAL;
#endif
}

int ior_sigismember(const ior_sigset_t *set, int signo)
{
	if (!set) {
		return -EINVAL;
	}
#ifdef _WIN32
	if (signo <= 0 || signo >= 32) {
		return -EINVAL;
	}
	return (set->bits >> signo) & 1U;
#else
	/* Same as ior_sigaddset(): sigismember validates nothing on BSD. */
	if (signo <= 0 || signo >= NSIG) {
		return -EINVAL;
	}
	int ret = sigismember(set, signo);
	return ret < 0 ? -EINVAL : ret;
#endif
}

#ifndef _WIN32
int ior_sigrequeue(const ior_siginfo_t *info)
{
	if (!info || info->si_signo <= 0 || info->si_signo >= NSIG) {
		return -EINVAL;
	}
	pid_t self = getpid();
#if defined(__linux__) && defined(SYS_rt_sigqueueinfo)
	siginfo_t copy = *info;
	if (syscall(SYS_rt_sigqueueinfo, self, copy.si_signo, &copy) == 0) {
		return 0;
	}
	if (errno != EPERM) {
		return -errno;
	}
	/* Only the main thread may queue a kernel's or kill()'s si_code. */
	copy.si_code = SI_QUEUE;
	return syscall(SYS_rt_sigqueueinfo, self, copy.si_signo, &copy) == 0 ? 0 : -errno;
#else
#ifdef IOR_HAVE_SIGQUEUE
	if (info->si_code == SI_QUEUE) {
		return sigqueue(self, info->si_signo, info->si_value) == 0 ? 0 : -errno;
	}
#endif
	return kill(self, info->si_signo) == 0 ? 0 : -errno;
#endif
}
#else
int ior_sigrequeue(const ior_siginfo_t *info)
{
#ifdef IOR_HAVE_IOCP
	return ior_iocp_sigrequeue(info);
#else
	(void) info;
	return -ENOTSUP;
#endif
}
#endif

/* Does the set name at least one signal? A wait on none would never end. */
static int ior_sigset_has_any(const ior_sigset_t *set)
{
#ifdef _WIN32
	return set->bits != 0;
#else
	for (int signo = 1; signo < NSIG; signo++) {
		if (sigismember(set, signo) == 1) {
			return 1;
		}
	}
	return 0;
#endif
}

int ior_prep_sigwait(ior_ctx *ctx, ior_sqe *sqe, const ior_sigset_t *set, ior_siginfo_t *info)
{
	if (!ctx || !sqe || !set || !ior_sigset_has_any(set)) {
		return -EINVAL;
	}
	return ctx->ops->prep_sigwait(ctx->backend_ctx, sqe, set, info);
}

int ior_prep_dir_changes(
		ior_ctx *ctx, ior_sqe *sqe, ior_fd_t dir, void *buf, unsigned nbytes, uint32_t flags)
{
	if (!ctx || !sqe || !buf || nbytes == 0 || ((uintptr_t) buf & 3)
			|| (flags & ~IOR_DIR_CHANGES_SUBTREE)) {
		return -EINVAL;
	}
	if (!ctx->ops->prep_dir_changes) {
		return -ENOTSUP;
	}
	ctx->ops->prep_dir_changes(sqe, dir, buf, nbytes, flags);
	return 0;
}

void ior_prep_cancel(ior_ctx *ctx, ior_sqe *sqe, void *user_data)
{
	if (ctx && sqe) {
		ctx->ops->prep_cancel(sqe, (uint64_t) (uintptr_t) user_data);
	}
}

void ior_prep_cancel_fd(ior_ctx *ctx, ior_sqe *sqe, ior_fd_t fd)
{
	if (ctx && sqe) {
		ctx->ops->prep_cancel_fd(sqe, fd);
	}
}

int ior_prep_work(ior_ctx *ctx, ior_sqe *sqe, ior_work_fn fn, void *arg)
{
	if (!ctx || !sqe || !fn) {
		return -EINVAL;
	}
	if (!ctx->ops->prep_work) {
		return -EOPNOTSUPP;
	}
	return ctx->ops->prep_work(ctx->backend_ctx, sqe, fn, arg);
}

int ior_work_cancelled(const ior_work_token *token)
{
	if (!token) {
		return 0;
	}
	// Cast away const: C11's atomic_load is not const-correct (fixed in C17).
	ior_work_token *t = (ior_work_token *) token;
	if (atomic_load_explicit(&t->cancelled, memory_order_acquire)) {
		return 1;
	}
	if (t->shutdown && atomic_load_explicit((_Atomic int *) t->shutdown, memory_order_acquire)) {
		return 1;
	}
	return 0;
}

void ior_sqe_set_data(ior_ctx *ctx, ior_sqe *sqe, void *data)
{
	if (ctx && sqe) {
		ctx->ops->sqe_set_data(sqe, data);
	}
}

void ior_sqe_set_flags(ior_ctx *ctx, ior_sqe *sqe, uint8_t flags)
{
	if (ctx && sqe) {
		ctx->ops->sqe_set_flags(sqe, flags);
	}
}

void *ior_cqe_get_data(ior_ctx *ctx, ior_cqe *cqe)
{
	return (ctx && cqe) ? ctx->ops->cqe_get_data(cqe) : NULL;
}

int32_t ior_cqe_get_res(ior_ctx *ctx, ior_cqe *cqe)
{
	return (ctx && cqe) ? ctx->ops->cqe_get_res(cqe) : 0;
}

uint32_t ior_cqe_get_flags(ior_ctx *ctx, ior_cqe *cqe)
{
	return (ctx && cqe) ? ctx->ops->cqe_get_flags(cqe) : 0;
}

/* Completion notification */
ior_fd_t ior_notify_fd(ior_ctx *ctx)
{
	return ctx ? ctx->ops->notify_fd(ctx->backend_ctx) : IOR_INVALID_FD;
}

int ior_notify_clear(ior_ctx *ctx)
{
	return ctx ? ctx->ops->notify_clear(ctx->backend_ctx) : -EINVAL;
}

/* Backend info */
ior_backend_type ior_get_backend_type(ior_ctx *ctx)
{
	return ctx ? ctx->backend : IOR_BACKEND_AUTO;
}

const char *ior_get_backend_name(ior_ctx *ctx)
{
	return ctx ? ctx->ops->backend_name() : "unknown";
}

uint32_t ior_get_features(ior_ctx *ctx)
{
	return ctx ? ctx->ops->get_features(ctx->backend_ctx) : 0;
}

/* Queue capacity */
unsigned ior_sq_entries(ior_ctx *ctx)
{
	return ctx ? ctx->ops->sq_entries(ctx->backend_ctx) : 0;
}

unsigned ior_cq_entries(ior_ctx *ctx)
{
	return ctx ? ctx->ops->cq_entries(ctx->backend_ctx) : 0;
}

unsigned ior_sq_space_left(ior_ctx *ctx)
{
	return ctx ? ctx->ops->sq_space_left(ctx->backend_ctx) : 0;
}

unsigned ior_cq_space_left(ior_ctx *ctx)
{
	return ctx ? ctx->ops->cq_space_left(ctx->backend_ctx) : 0;
}
