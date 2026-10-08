/* SPDX-License-Identifier: BSD-3-Clause */
#include "config.h"

#ifdef IOR_HAVE_IOCP

/*
 * winsock2.h must be included before windows.h (which ior_backend.h pulls in
 * via ior.h) so that the modern Winsock 2 declarations (WSASend/WSARecv/WSABUF/
 * SOCKET) win over the legacy winsock.h ones. WIN32_LEAN_AND_MEAN keeps
 * windows.h from implicitly including winsock.h; winsock2.h itself includes
 * windows.h in the correct order.
 */
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>

#include "ior_backend.h"
#include <stdlib.h>
#include <stddef.h>
#include <limits.h>
#include <string.h>
#include <errno.h>
#include <windows.h>
#include <winternl.h>
#include <assert.h>
#include <stdatomic.h>
#include <stdbool.h>

// ETIME is used for timer expiration (matches io_uring semantics)
#ifndef ETIME
#define ETIME 62 // Match Linux value
#endif

// IOR_TIMEOUT_ABS comes from ior.h. qpc_deadline_from_timespec() honors it, so
// the plain timer and the link timeout both interpret an absolute deadline
// against the QPC monotonic clock.

/*
 * Handle tracking for IOCP association
 * Windows requires each handle to be associated with exactly one IOCP
 */
#define HANDLE_SET_SIZE 256

typedef struct handle_set_entry {
	HANDLE handle;
	// Bumped before every CancelIoEx() on the handle; see
	// reissue_collateral_abort() for what it is compared against.
	uint32_t cancel_gen;
	// Bumped when the kernel accepts an association for a value already in
	// the set: proof the caller closed the old object and this value now
	// names a new one. Ops record it, so an abort of the old object's request
	// is never replayed onto the new object.
	uint32_t epoch;
	// The object under this value is tied to this context's port, as far as
	// ior knows: the process-wide owner map names this context for it (see
	// iocp_owner_record_locked). Cleared when another context associates a new
	// object under the value, so a stale entry is never taken for ours.
	bool owned;
	struct handle_set_entry *next;
} handle_set_entry;

typedef struct handle_set {
	handle_set_entry *buckets[HANDLE_SET_SIZE];
	CRITICAL_SECTION lock;
} handle_set;

struct ior_ctx_iocp;

/*
 * Where a submitted op currently is, for IOR_OP_ASYNC_CANCEL. Set at each
 * issue point before the op can complete, DONE once its completion is posted
 * (or dequeued), FREE while on the free list or merely prepped.
 */
enum {
	IOCP_OP_FREE = 0,
	IOCP_OP_DEFERRED, /* drain-deferred head in the pending list */
	IOCP_OP_LINKED, /* behind a link (or a paired link timeout); not cancellable */
	IOCP_OP_IO, /* overlapped I/O in flight */
	IOCP_OP_IO_CANCEL, /* overlapped I/O in flight, CancelIoEx requested on it */
	IOCP_OP_TIMER, /* armed on the timer thread */
	IOCP_OP_WORK, /* work object queued on the threadpool, callback not started */
	IOCP_OP_WORK_RUNNING, /* callback executing */
	IOCP_OP_POLL, /* registered with the poller */
	IOCP_OP_ACCEPT_MULTI, /* multishot accept parent: its AcceptEx children are in flight */
	IOCP_OP_WAIT, /* threadpool wait registered on a process handle */
	IOCP_OP_SIGWAIT, /* listed for the console control handler */
	IOCP_OP_DONE,
};

/* IOCP operation structure - wraps OVERLAPPED */
typedef struct ior_iocp_op {
	OVERLAPPED overlapped; // MUST be first for GetQueuedCompletionStatus casting
	ior_cqe cqe; // Embedded CQE - stable until cqe_seen()

	// Operation metadata (matches SQE fields)
	uint8_t opcode;
	uint8_t sqe_flags;
	uint16_t ioprio;
	ior_fd_t fd;
	uint64_t user_data;

	// I/O parameters
	void *buf;
	uint32_t len;
	uint64_t offset;

	// Socket I/O (WSASend/WSARecv) bookkeeping. The WSABUF and flags must stay
	// valid for the whole lifetime of the overlapped operation, so they live in
	// the op rather than on the issuing thread's stack. For WSARecv sock_flags
	// is an in/out parameter.
	WSABUF wsabuf;
	DWORD sock_flags;

	// IOR_OP_POLL: requested IOR_POLL_* mask; the ready mask is delivered in
	// work_res (posted like a work-op result). A multishot poll stays with
	// the poller and posts each readiness through a shadow op flagged
	// cqe_more (IOR_CQE_F_MORE on its CQE); WSAPoll being level-triggered,
	// the op is held out of the poll set (poll_held, poller thread only)
	// until the consumer marks that shadow's CQE seen, which sets
	// poll_rearm. The shadow names its parent, with the parent's gen as it
	// was, so a parent recycled meanwhile is left alone. A multishot
	// accept's children (below) name their parent the same way.
	uint32_t poll_mask;
	bool poll_multi;
	bool cqe_more;
	bool cqe_nonempty; // IOR_CQE_F_SOCK_NONEMPTY: a one-shot accept found more queued
	bool poll_held;
	_Atomic uint32_t poll_rearm;
	struct ior_iocp_op *poll_parent;
	uint32_t poll_parent_gen;
	// Bumped every time the op returns to the pool; never reset.
	uint32_t gen;

	// Timeout-specific fields. The caller's timespec is promised only until
	// submit returns: submit copies it into timeout_val and points timeout_ts
	// there, so a link timeout armed later reads the copy.
	ior_timespec *timeout_ts;
	ior_timespec timeout_val;
	uint32_t timeout_flags;

	// Timer bookkeeping (for IOR_OP_TIMER)
	uint64_t timer_deadline_ns; // Absolute deadline in monotonic time
	bool timer_armed; // True once enqueued into timer heap
	bool timer_cancelled; // True if timer was cancelled (future use)

	// Linked timeout (IOR_OP_LINK_TIMEOUT) pairing. On the guarded op,
	// link_timeout points to its watchdog timeout op; on the timeout op, guarded
	// points back to the op it guards. Exactly one of the completion path and the
	// timer thread resolves the pair, arbitrated by timer_armed under timers.lock.
	struct ior_iocp_op *link_timeout;
	struct ior_iocp_op *guarded;

	// Scheduling / ordering
	uint64_t seq; // submission sequence (1..)
	uint64_t drain_after; // for DRAIN: must wait until completed_count >= drain_after
	struct ior_iocp_op *link_next;

	bool linked_deferred; // true while waiting for predecessor in a LINK chain
	bool drain_deferred; // true while waiting for DRAIN barrier

	// Pending list linkage (for drain-deferred heads, and link-next heads that hit DRAIN)
	struct ior_iocp_op *next_pending;

	// Result tracking (filled by completion)
	DWORD bytes_transferred;
	DWORD error_code;

	// Flags for completion handling
	bool is_synthetic; // True if synthetic completion
	// Non-zero when submit failed the op's chain (see iocp_scan_staged): the
	// op's own error, or -ECANCELED for the rest of the chain. Never issued.
	int32_t submit_res;
	uint32_t accept_flags; // IOR_ACCEPT_*, checked at submit as io_uring does
	struct ior_iocp_op *backlog_next; // on ctx->backlog, see iocp_backlog_push

	// IOR_OP_WORK: user callback executed on the private Win32 threadpool. The
	// callback's return value (work_res) becomes the CQE result; the token lets
	// it observe a fired link timeout or context teardown.
	ior_work_fn work_fn;
	void *work_arg;
	int32_t work_res;
	struct ior_ctx_iocp *work_owner;
	struct ior_work_token token;

	// IOR_OP_WORK: the threadpool work object, so a queued callback can be
	// withdrawn by a cancel. Closed by the consumer once the op completes.
	PTP_WORK tp_work;

	// IOR_OP_ASYNC_CANCEL: what to match (user data, or fd with IOR_CANCEL_BY_FD).
	uint64_t cancel_key;
	uint32_t cancel_flags;

	// IOR_OP_WAITPID: the process handle opened for the pid, the threadpool
	// wait registered on it (closed by the consumer once the op completes),
	// and where the exit code goes.
	DWORD wait_pid;
	int *wait_status;
	HANDLE proc_handle;
	PTP_WAIT tp_wait;

	// IOR_OP_SIGWAIT: the signals waited for (a bit per CRT signal number),
	// where the details go, and the link in the context's list of waiting
	// ops (under g_sig_lock).
	uint32_t sig_mask;
	ior_siginfo_t *sig_info;
	struct ior_iocp_op *sig_next;

	// Overlapped I/O: the handle's cancel_gen and epoch when this request was
	// issued.
	uint32_t io_cancel_gen;
	uint32_t io_epoch;

	// IOR_OP_ACCEPT / IOR_OP_CONNECT. AcceptEx needs the accepted socket
	// created up front and a buffer for both addresses; the user's address
	// buffers are filled on completion. For connect, sa_len_val is addrlen.
	SOCKET accept_sock;
	struct sockaddr *sa;
	socklen_t *sa_len;
	socklen_t sa_len_val;
	DWORD accept_recvd;
	char accept_buf[2 * (sizeof(SOCKADDR_STORAGE) + 16)];

	// IOR_OP_ACCEPT, multishot (accept_multi, see issue_accept_multi): the
	// parent keeps a few AcceptEx requests outstanding, each a child op with
	// the parent's user data, cqe_more set and poll_parent naming it. The
	// parent's children are listed through accept_sibling, under
	// timers.lock, since the timer thread cancels them when the parent's
	// link timeout fires. accept_ending marks a parent on its way out
	// (cancelled, timed out, a child failed): no child is replaced, and the
	// last to complete posts the parent, with the error in error_code.
	bool accept_multi;
	bool accept_ending;
	struct ior_iocp_op *accept_children;
	struct ior_iocp_op *accept_sibling;
	uint32_t accept_nchildren;

	_Atomic int state; // IOCP_OP_*

	// Free list linkage (preserved across prep_*)
	struct ior_iocp_op *next_free;

	// Its packet, staged by the completion pump (see iocp_pump).
	struct ior_iocp_op *pump_next;
	DWORD pump_bytes;
	DWORD pump_error;

	// On the context's list of ops in flight (see live_add); consumer only.
	struct ior_iocp_op *live_prev;
	struct ior_iocp_op *live_next;
	bool live;
} ior_iocp_op;

/* A block of ops; the pool grows by adding one and never shrinks. */
typedef struct iocp_op_chunk {
	struct iocp_op_chunk *next;
	uint32_t count;
	ior_iocp_op ops[];
} iocp_op_chunk;

/* Ready queue for buffering completed operations */
typedef struct ready_queue {
	ior_iocp_op **ops; // Dynamic array
	uint32_t head;
	uint32_t tail;
	uint32_t count;
	uint32_t size; // Allocated size (power of 2)
	uint32_t mask; // size - 1, for bitmask wrapping
} ready_queue;

/* Timer manager - single thread managing all timers */
typedef struct timer_mgr {
	CRITICAL_SECTION lock;
	CONDITION_VARIABLE cv;
	HANDLE thread;
	_Atomic uint32_t stop;

	// Min-heap of ior_iocp_op* ordered by timer_deadline_ns
	ior_iocp_op **heap;
	uint32_t heap_len;
	uint32_t heap_cap;
} timer_mgr;

/*
 * IOR_OP_POLL multiplexer - one dedicated thread blocking in WSAPoll over
 * every pending poll op (sockets only). Registration and teardown wake it
 * through a loopback UDP socket pair (WSAPoll can only wait on sockets); a
 * fired link timeout flags the op's token from the timer thread and wakes it
 * the same way. The thread and the wakeup sockets are created lazily on the
 * first poll op; incoming ops are linked through next_pending.
 */
typedef struct iocp_poller {
	CRITICAL_SECTION lock;
	HANDLE thread; // NULL until the first poll op
	SOCKET wake_tx;
	SOCKET wake_rx;
	_Atomic uint32_t stop;
	// Set by a consumer re-arming a multishot poll before it sends a wake
	// byte, cleared by the poller before it reads the re-arm flags: one byte
	// per poller round, not per edge seen.
	_Atomic uint32_t wake_pending;
	ior_iocp_op *incoming; // protected by lock
	// Active ops, and the WSAPOLLFD set built from them before each wait
	// ([0] is wake_rx, slot[i] the active index behind pfds[i]); poller
	// thread only.
	ior_iocp_op **active;
	WSAPOLLFD *pfds;
	uint32_t *slot;
	uint32_t active_len;
	uint32_t active_cap;
} iocp_poller;

/*
 * Completion pump for ior_notify_fd(). Kernel I/O completes straight into
 * the port with no ior code running, so a loop that wants a waitable
 * descriptor needs a thread that dequeues on its behalf: the pump moves raw
 * packets into a staging queue and keeps a byte on a loopback UDP pair
 * (WSAPoll can only wait on sockets) while any completion has been staged
 * since the last ior_notify_clear() - one byte per wake cycle, not per
 * packet. The consumer then takes packets from staging instead of the port,
 * and all completion processing stays on the consumer thread. Started lazily
 * by the first ior_notify_fd() call; a context that never asks keeps
 * dequeuing from the port directly.
 */
typedef struct pump_entry {
	LPOVERLAPPED overlapped;
	DWORD bytes;
	DWORD error; // ERROR_SUCCESS, or the packet's GetLastError()
} pump_entry;

typedef struct iocp_pump {
	CRITICAL_SECTION lock;
	CONDITION_VARIABLE cv; // staging became non-empty
	HANDLE thread; // NULL until ior_notify_fd()
	SOCKET wake_tx;
	SOCKET wake_rx;
	// Packets staged, oldest first, linked through their ops: an op has at
	// most one packet out at a time, so staging needs no room of its own
	// however many ops are in flight (protected by lock).
	struct ior_iocp_op *staged_head;
	struct ior_iocp_op *staged_tail;
	// A wake byte is on the socket that ior_notify_clear() has not consumed
	// yet, so further packets need not send another (protected by lock).
	bool signalled;
} iocp_pump;

// Completion key of the packet that tells the pump thread to exit.
#define IOCP_PUMP_STOP_KEY ((ULONG_PTR) - 2)

/* QPC frequency, initialized once during backend init.
 *
 * Stored as an atomic so that the publishing thread's write is observed with
 * release semantics and reader threads acquire it. A non-zero value signals
 * "initialized"; QueryPerformanceFrequency never returns 0 on supported
 * platforms (XP+), so 0 is a safe sentinel. This matters on weakly-ordered
 * architectures (e.g. Windows on ARM64) where a plain store could be observed
 * out of order relative to the init flag. */
static _Atomic int64_t g_qpc_freq = 0;
static LONG g_qpc_freq_init = 0; // 0 = not done, 1 = done

/* IOCP backend context */
typedef struct ior_ctx_iocp {
	HANDLE iocp_handle;

	// Operation pool: grown in chunks as more ops are staged or in flight,
	// which nothing bounds but memory, as on io_uring.
	iocp_op_chunk *op_chunks;
	uint32_t pool_size; // ops in all chunks

	/*
	 * Ops submitted and not yet completed (dequeued), oldest first: what a
	 * cancel and teardown look through, rather than a pool that grows with
	 * the most ops ever in flight and never shrinks. Submit and dequeue both
	 * run on the consuming thread, which alone touches it.
	 */
	ior_iocp_op *live_head;
	ior_iocp_op *live_tail;

	// Free list (protected because timer thread may free ops on PQCS failure/teardown)
	CRITICAL_SECTION pool_lock;
	ior_iocp_op *free_list_head;
	uint32_t free_count;

	_Atomic uint32_t active_count; // ops published to IOCP but not yet dequeued into ready queue

	// Submission queue (software ring): free-running head/tail, indexed
	// through sq_mask, so every one of sq_size slots can be staged.
	ior_iocp_op **sq_array;
	uint32_t sq_head;
	uint32_t sq_tail;
	uint32_t sq_mask;

	/*
	 * Completions PostQueuedCompletionStatus could not queue (out of
	 * nonpaged pool). The packet drives links, link timeouts and drains, so
	 * it is kept here and taken by the next dequeue instead of being lost.
	 * Zero-initialized SRWLOCK, counted in active_count like a queued packet.
	 */
	SRWLOCK backlog_lock;
	struct ior_iocp_op *backlog_head;
	struct ior_iocp_op *backlog_tail;
	_Atomic uint32_t backlog_count;
	uint32_t sq_size;

	// Ready queue for completed operations
	ready_queue ready;

	// Timer manager
	timer_mgr timers;

	// IOR_OP_POLL readiness multiplexer
	iocp_poller poller;

	// ior_notify_fd() completion pump
	iocp_pump pump;

	// Winsock extension functions, fetched on first use (WSAIoctl).
	LPFN_ACCEPTEX fn_acceptex;
	LPFN_CONNECTEX fn_connectex;
	LPFN_GETACCEPTEXSOCKADDRS fn_getacceptexsockaddrs;

	// Handle association tracking
	handle_set handles;

	// Scheduling / ordering
	CRITICAL_SECTION sched_lock;
	ior_iocp_op *pending_head;
	ior_iocp_op *pending_tail;

	atomic_uint_fast64_t submit_seq; // total submitted (sequence generator)
	atomic_uint_fast64_t completed_cnt; // total completions dequeued from IOCP (not "seen")

	/*
	 * IOR_OP_WORK support: a private Win32 threadpool (created lazily on the
	 * first work op) runs the callbacks; completions are delivered through
	 * PostQueuedCompletionStatus like any synthetic completion. The cleanup
	 * group lets destroy wait for every submitted callback - queued ones
	 * included - honoring the "submitted callbacks always run" contract.
	 */
	_Atomic int shutdown; // lets running callbacks observe teardown via token
	PTP_POOL work_pool;
	PTP_CLEANUP_GROUP work_cleanup;
	TP_CALLBACK_ENVIRON work_env;

	/*
	 * IOR_OP_SIGWAIT support: the ops waiting for a console control event
	 * and this context's place in the process-wide list the one control
	 * handler walks (see iocp_sig_ctrl_handler). All under g_sig_lock.
	 */
	ior_iocp_op *sig_ops;
	struct ior_ctx_iocp *sig_next;
	bool sig_registered;

	uint32_t flags;
	uint32_t features;
} ior_ctx_iocp;

/*
 * Helper Functions
 */

static int win_error_to_errno(DWORD err)
{
	switch (err) {
		case ERROR_SUCCESS:
			return 0;
		case ERROR_FILE_NOT_FOUND:
		case ERROR_PATH_NOT_FOUND:
			return -ENOENT;
		case ERROR_ACCESS_DENIED:
			return -EACCES;
		case ERROR_NOT_ENOUGH_MEMORY:
		case ERROR_OUTOFMEMORY:
			return -ENOMEM;
		case ERROR_TIMEOUT:
			return -ETIME; // io_uring timeout semantics
		case ERROR_BUSY:
			return -EBUSY;
		case ERROR_IO_PENDING:
			return 0;
		case ERROR_HANDLE_EOF:
			return 0;
		case ERROR_BROKEN_PIPE:
			return -EPIPE;
		case ERROR_OPERATION_ABORTED:
			return -ECANCELED;
		case ERROR_INVALID_HANDLE:
			return -EBADF;
		case ERROR_INVALID_PARAMETER:
			return -EINVAL;
		case ERROR_NOT_SUPPORTED:
			return -ENOTSUP;
		case ERROR_ABANDONED_WAIT_0:
			return -ECANCELED;
		/*
		 * Winsock error codes (10000+) do not overlap with the ERROR_* range
		 * above, so they coexist in this switch. These surface from WSASend/
		 * WSARecv either synchronously (WSAGetLastError) or via the completion
		 * packet's error status.
		 */
		case WSAECONNRESET:
		case ERROR_NETNAME_DELETED:
			// What AFD reports for a request the peer's reset failed: a recv
			// on a reset connection, or the AcceptEx that takes a connection
			// reset while it was queued.
			return -ECONNRESET;
		case WSAECONNREFUSED:
		case ERROR_CONNECTION_REFUSED:
			return -ECONNREFUSED;
		case WSAENETUNREACH:
		case ERROR_NETWORK_UNREACHABLE:
			return -ENETUNREACH;
		case WSAEHOSTUNREACH:
		case ERROR_HOST_UNREACHABLE:
			return -EHOSTUNREACH;
		case ERROR_SEM_TIMEOUT:
			return -ETIMEDOUT;
		case WSAEADDRINUSE:
			return -EADDRINUSE;
		case WSAEISCONN:
			return -EISCONN;
		case WSAEAFNOSUPPORT:
			return -EAFNOSUPPORT;
		case WSAEINVAL:
			return -EINVAL;
		case WSAECONNABORTED:
			return -ECONNABORTED;
		case ERROR_CONNECTION_ABORTED:
			// What AFD reports for a request still pending when the socket
			// was closed (not ERROR_OPERATION_ABORTED, which only a cancel
			// produces).
			return -ECONNABORTED;
		case WSAENOTCONN:
			return -ENOTCONN;
		case WSAENOTSOCK:
			return -ENOTSOCK;
		case WSAESHUTDOWN:
			return -EPIPE;
		case WSAEWOULDBLOCK:
			return -EAGAIN;
		case WSAEMSGSIZE:
			return -EMSGSIZE;
		case WSAETIMEDOUT:
			return -ETIME;
		default:
			return -EIO;
	}
}

static uint32_t round_up_pow2(uint32_t n)
{
	if (n == 0) {
		return 1;
	}
	n--;
	n |= n >> 1;
	n |= n >> 2;
	n |= n >> 4;
	n |= n >> 8;
	n |= n >> 16;
	n++;
	return n;
}

/* ================= Ready queue ================= */

static int ready_queue_init(ready_queue *q, uint32_t size)
{
	size = round_up_pow2(size);

	q->ops = calloc(size, sizeof(ior_iocp_op *));
	if (!q->ops) {
		return -ENOMEM;
	}
	q->head = 0;
	q->tail = 0;
	q->count = 0;
	q->size = size;
	q->mask = size - 1;
	return 0;
}

static void ready_queue_destroy(ready_queue *q)
{
	if (q->ops) {
		free(q->ops);
		q->ops = NULL;
	}
}

static bool ready_queue_empty(ready_queue *q)
{
	return q->count == 0;
}

static bool ready_queue_full(ready_queue *q)
{
	return q->count >= q->size;
}

static int ready_queue_push(ready_queue *q, ior_iocp_op *op)
{
	if (ready_queue_full(q)) {
		return -EBUSY;
	}
	q->ops[q->tail] = op;
	q->tail = (q->tail + 1) & q->mask;
	q->count++;
	return 0;
}

static ior_iocp_op *ready_queue_peek(ready_queue *q)
{
	if (ready_queue_empty(q)) {
		return NULL;
	}
	return q->ops[q->head];
}

static ior_iocp_op *ready_queue_pop(ready_queue *q)
{
	if (ready_queue_empty(q)) {
		return NULL;
	}
	ior_iocp_op *op = q->ops[q->head];
	q->head = (q->head + 1) & q->mask;
	q->count--;
	return op;
}

/* ================= Handle set ================= */

static void handle_set_init(handle_set *set)
{
	memset(set->buckets, 0, sizeof(set->buckets));
	InitializeCriticalSection(&set->lock);
}

static void handle_set_destroy(handle_set *set)
{
	for (int i = 0; i < HANDLE_SET_SIZE; i++) {
		handle_set_entry *entry = set->buckets[i];
		while (entry) {
			handle_set_entry *next = entry->next;
			free(entry);
			entry = next;
		}
	}
	DeleteCriticalSection(&set->lock);
}

static uint32_t handle_hash(HANDLE h)
{
	uintptr_t val = (uintptr_t) h;
	return (uint32_t) (val % HANDLE_SET_SIZE);
}

static handle_set_entry *handle_set_find_locked(handle_set *set, HANDLE h)
{
	uint32_t bucket = handle_hash(h);
	handle_set_entry *entry = set->buckets[bucket];
	while (entry) {
		if (entry->handle == h) {
			return entry;
		}
		entry = entry->next;
	}
	return NULL;
}

static handle_set_entry *handle_set_insert_locked(handle_set *set, HANDLE h)
{
	uint32_t bucket = handle_hash(h);
	handle_set_entry *entry = malloc(sizeof(handle_set_entry));
	if (!entry) {
		return NULL;
	}
	entry->handle = h;
	entry->cancel_gen = 0;
	entry->epoch = 0;
	entry->owned = false;
	entry->next = set->buckets[bucket];
	set->buckets[bucket] = entry;
	return entry;
}

/* ================= Op pool ================= */

/* Add a chunk of size ops to the free list (pool_lock held, or at init). */
static int grow_op_pool(ior_ctx_iocp *ctx, uint32_t size)
{
	iocp_op_chunk *chunk = calloc(1, sizeof(*chunk) + (size_t) size * sizeof(ior_iocp_op));
	if (!chunk) {
		return -ENOMEM;
	}
	chunk->count = size;
	chunk->next = ctx->op_chunks;
	ctx->op_chunks = chunk;
	for (uint32_t i = 0; i < size; i++) {
		chunk->ops[i].next_free = ctx->free_list_head;
		ctx->free_list_head = &chunk->ops[i];
	}
	ctx->pool_size += size;
	ctx->free_count += size;
	return 0;
}

static void free_op_pool(ior_ctx_iocp *ctx)
{
	while (ctx->op_chunks) {
		iocp_op_chunk *next = ctx->op_chunks->next;
		free(ctx->op_chunks);
		ctx->op_chunks = next;
	}
}

static ior_iocp_op *alloc_op(ior_ctx_iocp *ctx)
{
	EnterCriticalSection(&ctx->pool_lock);

	// Doubling, so growth stays rare; only memory bounds the ops.
	if (!ctx->free_list_head && grow_op_pool(ctx, ctx->pool_size) < 0) {
		LeaveCriticalSection(&ctx->pool_lock);
		return NULL;
	}

	ior_iocp_op *op = ctx->free_list_head;
	ctx->free_list_head = op->next_free;
	ctx->free_count--;

	LeaveCriticalSection(&ctx->pool_lock);

	memset(&op->overlapped, 0, sizeof(OVERLAPPED));
	op->opcode = 0;
	op->sqe_flags = 0;
	op->ioprio = 0;
	op->fd = NULL;
	op->user_data = 0;
	op->buf = NULL;
	op->len = 0;
	op->offset = 0;

	op->wsabuf.buf = NULL;
	op->wsabuf.len = 0;
	op->sock_flags = 0;

	op->poll_mask = 0;
	op->poll_multi = false;
	op->cqe_more = false;
	op->cqe_nonempty = false;
	op->poll_held = false;
	atomic_store(&op->poll_rearm, 0);
	op->poll_parent = NULL;
	op->poll_parent_gen = 0;

	op->timeout_ts = NULL;
	op->timeout_flags = 0;

	op->timer_deadline_ns = 0;
	op->timer_armed = false;
	op->timer_cancelled = false;

	op->link_timeout = NULL;
	op->guarded = NULL;

	op->live_prev = NULL;
	op->live_next = NULL;
	op->live = false;

	op->seq = 0;
	op->drain_after = 0;
	op->link_next = NULL;
	op->linked_deferred = false;
	op->drain_deferred = false;
	op->next_pending = NULL;

	op->bytes_transferred = 0;
	op->error_code = 0;
	op->is_synthetic = false;
	op->submit_res = 0;
	op->backlog_next = NULL;

	op->work_fn = NULL;
	op->work_arg = NULL;
	op->work_res = 0;
	op->work_owner = NULL;
	atomic_init(&op->token.cancelled, 0);
	op->token.shutdown = NULL;

	op->tp_work = NULL;
	op->cancel_key = 0;
	op->cancel_flags = 0;
	op->wait_pid = 0;
	op->wait_status = NULL;
	op->proc_handle = NULL;
	op->tp_wait = NULL;
	op->sig_mask = 0;
	op->sig_info = NULL;
	op->sig_next = NULL;
	op->io_cancel_gen = 0;
	op->io_epoch = 0;
	op->accept_sock = INVALID_SOCKET;
	op->sa = NULL;
	op->sa_len = NULL;
	op->sa_len_val = 0;
	op->accept_recvd = 0;
	op->accept_multi = false;
	op->accept_ending = false;
	op->accept_children = NULL;
	op->accept_sibling = NULL;
	op->accept_nchildren = 0;
	atomic_store(&op->state, IOCP_OP_FREE);

	return op;
}

static void free_op(ior_ctx_iocp *ctx, ior_iocp_op *op)
{
	if (!op) {
		return;
	}

	// An accept that never handed its socket over (failed, cancelled, or
	// reclaimed at teardown) still owns it.
	if (op->accept_sock != INVALID_SOCKET) {
		closesocket(op->accept_sock);
		op->accept_sock = INVALID_SOCKET;
	}
	// A process wait's handle outlives its completion only until here. The
	// wait object is the consumer's to close (or the cleanup group's at
	// teardown), like tp_work.
	if (op->proc_handle) {
		CloseHandle(op->proc_handle);
		op->proc_handle = NULL;
	}

	atomic_store(&op->state, IOCP_OP_FREE);
	op->gen++;

	EnterCriticalSection(&ctx->pool_lock);

	op->next_free = ctx->free_list_head;
	ctx->free_list_head = op;
	ctx->free_count++;

	LeaveCriticalSection(&ctx->pool_lock);
}

// Put a submitted op on the list of ops in flight, as the newest.
static void live_add(ior_ctx_iocp *ctx, ior_iocp_op *op)
{
	op->live_prev = ctx->live_tail;
	op->live_next = NULL;
	if (ctx->live_tail) {
		ctx->live_tail->live_next = op;
	} else {
		ctx->live_head = op;
	}
	ctx->live_tail = op;
	op->live = true;
}

// Take a completed op off it; nothing for one never on it (a multishot edge).
static void live_remove(ior_ctx_iocp *ctx, ior_iocp_op *op)
{
	if (!op->live) {
		return;
	}
	if (op->live_prev) {
		op->live_prev->live_next = op->live_next;
	} else {
		ctx->live_head = op->live_next;
	}
	if (op->live_next) {
		op->live_next->live_prev = op->live_prev;
	} else {
		ctx->live_tail = op->live_prev;
	}
	op->live_prev = NULL;
	op->live_next = NULL;
	op->live = false;
}

/* ================= SQ ring ================= */

static int init_sq_ring(ior_ctx_iocp *ctx, uint32_t size)
{
	size = round_up_pow2(size);

	ctx->sq_array = calloc(size, sizeof(ior_iocp_op *));
	if (!ctx->sq_array) {
		return -ENOMEM;
	}

	ctx->sq_size = size;
	ctx->sq_mask = size - 1;
	ctx->sq_head = 0;
	ctx->sq_tail = 0;

	return 0;
}

static uint32_t sq_space_left(const ior_ctx_iocp *ctx)
{
	uint32_t staged = ctx->sq_tail - ctx->sq_head;
	return staged < ctx->sq_size ? ctx->sq_size - staged : 0;
}

static int sq_enqueue(ior_ctx_iocp *ctx, ior_iocp_op *op)
{
	if (sq_space_left(ctx) == 0) {
		return -ENOSPC;
	}

	ctx->sq_array[ctx->sq_tail & ctx->sq_mask] = op;
	ctx->sq_tail++;
	return 0;
}

/* ================= Scheduling helpers (LINK/DRAIN) ================= */

static void pending_enqueue_locked(ior_ctx_iocp *ctx, ior_iocp_op *op)
{
	// ctx->sched_lock must be held
	op->next_pending = NULL;

	if (!ctx->pending_tail) {
		ctx->pending_head = ctx->pending_tail = op;
	} else {
		ctx->pending_tail->next_pending = op;
		ctx->pending_tail = op;
	}
}

static void pending_remove_locked(ior_ctx_iocp *ctx, ior_iocp_op *op)
{
	// ctx->sched_lock must be held
	ior_iocp_op *prev = NULL;
	ior_iocp_op *cur = ctx->pending_head;

	while (cur) {
		if (cur == op) {
			if (prev) {
				prev->next_pending = cur->next_pending;
			} else {
				ctx->pending_head = cur->next_pending;
			}
			if (ctx->pending_tail == cur) {
				ctx->pending_tail = prev;
			}
			cur->next_pending = NULL;
			return;
		}
		prev = cur;
		cur = cur->next_pending;
	}
}

static bool drain_satisfied(ior_ctx_iocp *ctx, const ior_iocp_op *op)
{
	uint64_t done = atomic_load(&ctx->completed_cnt);
	return done >= op->drain_after;
}

/* ================= IO issue / completion plumbing ================= */

/*
 * Make the notify descriptor readable unless a byte is already outstanding
 * (see iocp_pump_thread_main). pump.lock must be held.
 */
static void iocp_pump_signal_locked(iocp_pump *p)
{
	if (!p->signalled) {
		char b = 0;
		if (send(p->wake_tx, &b, 1, 0) == 1) {
			p->signalled = true;
		}
	}
}

/*
 * Keep a completion the port refused (see backlog_head) and wake a consumer
 * that may be blocked: the pump's condition variable and wake byte, or a
 * stray NULL packet, which a direct dequeue takes as a spurious wakeup.
 * Whether the pump runs is decided under its lock, which iocp_pump_ensure
 * takes to publish the thread, so a pump started meanwhile signals for it.
 */
static void iocp_backlog_push(ior_ctx_iocp *ctx, ior_iocp_op *op)
{
	IOR_LOG_ERROR("PostQueuedCompletionStatus failed (%lu), completion kept", GetLastError());
	op->backlog_next = NULL;
	AcquireSRWLockExclusive(&ctx->backlog_lock);
	if (ctx->backlog_tail) {
		ctx->backlog_tail->backlog_next = op;
	} else {
		ctx->backlog_head = op;
	}
	ctx->backlog_tail = op;
	atomic_fetch_add(&ctx->backlog_count, 1);
	ReleaseSRWLockExclusive(&ctx->backlog_lock);

	iocp_pump *p = &ctx->pump;
	EnterCriticalSection(&p->lock);
	bool pumped = p->thread != NULL;
	if (pumped) {
		iocp_pump_signal_locked(p);
		WakeConditionVariable(&p->cv);
	}
	LeaveCriticalSection(&p->lock);
	if (!pumped) {
		(void) PostQueuedCompletionStatus(ctx->iocp_handle, 0, 0, NULL);
	}
}

static ior_iocp_op *iocp_backlog_pop(ior_ctx_iocp *ctx)
{
	if (atomic_load(&ctx->backlog_count) == 0) {
		return NULL;
	}
	AcquireSRWLockExclusive(&ctx->backlog_lock);
	ior_iocp_op *op = ctx->backlog_head;
	if (op) {
		ctx->backlog_head = op->backlog_next;
		if (!ctx->backlog_head) {
			ctx->backlog_tail = NULL;
		}
		atomic_fetch_sub(&ctx->backlog_count, 1);
	}
	ReleaseSRWLockExclusive(&ctx->backlog_lock);
	return op;
}

static int post_synthetic_completion(
		ior_ctx_iocp *ctx, ior_iocp_op *op, DWORD error_code, DWORD bytes_transferred)
{
	op->error_code = error_code;
	op->bytes_transferred = bytes_transferred;
	op->is_synthetic = true;
	atomic_store(&op->state, IOCP_OP_DONE);

	MemoryBarrier();

	atomic_fetch_add(&ctx->active_count, 1);
	if (!PostQueuedCompletionStatus(ctx->iocp_handle, bytes_transferred, 0, &op->overlapped)) {
		iocp_backlog_push(ctx, op);
	}
	return 0;
}

/*
 * Post a completion for an op whose active_count was already reserved (armed
 * timers, link timeouts, work ops). Unlike post_synthetic_completion it
 * does not increment active_count. Must be called without timers.lock held.
 */
static void post_armed_op(ior_ctx_iocp *ctx, ior_iocp_op *op, DWORD error_code)
{
	op->is_synthetic = true;
	op->error_code = error_code;
	op->bytes_transferred = 0;
	atomic_store(&op->state, IOCP_OP_DONE);

	MemoryBarrier();

	if (!PostQueuedCompletionStatus(ctx->iocp_handle, 0, 0, &op->overlapped)) {
		iocp_backlog_push(ctx, op);
	}
}

/*
 * The live context each handle value's object is tied to, as far as ior
 * knows: the one that associated it with its port last, or took it over. A
 * handle belongs to one port for as long as it is open, so this decides
 * whether a context refused a handle may take it (no owner: a context
 * destroyed since, or a port that is not ior's) or not (another live one,
 * which may still have requests on it). Keyed by the owner, not by which
 * contexts ever saw the value: values are recycled, and a context's set
 * keeps a value long after the object under it was closed.
 *
 * Changed only under g_owner_lock, exclusively, with the association it
 * records, so two contexts cannot both take a handle over. The contexts'
 * handles.lock nests inside it, never the other way round. A context's
 * records go only after its teardown has drained its port: until then a
 * handle moved away from it could still complete a request of its own on
 * the new port.
 */
typedef struct owner_entry {
	HANDLE handle;
	struct ior_ctx_iocp *owner;
	struct owner_entry *next;
} owner_entry;

static SRWLOCK g_owner_lock = SRWLOCK_INIT;
static owner_entry *g_owners[HANDLE_SET_SIZE];

static owner_entry **iocp_owner_find_locked(HANDLE h)
{
	owner_entry **pp = &g_owners[handle_hash(h)];
	while (*pp && (*pp)->handle != h) {
		pp = &(*pp)->next;
	}
	return pp;
}

/*
 * Name ctx the owner of h, which it has just associated or taken over. A
 * previous owner's object under h was closed (or h would not have moved),
 * so its entry no longer names what the value does. g_owner_lock held
 * exclusively.
 */
static int iocp_owner_record_locked(ior_ctx_iocp *ctx, HANDLE h)
{
	owner_entry **pp = iocp_owner_find_locked(h);
	owner_entry *o = *pp;
	if (!o) {
		o = malloc(sizeof(*o));
		if (!o) {
			return -ENOMEM;
		}
		o->handle = h;
		o->owner = NULL;
		o->next = NULL;
		*pp = o;
	}
	if (o->owner && o->owner != ctx) {
		EnterCriticalSection(&o->owner->handles.lock);
		handle_set_entry *prev = handle_set_find_locked(&o->owner->handles, h);
		if (prev) {
			prev->owned = false;
		}
		LeaveCriticalSection(&o->owner->handles.lock);
	}
	o->owner = ctx;
	return 0;
}

/*
 * Drop ctx's records once its port is drained: its handles are free to take.
 * Found in the map itself, not through ctx's set, which may lack an entry
 * for a record (an allocation failure): no record may outlive its owner.
 */
static void iocp_owner_forget(ior_ctx_iocp *ctx)
{
	AcquireSRWLockExclusive(&g_owner_lock);
	for (int i = 0; i < HANDLE_SET_SIZE; i++) {
		owner_entry **pp = &g_owners[i];
		while (*pp) {
			owner_entry *o = *pp;
			if (o->owner == ctx) {
				*pp = o->next;
				free(o);
			} else {
				pp = &o->next;
			}
		}
	}
	ReleaseSRWLockExclusive(&g_owner_lock);
}

/*
 * NtSetInformationFile(FileReplaceCompletionInformation), Windows 8.1+:
 * moves a handle to another completion port. From ntdll, as the SDK
 * declares neither the call nor the class.
 */
typedef struct ior_file_completion_information {
	HANDLE Port;
	PVOID Key;
} ior_file_completion_information;

typedef NTSTATUS(NTAPI *ior_nt_set_information_file_fn)(
		HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, ULONG);

#define IOR_FILE_REPLACE_COMPLETION_INFORMATION 61
#ifndef NT_SUCCESS
#define NT_SUCCESS(status) (((NTSTATUS) (status)) >= 0)
#endif

static INIT_ONCE g_nt_set_info_once = INIT_ONCE_STATIC_INIT;
static ior_nt_set_information_file_fn g_nt_set_info;

static BOOL CALLBACK iocp_nt_set_info_resolve(PINIT_ONCE once, PVOID param, PVOID *context)
{
	(void) once;
	(void) param;
	(void) context;
	HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
	if (ntdll) {
		g_nt_set_info = (ior_nt_set_information_file_fn) (void (*)(void)) GetProcAddress(
				ntdll, "NtSetInformationFile");
	}
	return TRUE;
}

/*
 * Move h to ctx's port, away from whatever port it is tied to. The kernel
 * refuses a handle with requests still pending on it (STATUS_UNSUCCESSFUL),
 * as their completions would follow it: the other port is still using it.
 */
static int iocp_take_over_handle(ior_ctx_iocp *ctx, HANDLE h)
{
	InitOnceExecuteOnce(&g_nt_set_info_once, iocp_nt_set_info_resolve, NULL, NULL);
	if (!g_nt_set_info) {
		return -EINVAL;
	}
	IO_STATUS_BLOCK iosb;
	ior_file_completion_information info = { ctx->iocp_handle, (PVOID) h };
	NTSTATUS status
			= g_nt_set_info(h, &iosb, &info, sizeof(info), IOR_FILE_REPLACE_COMPLETION_INFORMATION);
	if (NT_SUCCESS(status)) {
		return 0;
	}
	return status == (NTSTATUS) 0xC0000001L ? -EBUSY : -EINVAL; // STATUS_UNSUCCESSFUL
}

// The completion status of an op whose handle could not be tied to the port.
static DWORD association_error(int ret)
{
	switch (ret) {
		case -EBUSY:
			return ERROR_BUSY;
		case -ENOMEM:
			return ERROR_NOT_ENOUGH_MEMORY;
		default:
			return ERROR_INVALID_HANDLE;
	}
}

/*
 * Associate h with the port before every issue. Also returns the handle's
 * current cancel generation in *gen, which the op about to be issued records.
 *
 * The kernel is asked every time rather than once per handle value: ior does
 * not see the caller close a handle, and the next socket or file the process
 * opens routinely gets the same value back, so a "seen before" cache would
 * skip the association for a brand-new object and its completions would never
 * reach the port (a connect that never completes, a recv that never returns).
 * CreateIoCompletionPort on a handle that is already associated fails with
 * ERROR_INVALID_PARAMETER; an entry this context owns turns that into "still
 * ours, fine", the common case, which takes no lock but the context's own.
 *
 * Anything else (a value not seen, or one another context has associated a
 * new object under since) is settled under g_owner_lock. A handle belongs to
 * one port for as long as it is open, so one bound elsewhere is taken over
 * (no owner: a context destroyed since, or a port that is not ior's), unless
 * another live context owns it: that one may still have requests on it,
 * whose completions would follow the handle to this port (-EBUSY, as when
 * the kernel refuses to move a handle with requests pending).
 *
 * When the association succeeds for a value already in the set, or the
 * handle is taken over, the value may name a new object and the entry's
 * epoch moves on. The set only grows: entries are reused across such
 * recycling and freed at destroy, bounded by the process's peak number of
 * distinct handle values.
 */
static int ensure_handle_associated(ior_ctx_iocp *ctx, HANDLE h, uint32_t *gen, uint32_t *epoch)
{
	if (h == NULL || h == INVALID_HANDLE_VALUE) {
		return -EBADF;
	}

	EnterCriticalSection(&ctx->handles.lock);
	handle_set_entry *entry = handle_set_find_locked(&ctx->handles, h);
	if (entry && entry->owned) {
		if (CreateIoCompletionPort(h, ctx->iocp_handle, (ULONG_PTR) h, 0)) {
			entry->epoch++; // a new object under the value, and still ours
		} else if (GetLastError() != ERROR_INVALID_PARAMETER) {
			DWORD err = GetLastError();
			LeaveCriticalSection(&ctx->handles.lock);
			return win_error_to_errno(err);
		}
		*gen = entry->cancel_gen;
		*epoch = entry->epoch;
		LeaveCriticalSection(&ctx->handles.lock);
		return 0;
	}
	LeaveCriticalSection(&ctx->handles.lock);

	AcquireSRWLockExclusive(&g_owner_lock);
	int ret = 0;
	if (!CreateIoCompletionPort(h, ctx->iocp_handle, (ULONG_PTR) h, 0)) {
		DWORD err = GetLastError();
		owner_entry *o = *iocp_owner_find_locked(h);
		if (err != ERROR_INVALID_PARAMETER) {
			ret = win_error_to_errno(err);
		} else if (o && o->owner && o->owner != ctx) {
			ret = -EBUSY;
		} else if (!o || o->owner != ctx) {
			// Tied to a port no live context owns, or not one a port can take.
			ret = iocp_take_over_handle(ctx, h);
		}
		// Else ours already, with its entry lost to an allocation failure.
	}
	if (ret == 0) {
		ret = iocp_owner_record_locked(ctx, h);
	}
	if (ret == 0) {
		EnterCriticalSection(&ctx->handles.lock);
		entry = handle_set_find_locked(&ctx->handles, h);
		if (entry) {
			entry->epoch++;
		} else {
			entry = handle_set_insert_locked(&ctx->handles, h);
		}
		if (entry) {
			entry->owned = true;
		}
		*gen = entry ? entry->cancel_gen : 0;
		*epoch = entry ? entry->epoch : 0;
		LeaveCriticalSection(&ctx->handles.lock);
	}
	ReleaseSRWLockExclusive(&g_owner_lock);
	return ret;
}

/* Current cancel generation of an associated handle (0 if never associated).
 * A set lookup, so it can gate the kernel probe in reissue_collateral_abort(). */
static uint32_t handle_cancel_gen(ior_ctx_iocp *ctx, HANDLE h)
{
	EnterCriticalSection(&ctx->handles.lock);
	handle_set_entry *entry = handle_set_find_locked(&ctx->handles, h);
	uint32_t gen = entry ? entry->cancel_gen : 0;
	LeaveCriticalSection(&ctx->handles.lock);
	return gen;
}

/*
 * Cancel an op's overlapped request. AFD (Winsock) cancels every pending
 * request of the same kind on the socket, not only the one named by
 * lpOverlapped, so the handle's cancel generation is bumped first: the
 * consumer re-issues any other op on the handle whose abort arrives with a
 * stale generation (reissue_collateral_abort). The op itself must already be
 * in IOCP_OP_IO_CANCEL so that its own abort is reported.
 */
static BOOL cancel_overlapped_io(ior_ctx_iocp *ctx, ior_iocp_op *op)
{
	EnterCriticalSection(&ctx->handles.lock);
	handle_set_entry *entry = handle_set_find_locked(&ctx->handles, op->fd);
	if (entry) {
		entry->cancel_gen++;
	}
	LeaveCriticalSection(&ctx->handles.lock);

	return CancelIoEx((HANDLE) op->fd, &op->overlapped);
}

/*
 * issue_read / issue_write
 *
 * When ReadFile/WriteFile is called on a handle associated with an IOCP, the
 * default behavior is that a completion packet is posted for BOTH asynchronous
 * completions (ERROR_IO_PENDING) AND synchronous successes (returns TRUE).
 * The only case where no completion is posted is an immediate error that is
 * NOT ERROR_IO_PENDING.
 *
 * Therefore:
 *   - If the call returns TRUE (synchronous success) or fails with
 *     ERROR_IO_PENDING: a completion packet will arrive on the IOCP.
 *     We increment active_count and wait for it.
 *   - If the call fails with any other error: NO completion packet is posted.
 *     We must post a synthetic completion ourselves.
 *
 * Special case: ERROR_HANDLE_EOF means the read reached end-of-file. Windows
 * still posts a completion packet for this on overlapped handles, so we treat
 * it the same as a successful async start.
 */
static int issue_read(ior_ctx_iocp *ctx, ior_iocp_op *op)
{
	HANDLE h = op->fd;

	int ret = ensure_handle_associated(ctx, h, &op->io_cancel_gen, &op->io_epoch);
	if (ret < 0) {
		return post_synthetic_completion(ctx, op, association_error(ret), 0);
	}

	// IOR_OFF_NONE: an overlapped handle keeps no file position, and ReadFile
	// rejects an all-ones offset (ERROR_INVALID_PARAMETER) on a socket or pipe
	// as much as on a file, so read from 0 - which a socket or pipe ignores.
	uint64_t offset = op->offset == IOR_OFF_NONE ? 0 : op->offset;
	op->overlapped.Offset = (DWORD) (offset & 0xFFFFFFFF);
	op->overlapped.OffsetHigh = (DWORD) (offset >> 32);
	atomic_store(&op->state, IOCP_OP_IO);

	BOOL result = ReadFile(h, op->buf, op->len, NULL, &op->overlapped);
	if (result) {
		// Synchronous success: completion packet will still be posted to IOCP
		atomic_fetch_add(&ctx->active_count, 1);
		return 0;
	}

	DWORD err = GetLastError();
	if (err == ERROR_IO_PENDING || err == ERROR_HANDLE_EOF) {
		// Async in progress, or EOF - completion packet will be posted
		atomic_fetch_add(&ctx->active_count, 1);
		return 0;
	}

	// Immediate error with no completion packet - post synthetic
	return post_synthetic_completion(ctx, op, err, 0);
}

static int issue_write(ior_ctx_iocp *ctx, ior_iocp_op *op)
{
	HANDLE h = op->fd;

	int ret = ensure_handle_associated(ctx, h, &op->io_cancel_gen, &op->io_epoch);
	if (ret < 0) {
		return post_synthetic_completion(ctx, op, association_error(ret), 0);
	}

	// IOR_OFF_NONE passes through: WriteFile takes an all-ones offset as
	// "append" on a file and ignores it on a socket or pipe, the nearest
	// thing an overlapped handle has to a current position.
	op->overlapped.Offset = (DWORD) (op->offset & 0xFFFFFFFF);
	op->overlapped.OffsetHigh = (DWORD) (op->offset >> 32);
	atomic_store(&op->state, IOCP_OP_IO);

	BOOL result = WriteFile(h, op->buf, op->len, NULL, &op->overlapped);
	if (result) {
		// Synchronous success: completion packet will still be posted to IOCP
		atomic_fetch_add(&ctx->active_count, 1);
		return 0;
	}

	DWORD err = GetLastError();
	if (err == ERROR_IO_PENDING) {
		// Async in progress - completion packet will be posted
		atomic_fetch_add(&ctx->active_count, 1);
		return 0;
	}

	// Immediate error with no completion packet - post synthetic
	return post_synthetic_completion(ctx, op, err, 0);
}

/*
 * issue_send / issue_recv
 *
 * Socket counterparts of issue_read/issue_write. WSASend/WSARecv behave like
 * ReadFile/WriteFile with respect to IOCP: a completion packet is posted for
 * both synchronous success (return 0) and asynchronous start (WSA_IO_PENDING).
 * Any other Winsock error means no packet is posted, so we synthesize one.
 *
 * The op's fd is an ior_fd_t (HANDLE); sockets created with WSA_FLAG_OVERLAPPED
 * are valid IOCP targets, so we cast the handle to SOCKET for the Winsock call.
 */
static int issue_send(ior_ctx_iocp *ctx, ior_iocp_op *op)
{
	int ret = ensure_handle_associated(ctx, op->fd, &op->io_cancel_gen, &op->io_epoch);
	if (ret < 0) {
		return post_synthetic_completion(ctx, op, association_error(ret), 0);
	}

	op->wsabuf.buf = (CHAR *) op->buf;
	op->wsabuf.len = op->len;
	atomic_store(&op->state, IOCP_OP_IO);

	int rc = WSASend((SOCKET) op->fd, &op->wsabuf, 1, NULL, op->sock_flags, &op->overlapped, NULL);
	if (rc == 0) {
		// Synchronous success: completion packet will still be posted to IOCP
		atomic_fetch_add(&ctx->active_count, 1);
		return 0;
	}

	int err = WSAGetLastError();
	if (err == WSA_IO_PENDING) {
		atomic_fetch_add(&ctx->active_count, 1);
		return 0;
	}

	return post_synthetic_completion(ctx, op, (DWORD) err, 0);
}

static int issue_recv(ior_ctx_iocp *ctx, ior_iocp_op *op)
{
	int ret = ensure_handle_associated(ctx, op->fd, &op->io_cancel_gen, &op->io_epoch);
	if (ret < 0) {
		return post_synthetic_completion(ctx, op, association_error(ret), 0);
	}

	op->wsabuf.buf = (CHAR *) op->buf;
	op->wsabuf.len = op->len;
	atomic_store(&op->state, IOCP_OP_IO);

	// sock_flags is an in/out parameter for WSARecv and must remain valid for
	// the whole async operation, hence it lives in the op.
	int rc = WSARecv((SOCKET) op->fd, &op->wsabuf, 1, NULL, &op->sock_flags, &op->overlapped, NULL);
	if (rc == 0) {
		// Synchronous success: completion packet will still be posted to IOCP
		atomic_fetch_add(&ctx->active_count, 1);
		return 0;
	}

	int err = WSAGetLastError();
	if (err == WSA_IO_PENDING) {
		atomic_fetch_add(&ctx->active_count, 1);
		return 0;
	}

	return post_synthetic_completion(ctx, op, (DWORD) err, 0);
}

/* ================= Accept / connect (AcceptEx, ConnectEx) ================= */

// Fetch a Winsock extension function pointer through a socket of its family.
static int load_extension(SOCKET s, GUID guid, void **out)
{
	DWORD bytes = 0;
	if (WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &guid, sizeof(guid), out, sizeof(*out),
				&bytes, NULL, NULL)
			!= 0) {
		return -1;
	}
	return 0;
}

/*
 * AcceptEx needs the accepted socket created up front, of the listener's
 * family and protocol, overlapped so it can join the port later. The
 * accepted socket is handed to the caller in res on success (see
 * finish_socket_op) and closed on any failure.
 */
static int issue_accept(ior_ctx_iocp *ctx, ior_iocp_op *op)
{
	SOCKET ls = (SOCKET) op->fd;

	int ret = ensure_handle_associated(ctx, op->fd, &op->io_cancel_gen, &op->io_epoch);
	if (ret < 0) {
		return post_synthetic_completion(ctx, op, association_error(ret), 0);
	}

	// A re-issue after a collateral abort starts over with a fresh socket.
	if (op->accept_sock != INVALID_SOCKET) {
		closesocket(op->accept_sock);
		op->accept_sock = INVALID_SOCKET;
	}

	if (!ctx->fn_acceptex) {
		GUID guid = WSAID_ACCEPTEX;
		if (load_extension(ls, guid, (void **) &ctx->fn_acceptex) < 0) {
			return post_synthetic_completion(ctx, op, (DWORD) WSAGetLastError(), 0);
		}
	}
	if (!ctx->fn_getacceptexsockaddrs) {
		GUID guid = WSAID_GETACCEPTEXSOCKADDRS;
		if (load_extension(ls, guid, (void **) &ctx->fn_getacceptexsockaddrs) < 0) {
			return post_synthetic_completion(ctx, op, (DWORD) WSAGetLastError(), 0);
		}
	}

	WSAPROTOCOL_INFOW info;
	int info_len = sizeof(info);
	if (getsockopt(ls, SOL_SOCKET, SO_PROTOCOL_INFOW, (char *) &info, &info_len) != 0) {
		return post_synthetic_completion(ctx, op, (DWORD) WSAGetLastError(), 0);
	}
	SOCKET as = WSASocketW(FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, &info, 0,
			WSA_FLAG_OVERLAPPED);
	if (as == INVALID_SOCKET) {
		return post_synthetic_completion(ctx, op, (DWORD) WSAGetLastError(), 0);
	}
	op->accept_sock = as;
	op->accept_recvd = 0;
	atomic_store(&op->state, IOCP_OP_IO);

	// No data is received with the accept (dwReceiveDataLength 0), so the
	// completion arrives as soon as a connection is there.
	DWORD addr_room = sizeof(SOCKADDR_STORAGE) + 16;
	BOOL ok = ctx->fn_acceptex(
			ls, as, op->accept_buf, 0, addr_room, addr_room, &op->accept_recvd, &op->overlapped);
	if (ok) {
		// Synchronous success: completion packet will still be posted to IOCP
		atomic_fetch_add(&ctx->active_count, 1);
		return 0;
	}

	int err = WSAGetLastError();
	if (err == WSA_IO_PENDING) {
		atomic_fetch_add(&ctx->active_count, 1);
		return 0;
	}

	closesocket(as);
	op->accept_sock = INVALID_SOCKET;
	return post_synthetic_completion(ctx, op, (DWORD) err, 0);
}

/*
 * ConnectEx needs a bound socket; an unbound one is bound to the wildcard
 * address of the destination's family first, as connect(2) would do.
 */
static int issue_connect(ior_ctx_iocp *ctx, ior_iocp_op *op)
{
	SOCKET s = (SOCKET) op->fd;

	int ret = ensure_handle_associated(ctx, op->fd, &op->io_cancel_gen, &op->io_epoch);
	if (ret < 0) {
		return post_synthetic_completion(ctx, op, association_error(ret), 0);
	}
	if (!op->sa) {
		return post_synthetic_completion(ctx, op, ERROR_INVALID_PARAMETER, 0);
	}

	if (!ctx->fn_connectex) {
		GUID guid = WSAID_CONNECTEX;
		if (load_extension(s, guid, (void **) &ctx->fn_connectex) < 0) {
			return post_synthetic_completion(ctx, op, (DWORD) WSAGetLastError(), 0);
		}
	}

	SOCKADDR_STORAGE local;
	int local_len = sizeof(local);
	if (getsockname(s, (struct sockaddr *) &local, &local_len) != 0
			&& WSAGetLastError() == WSAEINVAL) {
		memset(&local, 0, sizeof(local));
		local.ss_family = op->sa->sa_family;
		int bind_len = op->sa->sa_family == AF_INET6 ? (int) sizeof(struct sockaddr_in6)
													 : (int) sizeof(struct sockaddr_in);
		if (bind(s, (struct sockaddr *) &local, bind_len) != 0) {
			return post_synthetic_completion(ctx, op, (DWORD) WSAGetLastError(), 0);
		}
	}

	atomic_store(&op->state, IOCP_OP_IO);
	BOOL ok = ctx->fn_connectex(s, op->sa, (int) op->sa_len_val, NULL, 0, NULL, &op->overlapped);
	if (ok) {
		atomic_fetch_add(&ctx->active_count, 1);
		return 0;
	}

	int err = WSAGetLastError();
	if (err == WSA_IO_PENDING) {
		atomic_fetch_add(&ctx->active_count, 1);
		return 0;
	}

	return post_synthetic_completion(ctx, op, (DWORD) err, 0);
}

/*
 * Completion side of accept and connect, run at dequeue before the CQE is
 * built: an accepted socket must inherit the listener's context and the
 * caller's address buffers are filled; a connected socket must have its
 * context updated too. A failure closes the accepted socket.
 */
static void finish_socket_op(ior_ctx_iocp *ctx, ior_iocp_op *op)
{
	if (op->opcode == IOR_OP_ACCEPT) {
		if (op->accept_sock == INVALID_SOCKET) {
			return;
		}
		if (op->error_code == ERROR_SUCCESS) {
			SOCKET ls = (SOCKET) op->fd;
			if (setsockopt(op->accept_sock, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT,
						(const char *) &ls, sizeof(ls))
					!= 0) {
				op->error_code = (DWORD) WSAGetLastError();
			} else if (op->sa && op->sa_len) {
				struct sockaddr *la = NULL, *ra = NULL;
				int la_len = 0, ra_len = 0;
				DWORD addr_room = sizeof(SOCKADDR_STORAGE) + 16;
				ctx->fn_getacceptexsockaddrs(
						op->accept_buf, 0, addr_room, addr_room, &la, &la_len, &ra, &ra_len);
				int n = ra_len < (int) *op->sa_len ? ra_len : (int) *op->sa_len;
				if (n > 0) {
					memcpy(op->sa, ra, (size_t) n);
				}
				*op->sa_len = (socklen_t) ra_len;
			}
			if (op->error_code == ERROR_SUCCESS && !op->poll_parent) {
				// IOR_CQE_F_SOCK_NONEMPTY for a one-shot accept: the listener
				// reads ready while a connection is queued (a poll with no
				// wait; an error counts as nothing queued, the hint being
				// optional). Not for a multishot's child: its siblings take
				// what is queued as it arrives.
				WSAPOLLFD pfd = { .fd = ls, .events = POLLRDNORM };
				op->cqe_nonempty = WSAPoll(&pfd, 1, 0) > 0 && (pfd.revents & POLLRDNORM);
			}
		}
		if (op->error_code != ERROR_SUCCESS) {
			closesocket(op->accept_sock);
			op->accept_sock = INVALID_SOCKET;
		}
	} else if (op->opcode == IOR_OP_CONNECT && op->error_code == ERROR_SUCCESS) {
		if (setsockopt((SOCKET) op->fd, SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT, NULL, 0) != 0) {
			op->error_code = (DWORD) WSAGetLastError();
		}
	}
}

/*
 * ================= Multishot accept =================
 *
 * AcceptEx is one-shot, so a multishot accept (the parent op) keeps
 * IOCP_ACCEPT_MULTI_DEPTH AcceptEx requests outstanding, each a child op on
 * the live list (teardown finds its request there, and a collateral abort
 * is re-issued as for any accept) but never a cancel's match: it names its
 * parent. A child that accepted a connection is the caller's completion,
 * with IOR_CQE_F_MORE, and is replaced by a new one; the parent itself
 * completes only once it is on its way out and its last child is in, so a
 * connection accepted before the parent's completion always precedes it.
 */
#define IOCP_ACCEPT_MULTI_DEPTH 4

// Under timers.lock.
static void accept_multi_link_locked(ior_iocp_op *parent, ior_iocp_op *child)
{
	child->accept_sibling = parent->accept_children;
	parent->accept_children = child;
	parent->accept_nchildren++;
}

// Under timers.lock.
static void accept_multi_unlink_locked(ior_iocp_op *parent, ior_iocp_op *child)
{
	for (ior_iocp_op **pp = &parent->accept_children; *pp; pp = &(*pp)->accept_sibling) {
		if (*pp == child) {
			*pp = child->accept_sibling;
			child->accept_sibling = NULL;
			parent->accept_nchildren--;
			return;
		}
	}
}

/*
 * Put one more AcceptEx out for a parent. Returns 0 once the child's request
 * is in flight, or its failure is on its way through the port (a synthetic
 * completion, which then takes the parent out), -ENOMEM with no op to be had,
 * -ECANCELED for a parent on its way out, which gets no more children.
 *
 * The child is linked and issued under timers.lock, the lock the timer thread
 * takes the parent out under when its link timeout fires
 * (accept_multi_end_locked): that pass cancels the children it finds, so a
 * child linked after it must not be issued, and one linked before it must
 * already be in flight, or it would be left out, never cancelled, and the
 * parent would complete only with the next connection.
 */
static int accept_multi_spawn(ior_ctx_iocp *ctx, ior_iocp_op *parent)
{
	ior_iocp_op *child = alloc_op(ctx);
	if (!child) {
		return -ENOMEM;
	}
	child->opcode = IOR_OP_ACCEPT;
	child->fd = parent->fd;
	child->user_data = parent->user_data;
	child->accept_flags = parent->accept_flags;
	child->cqe_more = true;
	child->poll_parent = parent;
	child->poll_parent_gen = parent->gen;

	EnterCriticalSection(&ctx->timers.lock);
	if (parent->accept_ending) {
		LeaveCriticalSection(&ctx->timers.lock);
		free_op(ctx, child);
		return -ECANCELED;
	}
	accept_multi_link_locked(parent, child);
	live_add(ctx, child);
	int ret = issue_accept(ctx, child);
	LeaveCriticalSection(&ctx->timers.lock);
	return ret;
}

/*
 * Take a parent out (timers.lock held): no child is replaced from now on,
 * the outstanding ones are cancelled, and the last of them to come in posts
 * the parent with error (see accept_multi_child_done). Nothing to do for a
 * parent already on its way out, which keeps what took it out. Every child
 * is marked before the first CancelIoEx, since AFD aborts them all with the
 * first one and a marked child's abort is reported rather than re-issued.
 */
static void accept_multi_end_locked(ior_ctx_iocp *ctx, ior_iocp_op *parent, DWORD error)
{
	if (atomic_load(&parent->state) != IOCP_OP_ACCEPT_MULTI || parent->accept_ending) {
		return;
	}
	parent->accept_ending = true;
	parent->error_code = error;
	for (ior_iocp_op *c = parent->accept_children; c; c = c->accept_sibling) {
		int expected = IOCP_OP_IO;
		atomic_compare_exchange_strong(&c->state, &expected, IOCP_OP_IO_CANCEL);
	}
	for (ior_iocp_op *c = parent->accept_children; c; c = c->accept_sibling) {
		if (atomic_load(&c->state) == IOCP_OP_IO_CANCEL) {
			cancel_overlapped_io(ctx, c);
		}
	}
}

/*
 * Start a multishot accept: the parent holds an active_count slot for its
 * own completion, posted by the consumer with post_armed_op, and puts its
 * children out. Without memory for a single child it completes at once.
 */
static int issue_accept_multi(ior_ctx_iocp *ctx, ior_iocp_op *op)
{
	atomic_fetch_add(&ctx->active_count, 1);
	atomic_store(&op->state, IOCP_OP_ACCEPT_MULTI);
	for (int i = 0; i < IOCP_ACCEPT_MULTI_DEPTH; i++) {
		if (accept_multi_spawn(ctx, op) < 0) {
			break;
		}
	}
	if (op->accept_nchildren == 0) {
		post_armed_op(ctx, op, ERROR_NOT_ENOUGH_MEMORY);
	}
	return 0;
}

/*
 * A child has been dequeued (its slot given back, finish_socket_op run).
 * Returns true if its CQE is the caller's: a connection it accepted while
 * its parent is in flight, even one on its way out (the connection is real,
 * and the parent's completion is still behind it).
 *
 * A failure of the request takes the parent out, the first one's error
 * being the parent's result: one that never got in flight (synthetic: no
 * socket to be had, AcceptEx refused, the listener not a socket) or an
 * abort (-ECANCELED: the parent's own cancellation, the listener closed
 * with the request pending, a CancelIoEx behind the library's back). A
 * connection that failed on its own is another matter: a peer that resets
 * while queued fails the AcceptEx that takes it (ERROR_NETNAME_DELETED)
 * and leaves the listener as it was, so as accept(2) never reports such a
 * connection on Linux it is dropped here and the child replaced. A
 * listener that is in fact gone refuses the replacement, which ends the
 * parent. A parent without memory for a replacement ends once no child is
 * left. A child of a parent the teardown completed is nobody's, and its
 * socket goes with it (free_op).
 */
static bool accept_multi_child_done(ior_ctx_iocp *ctx, ior_iocp_op *child)
{
	ior_iocp_op *parent = child->poll_parent;
	timer_mgr *tm = &ctx->timers;

	EnterCriticalSection(&tm->lock);
	bool alive = parent->gen == child->poll_parent_gen
			&& atomic_load(&parent->state) == IOCP_OP_ACCEPT_MULTI;
	bool deliver = false;
	bool replace = false;
	if (alive) {
		accept_multi_unlink_locked(parent, child);
		deliver = child->error_code == ERROR_SUCCESS;
		bool fatal = !deliver
				&& (child->is_synthetic || child->error_code == ERROR_OPERATION_ABORTED);
		if (fatal) {
			accept_multi_end_locked(ctx, parent, child->error_code);
		}
		replace = !fatal && !parent->accept_ending;
	}
	LeaveCriticalSection(&tm->lock);
	if (!alive) {
		return false;
	}

	if (replace && accept_multi_spawn(ctx, parent) < 0) {
		EnterCriticalSection(&tm->lock);
		if (parent->accept_nchildren == 0) {
			accept_multi_end_locked(ctx, parent, ERROR_NOT_ENOUGH_MEMORY);
		}
		LeaveCriticalSection(&tm->lock);
	}

	EnterCriticalSection(&tm->lock);
	bool last = parent->accept_nchildren == 0;
	DWORD error = parent->error_code;
	LeaveCriticalSection(&tm->lock);
	if (last) {
		post_armed_op(ctx, parent, error);
	}
	return deliver;
}

/*
 * ================= Work op support =================
 *
 * The callback runs on a private Win32 threadpool and delivers its completion
 * with PostQueuedCompletionStatus, so it flows through the same dequeue path
 * (and LINK/DRAIN/link-timeout machinery) as every other op.
 */

static VOID CALLBACK ior_iocp_work_callback(
		PTP_CALLBACK_INSTANCE instance, PVOID param, PTP_WORK work)
{
	(void) instance;
	(void) work;
	ior_iocp_op *op = param;
	ior_ctx_iocp *ctx = op->work_owner;

	// Claim the op before running anything: a cancel that claims it first
	// (IOCP_OP_WORK -> IOCP_OP_DONE) completes it as -ECANCELED itself and
	// the callback must not touch it any more.
	int expected = IOCP_OP_WORK;
	if (!atomic_compare_exchange_strong(&op->state, &expected, IOCP_OP_WORK_RUNNING)) {
		return;
	}

	op->work_res = op->work_fn(&op->token, op->work_arg);

	/* The active_count slot was reserved in issue_work: posting from this
	 * threadpool thread with a post-PQCS increment would race the consumer's
	 * decrement at dequeue and underflow the counter. */
	post_armed_op(ctx, op, ERROR_SUCCESS);
}

// One-time (per context) creation of the private threadpool.
static int iocp_work_ensure(ior_ctx_iocp *ctx)
{
	if (ctx->work_pool) {
		return 0;
	}

	ctx->work_pool = CreateThreadpool(NULL);
	if (!ctx->work_pool) {
		return -ENOMEM;
	}
	SetThreadpoolThreadMaximum(ctx->work_pool, 32);

	ctx->work_cleanup = CreateThreadpoolCleanupGroup();
	if (!ctx->work_cleanup) {
		CloseThreadpool(ctx->work_pool);
		ctx->work_pool = NULL;
		return -ENOMEM;
	}

	InitializeThreadpoolEnvironment(&ctx->work_env);
	SetThreadpoolCallbackPool(&ctx->work_env, ctx->work_pool);
	SetThreadpoolCallbackCleanupGroup(&ctx->work_env, ctx->work_cleanup, NULL);

	return 0;
}

static int issue_work(ior_ctx_iocp *ctx, ior_iocp_op *op)
{
	if (iocp_work_ensure(ctx) < 0) {
		return post_synthetic_completion(ctx, op, ERROR_NOT_ENOUGH_MEMORY, 0);
	}

	op->work_owner = ctx;
	atomic_init(&op->token.cancelled, 0);
	op->token.shutdown = &ctx->shutdown;

	// A work object per op (rather than TrySubmitThreadpoolCallback) so that a
	// cancel can withdraw the callback while it is still queued.
	op->tp_work = CreateThreadpoolWork(ior_iocp_work_callback, op, &ctx->work_env);
	if (!op->tp_work) {
		return post_synthetic_completion(ctx, op, ERROR_NOT_ENOUGH_MEMORY, 0);
	}

	// Reserve the active_count slot up front, like arm_timer: the callback
	// completes from another thread, so it must post with the slot already held.
	atomic_fetch_add(&ctx->active_count, 1);
	atomic_store(&op->state, IOCP_OP_WORK);

	SubmitThreadpoolWork(op->tp_work);
	return 0;
}

/*
 * ================= IOR_OP_WAITPID support =================
 *
 * A threadpool wait on the process handle (the same private pool as work
 * ops) fires once the process exits; the callback collects the exit code
 * and posts the completion. The state arbitrates between the callback and
 * a cancel (an async cancel, a fired link timeout, or teardown): whichever
 * moves IOCP_OP_WAIT on owns the completion.
 */

static VOID CALLBACK ior_iocp_wait_callback(
		PTP_CALLBACK_INSTANCE instance, PVOID param, PTP_WAIT wait, TP_WAIT_RESULT result)
{
	(void) instance;
	(void) wait;
	(void) result; // an INFINITE wait only ever reports WAIT_OBJECT_0
	ior_iocp_op *op = param;

	int expected = IOCP_OP_WAIT;
	if (!atomic_compare_exchange_strong(&op->state, &expected, IOCP_OP_DONE)) {
		return; // cancelled: whoever claimed it completes it
	}

	DWORD err = ERROR_SUCCESS;
	DWORD code = 0;
	if (!GetExitCodeProcess(op->proc_handle, &code)) {
		err = GetLastError();
	} else if (op->wait_status) {
		*op->wait_status = (int) code;
	}
	op->work_res = (int32_t) op->wait_pid;
	post_armed_op(op->work_owner, op, err);
}

static int issue_waitpid(ior_ctx_iocp *ctx, ior_iocp_op *op)
{
	// Only one process can be named: there is no "any child" here.
	if ((int32_t) op->wait_pid <= 0) {
		return post_synthetic_completion(ctx, op, ERROR_NOT_SUPPORTED, 0);
	}
	if (iocp_work_ensure(ctx) < 0) {
		return post_synthetic_completion(ctx, op, ERROR_NOT_ENOUGH_MEMORY, 0);
	}

	HANDLE h = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, op->wait_pid);
	if (!h) {
		DWORD err = GetLastError();
		if (err == ERROR_INVALID_PARAMETER) {
			// No such process: what waitpid says of a pid that is no child.
			op->work_res = -ECHILD;
			return post_synthetic_completion(ctx, op, ERROR_SUCCESS, 0);
		}
		return post_synthetic_completion(ctx, op, err, 0);
	}
	op->proc_handle = h;
	op->work_owner = ctx;

	op->tp_wait = CreateThreadpoolWait(ior_iocp_wait_callback, op, &ctx->work_env);
	if (!op->tp_wait) {
		return post_synthetic_completion(ctx, op, ERROR_NOT_ENOUGH_MEMORY, 0);
	}

	// Reserve the active_count slot up front, like issue_work: the callback
	// completes the op from another thread.
	atomic_fetch_add(&ctx->active_count, 1);
	atomic_store(&op->state, IOCP_OP_WAIT);

	// The state is claimable for a moment before the wait is armed, and
	// nothing claims it there: cancels run on the submitting thread, a link
	// timeout is armed only after this returns, teardown runs on the caller's
	// thread. Once armed the op is no longer ours to look at - a process
	// that has already exited fires the callback at once, which completes
	// the op, and a reaper may then close the wait object and recycle the
	// op before a check here could read it.
	SetThreadpoolWait(op->tp_wait, h, NULL);
	return 0;
}

/*
 * Take a registered process wait away from the threadpool: claim it (a
 * callback being dispatched right now then returns without touching the
 * op), withdraw the wait and let a running callback finish, and complete
 * the op as aborted. Returns false when the callback claimed it first: it
 * is completing with its real result.
 */
static bool iocp_waitpid_abort(ior_ctx_iocp *ctx, ior_iocp_op *op)
{
	int expected = IOCP_OP_WAIT;
	if (!atomic_compare_exchange_strong(&op->state, &expected, IOCP_OP_DONE)) {
		return false;
	}
	SetThreadpoolWait(op->tp_wait, NULL, NULL);
	WaitForThreadpoolWaitCallbacks(op->tp_wait, TRUE);
	post_armed_op(ctx, op, ERROR_OPERATION_ABORTED);
	return true;
}

/*
 * ================= IOR_OP_SIGWAIT support =================
 *
 * The signals Windows has are console control events, delivered on a thread
 * the system starts to handlers registered process-wide, so every context
 * with a sigwait pending stands in one list that one handler walks: the
 * first op whose set has the event's signal claims it (a CAS from
 * IOCP_OP_SIGWAIT, like a process wait's), takes the details and posts its
 * completion. With no taker the event goes on to the next handler (the
 * CRT's signal(), then the default action). The handler is installed with
 * the first context that registers and removed with the last; the CRT's
 * mapping of events to signals is kept: Ctrl+C is SIGINT, everything else
 * SIGBREAK.
 */

static SRWLOCK g_sig_lock = SRWLOCK_INIT;
static ior_ctx_iocp *g_sig_ctxs;

/*
 * Hand the event to the first pending op whose set has its signal. Returns
 * whether one took it.
 */
static bool iocp_sig_dispatch(DWORD type)
{
	int sig = type == CTRL_C_EVENT ? SIGINT : SIGBREAK;
	ior_iocp_op *taker = NULL;
	ior_ctx_iocp *owner = NULL;

	AcquireSRWLockExclusive(&g_sig_lock);
	for (ior_ctx_iocp *ctx = g_sig_ctxs; ctx && !taker; ctx = ctx->sig_next) {
		for (ior_iocp_op **pp = &ctx->sig_ops; *pp; pp = &(*pp)->sig_next) {
			ior_iocp_op *op = *pp;
			if (!(op->sig_mask & (1U << sig))) {
				continue;
			}
			int expected = IOCP_OP_SIGWAIT;
			if (!atomic_compare_exchange_strong(&op->state, &expected, IOCP_OP_DONE)) {
				continue; // being aborted: its owner unlinks it
			}
			*pp = op->sig_next;
			op->sig_next = NULL;
			taker = op;
			owner = ctx;
			break;
		}
	}
	ReleaseSRWLockExclusive(&g_sig_lock);

	if (!taker) {
		return false;
	}
	// The context outlives this post: its teardown drains the port until
	// every reserved completion, this one included, has arrived.
	if (taker->sig_info) {
		taker->sig_info->si_signo = sig;
		taker->sig_info->si_code = (int) type;
	}
	taker->work_res = sig;
	post_armed_op(owner, taker, ERROR_SUCCESS);
	return true;
}

static BOOL WINAPI iocp_sig_ctrl_handler(DWORD type)
{
	return iocp_sig_dispatch(type) ? TRUE : FALSE;
}

/*
 * ior_sigrequeue() on Windows: the event is offered again as on its arrival,
 * and with no taker goes where the handler would have passed it, as far as
 * a program can send it: raise() reaches the CRT's signal() handler, or its
 * default action.
 */
int ior_iocp_sigrequeue(const ior_siginfo_t *info)
{
	if (!info || (info->si_signo != SIGINT && info->si_signo != SIGBREAK)) {
		return -EINVAL;
	}
	DWORD type = info->si_signo == SIGINT ? CTRL_C_EVENT : (DWORD) info->si_code;
	if (info->si_signo == SIGBREAK && type != CTRL_BREAK_EVENT && type != CTRL_CLOSE_EVENT
			&& type != CTRL_LOGOFF_EVENT && type != CTRL_SHUTDOWN_EVENT) {
		type = CTRL_BREAK_EVENT;
	}
	if (iocp_sig_dispatch(type)) {
		return 0;
	}
	return raise(info->si_signo) == 0 ? 0 : -EINVAL;
}

// Put ctx on the handler's list, installing the handler for the first one.
// g_sig_lock held exclusively.
static bool iocp_sig_register_locked(ior_ctx_iocp *ctx)
{
	if (ctx->sig_registered) {
		return true;
	}
	if (!g_sig_ctxs && !SetConsoleCtrlHandler(iocp_sig_ctrl_handler, TRUE)) {
		return false;
	}
	ctx->sig_next = g_sig_ctxs;
	g_sig_ctxs = ctx;
	ctx->sig_registered = true;
	return true;
}

// Take ctx off the handler's list, removing the handler with the last one.
static void iocp_sig_unregister(ior_ctx_iocp *ctx)
{
	AcquireSRWLockExclusive(&g_sig_lock);
	if (ctx->sig_registered) {
		for (ior_ctx_iocp **pp = &g_sig_ctxs; *pp; pp = &(*pp)->sig_next) {
			if (*pp == ctx) {
				*pp = ctx->sig_next;
				break;
			}
		}
		ctx->sig_next = NULL;
		ctx->sig_registered = false;
		if (!g_sig_ctxs) {
			SetConsoleCtrlHandler(iocp_sig_ctrl_handler, FALSE);
		}
	}
	ReleaseSRWLockExclusive(&g_sig_lock);
}

static int issue_sigwait(ior_ctx_iocp *ctx, ior_iocp_op *op)
{
	op->work_owner = ctx;

	AcquireSRWLockExclusive(&g_sig_lock);
	bool ok = iocp_sig_register_locked(ctx);
	if (ok) {
		// Reserve the active_count slot up front, like a process wait: the
		// handler completes the op from the system's thread. Oldest first,
		// so ops take events in submission order.
		atomic_fetch_add(&ctx->active_count, 1);
		atomic_store(&op->state, IOCP_OP_SIGWAIT);
		op->sig_next = NULL;
		ior_iocp_op **pp = &ctx->sig_ops;
		while (*pp) {
			pp = &(*pp)->sig_next;
		}
		*pp = op;
	}
	ReleaseSRWLockExclusive(&g_sig_lock);

	if (!ok) {
		return post_synthetic_completion(ctx, op, ERROR_NOT_SUPPORTED, 0);
	}
	return 0;
}

/*
 * Take a listed sigwait away from the handler: claim it (a handler walking
 * the list then skips it), unlink it and complete it as aborted. Returns
 * false when the handler claimed it first: it is completing with its signal.
 */
static bool iocp_sigwait_abort(ior_ctx_iocp *ctx, ior_iocp_op *op)
{
	int expected = IOCP_OP_SIGWAIT;
	if (!atomic_compare_exchange_strong(&op->state, &expected, IOCP_OP_DONE)) {
		return false;
	}
	AcquireSRWLockExclusive(&g_sig_lock);
	for (ior_iocp_op **pp = &ctx->sig_ops; *pp; pp = &(*pp)->sig_next) {
		if (*pp == op) {
			*pp = op->sig_next;
			op->sig_next = NULL;
			break;
		}
	}
	ReleaseSRWLockExclusive(&g_sig_lock);
	post_armed_op(ctx, op, ERROR_OPERATION_ABORTED);
	return true;
}

/* ================= IOR_OP_POLL support ================= */

static SHORT ior_poll_mask_to_wsa(uint32_t ior_mask)
{
	SHORT ev = 0;
	if (ior_mask & IOR_POLL_IN) {
		ev |= POLLRDNORM | POLLRDBAND;
	}
	if (ior_mask & IOR_POLL_OUT) {
		ev |= POLLWRNORM;
	}
	// ERR/HUP/NVAL are revents-only on Windows and must not be requested.
	return ev;
}

static uint32_t wsa_to_ior_poll_mask(SHORT revents)
{
	uint32_t mask = 0;
	if (revents & (POLLRDNORM | POLLRDBAND)) {
		mask |= IOR_POLL_IN;
	}
	if (revents & POLLWRNORM) {
		mask |= IOR_POLL_OUT;
	}
	if (revents & POLLERR) {
		mask |= IOR_POLL_ERR;
	}
	if (revents & POLLHUP) {
		mask |= IOR_POLL_HUP;
	}
	if (revents & POLLNVAL) {
		mask |= IOR_POLL_NVAL;
	}
	return mask;
}

static void iocp_poller_wake(iocp_poller *p)
{
	char b = 0;
	(void) send(p->wake_tx, &b, 1, 0);
}

static void iocp_poller_drain_wake(iocp_poller *p)
{
	char buf[64];
	while (recv(p->wake_rx, buf, sizeof(buf), 0) > 0) { }
}

/* Remove active entry i by swapping in the last one. */
static void iocp_poller_remove(iocp_poller *p, uint32_t i)
{
	p->active_len--;
	p->active[i] = p->active[p->active_len];
}

/*
 * A consumer has marked a multishot poll's edge CQE seen: readiness has been
 * consumed as far as the contract asks, so let the poller watch the parent
 * again. The parent is named by pointer and by the gen it had when the edge
 * was posted; a parent that has ended and returned to the pool since (its
 * final CQE is behind the edge in the port, but a caller may mark them seen
 * in any order) has moved on and is left alone. A flag set on an op the
 * pool has just handed out again is harmless either way: alloc_op clears
 * it, and the poller reads it only on an op it holds.
 */
static void iocp_poll_edge_seen(ior_ctx_iocp *ctx, ior_iocp_op *edge)
{
	ior_iocp_op *parent = edge->poll_parent;
	if (!parent || parent->gen != edge->poll_parent_gen) {
		return;
	}
	atomic_store(&parent->poll_rearm, 1);
	iocp_poller *p = &ctx->poller;
	if (!atomic_exchange(&p->wake_pending, 1)) {
		iocp_poller_wake(p);
	}
}

/* The consumer's release of a CQE: re-arm the poll behind an edge, then free. */
static void consumer_free_op(ior_ctx_iocp *ctx, ior_iocp_op *op)
{
	if (op->poll_parent && op->opcode == IOR_OP_POLL) {
		iocp_poll_edge_seen(ctx, op);
	}
	free_op(ctx, op);
}

/*
 * Resolve readiness for the poll op at active index i, on the poller thread
 * (the op's active_count slot is held). A one-shot op completes and leaves
 * the set. A multishot op reports the readiness through a shadow op and
 * stays, unless no op can be had (no memory), in which case this readiness
 * is its last result. io_uring and the thread backend end a multishot on a
 * full completion queue; here its edges cannot pile up to begin with, the
 * op being held until the consumer has seen its last one. WSAPoll
 * is level-triggered and would report the same readiness again at once, so
 * the op is held out of the set until the consumer has seen the edge; a
 * timed hold is no use here, WSAPoll rounding any timeout up to the system
 * timer tick (15.6 ms by default).
 */
static void iocp_poller_fire(ior_ctx_iocp *ctx, iocp_poller *p, uint32_t i, SHORT revents)
{
	ior_iocp_op *op = p->active[i];

	if (revents & POLLNVAL) {
		// Not a socket (or a closed one) - poll works on sockets only.
		iocp_poller_remove(p, i);
		post_armed_op(ctx, op, WSAENOTSOCK);
		return;
	}

	int32_t mask = (int32_t) wsa_to_ior_poll_mask(revents);
	if (!op->poll_multi) {
		iocp_poller_remove(p, i);
		op->work_res = mask;
		post_armed_op(ctx, op, ERROR_SUCCESS);
		return;
	}

	ior_iocp_op *more = alloc_op(ctx);
	if (!more) {
		iocp_poller_remove(p, i);
		op->work_res = mask;
		post_armed_op(ctx, op, ERROR_SUCCESS);
		return;
	}
	more->opcode = IOR_OP_POLL;
	more->fd = op->fd;
	more->user_data = op->user_data;
	more->poll_mask = op->poll_mask;
	more->work_res = mask;
	more->cqe_more = true;
	more->poll_parent = op;
	more->poll_parent_gen = op->gen;
	(void) post_synthetic_completion(ctx, more, ERROR_SUCCESS, 0);
	op->poll_held = true;
}

static DWORD WINAPI iocp_poller_thread_main(LPVOID arg)
{
	ior_ctx_iocp *ctx = arg;
	iocp_poller *p = &ctx->poller;

	for (;;) {
		// Ingest newly registered ops.
		EnterCriticalSection(&p->lock);
		ior_iocp_op *in = p->incoming;
		p->incoming = NULL;
		LeaveCriticalSection(&p->lock);

		while (in) {
			ior_iocp_op *next = in->next_pending;
			in->next_pending = NULL;
			if (p->active_len == p->active_cap) {
				uint32_t cap = p->active_cap ? p->active_cap * 2 : 16;
				ior_iocp_op **active = realloc(p->active, cap * sizeof(*active));
				WSAPOLLFD *pfds = realloc(p->pfds, (cap + 1) * sizeof(*pfds));
				uint32_t *slot = realloc(p->slot, (cap + 1) * sizeof(*slot));
				if (active) {
					p->active = active;
				}
				if (pfds) {
					p->pfds = pfds;
				}
				if (slot) {
					p->slot = slot;
				}
				if (!active || !pfds || !slot) {
					post_armed_op(ctx, in, ERROR_NOT_ENOUGH_MEMORY);
					in = next;
					continue;
				}
				p->active_cap = cap;
			}
			p->active[p->active_len] = in;
			p->active_len++;
			in = next;
		}

		if (atomic_load(&p->stop)) {
			break;
		}

		// Drop ops whose link timeout fired (flagged by the timer thread).
		for (uint32_t i = 0; i < p->active_len;) {
			ior_iocp_op *op = p->active[i];
			if (atomic_load_explicit(&op->token.cancelled, memory_order_acquire)) {
				iocp_poller_remove(p, i);
				post_armed_op(ctx, op, ERROR_OPERATION_ABORTED);
			} else {
				i++;
			}
		}

		// Build the poll set: the wake socket, then every op not being held
		// after a multishot report, or held and re-armed since. The wake
		// flag is cleared before the re-arm flags are read: a consumer that
		// sets one after this read finds the flag clear and sends a byte,
		// which ends the wait below.
		atomic_store(&p->wake_pending, 0);
		p->pfds[0].fd = p->wake_rx;
		p->pfds[0].events = POLLRDNORM;
		p->pfds[0].revents = 0;
		uint32_t n = 1;
		for (uint32_t i = 0; i < p->active_len; i++) {
			ior_iocp_op *op = p->active[i];
			if (op->poll_held) {
				if (!atomic_exchange(&op->poll_rearm, 0)) {
					continue;
				}
				op->poll_held = false;
			}
			p->pfds[n].fd = (SOCKET) op->fd;
			p->pfds[n].events = ior_poll_mask_to_wsa(op->poll_mask);
			p->pfds[n].revents = 0;
			p->slot[n] = i;
			n++;
		}

		int ret = WSAPoll(p->pfds, n, -1);
		if (ret == SOCKET_ERROR) {
			// No per-socket status to act on; fail everything rather than spin.
			DWORD err = (DWORD) WSAGetLastError();
			while (p->active_len > 0) {
				ior_iocp_op *op = p->active[0];
				iocp_poller_remove(p, 0);
				post_armed_op(ctx, op, err);
			}
			continue;
		}

		if (p->pfds[0].revents) {
			iocp_poller_drain_wake(p);
		}
		// Highest active index first: removing one swaps the last active op
		// into its place, which is an index already handled or one that was
		// not polled, so the indices still to handle stay put.
		for (uint32_t k = n; k-- > 1;) {
			if (p->pfds[k].revents) {
				iocp_poller_fire(ctx, p, p->slot[k], p->pfds[k].revents);
			}
		}
	}

	// Shutdown: fail everything still pending, including late arrivals.
	EnterCriticalSection(&p->lock);
	ior_iocp_op *in = p->incoming;
	p->incoming = NULL;
	LeaveCriticalSection(&p->lock);
	while (in) {
		ior_iocp_op *next = in->next_pending;
		in->next_pending = NULL;
		post_armed_op(ctx, in, ERROR_OPERATION_ABORTED);
		in = next;
	}
	while (p->active_len > 0) {
		ior_iocp_op *op = p->active[0];
		iocp_poller_remove(p, 0);
		post_armed_op(ctx, op, ERROR_OPERATION_ABORTED);
	}
	return 0;
}

/*
 * One-time (per context) creation of the wakeup socket pair and the poller
 * thread. Assumes WSAStartup has been done by the application (it must have
 * been, to own sockets worth polling).
 */
static int iocp_poller_ensure(ior_ctx_iocp *ctx)
{
	iocp_poller *p = &ctx->poller;

	EnterCriticalSection(&p->lock);
	if (p->thread) {
		LeaveCriticalSection(&p->lock);
		return 0;
	}

	int ret = -ENOMEM;
	SOCKET rx = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	SOCKET tx = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (rx == INVALID_SOCKET || tx == INVALID_SOCKET) {
		goto fail;
	}

	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	addr.sin_port = 0;
	int alen = sizeof(addr);
	if (bind(rx, (struct sockaddr *) &addr, sizeof(addr)) != 0
			|| getsockname(rx, (struct sockaddr *) &addr, &alen) != 0
			|| connect(tx, (struct sockaddr *) &addr, sizeof(addr)) != 0) {
		goto fail;
	}
	u_long nonblock = 1;
	if (ioctlsocket(rx, FIONBIO, &nonblock) != 0) {
		goto fail;
	}

	// Pre-size the arrays: the thread may run before the first registration
	// arrives and always needs the wake slot pfds[0].
	p->active_cap = 16;
	p->active = malloc(p->active_cap * sizeof(*p->active));
	p->pfds = malloc((p->active_cap + 1) * sizeof(*p->pfds));
	p->slot = malloc((p->active_cap + 1) * sizeof(*p->slot));
	if (!p->active || !p->pfds || !p->slot) {
		goto fail;
	}

	p->wake_rx = rx;
	p->wake_tx = tx;
	p->thread = CreateThread(NULL, 0, iocp_poller_thread_main, ctx, 0, NULL);
	if (!p->thread) {
		p->wake_rx = INVALID_SOCKET;
		p->wake_tx = INVALID_SOCKET;
		goto fail;
	}

	LeaveCriticalSection(&p->lock);
	return 0;

fail:
	free(p->active);
	free(p->pfds);
	free(p->slot);
	p->active = NULL;
	p->pfds = NULL;
	p->slot = NULL;
	p->active_cap = 0;
	if (rx != INVALID_SOCKET) {
		closesocket(rx);
	}
	if (tx != INVALID_SOCKET) {
		closesocket(tx);
	}
	LeaveCriticalSection(&p->lock);
	return ret;
}

static int issue_poll(ior_ctx_iocp *ctx, ior_iocp_op *op)
{
	if (iocp_poller_ensure(ctx) < 0) {
		return post_synthetic_completion(ctx, op, ERROR_NOT_ENOUGH_MEMORY, 0);
	}

	atomic_init(&op->token.cancelled, 0);
	op->token.shutdown = &ctx->shutdown;

	// Reserve the active_count slot up front, like issue_work: the poller
	// thread completes the op, so it must post with the slot already held.
	atomic_fetch_add(&ctx->active_count, 1);
	atomic_store(&op->state, IOCP_OP_POLL);

	// Wake the poller only for the first op on an empty incoming list: one
	// already there has sent a byte the poller has not acted on yet (it takes
	// the list only after draining the byte that woke it), and it takes this
	// op with that one.
	iocp_poller *p = &ctx->poller;
	EnterCriticalSection(&p->lock);
	bool first = p->incoming == NULL;
	op->next_pending = p->incoming;
	p->incoming = op;
	LeaveCriticalSection(&p->lock);
	if (first) {
		iocp_poller_wake(p);
	}

	return 0;
}

static void op_to_cqe(ior_iocp_op *op)
{
	op->cqe.iocp.user_data = op->user_data;
	op->cqe.iocp.flags = (op->cqe_more ? IOR_CQE_F_MORE : 0)
			| (op->cqe_nonempty ? IOR_CQE_F_SOCK_NONEMPTY : 0);

	if (op->submit_res) {
		op->cqe.iocp.res = op->submit_res;
	} else if (op->error_code == ERROR_NO_DATA) {
		// A read of an empty PIPE_NOWAIT pipe, or a write to a pipe whose
		// reading end is closed.
		op->cqe.iocp.res = op->opcode == IOR_OP_READ ? -EAGAIN : -EPIPE;
	} else if (op->error_code != ERROR_SUCCESS) {
		op->cqe.iocp.res = win_error_to_errno(op->error_code);
	} else if (op->opcode == IOR_OP_WORK || op->opcode == IOR_OP_POLL
			|| op->opcode == IOR_OP_ASYNC_CANCEL || op->opcode == IOR_OP_WAITPID
			|| op->opcode == IOR_OP_SIGWAIT || op->opcode == IOR_OP_LINK_TIMEOUT) {
		// The callback's return value (ready poll mask, cancel result, the
		// waited pid, the signal, a link timeout's cancel of a running
		// callback), not a byte count.
		op->cqe.iocp.res = op->work_res;
	} else if (op->opcode == IOR_OP_ACCEPT) {
		// The accepted socket, now the caller's (handles fit in 32 bits).
		op->cqe.iocp.res = (int32_t) (intptr_t) op->accept_sock;
		op->accept_sock = INVALID_SOCKET;
	} else if (op->opcode == IOR_OP_CONNECT) {
		op->cqe.iocp.res = 0;
	} else {
		op->cqe.iocp.res = (int32_t) op->bytes_transferred;
	}
}

static ior_iocp_op *cqe_to_op(ior_cqe *cqe)
{
	size_t offset = offsetof(ior_iocp_op, cqe);
	return (ior_iocp_op *) ((char *) cqe - offset);
}

/* ================= Timer support ================= */

static void qpc_freq_init(void)
{
	/*
	 * Thread-safe one-shot initialization of g_qpc_freq.
	 * Uses InterlockedCompareExchange to ensure exactly one thread
	 * calls QueryPerformanceFrequency. The frequency is published with
	 * release semantics; waiters spin on an acquire load so the value is
	 * fully visible before use (correct even on weakly-ordered CPUs).
	 */
	if (InterlockedCompareExchange(&g_qpc_freq_init, 1, 0) == 0) {
		LARGE_INTEGER freq;
		QueryPerformanceFrequency(&freq);
		atomic_store_explicit(&g_qpc_freq, (int64_t) freq.QuadPart, memory_order_release);
	} else {
		// Another thread is initializing or has finished; spin until done.
		while (atomic_load_explicit(&g_qpc_freq, memory_order_acquire) == 0) {
			YieldProcessor();
		}
	}
}

static uint64_t qpc_now_ns(void)
{
	LARGE_INTEGER counter;
	QueryPerformanceCounter(&counter);

	uint64_t c = (uint64_t) counter.QuadPart;
	uint64_t f = (uint64_t) atomic_load_explicit(&g_qpc_freq, memory_order_acquire);

	uint64_t sec = c / f;
	uint64_t rem = c % f;

	return sec * 1000000000ULL + (rem * 1000000000ULL) / f;
}

/* The wall clock as nanoseconds since the Unix epoch (FILETIME counts 100 ns
 * units since 1601). */
static uint64_t realtime_now_ns(void)
{
	FILETIME ft;
	GetSystemTimePreciseAsFileTime(&ft);
	uint64_t t = ((uint64_t) ft.dwHighDateTime << 32) | ft.dwLowDateTime;
	return (t - 116444736000000000ULL) * 100ULL;
}

/* Time since boot including sleep, at millisecond resolution. */
static uint64_t boottime_now_ns(void)
{
	return GetTickCount64() * 1000000ULL;
}

/*
 * The QPC deadline a timeout names: now plus ts for a relative one, ts itself
 * for an absolute one on QPC, and for one on another clock (boot time, wall
 * clock) the QPC time as far ahead as ts is of that clock's reading now; a
 * deadline already past is now.
 */
static uint64_t qpc_deadline_from_timespec(const ior_timespec *ts, uint32_t flags)
{
	uint64_t ns = ior_timespec_ns(ts);

	if (!(flags & IOR_TIMEOUT_ABS)) {
		return qpc_now_ns() + ns;
	}
	if (!(flags & (IOR_TIMEOUT_REALTIME | IOR_TIMEOUT_BOOTTIME))) {
		return ns;
	}
	uint64_t clock_now = (flags & IOR_TIMEOUT_REALTIME) ? realtime_now_ns() : boottime_now_ns();
	uint64_t now = qpc_now_ns();
	return ns > clock_now ? now + (ns - clock_now) : now;
}

/* Timer heap */
static void timer_heap_swap(timer_mgr *tm, uint32_t i, uint32_t j)
{
	ior_iocp_op *tmp = tm->heap[i];
	tm->heap[i] = tm->heap[j];
	tm->heap[j] = tmp;
}

static void timer_heap_sift_up(timer_mgr *tm, uint32_t idx)
{
	while (idx > 0) {
		uint32_t parent = (idx - 1) / 2;
		if (tm->heap[idx]->timer_deadline_ns >= tm->heap[parent]->timer_deadline_ns) {
			break;
		}
		timer_heap_swap(tm, idx, parent);
		idx = parent;
	}
}

static void timer_heap_sift_down(timer_mgr *tm, uint32_t idx)
{
	uint32_t len = tm->heap_len;
	while (1) {
		uint32_t left = 2 * idx + 1;
		uint32_t right = 2 * idx + 2;
		uint32_t smallest = idx;

		if (left < len
				&& tm->heap[left]->timer_deadline_ns < tm->heap[smallest]->timer_deadline_ns) {
			smallest = left;
		}
		if (right < len
				&& tm->heap[right]->timer_deadline_ns < tm->heap[smallest]->timer_deadline_ns) {
			smallest = right;
		}

		if (smallest == idx) {
			break;
		}

		timer_heap_swap(tm, idx, smallest);
		idx = smallest;
	}
}

static int timer_heap_push(timer_mgr *tm, ior_iocp_op *op)
{
	if (tm->heap_len >= tm->heap_cap) {
		uint32_t new_cap = tm->heap_cap ? tm->heap_cap * 2 : 16;
		if (new_cap < 16) {
			new_cap = 16;
		}
		ior_iocp_op **new_heap = realloc(tm->heap, new_cap * sizeof(ior_iocp_op *));
		if (!new_heap) {
			return -ENOMEM;
		}
		tm->heap = new_heap;
		tm->heap_cap = new_cap;
	}

	tm->heap[tm->heap_len] = op;
	timer_heap_sift_up(tm, tm->heap_len);
	tm->heap_len++;
	return 0;
}

static ior_iocp_op *timer_heap_pop(timer_mgr *tm)
{
	if (tm->heap_len == 0) {
		return NULL;
	}

	ior_iocp_op *op = tm->heap[0];

	tm->heap_len--;
	if (tm->heap_len > 0) {
		tm->heap[0] = tm->heap[tm->heap_len];
		timer_heap_sift_down(tm, 0);
	}

	return op;
}

/* Remove a specific op from the heap (O(n) search). Returns true if found. */
static bool timer_heap_remove(timer_mgr *tm, ior_iocp_op *op)
{
	for (uint32_t i = 0; i < tm->heap_len; i++) {
		if (tm->heap[i] != op) {
			continue;
		}
		tm->heap_len--;
		if (i < tm->heap_len) {
			tm->heap[i] = tm->heap[tm->heap_len];
			// Restore heap order from i: try down, then up.
			timer_heap_sift_down(tm, i);
			timer_heap_sift_up(tm, i);
		}
		return true;
	}
	return false;
}

static ior_iocp_op *timer_heap_peek(timer_mgr *tm)
{
	if (tm->heap_len == 0) {
		return NULL;
	}
	return tm->heap[0];
}

/*
 * Whether op's link timeout is still armed, under timers.lock. A fired link
 * timeout may be posted ahead of op (a callback still running, an abort still
 * on its way), and the caller can then reap it and reuse its slot, so
 * op->link_timeout counts only while that slot still guards op: a slot reused
 * guards nothing (alloc_op) or another op, never op, which is still in flight.
 */
static bool link_timeout_armed_locked(ior_iocp_op *op)
{
	ior_iocp_op *lt = op->link_timeout;
	return lt->guarded == op && lt->timer_armed;
}

static DWORD WINAPI timer_thread_main(LPVOID arg)
{
	ior_ctx_iocp *ctx = (ior_ctx_iocp *) arg;
	timer_mgr *tm = &ctx->timers;

	EnterCriticalSection(&tm->lock);

	while (!atomic_load(&tm->stop)) {
		while (tm->heap_len == 0 && !atomic_load(&tm->stop)) {
			SleepConditionVariableCS(&tm->cv, &tm->lock, INFINITE);
		}

		if (atomic_load(&tm->stop)) {
			break;
		}

		ior_iocp_op *op = timer_heap_peek(tm);
		if (!op) {
			continue;
		}

		uint64_t now = qpc_now_ns();
		if (op->timer_deadline_ns > now) {
			uint64_t delta_ns = op->timer_deadline_ns - now;
			DWORD wait_ms = (DWORD) (delta_ns / 1000000ULL);
			if (wait_ms == 0) {
				wait_ms = 1;
			}
			SleepConditionVariableCS(&tm->cv, &tm->lock, wait_ms);
			continue;
		}

		op = timer_heap_pop(tm);
		op->timer_armed = false;

		if (op->guarded) {
			/*
			 * Link timeout fired first: this side won the arbitration (we cleared
			 * timer_armed under the lock, so the completion path will leave the
			 * pair to us). Cancel the in-flight guarded op - its -ECANCELED
			 * completion arrives through the normal IOCP path - and post this
			 * link timeout as -ETIME.
			 *
			 * A guarded work op still queued on the threadpool is claimed so
			 * its callback never runs, and completes as cancelled. A running
			 * one cannot be stopped: its token is flagged so the callback can
			 * bail out early, and as io_uring's link timeout on a running
			 * request this one completes now with the cancel's -EALREADY,
			 * the work op with its real result once the callback returns.
			 * The claim and the store happen under timers.lock, which the
			 * completion path also takes to resolve the pair before the op
			 * can be reaped and recycled, so the guarded op is guaranteed
			 * alive here.
			 */
			ior_iocp_op *guarded = op->guarded;
			// Work and poll ops have no OVERLAPPED I/O to cancel: flag their
			// token instead (the poller drops a flagged op once woken). A
			// process wait is withdrawn from the threadpool below, outside
			// the lock, and a signal wait from the control handler's list:
			// their aborts post the guarded op's own completion.
			bool token_cancel = guarded->opcode == IOR_OP_WORK || guarded->opcode == IOR_OP_POLL;
			bool is_poll = guarded->opcode == IOR_OP_POLL;
			bool is_wait = guarded->opcode == IOR_OP_WAITPID;
			bool is_sigwait = guarded->opcode == IOR_OP_SIGWAIT;
			bool is_accept_multi = guarded->opcode == IOR_OP_ACCEPT && guarded->accept_multi;
			bool work_queued = false;
			DWORD lt_error = ERROR_TIMEOUT;
			if (guarded->opcode == IOR_OP_WORK) {
				int expected = IOCP_OP_WORK;
				work_queued
						= atomic_compare_exchange_strong(&guarded->state, &expected, IOCP_OP_DONE);
				if (!work_queued) {
					// Running: -EALREADY. Done: the callback returned and
					// posted before the consumer resolved the pair, so the op
					// finished first and this completes as cancelled. Carried
					// in work_res, as a cancel's result: submit_res would make
					// a submit that has not reached this link timeout's SQE yet
					// (armed with its guarded op, deadline already due) post it
					// a second time, as one in a failed chain.
					op->work_res = expected == IOCP_OP_WORK_RUNNING ? -EALREADY : -ECANCELED;
					lt_error = ERROR_SUCCESS;
				}
			}
			if (token_cancel) {
				atomic_store_explicit(&guarded->token.cancelled, 1, memory_order_release);
			} else if (is_accept_multi) {
				// Its children's aborts come in through the port; the last
				// one posts the parent as cancelled (accept_multi_child_done).
				accept_multi_end_locked(ctx, guarded, ERROR_OPERATION_ABORTED);
			} else if (!is_wait && !is_sigwait) {
				// Still under timers.lock: the consumer resolves the pair
				// under it before the guarded op can be reaped and recycled,
				// and it judges a collateral abort under it too (see
				// reissue_collateral_abort), so mark and cancel here.
				int expected = IOCP_OP_IO;
				atomic_compare_exchange_strong(&guarded->state, &expected, IOCP_OP_IO_CANCEL);
				cancel_overlapped_io(ctx, guarded);
			}
			LeaveCriticalSection(&tm->lock);
			if (is_poll) {
				iocp_poller_wake(&ctx->poller);
			}
			if (is_wait) {
				(void) iocp_waitpid_abort(ctx, guarded);
			}
			if (is_sigwait) {
				(void) iocp_sigwait_abort(ctx, guarded);
			}
			if (work_queued) {
				// As a cancel of a queued callback (see iocp_cancel_one).
				WaitForThreadpoolWorkCallbacks(guarded->tp_work, TRUE);
				CloseThreadpoolWork(guarded->tp_work);
				guarded->tp_work = NULL;
				post_armed_op(ctx, guarded, ERROR_OPERATION_ABORTED);
			}
			post_armed_op(ctx, op, lt_error);
			EnterCriticalSection(&tm->lock);
			continue;
		}

		op->is_synthetic = true;
		op->error_code = ERROR_TIMEOUT;
		op->bytes_transferred = 0;
		atomic_store(&op->state, IOCP_OP_DONE);

		MemoryBarrier();

		LeaveCriticalSection(&tm->lock);
		if (!PostQueuedCompletionStatus(ctx->iocp_handle, 0, 0, &op->overlapped)) {
			// Timer arming already accounted for active_count.
			iocp_backlog_push(ctx, op);
		}
		EnterCriticalSection(&tm->lock);
	}

	LeaveCriticalSection(&tm->lock);
	return 0;
}

static int arm_timer(ior_ctx_iocp *ctx, ior_iocp_op *op)
{
	if (!op->timeout_ts) {
		return post_synthetic_completion(ctx, op, ERROR_INVALID_PARAMETER, 0);
	}

	if (op->timeout_ts->tv_sec < 0 || op->timeout_ts->tv_nsec < 0) {
		return post_synthetic_completion(ctx, op, ERROR_INVALID_PARAMETER, 0);
	}

	uint64_t deadline = qpc_deadline_from_timespec(op->timeout_ts, op->timeout_flags);

	timer_mgr *tm = &ctx->timers;

	EnterCriticalSection(&tm->lock);

	op->timer_deadline_ns = deadline;
	op->timer_armed = true;
	op->timer_cancelled = false;
	atomic_store(&op->state, IOCP_OP_TIMER);

	int ret = timer_heap_push(tm, op);
	if (ret == 0) {
		atomic_fetch_add(&ctx->active_count, 1);
		WakeConditionVariable(&tm->cv);
	}

	LeaveCriticalSection(&tm->lock);

	if (ret < 0) {
		return post_synthetic_completion(ctx, op, ERROR_NOT_ENOUGH_MEMORY, 0);
	}

	return 0;
}

/*
 * Arm the link timeout guarding an op that has just been issued (and is now
 * in-flight). Reserves an active_count slot, like arm_timer, so post_armed_op
 * balances it on resolution. On a heap-allocation failure the link timeout is
 * completed immediately as -ECANCELED.
 */
static void arm_link_timeout(ior_ctx_iocp *ctx, ior_iocp_op *guarded)
{
	ior_iocp_op *lt = guarded->link_timeout;
	timer_mgr *tm = &ctx->timers;

	uint64_t deadline = lt->timeout_ts
			? qpc_deadline_from_timespec(lt->timeout_ts, lt->timeout_flags)
			: qpc_now_ns();

	EnterCriticalSection(&tm->lock);
	lt->timer_deadline_ns = deadline;
	lt->timer_armed = true;
	atomic_store(&lt->state, IOCP_OP_LINKED); // cancelled through its guarded op
	int ret = timer_heap_push(tm, lt);
	if (ret == 0) {
		atomic_fetch_add(&ctx->active_count, 1);
		WakeConditionVariable(&tm->cv);
	} else {
		lt->timer_armed = false;
	}
	LeaveCriticalSection(&tm->lock);

	if (ret < 0) {
		(void) post_synthetic_completion(ctx, lt, ERROR_OPERATION_ABORTED, 0);
	}
}

/* ================= LINK/DRAIN core ================= */

static int issue_op(ior_ctx_iocp *ctx, ior_iocp_op *op); // forward

static void cancel_link_chain(ior_ctx_iocp *ctx, ior_iocp_op *first)
{
	// Cancel all remaining linked ops (that were not yet issued) with -ECANCELED.
	ior_iocp_op *cur = first;

	while (cur) {
		ior_iocp_op *next = cur->link_next;
		cur->link_next = NULL;

		// If it might be sitting in the pending drain list, remove it.
		EnterCriticalSection(&ctx->sched_lock);
		if (cur->drain_deferred) {
			pending_remove_locked(ctx, cur);
			cur->drain_deferred = false;
		}
		LeaveCriticalSection(&ctx->sched_lock);

		// It's still not issued (linked_deferred and/or drain_deferred heads). Complete it now.
		// Use ERROR_OPERATION_ABORTED => -ECANCELED via win_error_to_errno().
		(void) post_synthetic_completion(ctx, cur, ERROR_OPERATION_ABORTED, 0);

		cur = next;
	}
}

/* ================= IOR_OP_ASYNC_CANCEL ================= */

static bool iocp_op_has_fd(uint8_t opcode)
{
	switch (opcode) {
		case IOR_OP_READ:
		case IOR_OP_WRITE:
		case IOR_OP_SEND:
		case IOR_OP_RECV:
		case IOR_OP_POLL:
		case IOR_OP_ACCEPT:
		case IOR_OP_CONNECT:
			return true;
		default:
			return false;
	}
}

static bool iocp_cancel_match(const ior_iocp_op *op, const ior_iocp_op *c)
{
	if (c->cancel_flags & IOR_CANCEL_BY_FD) {
		return iocp_op_has_fd(op->opcode) && op->fd == c->fd;
	}
	return op->user_data == c->cancel_key;
}

/*
 * Cancel one in-flight op per io_uring semantics: 0 if it will complete with
 * -ECANCELED (its link timeout and chain follow through the normal dequeue
 * path), -EALREADY if it is executing and cannot be interrupted, -ENOENT if
 * it completed meanwhile. Each state's owner arbitrates: the pending list
 * under sched_lock, the timer heap under timers.lock, the kernel for
 * overlapped I/O (CancelIoEx), a CAS on the state for queued work, the token
 * for running work and poll ops.
 */
static int iocp_cancel_one(ior_ctx_iocp *ctx, ior_iocp_op *op)
{
	switch (atomic_load(&op->state)) {
		case IOCP_OP_DEFERRED: {
			EnterCriticalSection(&ctx->sched_lock);
			bool found = op->drain_deferred;
			if (found) {
				pending_remove_locked(ctx, op);
				op->drain_deferred = false;
			}
			LeaveCriticalSection(&ctx->sched_lock);
			if (!found) {
				return -ENOENT;
			}
			// Never issued: its link timeout was never armed and its chain
			// never started, so resolve both here.
			ior_iocp_op *rest = op->link_next;
			op->link_next = NULL;
			ior_iocp_op *lt = op->link_timeout;
			op->link_timeout = NULL;
			(void) post_synthetic_completion(ctx, op, ERROR_OPERATION_ABORTED, 0);
			if (lt) {
				lt->guarded = NULL;
				(void) post_synthetic_completion(ctx, lt, ERROR_OPERATION_ABORTED, 0);
			}
			if (rest) {
				cancel_link_chain(ctx, rest);
			}
			return 0;
		}

		case IOCP_OP_IO: {
			// Mark it first so the consumer reports the abort rather than
			// treating it as collateral damage of another cancel on the same
			// handle. The -ECANCELED completion arrives through the port; a
			// completion that already raced in keeps its real result
			// (io_uring does the same).
			int expected = IOCP_OP_IO;
			if (!atomic_compare_exchange_strong(&op->state, &expected, IOCP_OP_IO_CANCEL)) {
				return -ENOENT;
			}
			if (cancel_overlapped_io(ctx, op)) {
				return 0;
			}
			// Nothing to cancel: it is completing on its own, and its queued
			// packet - a real result, or an abort another cancel on the handle
			// already caused - is reported as it is. The mark stays: re-issuing
			// a collateral abort now would put an op the caller was told has
			// completed back in flight, with no CQE until data arrives.
			return GetLastError() == ERROR_NOT_FOUND ? -ENOENT : -EALREADY;
		}

		case IOCP_OP_TIMER: {
			timer_mgr *tm = &ctx->timers;
			EnterCriticalSection(&tm->lock);
			bool won = op->timer_armed && !op->guarded;
			if (won) {
				op->timer_armed = false;
				timer_heap_remove(tm, op);
			}
			LeaveCriticalSection(&tm->lock);
			if (!won) {
				return -ENOENT; // firing right now
			}
			post_armed_op(ctx, op, ERROR_OPERATION_ABORTED);
			return 0;
		}

		case IOCP_OP_WORK: {
			// Not started: claim it so the callback returns without running
			// the function (its CAS to IOCP_OP_WORK_RUNNING fails), withdraw
			// it from the pool queue and complete it here. The wait only
			// covers a callback that was already dispatched and is now
			// returning.
			int expected = IOCP_OP_WORK;
			if (!atomic_compare_exchange_strong(&op->state, &expected, IOCP_OP_DONE)) {
				return -ENOENT; // started meanwhile; a rescan sees IOCP_OP_WORK_RUNNING
			}
			WaitForThreadpoolWorkCallbacks(op->tp_work, TRUE);
			CloseThreadpoolWork(op->tp_work);
			op->tp_work = NULL;
			post_armed_op(ctx, op, ERROR_OPERATION_ABORTED);
			return 0;
		}

		case IOCP_OP_WORK_RUNNING:
			// A running callback cannot be interrupted; flag it so it can
			// return early.
			atomic_store_explicit(&op->token.cancelled, 1, memory_order_release);
			return -EALREADY;

		case IOCP_OP_POLL:
			// The poller drops a flagged op as -ECANCELED once woken.
			atomic_store_explicit(&op->token.cancelled, 1, memory_order_release);
			iocp_poller_wake(&ctx->poller);
			return 0;

		case IOCP_OP_ACCEPT_MULTI: {
			// Its children are cancelled; the last to come in posts it as
			// -ECANCELED. One already on its way out (a child failed, its
			// link timeout fired) completes on its own with what took it out.
			EnterCriticalSection(&ctx->timers.lock);
			bool ending = op->accept_ending;
			accept_multi_end_locked(ctx, op, ERROR_OPERATION_ABORTED);
			LeaveCriticalSection(&ctx->timers.lock);
			return ending ? -EALREADY : 0;
		}

		case IOCP_OP_WAIT:
			return iocp_waitpid_abort(ctx, op) ? 0 : -ENOENT;

		case IOCP_OP_SIGWAIT:
			return iocp_sigwait_abort(ctx, op) ? 0 : -ENOENT;

		default:
			return -ENOENT;
	}
}

/*
 * Execute a cancel op inline, like io_uring does at submit: look through the
 * ops in flight, oldest first, for the first match and post the result as
 * this op's completion.
 */
static int issue_cancel(ior_ctx_iocp *ctx, ior_iocp_op *c)
{
	int32_t ret;

	if ((c->cancel_flags & IOR_CANCEL_BY_FD) && (c->fd == NULL || c->fd == INVALID_HANDLE_VALUE)) {
		ret = -EBADF;
	} else {
		ret = -ENOENT;
		for (ior_iocp_op *op = ctx->live_head; op && ret == -ENOENT; op = op->live_next) {
			if (op == c) {
				continue;
			}
			int state = atomic_load(&op->state);
			if (state == IOCP_OP_FREE || state == IOCP_OP_LINKED || state == IOCP_OP_DONE
					|| state == IOCP_OP_IO_CANCEL) {
				continue; // IO_CANCEL: already being cancelled, its CQE is on its way
			}
			if (op->poll_parent) {
				continue; // a multishot accept's child: its parent is the op
			}
			if (!iocp_cancel_match(op, c)) {
				continue;
			}
			ret = iocp_cancel_one(ctx, op);
		}
	}

	c->work_res = ret;
	return post_synthetic_completion(ctx, c, ERROR_SUCCESS, 0);
}

/*
 * Collateral aborts. When CancelIoEx() names one pending request on a socket,
 * AFD aborts every pending request of that kind on the socket (both recvs
 * complete with ERROR_OPERATION_ABORTED when only one was cancelled), so a
 * cancel op or a fired link timeout takes the target's neighbours down with
 * it. Such an abort is recognised by exclusion and undone by re-issuing the
 * request: the op was not itself marked for cancellation (IOCP_OP_IO_CANCEL),
 * its link timeout has not fired, and the handle's cancel generation moved
 * while it was in flight. An abort with an unchanged generation is genuine
 * (the handle was closed, or cancelled behind the library's back) and is
 * reported as -ECANCELED. Returns true if the op is back in flight.
 *
 * Runs under timers.lock so it is ordered against the link timeout firing:
 * the timer thread marks and cancels the guarded op under that lock, so
 * either the timeout is still armed here (and will cancel the re-issued
 * request), or it has fired and this abort is its doing.
 */
static bool reissue_collateral_abort(ior_ctx_iocp *ctx, ior_iocp_op *op, DWORD bytes_transferred)
{
	// Only a request that moved no data can be replayed verbatim: a partial
	// write or send re-issued in full would duplicate what already went out,
	// and a partial read or recv would drop what already came in. Report
	// such an abort instead (it is not expected from AFD, which aborts only
	// requests it has not started serving).
	if (bytes_transferred != 0) {
		return false;
	}

	int (*issue)(ior_ctx_iocp *, ior_iocp_op *);
	switch (op->opcode) {
		case IOR_OP_READ:
			issue = issue_read;
			break;
		case IOR_OP_WRITE:
			issue = issue_write;
			break;
		case IOR_OP_SEND:
			issue = issue_send;
			break;
		case IOR_OP_RECV:
			issue = issue_recv;
			break;
		case IOR_OP_ACCEPT:
			// Restarted with a fresh accepted socket; a ConnectEx cannot be
			// replayed on the same socket and stays reported.
			issue = issue_accept;
			break;
		default:
			return false;
	}

	EnterCriticalSection(&ctx->timers.lock);
	bool collateral = atomic_load(&op->state) == IOCP_OP_IO
			&& (!op->link_timeout || link_timeout_armed_locked(op))
			// A cancel moved the generation while this request was in flight:
			// a set lookup, so an abort that is not a replay candidate at all
			// (one the library did not cause: the caller's own CancelIoEx, or
			// the issuing thread exiting - a close does not produce one, AFD
			// and the pipe driver report those as ERROR_CONNECTION_ABORTED and
			// ERROR_BROKEN_PIPE) is decided without going to the kernel.
			&& handle_cancel_gen(ctx, op->fd) != op->io_cancel_gen;
	if (collateral) {
		/*
		 * Only now re-validate the handle with the kernel. The caller may
		 * have closed it with this request in flight: then the association
		 * fails (dead value) or succeeds and moves the epoch on (the value
		 * names a new object), and either way the abort is reported as it is
		 * rather than replayed onto something else.
		 *
		 * Succeeding here associates that new object with this context's
		 * port, which cannot be undone - the probe is the only way to detect
		 * a recycled value, so it is kept behind the check above and reached
		 * only by an abort that would otherwise be replayed. Closing a
		 * descriptor with cancels in flight is what ior_prep_cancel_fd()
		 * warns against; an explicit registration API would remove the need
		 * for the probe altogether.
		 */
		uint32_t gen, epoch;
		collateral
				= ensure_handle_associated(ctx, op->fd, &gen, &epoch) == 0 && epoch == op->io_epoch;
	}
	if (collateral) {
		// Return the aborted request's active_count slot; issue_* reserves a
		// new one (or posts a synthetic failure if the handle is gone).
		atomic_fetch_sub(&ctx->active_count, 1);
		memset(&op->overlapped, 0, sizeof(op->overlapped));
		(void) issue(ctx, op);
	}
	LeaveCriticalSection(&ctx->timers.lock);

	return collateral;
}

static void sched_kick_drain(ior_ctx_iocp *ctx)
{
	// Try to issue any drain-deferred ops whose barrier is now satisfied.
	// Runs with ctx->sched_lock held by caller OR takes it internally.
	EnterCriticalSection(&ctx->sched_lock);

	ior_iocp_op *prev = NULL;
	ior_iocp_op *cur = ctx->pending_head;

	while (cur) {
		ior_iocp_op *next = cur->next_pending;

		// Only consider "heads" (not waiting on LINK predecessor).
		if (!cur->linked_deferred && cur->drain_deferred && drain_satisfied(ctx, cur)) {
			// Remove from pending list
			if (prev) {
				prev->next_pending = next;
			} else {
				ctx->pending_head = next;
			}
			if (ctx->pending_tail == cur) {
				ctx->pending_tail = prev;
			}
			cur->next_pending = NULL;
			cur->drain_deferred = false;

			LeaveCriticalSection(&ctx->sched_lock);

			// Issue outside lock
			int ret = issue_op(ctx, cur);
			if (ret < 0) {
				// If issuing failed in a LINK chain, cancel remaining
				if (cur->link_next) {
					cancel_link_chain(ctx, cur->link_next);
					cur->link_next = NULL;
				}
			}

			EnterCriticalSection(&ctx->sched_lock);

			// Restart scan since we dropped the lock and issued work.
			prev = NULL;
			cur = ctx->pending_head;
			continue;
		}

		prev = cur;
		cur = next;
	}

	LeaveCriticalSection(&ctx->sched_lock);
}

static int start_link_next(ior_ctx_iocp *ctx, ior_iocp_op *next)
{
	if (!next) {
		return 0;
	}

	// This op is no longer waiting on predecessor; it becomes the head.
	next->linked_deferred = false;

	// If it also has DRAIN, it must wait until its barrier is satisfied.
	if ((next->sqe_flags & IOR_SQE_IO_DRAIN) && !drain_satisfied(ctx, next)) {
		EnterCriticalSection(&ctx->sched_lock);
		next->drain_deferred = true;
		atomic_store(&next->state, IOCP_OP_DEFERRED);
		pending_enqueue_locked(ctx, next);
		LeaveCriticalSection(&ctx->sched_lock);
		return 0;
	}

	int ret = issue_op(ctx, next);
	if (ret < 0) {
		// Issue failed immediately, cancel remainder of chain
		if (next->link_next) {
			cancel_link_chain(ctx, next->link_next);
			next->link_next = NULL;
		}
	}
	return 0;
}

static int issue_op(ior_ctx_iocp *ctx, ior_iocp_op *op)
{
	int ret;
	if (ior_fixed_file_bad(op->opcode, op->sqe_flags, op->cancel_flags)) {
		op->submit_res = -EBADF; // never issued, like a failed chain's ops
		ret = post_synthetic_completion(ctx, op, ERROR_SUCCESS, 0);
	} else {
		switch (op->opcode) {
			case IOR_OP_NOP:
				ret = post_synthetic_completion(ctx, op, ERROR_SUCCESS, 0);
				break;

			case IOR_OP_READ:
				ret = issue_read(ctx, op);
				break;

			case IOR_OP_WRITE:
				ret = issue_write(ctx, op);
				break;

			case IOR_OP_SPLICE:
				ret = post_synthetic_completion(ctx, op, ERROR_NOT_SUPPORTED, 0);
				break;

			case IOR_OP_SEND:
				ret = issue_send(ctx, op);
				break;

			case IOR_OP_RECV:
				ret = issue_recv(ctx, op);
				break;

			case IOR_OP_ACCEPT:
				// A multishot accept's deadline is watched by the timer
				// thread, which takes its children down.
				ret = op->accept_multi ? issue_accept_multi(ctx, op) : issue_accept(ctx, op);
				break;

			case IOR_OP_CONNECT:
				ret = issue_connect(ctx, op);
				break;

			case IOR_OP_WORK:
				// Falls through to the link-timeout arming below: a guarded work
				// op's deadline is watched by the timer thread while the callback
				// runs on the threadpool.
				ret = issue_work(ctx, op);
				break;

			case IOR_OP_POLL:
				// Like WORK, a guarded poll's deadline is watched by the timer
				// thread, which flags the token and wakes the poller.
				ret = issue_poll(ctx, op);
				break;

			case IOR_OP_WAITPID:
				// The timer thread withdraws a guarded wait at its deadline.
				ret = issue_waitpid(ctx, op);
				break;

			case IOR_OP_SIGWAIT:
				// Likewise withdrawn from the control handler's list.
				ret = issue_sigwait(ctx, op);
				break;

			case IOR_OP_TIMER:
				ret = arm_timer(ctx, op);
				break;

			case IOR_OP_ASYNC_CANCEL:
				ret = issue_cancel(ctx, op);
				break;

			case IOR_OP_LINK_TIMEOUT:
				// A paired link timeout is armed via its guarded op, never issued
				// directly, and submit fails one with nothing to guard
				// (iocp_scan_staged), so this is not reached; were it, it would
				// still complete, as a plain timeout.
				ret = arm_timer(ctx, op);
				break;

			default:
				ret = post_synthetic_completion(ctx, op, ERROR_NOT_SUPPORTED, 0);
				break;
		}
	}

	if (op->link_timeout) {
		if (atomic_load(&op->state) == IOCP_OP_DONE) {
			// Done while being issued: as on io_uring, its link timeout is
			// cancelled rather than armed.
			ior_iocp_op *lt = op->link_timeout;
			op->link_timeout = NULL;
			(void) post_synthetic_completion(ctx, lt, ERROR_OPERATION_ABORTED, 0);
		} else if (ret == 0) {
			// The guarded op is now in flight; arm its link-timeout watchdog.
			arm_link_timeout(ctx, op);
		}
	}
	return ret;
}

/* ================= Backend ops ================= */

static int ior_iocp_backend_init(void **backend_ctx, ior_params *params)
{
	if (!backend_ctx || !params) {
		return -EINVAL;
	}

	// Ensure QPC frequency is initialized (thread-safe, one-shot)
	qpc_freq_init();

	ior_ctx_iocp *ctx = calloc(1, sizeof(*ctx));
	if (!ctx) {
		return -ENOMEM;
	}

	ctx->flags = params->flags;

	uint32_t sq_entries = params->sq_entries;
	if (sq_entries < 32) {
		sq_entries = 32;
	}
	sq_entries = round_up_pow2(sq_entries);

	uint32_t cq_entries = params->cq_entries;
	if (cq_entries == 0) {
		cq_entries = sq_entries * 2;
	}
	cq_entries = round_up_pow2(cq_entries);

	ctx->iocp_handle = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
	if (ctx->iocp_handle == NULL) {
		free(ctx);
		return win_error_to_errno(GetLastError());
	}

	int ret = ready_queue_init(&ctx->ready, cq_entries);
	if (ret < 0) {
		CloseHandle(ctx->iocp_handle);
		free(ctx);
		return ret;
	}

	handle_set_init(&ctx->handles);

	InitializeCriticalSection(&ctx->pool_lock);
	InitializeCriticalSection(&ctx->sched_lock);
	ctx->pending_head = NULL;
	ctx->pending_tail = NULL;

	atomic_store(&ctx->submit_seq, 0);
	atomic_store(&ctx->completed_cnt, 0);

	/*
	 * An op holds its pool entry from get_sqe until its completion is reaped.
	 * The pool starts at the completion queue's size and grows as needed:
	 * completions beyond the ready queue wait in the port, which bounds
	 * nothing, as io_uring's kernel keeps an overflowing completion.
	 */
	ret = grow_op_pool(ctx, cq_entries);
	if (ret < 0) {
		DeleteCriticalSection(&ctx->sched_lock);
		DeleteCriticalSection(&ctx->pool_lock);
		ready_queue_destroy(&ctx->ready);
		handle_set_destroy(&ctx->handles);
		CloseHandle(ctx->iocp_handle);
		free(ctx);
		return ret;
	}

	ret = init_sq_ring(ctx, sq_entries);
	if (ret < 0) {
		free_op_pool(ctx);
		DeleteCriticalSection(&ctx->sched_lock);
		DeleteCriticalSection(&ctx->pool_lock);
		ready_queue_destroy(&ctx->ready);
		handle_set_destroy(&ctx->handles);
		CloseHandle(ctx->iocp_handle);
		free(ctx);
		return ret;
	}

	// Timer manager
	InitializeCriticalSection(&ctx->timers.lock);
	InitializeConditionVariable(&ctx->timers.cv);

	ctx->timers.heap_cap = cq_entries;
	if (ctx->timers.heap_cap > 64) {
		ctx->timers.heap_cap = 64;
	}
	if (ctx->timers.heap_cap < 16) {
		ctx->timers.heap_cap = 16;
	}

	ctx->timers.heap = calloc(ctx->timers.heap_cap, sizeof(ior_iocp_op *));
	if (!ctx->timers.heap) {
		DeleteCriticalSection(&ctx->timers.lock);
		free(ctx->sq_array);
		free_op_pool(ctx);
		DeleteCriticalSection(&ctx->sched_lock);
		DeleteCriticalSection(&ctx->pool_lock);
		ready_queue_destroy(&ctx->ready);
		handle_set_destroy(&ctx->handles);
		CloseHandle(ctx->iocp_handle);
		free(ctx);
		return -ENOMEM;
	}

	ctx->timers.heap_len = 0;
	atomic_store(&ctx->timers.stop, 0);

	ctx->timers.thread = CreateThread(NULL, 0, timer_thread_main, ctx, 0, NULL);
	if (!ctx->timers.thread) {
		free(ctx->timers.heap);
		DeleteCriticalSection(&ctx->timers.lock);
		free(ctx->sq_array);
		free_op_pool(ctx);
		DeleteCriticalSection(&ctx->sched_lock);
		DeleteCriticalSection(&ctx->pool_lock);
		ready_queue_destroy(&ctx->ready);
		handle_set_destroy(&ctx->handles);
		CloseHandle(ctx->iocp_handle);
		free(ctx);
		return -ENOMEM;
	}

	// Poller bookkeeping; the thread and wakeup sockets are created lazily.
	InitializeCriticalSection(&ctx->poller.lock);
	ctx->poller.wake_tx = INVALID_SOCKET;
	ctx->poller.wake_rx = INVALID_SOCKET;
	atomic_store(&ctx->poller.stop, 0);

	// Completion pump bookkeeping; started by the first ior_notify_fd().
	InitializeCriticalSection(&ctx->pump.lock);
	InitializeConditionVariable(&ctx->pump.cv);
	ctx->pump.wake_tx = INVALID_SOCKET;
	ctx->pump.wake_rx = INVALID_SOCKET;

	atomic_store(&ctx->shutdown, 0);

	ctx->features = IOR_FEAT_NATIVE_ASYNC | IOR_FEAT_WORK | IOR_FEAT_POLL_ADD;
	params->sq_entries = ctx->sq_size;
	params->cq_entries = ctx->ready.size;
	params->features = ctx->features;

	*backend_ctx = ctx;
	return 0;
}

static void iocp_pump_stop(ior_ctx_iocp *ctx); // forward

static void ior_iocp_backend_destroy(void *backend_ctx)
{
	if (!backend_ctx) {
		return;
	}

	ior_ctx_iocp *ctx = backend_ctx;

	/*
	 * Let running work callbacks observe teardown through their tokens, then
	 * wait for every submitted callback to finish - queued ones still run
	 * (FALSE = do not cancel pending callbacks), honoring the contract that a
	 * submitted work op's callback always executes. Their completions land in
	 * the IOCP and are reclaimed by the drain loop below.
	 */
	atomic_store(&ctx->shutdown, 1);

	// Stop the timer thread first: it withdraws process waits at their
	// deadlines, which must not race the teardown of the wait objects below.
	atomic_store(&ctx->timers.stop, 1);
	EnterCriticalSection(&ctx->timers.lock);
	WakeConditionVariable(&ctx->timers.cv);
	LeaveCriticalSection(&ctx->timers.lock);

	WaitForSingleObject(ctx->timers.thread, INFINITE);
	CloseHandle(ctx->timers.thread);

	// Signal waits: each abort posts -ECANCELED (a handler that wins the
	// race posts the signal instead), then the context leaves the handler's
	// list, so no event reaches it any more.
	for (ior_iocp_op *op = ctx->live_head; op; op = op->live_next) {
		if (atomic_load(&op->state) == IOCP_OP_SIGWAIT) {
			(void) iocp_sigwait_abort(ctx, op);
		}
	}
	iocp_sig_unregister(ctx);

	if (ctx->work_pool) {
		/*
		 * Process waits next, while their wait objects still exist: a
		 * process that never exits would otherwise keep its slot counted
		 * and the drain below waiting. Each abort posts -ECANCELED (a
		 * callback that wins the race posts the real result instead).
		 */
		for (ior_iocp_op *op = ctx->live_head; op; op = op->live_next) {
			if (atomic_load(&op->state) == IOCP_OP_WAIT) {
				(void) iocp_waitpid_abort(ctx, op);
			}
		}
		CloseThreadpoolCleanupGroupMembers(ctx->work_cleanup, FALSE, NULL);
		CloseThreadpoolCleanupGroup(ctx->work_cleanup);
		DestroyThreadpoolEnvironment(&ctx->work_env);
		CloseThreadpool(ctx->work_pool);
		ctx->work_pool = NULL;
	}

	/*
	 * Stop the poller thread (after the timer thread, which may still wake it
	 * for cancelled poll ops). Pending polls are posted as -ECANCELED and
	 * reclaimed by the drain loop below.
	 */
	if (ctx->poller.thread) {
		atomic_store(&ctx->poller.stop, 1);
		iocp_poller_wake(&ctx->poller);
		WaitForSingleObject(ctx->poller.thread, INFINITE);
		CloseHandle(ctx->poller.thread);
		closesocket(ctx->poller.wake_tx);
		closesocket(ctx->poller.wake_rx);
		free(ctx->poller.active);
		free(ctx->poller.pfds);
		free(ctx->poller.slot);
	}
	DeleteCriticalSection(&ctx->poller.lock);

	// Stop the completion pump (after every producer thread): what it staged
	// is reclaimed, what is still in the port is drained below.
	iocp_pump_stop(ctx);
	DeleteCriticalSection(&ctx->pump.lock);

	// Drain timers without posting
	EnterCriticalSection(&ctx->timers.lock);
	while (ctx->timers.heap_len > 0) {
		ior_iocp_op *op = timer_heap_pop(&ctx->timers);
		if (!op) {
			break;
		}
		op->timer_armed = false;
		atomic_fetch_sub(&ctx->active_count, 1);
		free_op(ctx, op);
	}
	LeaveCriticalSection(&ctx->timers.lock);

	DeleteCriticalSection(&ctx->timers.lock);
	if (ctx->timers.heap) {
		free(ctx->timers.heap);
	}

	// Cancel any pending (deferred) ops without posting completions (teardown)
	EnterCriticalSection(&ctx->sched_lock);
	ior_iocp_op *p = ctx->pending_head;
	ctx->pending_head = ctx->pending_tail = NULL;
	LeaveCriticalSection(&ctx->sched_lock);

	while (p) {
		ior_iocp_op *next = p->next_pending;
		p->next_pending = NULL;
		p->drain_deferred = false;
		p->linked_deferred = false;
		// Not published to IOCP -> safe to free
		free_op(ctx, p);
		p = next;
	}

	/*
	 * Abort overlapped I/O still in flight: a parked recv or accept never
	 * completes on its own, and the drain below would wait for it forever.
	 * Each op is cancelled by its own OVERLAPPED rather than by handle, so a
	 * handle the caller closed long ago and the kernel has since reused for
	 * something else cannot be hit (CancelIoEx on it just fails). Every
	 * producer thread is stopped by now, so nothing is issued after this pass.
	 *
	 * The drain below has no time limit, so it rests on this invariant: every
	 * completion still counted in active_count is now forced to arrive. Armed
	 * timers were popped with the count given back, deferred ops were freed
	 * unposted, the poller posted its ops as -ECANCELED before it stopped,
	 * work callbacks were waited out by the cleanup group, process and
	 * signal waits were aborted above, and this pass cancels the overlapped
	 * requests. A new kind of op that is counted but not forced here would
	 * hang teardown instead of spinning out.
	 *
	 * Every op still in flight is on the live list (the ones freed above
	 * stay linked, but read FREE, and nothing is allocated any more).
	 */
	for (ior_iocp_op *op = ctx->live_head; op; op = op->live_next) {
		int state = atomic_load(&op->state);
		if (state == IOCP_OP_IO || state == IOCP_OP_IO_CANCEL) {
			atomic_store(&op->state, IOCP_OP_IO_CANCEL);
			CancelIoEx((HANDLE) op->fd, &op->overlapped);
		} else if (state == IOCP_OP_ACCEPT_MULTI) {
			// A multishot accept's slot is its own: post it now. Its
			// children are cancelled by this pass like any request, and
			// dropped when they arrive, as children of a completed parent.
			post_armed_op(ctx, op, ERROR_OPERATION_ABORTED);
		}
	}

	/*
	 * Drain all in-flight completions from the IOCP.
	 *
	 * active_count tracks ops that have been posted to the IOCP
	 * (via ReadFile/WriteFile/PostQueuedCompletionStatus) but not yet
	 * dequeued by GetQueuedCompletionStatus. We must dequeue them here
	 * or we'll spin forever.
	 */
	while (atomic_load(&ctx->active_count) > 0) {
		ior_iocp_op *kept = iocp_backlog_pop(ctx);
		if (kept) {
			atomic_fetch_sub(&ctx->active_count, 1);
			free_op(ctx, kept);
			continue;
		}

		DWORD bytes = 0;
		ULONG_PTR key = 0;
		LPOVERLAPPED overlapped = NULL;

		BOOL ok = GetQueuedCompletionStatus(ctx->iocp_handle, &bytes, &key, &overlapped, 100);

		if (!ok && overlapped == NULL) {
			DWORD gle = GetLastError();
			if (gle == WAIT_TIMEOUT || gle == ERROR_TIMEOUT) {
				// Nothing dequeued this round. Every counted completion is on
				// its way (the pass above cancelled what was parked), so keep
				// waiting rather than free the pool under the kernel's writes.
				continue;
			}
			if (gle == ERROR_ABANDONED_WAIT_0) {
				// IOCP handle was closed (shouldn't happen yet, but be safe)
				break;
			}
			// Unknown error - bail out
			break;
		}

		if (overlapped) {
			ior_iocp_op *op = (ior_iocp_op *) overlapped;
			atomic_fetch_sub(&ctx->active_count, 1);
			free_op(ctx, op);
		}
	}

	// Also drain any ops sitting in the ready queue
	while (!ready_queue_empty(&ctx->ready)) {
		ior_iocp_op *op = ready_queue_pop(&ctx->ready);
		if (op) {
			free_op(ctx, op);
		}
	}

	ready_queue_destroy(&ctx->ready);
	// Drained: its handles may go to another context now.
	iocp_owner_forget(ctx);
	handle_set_destroy(&ctx->handles);

	if (ctx->sq_array) {
		free(ctx->sq_array);
	}
	free_op_pool(ctx);

	DeleteCriticalSection(&ctx->sched_lock);
	DeleteCriticalSection(&ctx->pool_lock);

	if (ctx->iocp_handle) {
		CloseHandle(ctx->iocp_handle);
	}

	free(ctx);
}

static int ior_iocp_backend_get_sqe(void *backend_ctx, ior_sqe **sqe_out)
{
	if (!backend_ctx) {
		return -EINVAL;
	}

	ior_ctx_iocp *ctx = backend_ctx;

	// A full staging ring first: a submit is the cheaper remedy.
	if (sq_space_left(ctx) == 0) {
		return -ENOSPC;
	}

	// Only memory bounds the ops, as on io_uring: the pool grows.
	ior_iocp_op *op = alloc_op(ctx);
	if (!op) {
		return -ENOMEM;
	}

	if (sq_enqueue(ctx, op) < 0) {
		free_op(ctx, op);
		return -ENOSPC;
	}

	*sqe_out = (ior_sqe *) op;
	return 0;
}

static unsigned ior_iocp_backend_sq_entries(void *backend_ctx)
{
	return ((ior_ctx_iocp *) backend_ctx)->sq_size;
}

static unsigned ior_iocp_backend_cq_entries(void *backend_ctx)
{
	return ((ior_ctx_iocp *) backend_ctx)->ready.size;
}

static unsigned ior_iocp_backend_sq_space_left(void *backend_ctx)
{
	return sq_space_left((ior_ctx_iocp *) backend_ctx);
}

static unsigned ior_iocp_backend_cq_space_left(void *backend_ctx)
{
	// Room in the ready queue; completions beyond it wait in the port.
	ior_ctx_iocp *ctx = backend_ctx;
	return ctx->ready.count < ctx->ready.size ? ctx->ready.size - ctx->ready.count : 0;
}

/*
 * Find where io_uring would stop taking the staged entries: right after one
 * that fails the checks it makes on taking it, unless that one links on.
 * Every op of a chain holding such an entry gets submit_res: its own error,
 * or -ECANCELED for the rest, as io_uring fails the whole chain. Returns the
 * position to stop at.
 */
static uint32_t iocp_scan_staged(ior_ctx_iocp *ctx)
{
	uint32_t chain_start = ctx->sq_head;
	bool in_chain = false;
	bool prev_lt = false;
	bool chain_failed = false;

	for (uint32_t pos = ctx->sq_head; pos != ctx->sq_tail; pos++) {
		ior_iocp_op *op = ctx->sq_array[pos & ctx->sq_mask];
		op->submit_res = 0;
		if (!in_chain) {
			chain_start = pos;
			chain_failed = false;
		}
		int ret = 0;
		if (op->opcode == IOR_OP_TIMER) {
			ret = ior_timeout_check(op->timeout_ts, op->timeout_flags);
		} else if (op->opcode == IOR_OP_LINK_TIMEOUT) {
			ret = ior_link_timeout_check(op->timeout_ts, op->timeout_flags, in_chain, prev_lt);
		} else if (op->opcode == IOR_OP_ACCEPT) {
			ret = ior_accept_check(op->accept_flags);
		}
		bool link = (op->sqe_flags & IOR_SQE_IO_LINK) != 0;
		if (ret < 0) {
			op->submit_res = ret;
			chain_failed = true;
		}
		if (chain_failed && (!link || pos + 1 == ctx->sq_tail)) {
			for (uint32_t q = chain_start; q != pos + 1; q++) {
				ior_iocp_op *m = ctx->sq_array[q & ctx->sq_mask];
				if (!m->submit_res) {
					m->submit_res = -ECANCELED;
				}
			}
			chain_failed = false;
			if (ret < 0 && !link) {
				return pos + 1;
			}
		}
		prev_lt = op->opcode == IOR_OP_LINK_TIMEOUT;
		in_chain = link;
	}
	return ctx->sq_tail;
}

static int ior_iocp_backend_submit(void *backend_ctx)
{
	if (!backend_ctx) {
		return -EINVAL;
	}

	ior_ctx_iocp *ctx = backend_ctx;

	uint32_t submitted = 0;
	int last_error = 0;

	ior_iocp_op *prev = NULL;
	uint32_t bound = iocp_scan_staged(ctx);

	while (ctx->sq_head != bound) {
		ior_iocp_op *op = ctx->sq_array[ctx->sq_head & ctx->sq_mask];
		ctx->sq_head++;

		// Assign submission sequence
		op->seq = atomic_fetch_add(&ctx->submit_seq, 1) + 1;
		// In flight until its completion is dequeued, whatever happens below.
		live_add(ctx, op);

		if ((op->opcode == IOR_OP_TIMER || op->opcode == IOR_OP_LINK_TIMEOUT) && op->timeout_ts) {
			op->timeout_val = *op->timeout_ts;
			op->timeout_ts = &op->timeout_val;
		}

		// In a failed chain: completes with submit_res, never issued.
		if (op->submit_res) {
			(void) post_synthetic_completion(ctx, op, ERROR_SUCCESS, 0);
			submitted++;
			prev = NULL;
			continue;
		}

		// A link timeout already paired with its guarded op is armed when that
		// op is issued, not submitted as a standalone op. Still count it: its
		// SQE was consumed, and other backends report both entries of the pair.
		if (op->opcode == IOR_OP_LINK_TIMEOUT && op->guarded) {
			// Unless its guarded op, issued just before, armed it already
			// and the deadline has even fired and posted it.
			int expected = IOCP_OP_FREE;
			atomic_compare_exchange_strong(&op->state, &expected, IOCP_OP_LINKED);
			submitted++;
			prev = op;
			continue;
		}

		// DRAIN barrier means "wait for all prior completions"
		if (op->sqe_flags & IOR_SQE_IO_DRAIN) {
			op->drain_after = op->seq - 1;
		} else {
			op->drain_after = 0;
		}

		// Build LINK chain (prev is the predecessor if it had LINK set)
		if (prev && (prev->sqe_flags & IOR_SQE_IO_LINK)) {
			prev->link_next = op;
			op->linked_deferred = true;
			atomic_store(&op->state, IOCP_OP_LINKED);
		} else {
			op->linked_deferred = false;
		}

		// Pair a guarded op with an immediately following link timeout: the
		// link timeout watchdogs this op rather than chaining after it.
		if (op->sqe_flags & IOR_SQE_IO_LINK && ctx->sq_head != ctx->sq_tail) {
			ior_iocp_op *nxt = ctx->sq_array[ctx->sq_head & ctx->sq_mask];
			if (nxt->opcode == IOR_OP_LINK_TIMEOUT && !nxt->guarded) {
				op->link_timeout = nxt;
				nxt->guarded = op;
			}
		}

		// Decide whether to issue now
		int ret = 0;

		if (op->linked_deferred) {
			// Not a head: will be issued when predecessor completes successfully.
			ret = 0;
		} else if ((op->sqe_flags & IOR_SQE_IO_DRAIN) && !drain_satisfied(ctx, op)) {
			// Head but drain-deferred
			EnterCriticalSection(&ctx->sched_lock);
			op->drain_deferred = true;
			atomic_store(&op->state, IOCP_OP_DEFERRED);
			pending_enqueue_locked(ctx, op);
			LeaveCriticalSection(&ctx->sched_lock);
			ret = 0;
		} else {
			op->drain_deferred = false;
			ret = issue_op(ctx, op);
			if (ret < 0) {
				// If issuing the head failed immediately, cancel remaining chain.
				if (op->link_next) {
					cancel_link_chain(ctx, op->link_next);
					op->link_next = NULL;
				}
			}
		}

		if (ret < 0) {
			last_error = ret;
		} else {
			submitted++;
		}

		prev = op;
	}

	// If we deferred drains, a completion might already satisfy them; cheap kick.
	sched_kick_drain(ctx);

	if (last_error < 0 && submitted == 0) {
		return last_error;
	}

	return (int) submitted;
}

/* ================= Completion pump (ior_notify_fd) ================= */

static DWORD WINAPI iocp_pump_thread_main(LPVOID arg)
{
	ior_ctx_iocp *ctx = arg;
	iocp_pump *p = &ctx->pump;

	for (;;) {
		DWORD bytes = 0;
		ULONG_PTR key = 0;
		LPOVERLAPPED overlapped = NULL;
		BOOL ok = GetQueuedCompletionStatus(ctx->iocp_handle, &bytes, &key, &overlapped, INFINITE);
		DWORD err = ok ? ERROR_SUCCESS : GetLastError();

		if (!overlapped) {
			if (key == IOCP_PUMP_STOP_KEY || err == ERROR_ABANDONED_WAIT_0) {
				break;
			}
			continue; // stray packet (external PostQueuedCompletionStatus)
		}

		ior_iocp_op *op = (ior_iocp_op *) overlapped;
		op->pump_bytes = bytes;
		op->pump_error = err;
		op->pump_next = NULL;
		EnterCriticalSection(&p->lock);
		if (p->staged_tail) {
			p->staged_tail->pump_next = op;
		} else {
			p->staged_head = op;
		}
		p->staged_tail = op;
		/*
		 * Signal under the lock, after staging, and only if no byte is
		 * outstanding. The lock makes "stage, then signal" atomic against the
		 * consumer's "drain, then reset" in ior_notify_clear(), which rules
		 * out both failure modes of a socket byte as a flag: a packet staged
		 * after a clear always has a byte sent after that clear's drain (no
		 * lost wakeup), and a packet the consumer has already taken had its
		 * byte sent before it was taken, so a clear after reaping is never
		 * followed by a late byte. Coalescing to one byte per wake cycle is
		 * what keeps the pump off the send() syscall under load.
		 */
		iocp_pump_signal_locked(p);
		WakeConditionVariable(&p->cv);
		LeaveCriticalSection(&p->lock);
	}
	return 0;
}

/*
 * Take one packet from staging, waiting up to timeout_ms for one to arrive
 * (0 = poll, INFINITE = forever). Returns 0, -EAGAIN (timeout 0, none, or a
 * kept completion is waiting in the backlog) or
 * -ETIMEDOUT.
 */
static int iocp_pump_pop(ior_ctx_iocp *ctx, DWORD timeout_ms, pump_entry *out)
{
	iocp_pump *p = &ctx->pump;

	EnterCriticalSection(&p->lock);
	while (!p->staged_head) {
		if (atomic_load(&ctx->backlog_count)) {
			// The caller's next dequeue takes it (see iocp_backlog_push).
			LeaveCriticalSection(&p->lock);
			return -EAGAIN;
		}
		if (timeout_ms == 0) {
			LeaveCriticalSection(&p->lock);
			return -EAGAIN;
		}
		if (!SleepConditionVariableCS(&p->cv, &p->lock, timeout_ms)
				&& GetLastError() == ERROR_TIMEOUT) {
			LeaveCriticalSection(&p->lock);
			return -ETIMEDOUT;
		}
	}
	ior_iocp_op *op = p->staged_head;
	p->staged_head = op->pump_next;
	if (!p->staged_head) {
		p->staged_tail = NULL;
	}
	LeaveCriticalSection(&p->lock);
	op->pump_next = NULL;
	out->overlapped = &op->overlapped;
	out->bytes = op->pump_bytes;
	out->error = op->pump_error;
	return 0;
}

/*
 * Start the pump: a loopback UDP pair for the wakeup (both ends
 * non-blocking) and the thread. Runs on the consumer thread, so the switch
 * from direct dequeuing to staging happens between two of its own dequeues.
 */
static int iocp_pump_ensure(ior_ctx_iocp *ctx)
{
	iocp_pump *p = &ctx->pump;
	if (p->thread) {
		return 0;
	}

	SOCKET rx = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	SOCKET tx = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (rx == INVALID_SOCKET || tx == INVALID_SOCKET) {
		goto fail;
	}

	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	addr.sin_port = 0;
	int alen = sizeof(addr);
	if (bind(rx, (struct sockaddr *) &addr, sizeof(addr)) != 0
			|| getsockname(rx, (struct sockaddr *) &addr, &alen) != 0
			|| connect(tx, (struct sockaddr *) &addr, sizeof(addr)) != 0) {
		goto fail;
	}
	u_long nonblock = 1;
	if (ioctlsocket(rx, FIONBIO, &nonblock) != 0 || ioctlsocket(tx, FIONBIO, &nonblock) != 0) {
		goto fail;
	}

	p->staged_head = NULL;
	p->staged_tail = NULL;
	p->signalled = false;
	p->wake_rx = rx;
	p->wake_tx = tx;
	HANDLE thread = CreateThread(NULL, 0, iocp_pump_thread_main, ctx, 0, NULL);
	if (!thread) {
		p->wake_rx = INVALID_SOCKET;
		p->wake_tx = INVALID_SOCKET;
		goto fail;
	}
	// Published under the lock iocp_backlog_push decides under: a completion
	// the port refused before now is in the backlog, not the port, and its
	// wake packet went to the port, where the pump drops it as stray.
	// Completions dequeued already and waiting in the ready queue are
	// pending too, and ior_notify_fd() announces what is pending, as the
	// other backends do for everything in their completion queue. Only the
	// consuming thread, which is calling this, touches the ready queue.
	EnterCriticalSection(&p->lock);
	p->thread = thread;
	if (atomic_load(&ctx->backlog_count) || !ready_queue_empty(&ctx->ready)) {
		iocp_pump_signal_locked(p);
	}
	LeaveCriticalSection(&p->lock);
	return 0;

fail:
	if (rx != INVALID_SOCKET) {
		closesocket(rx);
	}
	if (tx != INVALID_SOCKET) {
		closesocket(tx);
	}
	return -ENOMEM;
}

/*
 * Stop the pump (destroy only). Packets it staged but the consumer never took
 * are reclaimed here; packets still in the port are left to the drain loop.
 */
static void iocp_pump_stop(ior_ctx_iocp *ctx)
{
	iocp_pump *p = &ctx->pump;
	if (!p->thread) {
		return;
	}

	PostQueuedCompletionStatus(ctx->iocp_handle, 0, IOCP_PUMP_STOP_KEY, NULL);
	WaitForSingleObject(p->thread, INFINITE);
	CloseHandle(p->thread);
	p->thread = NULL;

	while (p->staged_head) {
		ior_iocp_op *op = p->staged_head;
		p->staged_head = op->pump_next;
		atomic_fetch_sub(&ctx->active_count, 1);
		free_op(ctx, op);
	}
	p->staged_tail = NULL;
	closesocket(p->wake_tx);
	closesocket(p->wake_rx);
	p->wake_tx = INVALID_SOCKET;
	p->wake_rx = INVALID_SOCKET;
}

/* Dequeue one completion and push into ready queue */
static int dequeue_one_completion(ior_ctx_iocp *ctx, DWORD timeout_ms)
{
	if (ready_queue_full(&ctx->ready)) {
		IOR_LOG_ERROR("Ready queue full - cannot dequeue");
		return -EBUSY;
	}

	DWORD bytes_transferred = 0;
	ULONG_PTR completion_key = 0;
	LPOVERLAPPED overlapped = NULL;
	BOOL ok;
	DWORD gle;

	ior_iocp_op *kept = iocp_backlog_pop(ctx);
	if (kept) {
		// A synthetic completion the port refused: its result is in the op.
		overlapped = &kept->overlapped;
		bytes_transferred = kept->bytes_transferred;
		gle = ERROR_SUCCESS;
		ok = TRUE;
	} else if (ctx->pump.thread) {
		// The pump owns the port: take the packet it staged.
		pump_entry e;
		int ret = iocp_pump_pop(ctx, timeout_ms, &e);
		if (ret < 0) {
			return ret;
		}
		overlapped = e.overlapped;
		bytes_transferred = e.bytes;
		gle = e.error;
		ok = gle == ERROR_SUCCESS;
	} else {
		ok = GetQueuedCompletionStatus(
				ctx->iocp_handle, &bytes_transferred, &completion_key, &overlapped, timeout_ms);
		gle = ok ? ERROR_SUCCESS : GetLastError();
	}

	if (!ok) {
		if (overlapped == NULL) {
			if (gle == WAIT_TIMEOUT || gle == ERROR_TIMEOUT) {
				return (timeout_ms == 0) ? -EAGAIN : -ETIMEDOUT;
			}
			if (gle == ERROR_ABANDONED_WAIT_0) {
				// IOCP handle was closed while we were waiting
				return -ECANCELED;
			}
			return win_error_to_errno(gle);
		}
		// completion with error: proceed (gle carries error)
	}

	if (overlapped == NULL) {
		return -EAGAIN;
	}

	ior_iocp_op *op = (ior_iocp_op *) overlapped;

	if (!op->is_synthetic) {
		if (gle == ERROR_OPERATION_ABORTED
				&& reissue_collateral_abort(ctx, op, bytes_transferred)) {
			// Back in flight; nothing completed from the caller's view.
			return -EAGAIN;
		}
		op->error_code = gle;
		op->bytes_transferred = ok ? bytes_transferred : 0;
		atomic_store(&op->state, IOCP_OP_DONE);
	}
	live_remove(ctx, op);

	if (op->tp_work) {
		// The callback has posted this completion, so it is done with the
		// work object (or is just returning from it, which a close tolerates).
		CloseThreadpoolWork(op->tp_work);
		op->tp_work = NULL;
	}
	if (op->tp_wait) {
		// Likewise for a process wait; the process handle goes with the op.
		CloseThreadpoolWait(op->tp_wait);
		op->tp_wait = NULL;
	}

#ifndef NDEBUG
	uint32_t prev_active = atomic_fetch_sub(&ctx->active_count, 1);
	assert(prev_active > 0 && "active_count underflow detected");
#else
	atomic_fetch_sub(&ctx->active_count, 1);
#endif

	// Mark completion (for DRAIN barriers). A multishot poll's edge is not
	// the completion of a submitted op: the poll itself is still in flight.
	if (!op->cqe_more) {
		atomic_fetch_add(&ctx->completed_cnt, 1);
	}

	if ((op->opcode == IOR_OP_ACCEPT || op->opcode == IOR_OP_CONNECT) && !op->submit_res) {
		finish_socket_op(ctx, op);
	}
	if (op->opcode == IOR_OP_ACCEPT && op->poll_parent && !accept_multi_child_done(ctx, op)) {
		// Not the caller's: a failed child, or one whose parent completed.
		free_op(ctx, op);
		return -EAGAIN;
	}
	op_to_cqe(op);

	int ret = ready_queue_push(&ctx->ready, op);
	if (ret < 0) {
		IOR_LOG_ERROR("Ready queue push failed unexpectedly");
		return ret;
	}

	// LINK handling: on successful completion, start next; otherwise cancel the chain.
	ior_iocp_op *next = op->link_next;
	op->link_next = NULL;

	if (next) {
		if (op->cqe.iocp.res >= 0) {
			(void) start_link_next(ctx, next);
		} else {
			cancel_link_chain(ctx, next);
		}
	}

	/*
	 * Linked-timeout arbitration: if this completed op was guarded by a link
	 * timeout, resolve the pair. Whoever finds the timeout still armed (under
	 * timers.lock) owns posting it. If it is already disarmed, the timer thread
	 * fired first and has handled both sides, so we do nothing here (this op's
	 * own completion is the -ECANCELED produced by that CancelIoEx).
	 */
	if (op->link_timeout) {
		ior_iocp_op *lt = op->link_timeout;

		EnterCriticalSection(&ctx->timers.lock);
		bool won = link_timeout_armed_locked(op);
		op->link_timeout = NULL;
		if (won) {
			lt->timer_armed = false;
			timer_heap_remove(&ctx->timers, lt);
		}
		LeaveCriticalSection(&ctx->timers.lock);

		if (won) {
			// Guarded op finished before the deadline: cancel the link timeout.
			post_armed_op(ctx, lt, ERROR_OPERATION_ABORTED);
		}
	}

	// DRAIN handling: newly completed ops may unblock drain-deferred heads
	sched_kick_drain(ctx);

	return 0;
}

static int ior_iocp_backend_submit_and_wait(void *backend_ctx, unsigned wait_nr)
{
	if (!backend_ctx) {
		return -EINVAL;
	}

	ior_ctx_iocp *ctx = backend_ctx;

	int submitted = ior_iocp_backend_submit(backend_ctx);
	if (submitted < 0) {
		return submitted;
	}

	// Submit stopped at a bad entry: io_uring then returns without waiting.
	if (wait_nr == 0 || ctx->sq_head != ctx->sq_tail) {
		return submitted;
	}

	if (wait_nr > ctx->ready.size) {
		wait_nr = ctx->ready.size;
	}

	while (ctx->ready.count < wait_nr) {
		int ret = dequeue_one_completion(ctx, INFINITE);
		if (ret == -EAGAIN) {
			// A stray NULL completion packet was dequeued (e.g. an external
			// PostQueuedCompletionStatus with NULL overlapped). Under an
			// INFINITE wait this is not a terminal condition - real
			// completions are still pending, so keep waiting.
			continue;
		}
		if (ret < 0) {
			return ret;
		}
	}

	return submitted;
}

static int ior_iocp_backend_peek_cqe(void *backend_ctx, ior_cqe **cqe_out)
{
	if (!backend_ctx || !cqe_out) {
		return -EINVAL;
	}

	ior_ctx_iocp *ctx = backend_ctx;

	if (!ready_queue_empty(&ctx->ready)) {
		ior_iocp_op *op = ready_queue_peek(&ctx->ready);
		*cqe_out = &op->cqe;
		return 0;
	}

	int ret = dequeue_one_completion(ctx, 0);
	if (ret < 0) {
		return ret;
	}

	ior_iocp_op *op = ready_queue_peek(&ctx->ready);
	*cqe_out = &op->cqe;
	return 0;
}

static int ior_iocp_backend_wait_cqe(void *backend_ctx, ior_cqe **cqe_out)
{
	if (!backend_ctx || !cqe_out) {
		return -EINVAL;
	}

	ior_ctx_iocp *ctx = backend_ctx;

	/*
	 * Block until a completion is ready. A stray NULL completion packet (e.g.
	 * an external PostQueuedCompletionStatus with a NULL OVERLAPPED) surfaces as
	 * -EAGAIN from dequeue_one_completion under an INFINITE wait; that is not a
	 * real completion, so we keep waiting rather than returning it.
	 */
	for (;;) {
		if (!ready_queue_empty(&ctx->ready)) {
			ior_iocp_op *op = ready_queue_peek(&ctx->ready);
			*cqe_out = &op->cqe;
			return 0;
		}

		int ret = dequeue_one_completion(ctx, INFINITE);
		if (ret == -EAGAIN) {
			continue;
		}
		if (ret < 0) {
			return ret;
		}
	}
}

static int ior_iocp_backend_wait_cqe_timeout(
		void *backend_ctx, ior_cqe **cqe_out, ior_timespec *timeout)
{
	if (!backend_ctx || !cqe_out) {
		return -EINVAL;
	}

	ior_ctx_iocp *ctx = backend_ctx;

	// Turn the timeout into an absolute deadline so spurious (stray-packet)
	// wakeups can resume the wait without extending it. As on io_uring, a
	// negative one has already expired and a tv_nsec past a second adds up.
	int has_deadline = 0;
	uint64_t deadline_ns = 0;
	if (timeout) {
		deadline_ns = qpc_now_ns() + ior_timespec_ns(timeout);
		has_deadline = 1;
	}

	for (;;) {
		if (!ready_queue_empty(&ctx->ready)) {
			ior_iocp_op *op = ready_queue_peek(&ctx->ready);
			*cqe_out = &op->cqe;
			return 0;
		}

		// Compute how long to block. If the deadline has already passed we still
		// do one non-blocking poll (timeout_ms = 0) so a completion sitting in
		// the IOCP is not missed, then report -ETIME below.
		DWORD timeout_ms = INFINITE;
		if (has_deadline) {
			uint64_t now_ns = qpc_now_ns();
			if (now_ns >= deadline_ns) {
				timeout_ms = 0;
			} else {
				// Round remaining time up to whole milliseconds, clamped below
				// INFINITE (which doubles as the "no timeout" sentinel).
				uint64_t rem_ms = (deadline_ns - now_ns + 999999ULL) / 1000000ULL;
				timeout_ms = rem_ms >= INFINITE ? (INFINITE - 1) : (DWORD) rem_ms;
			}
		}

		int ret = dequeue_one_completion(ctx, timeout_ms);
		if (ret == 0) {
			continue; // got a completion; loop returns it from the ready queue
		}
		if (ret == -EAGAIN || ret == -ETIMEDOUT) {
			// Nothing ready (stray NULL packet, or the wait elapsed). Give up
			// only once the deadline has passed; otherwise resume waiting.
			if (has_deadline && qpc_now_ns() >= deadline_ns) {
				return -ETIME;
			}
			continue;
		}
		return ret; // genuine error
	}
}

static void ior_iocp_backend_cqe_seen(void *backend_ctx, ior_cqe *cqe)
{
	if (!backend_ctx || !cqe) {
		return;
	}

	ior_ctx_iocp *ctx = backend_ctx;
	ior_iocp_op *op = cqe_to_op(cqe);

	ior_iocp_op *head_op = ready_queue_peek(&ctx->ready);

	if (head_op == op) {
		// Fast path: in-order consumption, matching the common io_uring usage.
		ready_queue_pop(&ctx->ready);
		consumer_free_op(ctx, op);
		return;
	}

	/*
	 * Out-of-order cqe_seen. This happens if the caller peeked a batch (via
	 * peek_batch_cqe) and then marked CQEs seen individually rather than using
	 * cq_advance. Rather than abort(), locate the entry in the ready queue and
	 * remove it in place, compacting the ring. This keeps a misusing caller
	 * alive with consistent behaviour across debug and release builds.
	 */
	ready_queue *q = &ctx->ready;
	uint32_t found = UINT32_MAX;
	for (uint32_t i = 0; i < q->count; i++) {
		uint32_t idx = (q->head + i) & q->mask;
		if (q->ops[idx] == op) {
			found = i;
			break;
		}
	}

	if (found == UINT32_MAX) {
		IOR_LOG_ERROR("cqe_seen called for CQE not in ready queue: %p", (void *) op);
		return;
	}

	IOR_LOG_WARN(
			"cqe_seen called out of order (offset %u of %u); removing in place", found, q->count);

	// Shift later entries down by one to fill the gap.
	for (uint32_t i = found; i + 1 < q->count; i++) {
		uint32_t cur = (q->head + i) & q->mask;
		uint32_t nxt = (q->head + i + 1) & q->mask;
		q->ops[cur] = q->ops[nxt];
	}

	q->tail = (q->tail - 1) & q->mask;
	q->count--;

	consumer_free_op(ctx, op);
}

static unsigned ior_iocp_backend_peek_batch_cqe(void *backend_ctx, ior_cqe **cqes, unsigned max)
{
	if (!backend_ctx || !cqes || max == 0) {
		return 0;
	}

	ior_ctx_iocp *ctx = backend_ctx;

	if (max > ctx->ready.size) {
		max = ctx->ready.size;
	}

	unsigned count = 0;

	// Drain whatever is already buffered. Bound by ready.count, not just
	// emptiness: this peeks without popping, so the entries stay in the queue
	// (e.g. a completion left behind by a prior wait_cqe). Looping on
	// !ready_queue_empty() would never terminate on the count and would read
	// past the live entries into NULL ring slots.
	while (count < max && count < ctx->ready.count) {
		ior_iocp_op *op = ctx->ready.ops[(ctx->ready.head + count) & ctx->ready.mask];
		cqes[count] = &op->cqe;
		count++;
	}

	unsigned need = max - count;
	for (unsigned i = 0; i < need; i++) {
		int ret = dequeue_one_completion(ctx, 0);
		if (ret < 0) {
			break;
		}
		ior_iocp_op *op = ctx->ready.ops[(ctx->ready.head + count) & ctx->ready.mask];
		cqes[count] = &op->cqe;
		count++;
	}

	return count;
}

static void ior_iocp_backend_cq_advance(void *backend_ctx, unsigned nr)
{
	if (!backend_ctx || nr == 0) {
		return;
	}

	ior_ctx_iocp *ctx = backend_ctx;

	for (unsigned i = 0; i < nr; i++) {
		ior_iocp_op *op = ready_queue_pop(&ctx->ready);
		if (!op) {
			break;
		}
		consumer_free_op(ctx, op);
	}
}

/* ================= SQE preparation helpers ================= */

static void ior_iocp_backend_prep_nop(ior_sqe *sqe)
{
	ior_iocp_op *op = (ior_iocp_op *) sqe;
	memset(&op->overlapped, 0, sizeof(OVERLAPPED));
	op->opcode = IOR_OP_NOP;
	op->fd = NULL;
}

static void ior_iocp_backend_prep_read(
		ior_sqe *sqe, ior_fd_t fd, void *buf, unsigned nbytes, uint64_t offset)
{
	ior_iocp_op *op = (ior_iocp_op *) sqe;
	memset(&op->overlapped, 0, sizeof(OVERLAPPED));
	op->opcode = IOR_OP_READ;
	op->fd = fd;
	op->buf = buf;
	op->len = nbytes;
	op->offset = offset;
}

static void ior_iocp_backend_prep_write(
		ior_sqe *sqe, ior_fd_t fd, const void *buf, unsigned nbytes, uint64_t offset)
{
	ior_iocp_op *op = (ior_iocp_op *) sqe;
	memset(&op->overlapped, 0, sizeof(OVERLAPPED));
	op->opcode = IOR_OP_WRITE;
	op->fd = fd;
	op->buf = (void *) buf;
	op->len = nbytes;
	op->offset = offset;
}

static void ior_iocp_backend_prep_splice(ior_sqe *sqe, ior_fd_t fd_in, uint64_t off_in,
		ior_fd_t fd_out, uint64_t off_out, unsigned nbytes, unsigned flags)
{
	ior_iocp_op *op = (ior_iocp_op *) sqe;
	memset(&op->overlapped, 0, sizeof(OVERLAPPED));
	op->opcode = IOR_OP_SPLICE;
	op->fd = NULL;
	(void) fd_in;
	(void) off_in;
	(void) fd_out;
	(void) off_out;
	(void) nbytes;
	(void) flags;
}

static void ior_iocp_backend_prep_timeout(
		ior_sqe *sqe, ior_timespec *ts, unsigned count, unsigned flags)
{
	ior_iocp_op *op = (ior_iocp_op *) sqe;
	memset(&op->overlapped, 0, sizeof(OVERLAPPED));
	op->opcode = IOR_OP_TIMER;
	op->fd = NULL;
	op->timeout_ts = ts;
	op->timeout_flags = flags;
	(void) count;
}

static void ior_iocp_backend_prep_link_timeout(ior_sqe *sqe, ior_timespec *ts, unsigned flags)
{
	ior_iocp_op *op = (ior_iocp_op *) sqe;
	memset(&op->overlapped, 0, sizeof(OVERLAPPED));
	op->opcode = IOR_OP_LINK_TIMEOUT;
	op->fd = NULL;
	op->timeout_ts = ts;
	op->timeout_flags = flags;
}

static void ior_iocp_backend_prep_send(
		ior_sqe *sqe, ior_fd_t sockfd, const void *buf, unsigned nbytes, int flags)
{
	ior_iocp_op *op = (ior_iocp_op *) sqe;
	memset(&op->overlapped, 0, sizeof(OVERLAPPED));
	op->opcode = IOR_OP_SEND;
	op->fd = sockfd;
	op->buf = (void *) buf;
	op->len = nbytes;
	op->sock_flags = (DWORD) flags;
}

static void ior_iocp_backend_prep_recv(
		ior_sqe *sqe, ior_fd_t sockfd, void *buf, unsigned nbytes, int flags)
{
	ior_iocp_op *op = (ior_iocp_op *) sqe;
	memset(&op->overlapped, 0, sizeof(OVERLAPPED));
	op->opcode = IOR_OP_RECV;
	op->fd = sockfd;
	op->buf = buf;
	op->len = nbytes;
	op->sock_flags = (DWORD) flags;
}

static void ior_iocp_backend_prep_poll_add(ior_sqe *sqe, ior_fd_t fd, uint32_t poll_mask)
{
	ior_iocp_op *op = (ior_iocp_op *) sqe;
	memset(&op->overlapped, 0, sizeof(OVERLAPPED));
	op->opcode = IOR_OP_POLL;
	op->fd = fd;
	op->poll_mask = poll_mask;
}

static void ior_iocp_backend_prep_poll_multishot(ior_sqe *sqe, ior_fd_t fd, uint32_t poll_mask)
{
	ior_iocp_backend_prep_poll_add(sqe, fd, poll_mask);
	((ior_iocp_op *) sqe)->poll_multi = true;
}

static void ior_iocp_backend_prep_accept(
		ior_sqe *sqe, ior_fd_t fd, struct sockaddr *addr, socklen_t *addrlen, unsigned flags)
{
	ior_iocp_op *op = (ior_iocp_op *) sqe;
	memset(&op->overlapped, 0, sizeof(OVERLAPPED));
	op->opcode = IOR_OP_ACCEPT;
	op->fd = fd;
	op->sa = addr;
	op->sa_len = addrlen;
	// Only checked at submit: an accepted socket is overlapped like any other.
	op->accept_flags = flags;
}

static void ior_iocp_backend_prep_accept_multishot(ior_sqe *sqe, ior_fd_t fd, unsigned flags)
{
	ior_iocp_backend_prep_accept(sqe, fd, NULL, NULL, flags);
	((ior_iocp_op *) sqe)->accept_multi = true;
}

static void ior_iocp_backend_prep_connect(
		ior_sqe *sqe, ior_fd_t fd, const struct sockaddr *addr, socklen_t addrlen)
{
	ior_iocp_op *op = (ior_iocp_op *) sqe;
	memset(&op->overlapped, 0, sizeof(OVERLAPPED));
	op->opcode = IOR_OP_CONNECT;
	op->fd = fd;
	op->sa = (struct sockaddr *) addr;
	op->sa_len_val = addrlen;
}

static int ior_iocp_backend_prep_waitpid(
		void *backend_ctx, ior_sqe *sqe, ior_pid_t pid, int *status, int options)
{
	(void) backend_ctx;
	(void) options; // no WNOHANG or job control here
	ior_iocp_op *op = (ior_iocp_op *) sqe;
	memset(&op->overlapped, 0, sizeof(OVERLAPPED));
	op->opcode = IOR_OP_WAITPID;
	op->fd = NULL;
	op->wait_pid = pid;
	op->wait_status = status;
	return 0;
}

static int ior_iocp_backend_prep_sigwait(
		void *backend_ctx, ior_sqe *sqe, const ior_sigset_t *set, ior_siginfo_t *info)
{
	(void) backend_ctx;
	ior_iocp_op *op = (ior_iocp_op *) sqe;
	memset(&op->overlapped, 0, sizeof(OVERLAPPED));
	op->fd = NULL;
	// Console control events are all there is: Ctrl+C, and Ctrl+Break with
	// the close, logoff and shutdown events behind it. Anything else leaves
	// the entry a no-op.
	if (set->bits & ~((1U << SIGINT) | (1U << SIGBREAK))) {
		op->opcode = IOR_OP_NOP;
		return -ENOTSUP;
	}
	op->opcode = IOR_OP_SIGWAIT;
	op->sig_mask = set->bits;
	op->sig_info = info;
	return 0;
}

static void ior_iocp_backend_prep_cancel(ior_sqe *sqe, uint64_t user_data)
{
	ior_iocp_op *op = (ior_iocp_op *) sqe;
	memset(&op->overlapped, 0, sizeof(OVERLAPPED));
	op->opcode = IOR_OP_ASYNC_CANCEL;
	op->fd = NULL;
	op->cancel_key = user_data;
	op->cancel_flags = 0;
}

static void ior_iocp_backend_prep_cancel_fd(ior_sqe *sqe, ior_fd_t fd)
{
	ior_iocp_op *op = (ior_iocp_op *) sqe;
	memset(&op->overlapped, 0, sizeof(OVERLAPPED));
	op->opcode = IOR_OP_ASYNC_CANCEL;
	op->fd = fd;
	op->cancel_key = 0;
	op->cancel_flags = IOR_CANCEL_BY_FD;
}

static int ior_iocp_backend_prep_work(void *backend_ctx, ior_sqe *sqe, ior_work_fn fn, void *arg)
{
	(void) backend_ctx;
	ior_iocp_op *op = (ior_iocp_op *) sqe;
	memset(&op->overlapped, 0, sizeof(OVERLAPPED));
	op->opcode = IOR_OP_WORK;
	op->fd = NULL;
	op->work_fn = fn;
	op->work_arg = arg;
	return 0;
}

static void ior_iocp_backend_sqe_set_data(ior_sqe *sqe, void *data)
{
	ior_iocp_op *op = (ior_iocp_op *) sqe;
	op->user_data = (uint64_t) (uintptr_t) data;
}

static void ior_iocp_backend_sqe_set_flags(ior_sqe *sqe, uint8_t flags)
{
	ior_iocp_op *op = (ior_iocp_op *) sqe;
	op->sqe_flags = flags;
}

/* ================= CQE accessors ================= */

static void *ior_iocp_backend_cqe_get_data(ior_cqe *cqe)
{
	return (void *) (uintptr_t) cqe->iocp.user_data;
}

static int32_t ior_iocp_backend_cqe_get_res(ior_cqe *cqe)
{
	return cqe->iocp.res;
}

static uint32_t ior_iocp_backend_cqe_get_flags(ior_cqe *cqe)
{
	return cqe->iocp.flags;
}

/* ================= Completion notification ================= */

static ior_fd_t ior_iocp_backend_notify_fd(void *backend_ctx)
{
	if (!backend_ctx) {
		return IOR_INVALID_FD;
	}
	ior_ctx_iocp *ctx = backend_ctx;
	if (iocp_pump_ensure(ctx) < 0) {
		return IOR_INVALID_FD;
	}
	return (ior_fd_t) ctx->pump.wake_rx;
}

static int ior_iocp_backend_notify_clear(void *backend_ctx)
{
	if (!backend_ctx) {
		return -EINVAL;
	}
	ior_ctx_iocp *ctx = backend_ctx;
	if (!ctx->pump.thread) {
		return -EINVAL;
	}
	// Drain, then reset, under the pump lock: see iocp_pump_thread_main for
	// why the pair must be atomic against "stage, then signal".
	iocp_pump *p = &ctx->pump;
	EnterCriticalSection(&p->lock);
	char buf[64];
	while (recv(p->wake_rx, buf, sizeof(buf), 0) > 0) { }
	p->signalled = false;
	LeaveCriticalSection(&p->lock);
	return 0;
}

/* ================= Backend info ================= */

static const char *ior_iocp_backend_name(void)
{
	return "iocp";
}

static uint32_t ior_iocp_backend_get_features(void *backend_ctx)
{
	if (!backend_ctx) {
		return 0;
	}
	ior_ctx_iocp *ctx = backend_ctx;
	return ctx->features;
}

/* Export vtable */
const ior_backend_ops ior_iocp_ops = {
	.init = ior_iocp_backend_init,
	.destroy = ior_iocp_backend_destroy,
	.get_sqe = ior_iocp_backend_get_sqe,
	.submit = ior_iocp_backend_submit,
	.submit_and_wait = ior_iocp_backend_submit_and_wait,
	.peek_cqe = ior_iocp_backend_peek_cqe,
	.wait_cqe = ior_iocp_backend_wait_cqe,
	.wait_cqe_timeout = ior_iocp_backend_wait_cqe_timeout,
	.cqe_seen = ior_iocp_backend_cqe_seen,
	.peek_batch_cqe = ior_iocp_backend_peek_batch_cqe,
	.cq_advance = ior_iocp_backend_cq_advance,
	.prep_nop = ior_iocp_backend_prep_nop,
	.prep_read = ior_iocp_backend_prep_read,
	.prep_write = ior_iocp_backend_prep_write,
	.prep_splice = ior_iocp_backend_prep_splice,
	.prep_timeout = ior_iocp_backend_prep_timeout,
	.prep_link_timeout = ior_iocp_backend_prep_link_timeout,
	.prep_send = ior_iocp_backend_prep_send,
	.prep_recv = ior_iocp_backend_prep_recv,
	.prep_poll_add = ior_iocp_backend_prep_poll_add,
	.prep_poll_multishot = ior_iocp_backend_prep_poll_multishot,
	.prep_accept = ior_iocp_backend_prep_accept,
	.prep_accept_multishot = ior_iocp_backend_prep_accept_multishot,
	.prep_connect = ior_iocp_backend_prep_connect,
	.prep_cancel = ior_iocp_backend_prep_cancel,
	.prep_cancel_fd = ior_iocp_backend_prep_cancel_fd,
	.prep_waitpid = ior_iocp_backend_prep_waitpid,
	.prep_sigwait = ior_iocp_backend_prep_sigwait,
	.prep_work = ior_iocp_backend_prep_work,
	.sqe_set_data = ior_iocp_backend_sqe_set_data,
	.sqe_set_flags = ior_iocp_backend_sqe_set_flags,
	.cqe_get_data = ior_iocp_backend_cqe_get_data,
	.cqe_get_res = ior_iocp_backend_cqe_get_res,
	.cqe_get_flags = ior_iocp_backend_cqe_get_flags,
	.notify_fd = ior_iocp_backend_notify_fd,
	.notify_clear = ior_iocp_backend_notify_clear,
	.backend_name = ior_iocp_backend_name,
	.get_features = ior_iocp_backend_get_features,
	.sq_entries = ior_iocp_backend_sq_entries,
	.cq_entries = ior_iocp_backend_cq_entries,
	.sq_space_left = ior_iocp_backend_sq_space_left,
	.cq_space_left = ior_iocp_backend_cq_space_left,
};

#endif /* IOR_HAVE_IOCP */
