/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * test_dir_changes.c - IOR_OP_DIR_CHANGES.
 *
 * On Windows: the feature bit, a file created in the directory, a change in
 * a subdirectory with and without IOR_DIR_CHANGES_SUBTREE, changes made
 * between two ops kept for the second, cancellation, and bad arguments.
 * Elsewhere the default and the threads backend refuse the op with -ENOTSUP
 * and report no feature.
 */
#include "test_utils.h"
#ifdef _WIN32
#include <windows.h>
#include <stdbool.h>
#include <wchar.h>
#endif

#define TAG_DIR ((void *) 0x1)
#define TAG_CANCEL ((void *) 0x2)

#ifdef _WIN32

typedef struct dc_state {
	ior_ctx *ctx;
	wchar_t root[MAX_PATH];
	HANDLE dir;
	DWORD buf[1024]; /* 4 KiB, DWORD-aligned as the op requires */
} dc_state;

static void dc_path(const dc_state *s, const wchar_t *name, wchar_t *out)
{
	_snwprintf(out, MAX_PATH, L"%ls\\%ls", s->root, name);
	out[MAX_PATH - 1] = L'\0';
}

static void dc_touch(const dc_state *s, const wchar_t *name)
{
	wchar_t path[MAX_PATH];
	dc_path(s, name, path);
	HANDLE h
			= CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	assert_true(h != INVALID_HANDLE_VALUE);
	DWORD written = 0;
	assert_true(WriteFile(h, "x", 1, &written, NULL));
	CloseHandle(h);
}

static void dc_mkdir(const dc_state *s, const wchar_t *name)
{
	wchar_t path[MAX_PATH];
	dc_path(s, name, path);
	assert_true(CreateDirectoryW(path, NULL));
}

/* Deletes what the tests create, deepest first */
static void dc_remove_all(const dc_state *s)
{
	static const wchar_t *const files[] = { L"sub\\b.txt", L"a.txt", L"c.txt" };
	wchar_t path[MAX_PATH];
	for (size_t i = 0; i < sizeof(files) / sizeof(files[0]); i++) {
		dc_path(s, files[i], path);
		DeleteFileW(path);
	}

	dc_path(s, L"sub", path);
	RemoveDirectoryW(path);
	RemoveDirectoryW(s->root);
}

static int setup_dc(void **state)
{
	dc_state *s = calloc(1, sizeof(*s));
	assert_non_null(s);
	wchar_t tmp[MAX_PATH];
	assert_true(GetTempPathW(MAX_PATH, tmp) > 0);
	_snwprintf(s->root, MAX_PATH, L"%lsior_dc_%lu_%llu", tmp, GetCurrentProcessId(),
			(unsigned long long) test_monotonic_now_ns());
	assert_true(CreateDirectoryW(s->root, NULL));
	s->dir = CreateFileW(s->root, FILE_LIST_DIRECTORY,
			FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING,
			FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED, NULL);
	assert_true(s->dir != INVALID_HANDLE_VALUE);
	assert_return_code(ior_queue_init(32, &s->ctx), 0);
	*state = s;
	return 0;
}

static int teardown_dc(void **state)
{
	dc_state *s = *state;
	if (s) {
		if (s->ctx) {
			ior_queue_exit(s->ctx);
		}

		CloseHandle(s->dir);
		dc_remove_all(s);
		free(s);
	}
	return 0;
}

static void dc_submit(dc_state *s, uint32_t flags)
{
	ior_sqe *sqe = ior_get_sqe(s->ctx);
	assert_non_null(sqe);
	assert_int_equal(ior_prep_dir_changes(s->ctx, sqe, s->dir, s->buf, sizeof(s->buf), flags), 0);
	ior_sqe_set_data(s->ctx, sqe, TAG_DIR);
	assert_int_equal(ior_submit(s->ctx), 1);
}

/* The op's result, after at most timeout_s */
static int32_t dc_reap(dc_state *s, int timeout_s)
{
	ior_cqe *cqe = NULL;
	ior_timespec to = { .tv_sec = timeout_s, .tv_nsec = 0 };
	int ret;
	while ((ret = ior_wait_cqe_timeout(s->ctx, &cqe, &to)) == -EINTR) { }
	assert_int_equal(ret, 0);
	assert_ptr_equal(ior_cqe_get_data(s->ctx, cqe), TAG_DIR);
	int32_t res = ior_cqe_get_res(s->ctx, cqe);
	ior_cqe_seen(s->ctx, cqe);
	return res;
}

/* Whether a record in the first len bytes of buf reports the entry name with action */
static bool dc_reported(const dc_state *s, int32_t len, DWORD action, const wchar_t *name)
{
	const char *at = (const char *) s->buf;
	const char *end = at + len;
	size_t name_len = wcslen(name);
	while (at < end) {
		const FILE_NOTIFY_INFORMATION *info = (const FILE_NOTIFY_INFORMATION *) at;
		if (info->Action == action && info->FileNameLength == name_len * sizeof(wchar_t)
				&& wmemcmp(info->FileName, name, name_len) == 0) {
			return true;
		}

		if (info->NextEntryOffset == 0) {
			break;
		}

		at += info->NextEntryOffset;
	}
	return false;
}

static void test_dir_changes_feature(void **state)
{
	dc_state *s = *state;
	assert_true(ior_get_features(s->ctx) & IOR_FEAT_DIR_CHANGES);
}

static void test_dir_changes_created(void **state)
{
	dc_state *s = *state;
	dc_submit(s, 0);
	dc_touch(s, L"a.txt");
	int32_t res = dc_reap(s, 5);
	assert_true(res > 0);
	assert_true(dc_reported(s, res, FILE_ACTION_ADDED, L"a.txt"));
}

static void test_dir_changes_subtree(void **state)
{
	dc_state *s = *state;
	dc_mkdir(s, L"sub");
	dc_submit(s, IOR_DIR_CHANGES_SUBTREE);
	dc_touch(s, L"sub\\b.txt");
	int32_t res = dc_reap(s, 5);
	assert_true(res > 0);
	assert_true(dc_reported(s, res, FILE_ACTION_ADDED, L"sub\\b.txt"));
}

/*
 * Without the subtree flag a subdirectory's own entries are not reported. The
 * file in sub may first come out as sub's own change, so the ops go on until
 * a.txt, made after it, is reported.
 */
static void test_dir_changes_no_subtree(void **state)
{
	dc_state *s = *state;
	dc_mkdir(s, L"sub");
	dc_submit(s, 0);
	dc_touch(s, L"sub\\b.txt");
	dc_touch(s, L"a.txt");

	bool saw_a = false;
	for (int i = 0; i < 4 && !saw_a; i++) {
		if (i > 0) {
			dc_submit(s, 0);
		}

		int32_t res = dc_reap(s, 5);
		assert_true(res > 0);
		assert_false(dc_reported(s, res, FILE_ACTION_ADDED, L"sub\\b.txt"));
		saw_a = dc_reported(s, res, FILE_ACTION_ADDED, L"a.txt");
	}

	assert_true(saw_a);
}

/* The watch lives on the handle: what changes between two ops is kept */
static void test_dir_changes_between_ops(void **state)
{
	dc_state *s = *state;
	dc_submit(s, 0);
	dc_touch(s, L"a.txt");
	assert_true(dc_reap(s, 5) > 0);
	dc_touch(s, L"c.txt");
	dc_submit(s, 0);
	int32_t res = dc_reap(s, 5);
	assert_true(res > 0);
	assert_true(dc_reported(s, res, FILE_ACTION_ADDED, L"c.txt"));
}

static void test_dir_changes_cancel(void **state)
{
	dc_state *s = *state;
	dc_submit(s, 0);

	ior_sqe *sqe = ior_get_sqe(s->ctx);
	assert_non_null(sqe);
	ior_prep_cancel(s->ctx, sqe, TAG_DIR);
	ior_sqe_set_data(s->ctx, sqe, TAG_CANCEL);
	assert_int_equal(ior_submit(s->ctx), 1);

	int32_t dir_res = 1, cancel_res = 1;
	for (int i = 0; i < 2; i++) {
		ior_cqe *cqe = NULL;
		ior_timespec to = { .tv_sec = 5, .tv_nsec = 0 };
		assert_int_equal(ior_wait_cqe_timeout(s->ctx, &cqe, &to), 0);
		if (ior_cqe_get_data(s->ctx, cqe) == TAG_DIR) {
			dir_res = ior_cqe_get_res(s->ctx, cqe);
		} else {
			cancel_res = ior_cqe_get_res(s->ctx, cqe);
		}

		ior_cqe_seen(s->ctx, cqe);
	}

	assert_int_equal(dir_res, -ECANCELED);
	assert_int_equal(cancel_res, 0);
}

static void test_dir_changes_bad_args(void **state)
{
	dc_state *s = *state;
	ior_sqe *sqe = ior_get_sqe(s->ctx);
	assert_non_null(sqe);
	assert_int_equal(ior_prep_dir_changes(s->ctx, sqe, s->dir, NULL, 4096, 0), -EINVAL);
	assert_int_equal(ior_prep_dir_changes(s->ctx, sqe, s->dir, s->buf, 0, 0), -EINVAL);
	assert_int_equal(
			ior_prep_dir_changes(s->ctx, sqe, s->dir, (char *) s->buf + 1, sizeof(s->buf) - 4, 0),
			-EINVAL);
	assert_int_equal(
			ior_prep_dir_changes(s->ctx, sqe, s->dir, s->buf, sizeof(s->buf), 1U << 1), -EINVAL);
	ior_prep_nop(s->ctx, sqe);
	assert_int_equal(ior_submit(s->ctx), 1);
}

int main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup_teardown(test_dir_changes_feature, setup_dc, teardown_dc),
		cmocka_unit_test_setup_teardown(test_dir_changes_created, setup_dc, teardown_dc),
		cmocka_unit_test_setup_teardown(test_dir_changes_subtree, setup_dc, teardown_dc),
		cmocka_unit_test_setup_teardown(test_dir_changes_no_subtree, setup_dc, teardown_dc),
		cmocka_unit_test_setup_teardown(test_dir_changes_between_ops, setup_dc, teardown_dc),
		cmocka_unit_test_setup_teardown(test_dir_changes_cancel, setup_dc, teardown_dc),
		cmocka_unit_test_setup_teardown(test_dir_changes_bad_args, setup_dc, teardown_dc),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}

#else /* !_WIN32 */

/* The op is refused on ctx's backend, with no feature bit */
static void dc_refused(ior_ctx *ctx)
{
	char buf[64] __attribute__((aligned(4)));
	assert_false(ior_get_features(ctx) & IOR_FEAT_DIR_CHANGES);
	ior_sqe *sqe = ior_get_sqe(ctx);
	assert_non_null(sqe);
	assert_int_equal(ior_prep_dir_changes(ctx, sqe, 0, buf, sizeof(buf), 0), -ENOTSUP);
	ior_prep_nop(ctx, sqe);
	assert_int_equal(ior_submit(ctx), 1);
}

static void test_dir_changes_unsupported(void **state)
{
	test_state *ts = *state;
	dc_refused(ts->ctx);
}

static void test_dir_changes_unsupported_threads(void **state)
{
	(void) state;
	ior_ctx *ctx;
	ior_params params = { .sq_entries = 32, .cq_entries = 64, .backend = IOR_BACKEND_THREADS };
	assert_return_code(ior_queue_init_params(32, &ctx, &params), 0);
	dc_refused(ctx);
	ior_queue_exit(ctx);
}

int main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup_teardown(
				test_dir_changes_unsupported, setup_ior_ctx, teardown_ior_ctx),
		cmocka_unit_test(test_dir_changes_unsupported_threads),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}

#endif /* _WIN32 */
