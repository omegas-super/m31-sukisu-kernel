// SPDX-License-Identifier: GPL-2.0
/*
 * SukiSU-Ultra's `builtin` branch talks to the newer SUSFS kernel API.
 * The 4.14 SUSFS implementation (fs/susfs.c) predates that API, so this
 * shim supplies the small set of symbols the builtin calls but 4.14 lacks.
 *
 * Features the 4.14 tree cannot implement are accepted and ignored; the
 * core lists (sus_path / sus_mount / sus_kstat / open_redirect /
 * spoof_uname) are served by fs/susfs.c itself.
 */
#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/workqueue.h>
#include <linux/namei.h>
#include <linux/atomic.h>
#include <linux/bitops.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/kthread.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/rcupdate.h>
#include <linux/stat.h>
#include <linux/user_namespace.h>
#include <linux/susfs.h>
#include <linux/susfs_def.h>
#include <linux/ksu_selinux_hide.h>

#if defined(CONFIG_KSU_SUSFS_SUS_MOUNT) || defined(CONFIG_KSU_SUSFS_TRY_UMOUNT)
/*
 * fs/susfs.c (4.14) calls this legacy KernelSU umount helper from
 * susfs_try_umount().  The real work is done by the __weak path_umount()
 * shim in drivers/kernelsu/kernel_compat.c (4.14 has no path_umount()):
 * it resolves the mount by path and calls sys_umount() with KERNEL_DS.
 *
 * path_umount() consumes the reference obtained by kern_path() and calls
 * path_put() itself (also on its error path), so never path_put() here.
 */
void ksu_try_umount(const char *mnt, bool check_mnt, int flags, uid_t uid);
extern int path_umount(struct path *path, int flags);

void ksu_try_umount(const char *mnt, bool check_mnt, int flags, uid_t uid)
{
	struct path path;
	int err;

	(void)check_mnt;
	(void)uid;

	if (!mnt)
		return;

	err = kern_path(mnt, LOOKUP_FOLLOW, &path);
	if (err)
		return;

	err = path_umount(&path, flags);
	if (err)
		pr_info("susfs: umount '%s' failed: %d\n", mnt, err);
}
#endif

#ifdef CONFIG_KSU_SUSFS_TRY_UMOUNT
/*
 * fs/namespace.c (4.14) calls susfs_try_umount_all() from
 * susfs_run_try_umount_for_current_mnt_ns(), but fs/susfs.c only provides
 * the list-based susfs_try_umount().  Bridge the two names so that a
 * CONFIG_KSU_SUSFS_TRY_UMOUNT build links; both walk LH_TRY_UMOUNT_PATH.
 */
void susfs_try_umount_all(uid_t uid);

void susfs_try_umount_all(uid_t uid)
{
	susfs_try_umount(uid);
}
#endif

bool susfs_starts_with(const char *str, const char *prefix)
{
	size_t len = strlen(prefix);

	return !strncmp(str, prefix, len);
}

bool susfs_ends_with(const char *str, const char *suffix)
{
	size_t str_len = strlen(str);
	size_t suffix_len = strlen(suffix);

	if (str_len < suffix_len)
		return false;
	return !strcmp(str + str_len - suffix_len, suffix);
}

/*
 * B2a: the 4.14 SUSFS hiding gates (fs/stat.c, fs/statfs.c, fs/namei.c,
 * fs/readdir.c, fs/dcache.c, ...) all test
 * TASK_STRUCT_NON_ROOT_USER_APP_PROC (BIT(24)) on current->susfs_task_state.
 * SukiSU's newer kernels set that same bit from this helper; writing
 * TASK_STRUCT_NO_SU (BIT(27)) instead marked nothing the 4.14 code reads,
 * so sus-path / sus-kstat / statfs hiding was silently inert.
 */
void susfs_set_current_proc_no_su(void)
{
	current->susfs_task_state |= TASK_STRUCT_NON_ROOT_USER_APP_PROC;
}

/*
 * The two helpers below only feed newer-SUSFS task-state flags.  Nothing in
 * the 4.14 tree reads BIT(25)/BIT(26) from susfs_task_state, so these writes
 * are harmless: keep them for SukiSU ABI/behaviour compatibility.
 */
void susfs_set_current_proc_umounted(void)
{
	current->susfs_task_state |= TASK_STRUCT_UMOUNTED;
}

void susfs_set_current_proc_umounted_for_zygote_next(void)
{
	current->susfs_task_state |= TASK_STRUCT_UMOUNTED_FOR_ZYGOTE_NEXT;
}

#ifdef CONFIG_KSU_SUSFS_SUS_PATH
int susfs_add_sus_path_loop(void __user *user_info)
{
	/* The loop-device payload is the same st_susfs_sus_path on 4.14. */
	return susfs_add_sus_path(user_info);
}
#endif

#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
int susfs_set_hide_sus_mnts_for_non_su_procs(void __user *user_info)
{
	/* Not available on the 4.14 variant. */
	(void)user_info;
	return 0;
}
#endif

#ifdef CONFIG_KSU_SUSFS_ENABLE_LOG
int susfs_enable_log(void __user *user_info)
{
	bool enabled;

	if (copy_from_user(&enabled, user_info, sizeof(enabled)))
		return -EFAULT;
	susfs_set_log(enabled);
	return 0;
}
#endif

#ifdef CONFIG_KSU_SUSFS_SUS_MAP
int susfs_add_sus_map(void __user *user_info)
{
	/* SUS_MAP is intentionally not built on this tree. */
	(void)user_info;
	return 0;
}
#endif

int susfs_set_avc_log_spoofing(void __user *user_info)
{
	u32 enabled;

	/*
	 * The 4.14 port implements AVC log spoofing natively (no kprobes):
	 * security/selinux/avc.c calls ksu_slow_avc_audit() and the shared
	 * toggle lives in security/selinux/ksu_selinux_hide.c.  Accept both
	 * the SUSFS command (this one) and the KernelSU avc_spoof feature.
	 */
	if (copy_from_user(&enabled, user_info, sizeof(enabled)))
		return -EFAULT;

	ksu_avc_spoof_set(enabled != 0);
	return 0;
}

int susfs_get_enabled_features(void __user *user_info)
{
	struct st_susfs_enabled_features info;

	memset(&info, 0, sizeof(info));
#ifdef CONFIG_KSU_SUSFS_SUS_PATH
	strlcat(info.enabled_features, "sus_path,", sizeof(info.enabled_features));
#endif
#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
	strlcat(info.enabled_features, "sus_mount,", sizeof(info.enabled_features));
#endif
#ifdef CONFIG_KSU_SUSFS_SUS_KSTAT
	strlcat(info.enabled_features, "sus_kstat,", sizeof(info.enabled_features));
#endif
#ifdef CONFIG_KSU_SUSFS_TRY_UMOUNT
	strlcat(info.enabled_features, "try_umount,", sizeof(info.enabled_features));
#endif
#ifdef CONFIG_KSU_SUSFS_SPOOF_UNAME
	strlcat(info.enabled_features, "spoof_uname,", sizeof(info.enabled_features));
#endif
#ifdef CONFIG_KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG
	strlcat(info.enabled_features, "spoof_cmdline,", sizeof(info.enabled_features));
#endif
#ifdef CONFIG_KSU_SUSFS_HIDE_KSU_SUSFS_SYMBOLS
	strlcat(info.enabled_features, "hide_symbols,", sizeof(info.enabled_features));
#endif
#ifdef CONFIG_KSU_SUSFS_ENABLE_LOG
	strlcat(info.enabled_features, "enable_log,", sizeof(info.enabled_features));
#endif
#ifdef CONFIG_KSU_SUSFS_OPEN_REDIRECT
	strlcat(info.enabled_features, "open_redirect,", sizeof(info.enabled_features));
#endif
	/* Implemented by the 4.14 port (KernelSU feature id 10003 + SUSFS cmd). */
	strlcat(info.enabled_features, "avc_log_spoofing,", sizeof(info.enabled_features));
	/* Implemented by the 4.14 port (SUSFS 2.x backport, see below). */
	strlcat(info.enabled_features, "priority_uid_filter,", sizeof(info.enabled_features));
	if (copy_to_user(user_info, &info, sizeof(info)))
		return -EFAULT;
	return 0;
}

/* ------------------------------------------------------------------------- */
/* SUSFS 2.x priority-UID filter (SukiSU `builtin` backport)                 */
/*                                                                           */
/* The current SukiSU `builtin` branch calls susfs_set_priority_uid_filter()  */
/* and susfs_parse_priority_app_strings(), which the 4.14 SUSFS 1.5.5 port   */
/* does not provide.  This backport keeps the same userspace ABI: userspace   */
/* sends a comma-separated package-name list; the kernel resolves each app's  */
/* uid from /data/data/<pkg> and hides the process priority/ioprio of those   */
/* uids from app-UID callers (getpriority/setpriority/ioprio_get/ioprio_set). */
/* ------------------------------------------------------------------------- */
struct susfs_priority_uid_filter_bitmap {
	struct rcu_head		rcu;
	unsigned long		bits[SUSFS_PRIORITY_UID_FILTER_BITMAP_LEN];
};

static struct susfs_priority_uid_filter_bitmap __rcu *susfs_priority_bitmap;
static DEFINE_MUTEX(susfs_priority_mutex);
static char *susfs_priority_app_strings;
static atomic_t susfs_priority_worker_running = ATOMIC_INIT(0);

static bool susfs_is_valid_app_name(const char *app_name)
{
	const char *p = app_name;
	size_t len = strlen(app_name);

	if (len == 0 || len > 255)
		return false;
	if (!strcmp(app_name, ".") || !strcmp(app_name, ".."))
		return false;

	for (; *p != '\0'; p++) {
		if ((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
		    (*p >= '0' && *p <= '9') || *p == '.' || *p == '_')
			continue;
		return false;
	}

	return true;
}

static int susfs_resolve_priority_app_uid(const char *app_name, uid_t *uid)
{
	char app_path[512];
	struct path path;
	struct kstat st;
	int len, ret;

	len = scnprintf(app_path, sizeof(app_path), "/data/data/%s", app_name);
	if (len <= 0 || len >= (int)sizeof(app_path))
		return -EINVAL;

	ret = kern_path(app_path, LOOKUP_FOLLOW, &path);
	if (ret)
		return ret;

	ret = vfs_getattr(&path, &st, STATX_BASIC_STATS, 0);
	path_put(&path);
	if (ret)
		return ret;

	*uid = from_kuid(&init_user_ns, st.uid);
	if (*uid < SUSFS_PRIORITY_UID_FILTER_MIN_UID ||
	    *uid > SUSFS_PRIORITY_UID_FILTER_MAX_UID)
		return -EINVAL;

	return 0;
}

static int susfs_parse_priority_app_names(char *app_str, unsigned long *bits,
					  bool skip_failed)
{
	char *token, *saveptr = app_str;
	uid_t uid = 0;
	int ret;

	while ((token = strsep(&saveptr, ",")) != NULL) {
		token = strim(token);
		if (*token == '\0')
			continue;

		if (!susfs_is_valid_app_name(token))
			return -EINVAL;

		ret = susfs_resolve_priority_app_uid(token, &uid);
		if (ret) {
			if (skip_failed)
				continue;
			return ret;
		}

		if (uid < SUSFS_PRIORITY_UID_FILTER_MIN_UID ||
		    uid > SUSFS_PRIORITY_UID_FILTER_MAX_UID) {
			if (!skip_failed)
				return -EINVAL;
			continue;
		}

		set_bit(uid - SUSFS_PRIORITY_UID_FILTER_MIN_UID, bits);
		pr_info("susfs: priority filter app '%s' uid %u\n", token, uid);
	}

	return 0;
}

/*
 * Resolving /data/data/<pkg> needs to bypass the caller's SELinux domain
 * (ksud runs as the su domain), so the lookup runs with kernel credentials.
 */
static const struct cred *susfs_priority_override_creds(void)
{
	struct cred *cred = prepare_kernel_cred(NULL);
	const struct cred *old;

	if (!cred)
		return NULL;

#ifdef CONFIG_RKP_KDP
	/*
	 * Samsung RKP: rkp_override_creds() consumes the reference to the
	 * passed credential, installs a read-only copy and updates the pointer.
	 */
	old = rkp_override_creds(&cred);
#else
	old = override_creds(cred);
	put_cred(cred);
#endif

	return old;
}

static void susfs_priority_restore_creds(const struct cred *old)
{
	if (old)
		revert_creds(old);
}

static void susfs_priority_publish(struct susfs_priority_uid_filter_bitmap *bitmap,
				   char *app_strings)
{
	struct susfs_priority_uid_filter_bitmap *old;

	mutex_lock(&susfs_priority_mutex);
	old = rcu_dereference_raw(susfs_priority_bitmap);
	rcu_assign_pointer(susfs_priority_bitmap, bitmap);
	if (app_strings) {
		kvfree(susfs_priority_app_strings);
		susfs_priority_app_strings = app_strings;
	}
	mutex_unlock(&susfs_priority_mutex);

	if (old)
		kfree_rcu(old, rcu);
}

void susfs_set_priority_uid_filter(void __user **user_info)
{
	struct st_susfs_priority_uid_filter *info;
	struct susfs_priority_uid_filter_bitmap *new_bitmap = NULL;
	const struct cred *old_cred = NULL;
	char *new_app_strings = NULL;
	size_t app_str_len;
	int err = 0;

	if (!user_info || !*user_info) {
		err = -EINVAL;
		goto out;
	}

	info = kvmalloc(sizeof(*info), GFP_KERNEL | __GFP_ZERO);
	if (!info) {
		err = -ENOMEM;
		goto out;
	}

	if (copy_from_user(info, (void __user *)*user_info, sizeof(*info))) {
		err = -EFAULT;
		goto out_free_info;
	}

	/* the app names string must be null terminated within the buffer */
	if (!memchr(info->app_strings, '\0', sizeof(info->app_strings))) {
		err = -EINVAL;
		goto out_free_info;
	}
	if (*info->app_strings == '\0') {
		err = -EINVAL;
		goto out_free_info;
	}

	app_str_len = strlen(info->app_strings);
	new_app_strings = kvmalloc(app_str_len + 1, GFP_KERNEL | __GFP_ZERO);
	if (!new_app_strings) {
		err = -ENOMEM;
		goto out_free_info;
	}
	memcpy(new_app_strings, info->app_strings, app_str_len + 1);

	new_bitmap = kzalloc(sizeof(*new_bitmap), GFP_KERNEL);
	if (!new_bitmap) {
		err = -ENOMEM;
		goto out_free_strings;
	}

	old_cred = susfs_priority_override_creds();
	if (!old_cred) {
		err = -EINVAL;
		goto out_free_bitmap;
	}
	err = susfs_parse_priority_app_names(info->app_strings,
					     new_bitmap->bits, false);
	susfs_priority_restore_creds(old_cred);
	if (err)
		goto out_free_bitmap;

	susfs_priority_publish(new_bitmap, new_app_strings);
	new_bitmap = NULL;
	new_app_strings = NULL;
	pr_info("susfs: priority uid filter is set\n");

out_free_bitmap:
	kfree(new_bitmap);
out_free_strings:
	kvfree(new_app_strings);
out_free_info:
	kvfree(info);
out:
	if (user_info && *user_info) {
		if (copy_to_user(&((struct st_susfs_priority_uid_filter __user *)*user_info)->err,
				 &err, sizeof(err)))
			err = -EFAULT;
	}
	pr_info("susfs: CMD_SUSFS_SET_PRIORITY_UID_FILTER -> ret: %d\n", err);
}

/*
 * Refresh the bitmap after package install/uninstall, because an app's uid can
 * change when it is reinstalled.  Runs in a worker because the lookup needs
 * kernel credentials and must not disturb the caller.
 */
static int susfs_priority_app_strings_worker(void *data)
{
	struct susfs_priority_uid_filter_bitmap *new_bitmap = NULL;
	const struct cred *old_cred;
	char *app_strings = NULL;
	size_t app_str_len = 0;
	int ret = 0;

	old_cred = susfs_priority_override_creds();
	if (!old_cred)
		goto out;

	mutex_lock(&susfs_priority_mutex);
	if (susfs_priority_app_strings) {
		app_str_len = strlen(susfs_priority_app_strings);
		app_strings = kvmalloc(app_str_len + 1, GFP_KERNEL | __GFP_ZERO);
		if (app_strings)
			memcpy(app_strings, susfs_priority_app_strings,
			       app_str_len + 1);
	}
	mutex_unlock(&susfs_priority_mutex);

	if (!app_strings)
		goto out_restore;

	new_bitmap = kzalloc(sizeof(*new_bitmap), GFP_KERNEL);
	if (!new_bitmap)
		goto out_restore;

	/* apps that are uninstalled already are skipped */
	ret = susfs_parse_priority_app_names(app_strings, new_bitmap->bits, true);
	if (ret)
		goto out_restore;

	susfs_priority_publish(new_bitmap, NULL);
	new_bitmap = NULL;
	pr_info("susfs: priority uid filter refreshed\n");

out_restore:
	susfs_priority_restore_creds(old_cred);
out:
	kfree(new_bitmap);
	kvfree(app_strings);
	atomic_set(&susfs_priority_worker_running, 0);
	return ret;
}

void susfs_parse_priority_app_strings(void)
{
	if (atomic_cmpxchg(&susfs_priority_worker_running, 0, 1))
		return;

	if (IS_ERR(kthread_run(susfs_priority_app_strings_worker, NULL,
			       "susfs_prio_appstr"))) {
		atomic_set(&susfs_priority_worker_running, 0);
		pr_err("susfs: failed to start the priority filter refresh thread\n");
	}
}

/*
 * Lockless lookup for the getpriority/setpriority/ioprio syscall paths.
 * The caller holds rcu_read_lock().
 */
bool susfs_is_priority_uid_filtered(uid_t uid)
{
	struct susfs_priority_uid_filter_bitmap *bitmap;
	uid_t app_id = uid % 100000;

	if (app_id < SUSFS_PRIORITY_UID_FILTER_MIN_UID ||
	    app_id > SUSFS_PRIORITY_UID_FILTER_MAX_UID)
		return false;

	bitmap = rcu_dereference(susfs_priority_bitmap);
	if (likely(bitmap) &&
	    test_bit(app_id - SUSFS_PRIORITY_UID_FILTER_MIN_UID, bitmap->bits))
		return true;

	return false;
}

int susfs_show_variant(void __user *user_info)
{
	struct st_susfs_variant info;

	memset(&info, 0, sizeof(info));
	strlcpy(info.susfs_variant, SUSFS_VARIANT, sizeof(info.susfs_variant));
	if (copy_to_user(user_info, &info, sizeof(info)))
		return -EFAULT;
	return 0;
}

int susfs_show_version(void __user *user_info)
{
	struct st_susfs_version info;

	memset(&info, 0, sizeof(info));
	strlcpy(info.susfs_version, SUSFS_VERSION, sizeof(info.susfs_version));
	if (copy_to_user(user_info, &info, sizeof(info)))
		return -EFAULT;
	return 0;
}

static void susfs_extra_work_fn(struct work_struct *work)
{
	(void)work;
}

struct work_struct susfs_extra_works =
	__WORK_INITIALIZER(susfs_extra_works, susfs_extra_work_fn);

void susfs_start_sdcard_monitor_fn(void)
{
	/*
	 * 4.14 has no sdcard monitor.  Module mounts are refreshed by the
	 * manager's own post-fs-data flow, so there is nothing to start.
	 */
}
