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
#ifdef CONFIG_KSU_SUSFS_OPEN_REDIRECT
	strlcat(info.enabled_features, "open_redirect,", sizeof(info.enabled_features));
#endif
	/* Implemented by the 4.14 port (KernelSU feature id 10003 + SUSFS cmd). */
	strlcat(info.enabled_features, "avc_log_spoofing,", sizeof(info.enabled_features));
	if (copy_to_user(user_info, &info, sizeof(info)))
		return -EFAULT;
	return 0;
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
