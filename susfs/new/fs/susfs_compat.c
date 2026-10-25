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
#include <linux/susfs.h>
#include <linux/susfs_def.h>

#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
/*
 * fs/susfs.c (4.14) still calls the legacy KernelSU umount helper.
 * SukiSU drives the real unmount through ksu_handle_umount(), so keep
 * this path inert instead of duplicating the work.
 */
void ksu_try_umount(const char *mnt, bool check_mnt, int flags, uid_t uid)
{
	(void)mnt;
	(void)check_mnt;
	(void)flags;
	(void)uid;
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

void susfs_set_current_proc_no_su(void)
{
	current->susfs_task_state |= TASK_STRUCT_NO_SU;
}

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
	/* AVC log spoofing is a 5.10+ SELinux feature. */
	(void)user_info;
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
