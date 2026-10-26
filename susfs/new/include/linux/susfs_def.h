#ifndef KSU_SUSFS_DEF_H
#define KSU_SUSFS_DEF_H

#include <linux/bits.h>
#include <linux/bitops.h>

/********/
/* ENUM */
/********/
/* shared with userspace ksu_susfs tool */
#define CMD_SUSFS_ADD_SUS_PATH 0x55550
/* SukiSU-Ultra ksud ABI (userspace/ksud/src/susfs/abi/consts.rs). */
#define SUSFS_MAGIC 0xFAFAFAFA
#define CMD_SUSFS_ADD_SUS_PATH_LOOP 0x55553
#define CMD_SUSFS_HIDE_SUS_MNTS_FOR_NON_SU_PROCS 0x55561
#define CMD_SUSFS_HIDE_SUS_MOUNTS_FOR_NON_SU_PROCS 0x55561
#define CMD_SUSFS_ENABLE_AVC_LOG_SPOOFING 0x60010
#define CMD_SUSFS_ADD_SUS_MAP 0x60020
#define CMD_SUSFS_SET_PRIORITY_UID_FILTER 0x60030
#define CMD_SUSFS_ADD_SUS_MOUNT 0x55560
#define CMD_SUSFS_ADD_SUS_KSTAT 0x55570
#define CMD_SUSFS_UPDATE_SUS_KSTAT 0x55571
#define CMD_SUSFS_ADD_SUS_KSTAT_STATICALLY 0x55572
#define CMD_SUSFS_ADD_TRY_UMOUNT 0x55580
#define CMD_SUSFS_SET_UNAME 0x55590
#define CMD_SUSFS_ENABLE_LOG 0x555a0
#define CMD_SUSFS_SET_CMDLINE_OR_BOOTCONFIG 0x555b0
#define CMD_SUSFS_ADD_OPEN_REDIRECT 0x555c0
#define CMD_SUSFS_RUN_UMOUNT_FOR_CURRENT_MNT_NS 0x555d0
#define CMD_SUSFS_SHOW_VERSION 0x555e1
#define CMD_SUSFS_SHOW_ENABLED_FEATURES 0x555e2
#define CMD_SUSFS_SHOW_VARIANT 0x555e3
#define CMD_SUSFS_SHOW_SUS_SU_WORKING_MODE 0x555e4
#define CMD_SUSFS_IS_SUS_SU_READY 0x555f0
#define CMD_SUSFS_SUS_SU 0x60000

#define SUSFS_MAX_LEN_PATHNAME 256 // 256 should address many paths already unless you are doing some strange experimental stuff, then set your own desired length
#define SUSFS_FAKE_CMDLINE_OR_BOOTCONFIG_SIZE 8192

/*
 * SukiSU `builtin` compat: SUSFS 2.x priority-UID filter.
 * The filter hides the process priority/ioprio of the listed app UIDs from
 * app-UID callers (getpriority/setpriority/ioprio_set/ioprio_get).
 */
#define SUSFS_PRIORITY_UID_FILTER_MIN_UID 10000
#define SUSFS_PRIORITY_UID_FILTER_MAX_UID 19999
#define SUSFS_PRIORITY_UID_FILTER_UID_NUM \
	(SUSFS_PRIORITY_UID_FILTER_MAX_UID - SUSFS_PRIORITY_UID_FILTER_MIN_UID + 1)
#define SUSFS_PRIORITY_UID_FILTER_BITMAP_LEN \
	BITS_TO_LONGS(SUSFS_PRIORITY_UID_FILTER_UID_NUM)
#define SUSFS_PRIORITY_UID_FILTER_APP_STR_SIZE 65535

#define TRY_UMOUNT_DEFAULT 0 /* used by susfs_try_umount() */
#define TRY_UMOUNT_DETACH 1 /* used by susfs_try_umount() */

#define SUS_SU_DISABLED 0
#define SUS_SU_WITH_OVERLAY 1 /* deprecated */
#define SUS_SU_WITH_HOOKS 2

#define DEFAULT_SUS_MNT_ID 100000 /* used by mount->mnt_id */
#define DEFAULT_SUS_MNT_ID_FOR_KSU_PROC_UNSHARE 1000000 /* used by vfsmount->susfs_mnt_id_backup */
#define DEFAULT_SUS_MNT_GROUP_ID 1000 /* used by mount->mnt_group_id */

/*
 * inode->i_state => storing flag 'INODE_STATE_'
 * mount->mnt.susfs_mnt_id_backup => storing original mnt_id of normal mounts or custom sus mnt_id of sus mounts
 * task_struct->susfs_last_fake_mnt_id => storing last valid fake mnt_id
 * task_struct->susfs_task_state => storing flag 'TASK_STRUCT_'
 */

#define INODE_STATE_SUS_PATH BIT(24)
#define INODE_STATE_SUS_MOUNT BIT(25)
#define INODE_STATE_SUS_KSTAT BIT(26)
#define INODE_STATE_OPEN_REDIRECT BIT(27)

#define TASK_STRUCT_NON_ROOT_USER_APP_PROC BIT(24)

#define MAGIC_MOUNT_WORKDIR "/debug_ramdisk/workdir"
#define DATA_ADB_UMOUNT_FOR_ZYGOTE_SYSTEM_PROCESS "/data/adb/susfs_umount_for_zygote_system_process"
#define DATA_ADB_NO_AUTO_ADD_SUS_BIND_MOUNT "/data/adb/susfs_no_auto_add_sus_bind_mount"
#define DATA_ADB_NO_AUTO_ADD_SUS_KSU_DEFAULT_MOUNT "/data/adb/susfs_no_auto_add_sus_ksu_default_mount"
#define DATA_ADB_NO_AUTO_ADD_TRY_UMOUNT_FOR_BIND_MOUNT "/data/adb/susfs_no_auto_add_try_umount_for_bind_mount"

/*
 * SukiSU builtin compat: newer SUSFS task-state flags (same task field).
 * None of these bits is read by the 4.14 code.  The 4.14 hiding gates test
 * TASK_STRUCT_NON_ROOT_USER_APP_PROC (BIT(24), above) instead, so do not
 * write TASK_STRUCT_NO_SU for the "non-root user app" state.
 */
#define TASK_STRUCT_UMOUNTED BIT(25)			/* unread on 4.14 */
#define TASK_STRUCT_UMOUNTED_FOR_ZYGOTE_NEXT BIT(26)	/* unread on 4.14 */
#define TASK_STRUCT_NO_SU BIT(27)			/* unread on 4.14 */
#endif // #ifndef KSU_SUSFS_DEF_H
