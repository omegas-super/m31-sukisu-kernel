#!/usr/bin/env python3
"""4.14 SELinux features for the SukiSU `builtin` tree.

The SukiSU manager (v4.2.1-r2) exposes two kernel features that upstream only
implements for >= 5.10 (SELinux hide) or via kprobes (AVC spoof):

  * KSU_FEATURE_SELINUX_HIDE = 4   -- "hide SELinux modifications"
  * KSU_FEATURE_AVC_SPOOF   = 10003 -- "AVC log spoofing"

This script ports both to Linux 4.14 without kprobes by patching the kernel
tree at build time and adding the two feature handlers to the KernelSU tree.

Kernel tree (CONFIG_KSU builds only; stock builds never run this script):
  * new  security/selinux/ksu_selinux_hide.c   -- implementation
  * new  include/linux/ksu_selinux_hide.h      -- declarations
  * edit security/selinux/Makefile             -- selinux-$(CONFIG_KSU) += ...
  * edit security/selinux/avc.c                -- slow_avc_audit() AVC spoof hook
  * edit security/selinux/selinuxfs.c          -- transaction-write + policy-view hooks
  * edit security/selinux/ss/services.c        -- capture the original policy blob
  * edit fs/proc/base.c                        -- block dirty attr/current writes

KernelSU tree:
  * new  feature/selinux_hide_414.c            -- handler id 4
  * new  feature/avc_spoof.c                   -- handler id 10003
  * edit uapi/feature.h                        -- unguard id 4, add id 10003
  * edit policy/feature.c                      -- feature name entries
  * edit ksu_main.c                            -- includes + init calls

Every edit is anchored and idempotent; any anchor drift aborts before writing.

usage: fix_selinux_features.py <kernel-root> <drivers/kernelsu>
"""
import sys
from pathlib import Path

MARK = "KernelSU 4.14"

KERNEL_HEADER = """/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * KernelSU 4.14 SELinux support: SELinux-hide + AVC-log spoofing.
 * Toggled from the KernelSU feature framework; see
 * security/selinux/ksu_selinux_hide.c.
 */
#ifndef _LINUX_KSU_SELINUX_HIDE_H
#define _LINUX_KSU_SELINUX_HIDE_H

#include <linux/compiler_types.h>
#include <linux/types.h>

struct file;

bool ksu_selinux_hide_is_enabled(void);
void ksu_selinux_hide_set_enabled(bool enabled);
bool ksu_selinux_hide_block_context(const char *ctx);

int ksu_selinux_hide_transaction_pre(struct file *file, unsigned long ino,
				     const char __user *buf, size_t size,
				     loff_t *pos);
void ksu_selinux_hide_transaction_post(struct file *file, unsigned long ino,
				       const char *req, size_t size);
bool ksu_selinux_hide_policy_view(void **data, size_t *len);
void ksu_selinux_hide_capture_policy(const void *data, size_t len);
int ksu_selinux_hide_block_attr(const char __user *buf, size_t count);

bool ksu_avc_spoof_is_enabled(void);
void ksu_avc_spoof_set(bool enabled);
void ksu_slow_avc_audit(u32 *tsid);

#endif /* _LINUX_KSU_SELINUX_HIDE_H */
"""

KERNEL_SOURCE = r"""// SPDX-License-Identifier: GPL-2.0-only
/*
 * KernelSU 4.14 SELinux support.
 *
 * SELinux hide: apps (uid >= 10000) must not be able to tell that the running
 * policy differs from the stock one.  The original policy blob is captured on
 * the first security_load_policy() (before ksud loads its patched policy) and
 * served to app UIDs on /sys/fs/selinux/policy; app-UID context validation and
 * /proc/self/attr/current writes for root-related labels are refused, exactly
 * as they would be on a stock policy without those labels.
 *
 * AVC log spoofing: AVC audit records for the su/ksu domains are rendered with
 * the priv_app SID so denial logs do not leak the root context.  The decision
 * itself is untouched.
 *
 * Build-time hooks only: no kprobes, no runtime text patching.
 */
#include <linux/cred.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/mutex.h>
#include <linux/printk.h>
#include <linux/ratelimit.h>
#include <linux/security.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>

#include <linux/ksu_selinux_hide.h>

#define KSU_HIDE_APP_UID_MIN	10000U
#define KSU_SEL_CONTEXT_INO	5	/* enum sel_inos: SEL_CONTEXT */
#define KSU_SEL_ACCESS_INO	6	/* enum sel_inos: SEL_ACCESS */
#define KSU_SEL_VALIDATE_TRANS_INO 21	/* enum sel_inos: SEL_VALIDATE_TRANS */
#define KSU_POLICY_MAX_LEN	(16U << 20)

static bool ksu_selinux_hide_on __read_mostly;
static bool ksu_avc_spoof_on __read_mostly;

static DEFINE_MUTEX(ksu_policy_view_mutex);
static void *ksu_policy_blob __read_mostly;
static size_t ksu_policy_blob_len __read_mostly;

static u32 ksu_avc_su_sid;
static u32 ksu_avc_ksu_sid;
static u32 ksu_avc_priv_app_sid;

/*
 * Labels that only exist (or only mean "root") because the policy was
 * modified.  A stock policy rejects these contexts with EINVAL.
 */
static const char *const ksu_dirty_markers[] = {
	":su:", ":ksu:", ":sukisu:", ":adbroot:", ":magisk:", ":droidspacesd:",
};

static bool ksu_is_app_uid(void)
{
	return current_uid().val >= KSU_HIDE_APP_UID_MIN;
}

static bool ksu_context_is_dirty(const char *ctx)
{
	size_t i;

	if (!ctx)
		return false;

	for (i = 0; i < ARRAY_SIZE(ksu_dirty_markers); i++) {
		if (strstr(ctx, ksu_dirty_markers[i]))
			return true;
	}

	return false;
}

bool ksu_selinux_hide_is_enabled(void)
{
	return ksu_selinux_hide_on;
}

void ksu_selinux_hide_set_enabled(bool enabled)
{
	ksu_selinux_hide_on = enabled;
	pr_info("ksu_selinux_hide: %s\n", enabled ? "enabled" : "disabled");
}

bool ksu_selinux_hide_block_context(const char *ctx)
{
	return ksu_selinux_hide_on && ksu_is_app_uid() && ksu_context_is_dirty(ctx);
}

/* ------------------------------------------------------------------------- */
/* AVC log spoofing                                                          */
/* ------------------------------------------------------------------------- */

bool ksu_avc_spoof_is_enabled(void)
{
	return ksu_avc_spoof_on;
}

static void ksu_avc_resolve_sids(void)
{
	if (ksu_avc_priv_app_sid)
		return;

	security_secctx_to_secid("u:r:su:s0", strlen("u:r:su:s0"),
				 &ksu_avc_su_sid);
	security_secctx_to_secid("u:r:ksu:s0", strlen("u:r:ksu:s0"),
				 &ksu_avc_ksu_sid);
	security_secctx_to_secid("u:r:priv_app:s0:c512,c768",
				 strlen("u:r:priv_app:s0:c512,c768"),
				 &ksu_avc_priv_app_sid);
}

void ksu_avc_spoof_set(bool enabled)
{
	if (enabled) {
		ksu_avc_resolve_sids();
		if (!ksu_avc_priv_app_sid) {
			pr_warn("ksu_avc_spoof: could not resolve SIDs\n");
			return;
		}
	}

	ksu_avc_spoof_on = enabled;
	pr_info("ksu_avc_spoof: %s\n", enabled ? "enabled" : "disabled");
}

void ksu_slow_avc_audit(u32 *tsid)
{
	if (!ksu_avc_spoof_on || !ksu_avc_priv_app_sid || !tsid)
		return;

	if (*tsid == ksu_avc_su_sid || *tsid == ksu_avc_ksu_sid)
		*tsid = ksu_avc_priv_app_sid;
}

/* ------------------------------------------------------------------------- */
/* SELinux hide: original policy capture / view                              */
/* ------------------------------------------------------------------------- */

void ksu_selinux_hide_capture_policy(const void *data, size_t len)
{
	void *copy;

	if (ksu_policy_blob || !data || !len || len > KSU_POLICY_MAX_LEN)
		return;

	copy = vmalloc_user(len);
	if (!copy)
		return;

	memcpy(copy, data, len);

	mutex_lock(&ksu_policy_view_mutex);
	if (!ksu_policy_blob) {
		ksu_policy_blob = copy;
		ksu_policy_blob_len = len;
		copy = NULL;
	}
	mutex_unlock(&ksu_policy_view_mutex);

	if (copy) {
		vfree(copy);
		return;
	}

	pr_info("ksu_selinux_hide: captured original policy (%zu bytes)\n", len);
}

bool ksu_selinux_hide_policy_view(void **data, size_t *len)
{
	void *copy;
	size_t copy_len;

	if (!ksu_selinux_hide_on || !ksu_is_app_uid() || !data || !len)
		return false;

	mutex_lock(&ksu_policy_view_mutex);
	if (!ksu_policy_blob) {
		mutex_unlock(&ksu_policy_view_mutex);
		return false;
	}
	copy_len = ksu_policy_blob_len;
	copy = vmalloc_user(copy_len);
	if (copy)
		memcpy(copy, ksu_policy_blob, copy_len);
	mutex_unlock(&ksu_policy_view_mutex);

	if (!copy)
		return false;

	*data = copy;
	*len = copy_len;
	return true;
}

/* ------------------------------------------------------------------------- */
/* SELinux hide: selinuxfs transaction writes                                */
/* ------------------------------------------------------------------------- */

int ksu_selinux_hide_transaction_pre(struct file *file, unsigned long ino,
				     const char __user *buf, size_t size,
				     loff_t *pos)
{
	char kbuf[256];
	size_t len;

	if (!ksu_selinux_hide_on || !ksu_is_app_uid())
		return 0;

	if (ino != KSU_SEL_CONTEXT_INO && ino != KSU_SEL_VALIDATE_TRANS_INO)
		return 0;

	len = size < sizeof(kbuf) - 1 ? size : sizeof(kbuf) - 1;
	if (copy_from_user(kbuf, buf, len))
		return 0;
	kbuf[len] = '\0';

	if (ksu_context_is_dirty(kbuf)) {
		pr_info_ratelimited("ksu_selinux_hide: blocked context query: %.48s\n",
				    kbuf);
		return -EINVAL;
	}

	return 0;
}

void ksu_selinux_hide_transaction_post(struct file *file, unsigned long ino,
				       const char *req, size_t size)
{
	struct simple_transaction_argresp *ar;
	char reqbuf[256];
	char *scon, *tcon, *sp;
	int n;

	if (!ksu_selinux_hide_on || !ksu_is_app_uid())
		return;
	if (ino != KSU_SEL_ACCESS_INO || !file || !req)
		return;

	/* request format: "<scon> <tcon> <tclass>" */
	if (size >= sizeof(reqbuf))
		size = sizeof(reqbuf) - 1;
	memcpy(reqbuf, req, size);
	reqbuf[size] = '\0';

	scon = reqbuf;
	sp = strchr(scon, ' ');
	if (!sp)
		return;
	*sp++ = '\0';
	tcon = sp;
	sp = strchr(tcon, ' ');
	if (sp)
		*sp = '\0';

	if (!ksu_context_is_dirty(scon) && !ksu_context_is_dirty(tcon))
		return;

	ar = file->private_data;
	if (!ar)
		return;

	/* answer as a stock policy would: no permissions, deny audit */
	n = scnprintf(ar->data, SIMPLE_TRANSACTION_LIMIT,
		      "%x %x %x %x %u %x", 0, 0xffffffff, 0, 0xffffffff, 1, 0);
	if (n > 0) {
		ar->data[n] = '\0';
		ar->size = n;
	}

	pr_info_ratelimited("ksu_selinux_hide: denied access query: %.32s -> %.32s\n",
			    scon, tcon);
}

/* ------------------------------------------------------------------------- */
/* SELinux hide: /proc/<pid>/attr/current writes                             */
/* ------------------------------------------------------------------------- */

int ksu_selinux_hide_block_attr(const char __user *buf, size_t count)
{
	char kbuf[256];
	size_t len;

	if (!ksu_selinux_hide_on || !ksu_is_app_uid())
		return 0;

	len = count < sizeof(kbuf) - 1 ? count : sizeof(kbuf) - 1;
	if (copy_from_user(kbuf, buf, len))
		return 0;
	kbuf[len] = '\0';

	if (ksu_context_is_dirty(kbuf)) {
		pr_info_ratelimited("ksu_selinux_hide: blocked attr write: %.48s\n",
				    kbuf);
		return -EINVAL;
	}

	return 0;
}
"""

KSU_HIDE_414 = r"""// SPDX-License-Identifier: GPL-2.0-only
/*
 * KernelSU 4.14 SELinux-hide feature handler (KSU_FEATURE_SELINUX_HIDE = 4).
 * The actual work is done by security/selinux/ksu_selinux_hide.c.
 */
#include <linux/ksu_selinux_hide.h>
#include <linux/types.h>

#include "feature/selinux_hide.h"
#include "policy/feature.h"
#include "uapi/feature.h"

static int selinux_hide_414_get(u64 *value)
{
	*value = ksu_selinux_hide_is_enabled() ? 1 : 0;
	return 0;
}

static int selinux_hide_414_set(u64 value)
{
	ksu_selinux_hide_set_enabled(value != 0);
	return 0;
}

static const struct ksu_feature_handler selinux_hide_414_handler = {
	.feature_id = KSU_FEATURE_SELINUX_HIDE,
	.name = "selinux_hide",
	.get_handler = selinux_hide_414_get,
	.set_handler = selinux_hide_414_set,
};

/* The upstream >= 5.10 implementation backs up sepolicy in these hooks; the
 * 4.14 port captures the original policy at first load instead. */
void ksu_selinux_hide_handle_second_stage(void) { }
void ksu_selinux_hide_handle_post_fs_data(void) { }
void ksu_selinux_hide_drop_backup_if_unused(void) { }

void __init ksu_selinux_hide_init(void)
{
	if (ksu_register_feature_handler(&selinux_hide_414_handler))
		pr_err("selinux_hide_414: feature registration failed\n");
}

void __exit ksu_selinux_hide_exit(void)
{
	ksu_unregister_feature_handler(KSU_FEATURE_SELINUX_HIDE);
}
"""

KSU_AVC_SPOOF = r"""// SPDX-License-Identifier: GPL-2.0-only
/*
 * KernelSU 4.14 AVC-log-spoofing feature handler (KSU_FEATURE_AVC_SPOOF =
 * 10003).  The actual work is done by security/selinux/ksu_selinux_hide.c.
 */
#include <linux/ksu_selinux_hide.h>
#include <linux/types.h>

#include "policy/feature.h"
#include "uapi/feature.h"

static int avc_spoof_get(u64 *value)
{
	*value = ksu_avc_spoof_is_enabled() ? 1 : 0;
	return 0;
}

static int avc_spoof_set(u64 value)
{
	ksu_avc_spoof_set(value != 0);
	return 0;
}

static const struct ksu_feature_handler avc_spoof_handler = {
	.feature_id = KSU_FEATURE_AVC_SPOOF,
	.name = "avc_spoof",
	.get_handler = avc_spoof_get,
	.set_handler = avc_spoof_set,
};

void __init ksu_avc_spoof_init(void)
{
	if (ksu_register_feature_handler(&avc_spoof_handler))
		pr_err("avc_spoof: feature registration failed\n");
}

void __exit ksu_avc_spoof_exit(void)
{
	ksu_unregister_feature_handler(KSU_FEATURE_AVC_SPOOF);
}
"""


def die(msg):
    raise SystemExit("fix_selinux_features: ABORT: " + msg)


def read_text(path):
    if not path.is_file():
        die("missing file: {}".format(path))
    # universal newlines: a Windows checkout (CRLF) must patch exactly like the
    # Linux CI checkout (LF).  The files are written back with LF.
    with open(path, "r", encoding="utf-8", newline=None) as fh:
        return fh.read()


def write_text(path, text):
    with open(path, "w", encoding="utf-8", newline="") as fh:
        fh.write(text)


def write_new(path, text, marker):
    """Create a generated file; idempotent if it already has our marker."""
    if path.exists():
        current = read_text(path)
        if marker in current:
            print("  [skipped] {} (already present)".format(path))
            return
        die("{} exists but is not the generated file".format(path))
    path.parent.mkdir(parents=True, exist_ok=True)
    write_text(path, text)
    print("  [created] {}".format(path))


def patch(path, old, new, label, marker=None):
    text = read_text(path)
    if marker:
        if marker in text:
            print("  [skipped] {}: {}".format(path.name, label))
            return
    elif new in text and old not in text:
        print("  [skipped] {}: {}".format(path.name, label))
        return
    count = text.count(old)
    if count != 1:
        die("{}: '{}' anchor found {} time(s), expected 1".format(path, label, count))
    write_text(path, text.replace(old, new, 1))
    print("  [patched] {}: {}".format(path.name, label))


def patch_kernel(kernel):
    print("fix_selinux_features: kernel tree = {}".format(kernel))

    header = kernel / "include" / "linux" / "ksu_selinux_hide.h"
    source = kernel / "security" / "selinux" / "ksu_selinux_hide.c"
    write_new(header, KERNEL_HEADER, MARK)
    write_new(source, KERNEL_SOURCE, MARK)

    makefile = kernel / "security" / "selinux" / "Makefile"
    text = read_text(makefile)
    line = "selinux-$(CONFIG_KSU) += ksu_selinux_hide.o\n"
    if line not in text:
        anchor = "selinux-$(CONFIG_NETLABEL) += netlabel.o\n"
        if anchor not in text:
            die("{}: netlabel anchor missing".format(makefile))
        text = text.replace(anchor, anchor + "\n" + line, 1)
        write_text(makefile, text)
        print("  [patched] Makefile: ksu_selinux_hide.o")
    else:
        print("  [skipped] Makefile: ksu_selinux_hide.o")

    avc = kernel / "security" / "selinux" / "avc.c"
    patch(
        avc,
        '#include "classmap.h"\n',
        '#include "classmap.h"\n\n#include <linux/ksu_selinux_hide.h>\n',
        "ksu_selinux_hide include",
        marker="#include <linux/ksu_selinux_hide.h>",
    )
    patch(
        avc,
        "\tstruct common_audit_data stack_data;\n"
        "\tstruct selinux_audit_data sad;\n",
        "\tstruct common_audit_data stack_data;\n"
        "\tstruct selinux_audit_data sad;\n"
        "\n"
        "\tksu_slow_avc_audit(&tsid);\n",
        "slow_avc_audit AVC-spoof hook",
        marker="ksu_slow_avc_audit(&tsid);",
    )

    selinuxfs = kernel / "security" / "selinux" / "selinuxfs.c"
    patch(
        selinuxfs,
        '#include "objsec.h"\n',
        '#include "objsec.h"\n\n#include <linux/ksu_selinux_hide.h>\n',
        "ksu_selinux_hide include",
        marker="#include <linux/ksu_selinux_hide.h>",
    )
    patch(
        selinuxfs,
        "\tino_t ino = file_inode(file)->i_ino;\n"
        "\tchar *data;\n"
        "\tssize_t rv;\n"
        "\n"
        "\tif (ino >= ARRAY_SIZE(write_op) || !write_op[ino])\n",
        "\tino_t ino = file_inode(file)->i_ino;\n"
        "\tchar *data;\n"
        "\tssize_t rv;\n"
        "\n"
        "\trv = ksu_selinux_hide_transaction_pre(file, ino, buf, size, pos);\n"
        "\tif (rv)\n"
        "\t\treturn rv;\n"
        "\n"
        "\tif (ino >= ARRAY_SIZE(write_op) || !write_op[ino])\n",
        "selinux_transaction_write pre-hook",
        marker="ksu_selinux_hide_transaction_pre(file, ino, buf, size, pos);",
    )
    patch(
        selinuxfs,
        "\trv = write_op[ino](file, data, size);\n"
        "\tif (rv > 0) {\n"
        "\t\tsimple_transaction_set(file, rv);\n"
        "\t\trv = size;\n"
        "\t}\n",
        "#ifdef CONFIG_KSU\n"
        "\t{\n"
        "\t\tchar ksu_req[256];\n"
        "\t\tsize_t ksu_req_len = size < sizeof(ksu_req) - 1 ?\n"
        "\t\t\t\t\t size : sizeof(ksu_req) - 1;\n"
        "\n"
        "\t\tmemcpy(ksu_req, data, ksu_req_len);\n"
        "\t\tksu_req[ksu_req_len] = '\\0';\n"
        "\t\trv = write_op[ino](file, data, size);\n"
        "\t\tif (rv > 0) {\n"
        "\t\t\tsimple_transaction_set(file, rv);\n"
        "\t\t\tksu_selinux_hide_transaction_post(file, ino, ksu_req,\n"
        "\t\t\t\t\t\t\t  ksu_req_len);\n"
        "\t\t\trv = size;\n"
        "\t\t}\n"
        "\t}\n"
        "#else\n"
        "\trv = write_op[ino](file, data, size);\n"
        "\tif (rv > 0) {\n"
        "\t\tsimple_transaction_set(file, rv);\n"
        "\t\trv = size;\n"
        "\t}\n"
        "#endif\n",
        "selinux_transaction_write post-hook",
        marker="ksu_selinux_hide_transaction_post(file, ino, ksu_req,",
    )
    patch(
        selinuxfs,
        "\trc = security_read_policy(state, &plm->data, &plm->len);\n"
        "\tif (rc)\n"
        "\t\tgoto err;\n"
        "\n"
        "\tfsi->policy_opened = 1;\n",
        "\trc = security_read_policy(state, &plm->data, &plm->len);\n"
        "\tif (rc)\n"
        "\t\tgoto err;\n"
        "\n"
        "\t{\n"
        "\t\tvoid *ksu_view = NULL;\n"
        "\t\tsize_t ksu_view_len = 0;\n"
        "\n"
        "\t\tif (ksu_selinux_hide_policy_view(&ksu_view, &ksu_view_len)) {\n"
        "\t\t\tvfree(plm->data);\n"
        "\t\t\tplm->data = ksu_view;\n"
        "\t\t\tplm->len = ksu_view_len;\n"
        "\t\t}\n"
        "\t}\n"
        "\n"
        "\tfsi->policy_opened = 1;\n",
        "sel_open_policy clean-policy view",
        marker="ksu_selinux_hide_policy_view(&ksu_view, &ksu_view_len)",
    )

    services = kernel / "security" / "selinux" / "ss" / "services.c"
    patch(
        services,
        '#include "services.h"\n',
        '#include "services.h"\n\n#include <linux/ksu_selinux_hide.h>\n',
        "ksu_selinux_hide include",
        marker="#include <linux/ksu_selinux_hide.h>",
    )
    patch(
        services,
        "\tstruct policy_file file = { data, len }, *fp = &file;\n"
        "\n"
        "\toldpolicydb = kzalloc(2 * sizeof(*oldpolicydb), GFP_KERNEL);\n",
        "\tstruct policy_file file = { data, len }, *fp = &file;\n"
        "\n"
        "\tif (!selinux_initialized(state))\n"
        "\t\tksu_selinux_hide_capture_policy(data, len);\n"
        "\n"
        "\toldpolicydb = kzalloc(2 * sizeof(*oldpolicydb), GFP_KERNEL);\n",
        "capture original policy on first load",
        marker="ksu_selinux_hide_capture_policy(data, len);",
    )

    base = kernel / "fs" / "proc" / "base.c"
    patch(
        base,
        "#include <linux/seq_file.h>\n",
        "#include <linux/seq_file.h>\n\n#include <linux/ksu_selinux_hide.h>\n",
        "ksu_selinux_hide include",
        marker="#include <linux/ksu_selinux_hide.h>",
    )
    patch(
        base,
        "{\n"
        "\tstruct inode * inode = file_inode(file);\n"
        "\tstruct task_struct *task;\n"
        "\tvoid *page;\n"
        "\tint rv;\n"
        "\n"
        "\t/* A task may only write when it was the opener. */\n",
        "{\n"
        "\tstruct inode * inode = file_inode(file);\n"
        "\tstruct task_struct *task;\n"
        "\tvoid *page;\n"
        "\tint rv;\n"
        "\n"
        "\trv = ksu_selinux_hide_block_attr(buf, count);\n"
        "\tif (rv)\n"
        "\t\treturn rv;\n"
        "\n"
        "\t/* A task may only write when it was the opener. */\n",
        "block dirty attr/current writes",
        marker="ksu_selinux_hide_block_attr(buf, count);",
    )


def patch_ksu(ksu):
    print("fix_selinux_features: KernelSU tree = {}".format(ksu))

    write_new(ksu / "feature" / "selinux_hide_414.c", KSU_HIDE_414, MARK)
    write_new(ksu / "feature" / "avc_spoof.c", KSU_AVC_SPOOF, MARK)

    uapi = ksu / "include" / "uapi" / "feature.h"
    patch(
        uapi,
        "#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)\n"
        "    KSU_FEATURE_SELINUX_HIDE = 4,\n"
        "#endif\n",
        "    KSU_FEATURE_SELINUX_HIDE = 4,\n",
        "unguard KSU_FEATURE_SELINUX_HIDE",
    )
    patch(
        uapi,
        "    KSU_FEATURE_MOUNT_HIDE = 16,\n\n    KSU_FEATURE_MAX\n",
        "    KSU_FEATURE_MOUNT_HIDE = 16,\n\n"
        "    KSU_FEATURE_AVC_SPOOF = 10003,\n\n"
        "    KSU_FEATURE_MAX\n",
        "add KSU_FEATURE_AVC_SPOOF",
    )

    feature_c = ksu / "policy" / "feature.c"
    patch(
        feature_c,
        "#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)\n"
        '    [KSU_FEATURE_SELINUX_HIDE] = "selinux_hide",\n'
        "#endif\n",
        '    [KSU_FEATURE_SELINUX_HIDE] = "selinux_hide",\n',
        "unguard selinux_hide feature name",
    )
    patch(
        feature_c,
        '    [KSU_FEATURE_MOUNT_HIDE] = "mount_hide",\n',
        '    [KSU_FEATURE_MOUNT_HIDE] = "mount_hide",\n'
        '    [KSU_FEATURE_AVC_SPOOF] = "avc_spoof",\n',
        "add avc_spoof feature name",
        marker='[KSU_FEATURE_AVC_SPOOF] = "avc_spoof",',
    )

    main_c = ksu / "ksu_main.c"
    patch(
        main_c,
        "#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)\n"
        '#include "feature/selinux_hide.h"\n'
        "#endif\n",
        '#include "feature/selinux_hide.h"\n',
        "include selinux_hide.h for 4.14",
    )
    patch(
        main_c,
        "#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)\n"
        '#include "feature/selinux_hide.c"\n'
        "#endif\n",
        "#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)\n"
        '#include "feature/selinux_hide.c"\n'
        "#else\n"
        '#include "feature/selinux_hide_414.c"\n'
        "#endif\n"
        '#include "feature/avc_spoof.c"\n',
        "include 4.14 selinux_hide + avc_spoof",
        marker='#include "feature/avc_spoof.c"',
    )
    patch(
        main_c,
        "#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)\n"
        "    ksu_selinux_hide_init();\n"
        "#endif\n",
        "    ksu_selinux_hide_init();\n"
        "    ksu_avc_spoof_init();\n",
        "init 4.14 selinux_hide + avc_spoof",
    )


def main(argv):
    if len(argv) != 3:
        raise SystemExit(
            "usage: fix_selinux_features.py <kernel-root> <drivers/kernelsu>"
        )

    kernel = Path(argv[1]).resolve()
    ksu = Path(argv[2]).resolve()

    if not (kernel / "security" / "selinux").is_dir():
        die("{} does not look like a kernel tree".format(kernel))
    if not (ksu / "policy" / "feature.c").is_file():
        die("{} does not look like drivers/kernelsu".format(ksu))

    patch_kernel(kernel)
    patch_ksu(ksu)
    print("fix_selinux_features: OK (SELinux hide id 4 + AVC spoof id 10003 for 4.14)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
