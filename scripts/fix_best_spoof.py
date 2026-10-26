#!/usr/bin/env python3
"""M31 "best spoof" kernel hooks for the 4.14 SukiSU/SUSFS kernel.

Two independent features are installed at build time:

1. Bootloader-locked / verified-boot spoofing (always, CONFIG_KSU builds):
   Android init reads /proc/cmdline very early and derives ro.boot.* from it.
   `fs/ksu_boot_spoof.c` rewrites the bootloader-state tokens
   (androidboot.verifiedbootstate, androidboot.flash.locked,
   androidboot.vbmeta.device_state, androidboot.warranty_bit) to the
   locked/green values before init runs, so ro.boot.* reports a locked
   bootloader; it also rewrites the device-tree /chosen/bootargs property.
   The real AVB decision is untouched.  Disable with the `ksu_nobootspoof`
   kernel cmdline token.

2. SUSFS priority-UID filter (SUSFS mode only, CONFIG_KSU_SUSFS):
   backport of the SUSFS 2.x getpriority/ioprio filter that the current
   SukiSU `builtin` branch expects (CMD_SUSFS_SET_PRIORITY_UID_FILTER).  The
   filter itself lives in fs/susfs_compat.c; this script adds the syscall
   hooks in kernel/sys.c and block/ioprio.c.

usage: fix_best_spoof.py <kernel-root> <stock|ksu|susfs>
"""
import sys
from pathlib import Path

MARK = "KernelSU 4.14 boot spoof"

BOOT_SPOOF_H = """/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * KernelSU 4.14: bootloader-locked / verified-boot spoofing.
 */
#ifndef _LINUX_KSU_BOOT_SPOOF_H
#define _LINUX_KSU_BOOT_SPOOF_H

struct seq_file;

int ksu_boot_spoof_cmdline(struct seq_file *m);

#endif /* _LINUX_KSU_BOOT_SPOOF_H */
"""

BOOT_SPOOF_C = r"""// SPDX-License-Identifier: GPL-2.0-only
/*
 * KernelSU 4.14: bootloader-locked / verified-boot spoofing.
 *
 * Android init reads /proc/cmdline before it starts the property service and
 * derives ro.boot.* from the androidboot.* tokens.  Rewriting the
 * bootloader-state tokens there (before /init runs) makes
 *   ro.boot.verifiedbootstate=green
 *   ro.boot.flash.locked=1
 *   ro.boot.vbmeta.device_state=locked
 *   ro.boot.warranty_bit=0
 * and every later reader of /proc/cmdline sees the same locked values.  The
 * device-tree /chosen/bootargs property is rewritten as well so
 * /proc/device-tree/chosen/bootargs cannot leak the real state.
 *
 * The real bootloader/AVB decision is untouched; this only changes what the
 * running OS reports.  Disable with the `ksu_nobootspoof` kernel cmdline token.
 */
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/mutex.h>
#include <linux/of.h>
#include <linux/printk.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>

#include <linux/ksu_boot_spoof.h>

#define KSU_BOOT_SPOOF_MAX_LEN	8192

static bool ksu_boot_spoof_enabled __read_mostly = true;
static char *ksu_boot_spoof_buf;
static DEFINE_MUTEX(ksu_boot_spoof_mutex);

struct ksu_boot_spoof_token {
	const char *key;	/* token prefix, including '=' */
	const char *value;
};

static const struct ksu_boot_spoof_token ksu_boot_spoof_tokens[] = {
	/*
	 * Only bootloader-state tokens that are not used by first-stage mount
	 * decisions are rewritten before init runs (ro.boot.veritymode and the
	 * ro.boot.vbmeta.* metadata are left to the manager's hide-BL script,
	 * which runs after boot).  Forcing veritymode=enforcing early could
	 * make fs_mgr enable dm-verity on partitions that have no verity data.
	 */
	{ "androidboot.verifiedbootstate=", "green" },
	{ "androidboot.flash.locked=", "1" },
	{ "androidboot.vbmeta.device_state=", "locked" },
	{ "androidboot.warranty_bit=", "0" },
	{ "warranty_bit=", "0" },
	{ "androidboot.realmebootstate=", "green" },
	{ "androidboot.secureboot.lockstate=", "locked" },
};

static int __init ksu_boot_spoof_setup(char *str)
{
	ksu_boot_spoof_enabled = false;
	return 1;
}
__setup("ksu_nobootspoof", ksu_boot_spoof_setup);

static char *ksu_boot_spoof_build(const char *cmdline)
{
	char *buf, *out;
	const char *p;
	size_t room = KSU_BOOT_SPOOF_MAX_LEN - 1;

	if (!cmdline || !*cmdline)
		return NULL;

	buf = kzalloc(KSU_BOOT_SPOOF_MAX_LEN, GFP_KERNEL);
	if (!buf)
		return NULL;

	out = buf;
	p = cmdline;
	while (*p && (size_t)(out - buf) < room) {
		const char *start = p;
		size_t len, i;
		bool replaced = false;

		while (*p && *p != ' ')
			p++;
		len = p - start;
		if (!len) {
			p++;
			continue;
		}

		for (i = 0; i < ARRAY_SIZE(ksu_boot_spoof_tokens); i++) {
			size_t klen = strlen(ksu_boot_spoof_tokens[i].key);

			if (len >= klen &&
			    !strncmp(start, ksu_boot_spoof_tokens[i].key, klen)) {
				int n = scnprintf(out, room - (out - buf), "%s%s",
						  ksu_boot_spoof_tokens[i].key,
						  ksu_boot_spoof_tokens[i].value);

				out += n;
				replaced = true;
				break;
			}
		}

		if (!replaced) {
			size_t avail = room - (out - buf);
			size_t cp = len < avail ? len : avail;

			memcpy(out, start, cp);
			out += cp;
		}

		if (*p == ' ') {
			if ((size_t)(out - buf) < room)
				*out++ = ' ';
			p++;
		}
	}
	*out = '\0';

	return buf;
}

static const char *ksu_boot_spoof_get(void)
{
	if (!ksu_boot_spoof_enabled)
		return NULL;

	mutex_lock(&ksu_boot_spoof_mutex);
	if (!ksu_boot_spoof_buf) {
		ksu_boot_spoof_buf = ksu_boot_spoof_build(saved_command_line);
		if (ksu_boot_spoof_buf)
			pr_info("ksu_boot_spoof: reporting verified boot as green/locked\n");
	}
	mutex_unlock(&ksu_boot_spoof_mutex);

	return ksu_boot_spoof_buf;
}

int ksu_boot_spoof_cmdline(struct seq_file *m)
{
	const char *cmdline = ksu_boot_spoof_get();

	if (!cmdline)
		return 0;

	seq_puts(m, cmdline);
	return 1;
}

#ifdef CONFIG_OF
static int __init ksu_boot_spoof_dt_init(void)
{
	struct device_node *np;
	struct property *pp;
	char *buf;
	size_t len;

	if (!ksu_boot_spoof_enabled)
		return 0;

	np = of_find_node_by_path("/chosen");
	if (!np)
		return 0;

	pp = of_find_property(np, "bootargs", NULL);
	if (!pp || !pp->value || pp->length < 2)
		return 0;

	buf = ksu_boot_spoof_build((const char *)pp->value);
	if (!buf)
		return 0;

	len = strlen(buf);
	if (len + 1 <= (size_t)pp->length) {
		memcpy(pp->value, buf, len + 1);
		pp->length = len + 1;
	}
	kfree(buf);

	return 0;
}
late_initcall(ksu_boot_spoof_dt_init);
#endif /* CONFIG_OF */
"""


def die(msg):
    raise SystemExit("fix_best_spoof: ABORT: " + msg)


def read_text(path):
    if not path.is_file():
        die("missing file: {}".format(path))
    with open(path, "r", encoding="utf-8", newline=None) as fh:
        return fh.read()


def write_text(path, text):
    with open(path, "w", encoding="utf-8", newline="") as fh:
        fh.write(text)


def write_new(path, text, marker):
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


def insert_at_nth(path, anchor, insertion, n, label):
    text = read_text(path)
    pos = -1
    start = 0
    for _ in range(n):
        pos = text.find(anchor, start)
        if pos < 0:
            die("{}: '{}' anchor #{} missing".format(path, label, n))
        start = pos + len(anchor)
    after = pos + len(anchor)
    if text.startswith(insertion, after):
        print("  [skipped] {}: {}".format(path.name, label))
        return
    write_text(path, text[:after] + insertion + text[after:])
    print("  [patched] {}: {}".format(path.name, label))


def append_line(path, line, label):
    text = read_text(path)
    if line in text:
        print("  [skipped] {}: {}".format(path.name, label))
        return
    if not text.endswith("\n"):
        text += "\n"
    write_text(path, text + line + "\n")
    print("  [patched] {}: {}".format(path.name, label))


def patch_kernel(kernel):
    print("fix_best_spoof: kernel tree = {}".format(kernel))

    write_new(kernel / "include" / "linux" / "ksu_boot_spoof.h", BOOT_SPOOF_H, MARK)
    write_new(kernel / "fs" / "ksu_boot_spoof.c", BOOT_SPOOF_C, MARK)

    append_line(
        kernel / "fs" / "Makefile",
        "obj-$(CONFIG_KSU) += ksu_boot_spoof.o",
        "ksu_boot_spoof.o",
    )

    cmdline = kernel / "fs" / "proc" / "cmdline.c"
    patch(
        cmdline,
        "#include <linux/seq_file.h>\n",
        "#include <linux/seq_file.h>\n"
        "\n"
        "#ifdef CONFIG_KSU\n"
        "#include <linux/ksu_boot_spoof.h>\n"
        "#endif\n",
        "ksu_boot_spoof include",
        marker="#include <linux/ksu_boot_spoof.h>",
    )
    patch(
        cmdline,
        "\tseq_printf(m, \"%s\\n\", saved_command_line);\n",
        "#ifdef CONFIG_KSU\n"
        "\tif (ksu_boot_spoof_cmdline(m)) {\n"
        "\t\tseq_putc(m, '\\n');\n"
        "\t\treturn 0;\n"
        "\t}\n"
        "#endif\n"
        "\tseq_printf(m, \"%s\\n\", saved_command_line);\n",
        "bootloader-state spoof in /proc/cmdline",
        marker="ksu_boot_spoof_cmdline(m)",
    )

    sys_c = kernel / "kernel" / "sys.c"
    patch(
        sys_c,
        "SYSCALL_DEFINE3(setpriority, int, which, int, who, int, niceval)\n",
        "#ifdef CONFIG_KSU_SUSFS\n"
        "extern bool susfs_is_priority_uid_filtered(uid_t uid);\n"
        "#endif\n"
        "\n"
        "SYSCALL_DEFINE3(setpriority, int, which, int, who, int, niceval)\n",
        "priority-filter extern",
        marker="extern bool susfs_is_priority_uid_filtered(uid_t uid);",
    )
    hook = (
        "#ifdef CONFIG_KSU_SUSFS\n"
        "\t\t\tif (__kuid_val(cred->uid) >= 10000 &&\n"
        "\t\t\t    susfs_is_priority_uid_filtered(__kuid_val(uid)))\n"
        "\t\t\t\tgoto out_unlock;\n"
        "#endif\n"
    )
    anchor = "\t\telse if (!uid_eq(uid, cred->uid)) {\n"
    insert_at_nth(sys_c, anchor, hook, 1, "setpriority priority-filter hook")
    insert_at_nth(sys_c, anchor, hook, 2, "getpriority priority-filter hook")

    ioprio = kernel / "block" / "ioprio.c"
    patch(
        ioprio,
        "SYSCALL_DEFINE3(ioprio_set, int, which, int, who, int, ioprio)\n",
        "#ifdef CONFIG_KSU_SUSFS\n"
        "extern bool susfs_is_priority_uid_filtered(uid_t uid);\n"
        "#endif\n"
        "\n"
        "SYSCALL_DEFINE3(ioprio_set, int, which, int, who, int, ioprio)\n",
        "priority-filter extern",
        marker="extern bool susfs_is_priority_uid_filtered(uid_t uid);",
    )
    patch(
        ioprio,
        "\t\tcase IOPRIO_WHO_USER:\n"
        "\t\t\tuid = make_kuid(current_user_ns(), who);\n"
        "\t\t\tif (!uid_valid(uid))\n"
        "\t\t\t\tbreak;\n",
        "\t\tcase IOPRIO_WHO_USER:\n"
        "\t\t\tuid = make_kuid(current_user_ns(), who);\n"
        "#ifdef CONFIG_KSU_SUSFS\n"
        "\t\t\tif (who && __kuid_val(current_uid()) >= 10000 &&\n"
        "\t\t\t    susfs_is_priority_uid_filtered(__kuid_val(uid)))\n"
        "\t\t\t\tbreak;\n"
        "#endif\n"
        "\t\t\tif (!uid_valid(uid))\n"
        "\t\t\t\tbreak;\n",
        "ioprio_set priority-filter hook",
        marker="ioprio_set priority-filter hook",
    )
    patch(
        ioprio,
        "\t\tcase IOPRIO_WHO_USER:\n"
        "\t\t\tuid = make_kuid(current_user_ns(), who);\n"
        "\t\t\tif (!who)\n",
        "\t\tcase IOPRIO_WHO_USER:\n"
        "\t\t\tuid = make_kuid(current_user_ns(), who);\n"
        "#ifdef CONFIG_KSU_SUSFS\n"
        "\t\t\tif (who && __kuid_val(current_uid()) >= 10000 &&\n"
        "\t\t\t    susfs_is_priority_uid_filtered(__kuid_val(uid)))\n"
        "\t\t\t\tbreak;\n"
        "#endif\n"
        "\t\t\tif (!who)\n",
        "ioprio_get priority-filter hook",
        marker="ioprio_get priority-filter hook",
    )


def main(argv):
    if len(argv) != 3:
        raise SystemExit("usage: fix_best_spoof.py <kernel-root> <stock|ksu|susfs>")

    kernel = Path(argv[1]).resolve()
    mode = argv[2]

    if mode not in ("stock", "ksu", "susfs"):
        raise SystemExit("fix_best_spoof: unknown mode {}".format(mode))
    if not (kernel / "fs" / "proc" / "cmdline.c").is_file():
        die("{} does not look like a kernel tree".format(kernel))

    patch_kernel(kernel)
    print("fix_best_spoof: OK (bootloader-locked spoof + priority-UID hooks)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
