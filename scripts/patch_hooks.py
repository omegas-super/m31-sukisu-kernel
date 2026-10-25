#!/usr/bin/env python3
"""Insert SukiSU manual hooks into the 4.14 universal9611 kernel tree.

The kernel tree has no git metadata, so this script patches by exact anchor
strings and is idempotent (it skips a file if the hook call is already there).

The call is inserted before the first statement of the function, i.e. after
the local declarations, so the kernel's -Wdeclaration-after-statement stays
quiet.
"""
import pathlib
import sys

if len(sys.argv) < 2:
    raise SystemExit("usage: patch_hooks.py <kernel-root> [ksu|susfs]")

ROOT = pathlib.Path(sys.argv[1]).resolve()
MODE = sys.argv[2] if len(sys.argv) > 2 else "ksu"

PATCHES = [
    {
        "file": "fs/exec.c",
        "anchor": "static int __do_execve_file(int fd, struct filename *filename,",
        "call_anchor": "\tif (IS_ERR(filename))",
        "decl": "extern int ksu_handle_execveat(int *fd, struct filename **filename_ptr, void *argv, void *envp, int *flags);",
        "call": "\tksu_handle_execveat(&fd, &filename, &argv, &envp, &flags);",
        "marker": "ksu_handle_execveat(&fd",
    },
    {
        "file": "fs/open.c",
        "anchor": "SYSCALL_DEFINE3(faccessat, int, dfd, const char __user *, filename, int, mode)",
        "call_anchor": "\tif (mode & ~S_IRWXO)",
        "decl": "extern int ksu_handle_faccessat(int *dfd, const char __user **filename_user, int *mode, int *__unused_flags);",
        "call": "\tksu_handle_faccessat(&dfd, &filename, &mode, NULL);",
        "marker": "ksu_handle_faccessat(&dfd",
    },
    {
        "file": "fs/stat.c",
        "anchor": "int vfs_statx(int dfd, const char __user *filename, int flags,",
        "call_anchor": "\tif ((flags & ~(AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT |",
        "decl": "extern int ksu_handle_stat(int *dfd, const char __user **filename_user, int *flags);",
        "call": "\tksu_handle_stat(&dfd, &filename, &flags);",
        "marker": "ksu_handle_stat(&dfd",
    },
    {
        "file": "fs/read_write.c",
        "anchor": "ssize_t vfs_read(struct file *file, char __user *buf, size_t count, loff_t *pos)",
        "call_after": "ssize_t vfs_read(struct file *file, char __user *buf, size_t count, loff_t *pos)\n{\n\tssize_t ret;\n",
        "decl": "extern bool ksu_vfs_read_hook;\nextern int ksu_handle_vfs_read(struct file **file_ptr, char __user **buf_ptr, size_t *count_ptr, loff_t **pos);",
        "call": "\tif (ksu_vfs_read_hook)\n\t\tksu_handle_vfs_read(&file, &buf, &count, &pos);",
        "marker": "ksu_handle_vfs_read(&file",
    },
    {
        "file": "kernel/reboot.c",
        "anchor": "SYSCALL_DEFINE4(reboot, int, magic1, int, magic2, unsigned int, cmd,",
        "call_anchor": "\t/* We only trust the superuser with rebooting the system. */",
        "decl": "extern int ksu_handle_sys_reboot(int magic1, int magic2, unsigned int cmd, void __user **arg);",
        "call": """	if (ksu_handle_sys_reboot(magic1, magic2, cmd, &arg) == 0 && magic1 != LINUX_REBOOT_MAGIC1)
		return 0;""",
        "marker": "ksu_handle_sys_reboot(magic1",
    },
    {
        "file": "drivers/input/input.c",
        "anchor": "static void input_handle_event(struct input_dev *dev,",
        "call_after": "\tint disposition = input_get_disposition(dev, type, code, &value);\n",
        "decl": "extern bool ksu_input_hook __read_mostly;\nextern int ksu_handle_input_handle_event(unsigned int *type, unsigned int *code, int *value);",
        "call": "\tif (unlikely(ksu_input_hook))\n\t\tksu_handle_input_handle_event(&type, &code, &value);",
        "marker": "ksu_handle_input_handle_event(&type",
    },
]

# With CONFIG_KSU_SUSFS the task_fix_setuid LSM hook is not registered, so
# ksu_handle_umount() must be driven from the setresuid syscall directly.
SUSFS_PATCH = {
    "file": "kernel/sys.c",
    "anchor": "SYSCALL_DEFINE3(setresuid, uid_t, ruid, uid_t, euid, uid_t, suid)",
    "call_after": "\tkuid_t kruid, keuid, ksuid;\n",
    "decl": "extern int ksu_handle_setresuid(uid_t ruid, uid_t euid, uid_t suid);",
    "call": "\tksu_handle_setresuid(ruid, euid, suid);",
    "marker": "ksu_handle_setresuid(ruid",
}

if MODE == "susfs":
    PATCHES.append(SUSFS_PATCH)


def require_once(text, needle, path, what):
    count = text.count(needle)
    if count != 1:
        raise SystemExit(f"{path}: {what} found {count} times (expected 1): {needle!r}")


def apply(entry):
    path = ROOT / entry["file"]
    if not path.is_file():
        raise SystemExit(f"missing file: {path}")

    text = path.read_text(encoding="utf-8")
    if entry["marker"] in text:
        print(f"already patched: {entry['file']}")
        return

    require_once(text, entry["anchor"], entry["file"], "function anchor")

    decl = "#ifdef CONFIG_KSU\n" + entry["decl"] + "\n#endif\n"
    text = text.replace(entry["anchor"], decl + entry["anchor"], 1)

    call = "#ifdef CONFIG_KSU\n" + entry["call"] + "\n#endif\n"
    if "call_after" in entry:
        require_once(text, entry["call_after"], entry["file"], "call-after anchor")
        text = text.replace(entry["call_after"], entry["call_after"] + "\n" + call, 1)
    else:
        require_once(text, entry["call_anchor"], entry["file"], "statement anchor")
        text = text.replace(entry["call_anchor"], call + entry["call_anchor"], 1)

    path.write_text(text, encoding="utf-8")
    print(f"patched: {entry['file']}")


for patch in PATCHES:
    apply(patch)

print(f"done ({MODE})")
