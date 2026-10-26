#!/usr/bin/env python3
"""Rewrite SukiSU builtin sources for Linux 4.14 header paths.

SukiSU's `builtin` branch targets newer kernels; on 4.14 several
`<linux/...>` headers live under `<uapi/...>` and `static_call.h`
does not exist at all.  Keep the fixes in one place so the CI build
is reproducible.

Usage: fix_builtin.py <drivers/kernelsu> [ksu|susfs]

The optional mode selects fixes that only one configuration needs:
  - susfs: port the SUSFS-branch faccessat/stat hooks to the 4.14
    user-pointer ABI (the struct-filename variant would oops), and
    initialise the SUSFS SIDs from the 4.14 apply_kernelsu_rules().
  - ksu (default): non-SUSFS builds take `struct user_arg_ptr` by value,
    so USER_ARG_NULL must be dereferenced.
"""
import re
import sys
from pathlib import Path

FIXES = [
    (
        "kernel_includes.h",
        "#include <linux/static_call.h>",
        "#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)\n"
        "#include <linux/static_call.h>\n"
        "#endif",
    ),
    (
        "kernel_includes.h",
        "#include <linux/ioctl.h>",
        "#include <uapi/asm-generic/ioctl.h>",
    ),
    (
        "kernel_includes.h",
        "#include <linux/limits.h>",
        "#include <uapi/linux/limits.h>",
    ),
    (
        "kernel_includes.h",
        "#include <linux/input-event-codes.h>",
        "#include <uapi/linux/input-event-codes.h>",
    ),
    (
        "include/uapi/extension.h",
        "#include <linux/ioctl.h>",
        "#include <uapi/asm-generic/ioctl.h>",
    ),
    (
        "include/uapi/supercall.h",
        "#include <linux/ioctl.h>",
        "#include <uapi/asm-generic/ioctl.h>",
    ),
    (
        "preinit/common/preinit.h",
        "#if !defined(CONFIG_ARM64) || !defined(KSU_CAN_USE_JUMP_LABEL)\n"
        "#define KSU_NO_PREINIT\n"
        "#endif",
        "#if !defined(CONFIG_ARM64) || !defined(KSU_CAN_USE_JUMP_LABEL)\n"
        "#ifndef KSU_NO_PREINIT\n"
        "#define KSU_NO_PREINIT\n"
        "#endif\n"
        "#endif",
    ),
    (
        "extension/kpm/super_access.c",
        "#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 19, 0)\n"
        "DEFINE_MEMBER(task_struct, pids[PIDTYPE_PID].pid)\n"
        "#else\n"
        "DEFINE_MEMBER(task_struct, thread_pid)\n"
        "#endif",
        "DEFINE_MEMBER(task_struct, thread_pid)",
    ),
    (
        "policy/feature.c",
        "static const struct ksu_feature_handler *feature_handlers[KSU_FEATURE_MAX];",
        "#include <uapi/feature.h>\n\n"
        "static const struct ksu_feature_handler *feature_handlers[KSU_FEATURE_MAX];",
    ),
    (
        "runtime/ksud.c",
        "bool ksu_module_mounted __read_mostly = false;",
        "#include \"feature/selinux_hide.h\"\n\n"
        "bool ksu_module_mounted __read_mostly = false;",
    ),
    (
        "selinux/rules.c",
        "    struct selinux_policy *pol, *old_pol;\n"
        "    struct policydb *db;",
        "    struct selinux_policy *pol, *old_pol;\n"
        "    struct policydb *db;\n"
        "    (void)pol;\n"
        "    (void)old_pol;",
    ),
    (
        "policy/feature.c",
        "    [KSU_FEATURE_SELINUX_HIDE] = \"selinux_hide\",",
        "#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)\n"
        "    [KSU_FEATURE_SELINUX_HIDE] = \"selinux_hide\",\n"
        "#endif",
    ),
    (
        "runtime/ksud.c",
        "    ksu_selinux_hide_handle_post_fs_data();",
        "#if defined(CONFIG_KSU_SUSFS) && LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)\n"
        "    ksu_selinux_hide_handle_post_fs_data();\n"
        "#endif",
    ),
    (
        "runtime/ksud.c",
        "                ksu_selinux_hide_handle_second_stage();",
        "#if defined(CONFIG_KSU_SUSFS) && LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)\n"
        "                ksu_selinux_hide_handle_second_stage();\n"
        "#endif",
    ),
    (
        "runtime/ksud.c",
        "#endif\n            ksu_selinux_hide_handle_second_stage();",
        "#endif\n#if defined(CONFIG_KSU_SUSFS) && LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)\n"
        "            ksu_selinux_hide_handle_second_stage();\n"
        "#endif",
    ),
    (
        "ksu_main.c",
        "#ifdef CONFIG_KSU_SUSFS\n#include \"feature/selinux_hide.c\"",
        "#if defined(CONFIG_KSU_SUSFS) && LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)\n"
        "#include \"feature/selinux_hide.c\"",
    ),
]


# B1: replacement for the two SUSFS-branch hooks in feature/sucompat.c.
# fs/open.c and fs/stat.c pass `const char __user **` on 4.14; the upstream
# SUSFS branch instead takes `struct filename **` and dereferences it as a
# kernel pointer, which oopses on the first stat()/faccessat() (bootloop).
# This mirrors the non-SUSFS branch's user-pointer handling but keeps the
# SUSFS branch's su->sh rewrite (no escalation on faccessat/stat).
SUSFS_SUCOMPAT_ABI_BLOCK = '''static noinline int ksu_sucompat_user_common_susfs(const char __user **filename_user, const char *syscall_name)
{
    char path[sizeof(su_path)] = { 0 };
    long len = ksu_strncpy_from_user_nofault(path, *filename_user, sizeof(path));

    if (unlikely(len <= 0))
        return -EFAULT;

    if (likely(memcmp(path, su_path, sizeof(su_path))))
        return 0;

    if (!ksu_su_compat_enabled)
        return 0;

    if (likely(test_thread_flag(TIF_SECCOMP)))
        return 0;

    if (!ksu_is_allow_uid_for_current(current_uid().val))
        return 0;

    if (current_chrooted()) {
        pr_err("%s: su found but NOT allowed! Because current process is running in chrooted environment\\n", syscall_name);
        return 0;
    }

    pr_info("%s: su->sh!\\n", syscall_name);
    *filename_user = sh_user_path();
    return 0;
}

int ksu_handle_faccessat(int *dfd, const char __user **filename_user, int *mode, int *__unused_flags)
{
    (void)dfd;
    (void)mode;
    (void)__unused_flags;

    if (!filename_user || !*filename_user)
        return 0;

    return ksu_sucompat_user_common_susfs(filename_user, "faccessat");
}

int ksu_handle_stat(int *dfd, const char __user **filename_user, int *flags)
{
    (void)dfd;
    (void)flags;

    if (!filename_user || !*filename_user)
        return 0;

    return ksu_sucompat_user_common_susfs(filename_user, "newfstatat");
}
'''


def stub_cpu_spoof(root_path: Path) -> None:
    path = root_path / "extension/cpu_spoof.c"
    if not path.exists():
        sys.exit(f"missing file: {path}")
    text = path.read_text(encoding="utf-8")
    if "LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0)" in text:
        print(f"skip (already stubbed): {path}")
        return
    marker = "#if defined(CONFIG_ARM64) || defined(__aarch64__)"
    if marker not in text:
        sys.exit(f"cpu_spoof marker not found: {path}")
    stub = (
        "#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0)\n"
        "/* 4.14: the vDSO datapage API is different; disable CPU spoof. */\n"
        "int ksu_extension_cpu_spoof_io(u32 id, void __user *raw)\n"
        "{\n"
        "\t(void)id;\n"
        "\t(void)raw;\n"
        "\treturn -EOPNOTSUPP;\n"
        "}\n"
        "#else\n"
    )
    text = text.replace(marker, stub + marker, 1)
    text = text.rstrip() + "\n#endif /* LINUX_VERSION_CODE < 5.10 */\n"
    path.write_text(text, encoding="utf-8")
    print(f"patched: {path}: cpu_spoof 4.14 stub")


def fix_access_ok(root_path: Path) -> None:
    compat = root_path / "kernel_compat.h"
    if not compat.exists():
        sys.exit(f"missing file: {compat}")
    text = compat.read_text(encoding="utf-8")
    if "ksu_access_ok" not in text:
        text += (
            "\n#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 0, 0)\n"
            "#define ksu_access_ok(addr, size) access_ok(VERIFY_READ, (addr), (size))\n"
            "#else\n"
            "#define ksu_access_ok(addr, size) access_ok((addr), (size))\n"
            "#endif\n"
        )
        compat.write_text(text, encoding="utf-8")
        print(f"patched: {compat}: ksu_access_ok")
    for path in sorted((root_path / "extension/kpm").glob("*.c")):
        text = path.read_text(encoding="utf-8")
        patched = re.sub(r"(?<!ksu_)access_ok\(", "ksu_access_ok(", text)
        if patched == text:
            continue
        path.write_text(patched, encoding="utf-8")
        print(f"patched: {path}: access_ok -> ksu_access_ok")



def fix_susfs_dispatch(root_path: Path) -> None:
    """ksud passes a void __user * payload; dispatch receives void __user **."""
    path = root_path / "supercall" / "dispatch.c"
    text = path.read_text(encoding="utf-8")
    if "susfs_arg" in text:
        return
    NL = chr(10)
    anchor = "    if (magic2 == SUSFS_MAGIC && current_uid().val == 0) {" + NL
    if anchor not in text:
        print(f"skip: {path}: susfs dispatch anchor missing")
        return
    inject = anchor + (
        "        void __user *susfs_arg = arg ? (void __user *)*arg : NULL;" + NL + NL
        + "        if (!susfs_arg)" + NL
        + "            return -EINVAL;" + NL
    )
    text = text.replace(anchor, inject, 1)
    for fn in (
        "susfs_add_sus_path",
        "susfs_add_sus_path_loop",
        "susfs_set_hide_sus_mnts_for_non_su_procs",
        "susfs_add_sus_kstat",
        "susfs_update_sus_kstat",
        "susfs_set_uname",
        "susfs_enable_log",
        "susfs_set_cmdline_or_bootconfig",
        "susfs_add_open_redirect",
        "susfs_add_sus_map",
        "susfs_set_avc_log_spoofing",
        "susfs_get_enabled_features",
        "susfs_show_variant",
        "susfs_show_version",
    ):
        text = text.replace(f"{fn}(arg)", f"{fn}(susfs_arg)")
    path.write_text(text, encoding="utf-8")
    print(f"patched: {path}: susfs dispatch arg deref")

def fix_susfs_sucompat_abi(root_path: Path) -> None:
    """B1: rewrite the SUSFS-branch faccessat/stat hooks to the 4.14 ABI.

    patch_hooks.py calls ksu_handle_faccessat()/ksu_handle_stat() with a
    `const char __user **` (what fs/open.c and fs/stat.c have), in both
    modes.  The upstream SUSFS branch of sucompat.c expects
    `struct filename **` and dereferences it as a kernel pointer, so the
    SUSFS build would oops on the first stat/faccessat.  Replace only those
    two functions; the execveat hooks keep `struct filename **` (correct).
    The declarations in feature/sucompat.h must match the new definitions.
    """
    path = root_path / "feature" / "sucompat.c"
    if not path.exists():
        sys.exit(f"missing file: {path}")
    text = path.read_text(encoding="utf-8")
    if "ksu_sucompat_user_common_susfs" in text:
        print(f"skip (already fixed): {path}: SUSFS faccessat/stat ABI")
    else:
        start_marker = "int ksu_handle_faccessat(int *dfd, struct filename **filename, int *mode,"
        start_count = text.count(start_marker)
        if start_count != 1:
            sys.exit(f"{path}: SUSFS faccessat anchor found {start_count} times (expected 1)")

        start = text.index(start_marker)
        else_pos = text.find("\n#else\n", start)
        if else_pos < 0:
            sys.exit(f"{path}: branch '#else' not found after the SUSFS faccessat hook")
        region = text[start:else_pos]

        for needle, what in (
            ("int ksu_handle_faccessat(int *dfd, struct filename **filename", "ksu_handle_faccessat"),
            ("int ksu_handle_stat(int *dfd, struct filename **filename, int *flags)", "ksu_handle_stat"),
        ):
            found = region.count(needle)
            if found != 1:
                sys.exit(f"{path}: {what} definition found {found} times in SUSFS block (expected 1)")
        if "ksu_handle_execveat" in region:
            sys.exit(f"{path}: SUSFS block unexpectedly contains execveat hooks, refusing to patch")
        if "const char __user **" in region:
            sys.exit(f"{path}: SUSFS block already uses user pointers, unexpected layout")
        if not region.endswith("}\n"):
            sys.exit(f"{path}: SUSFS block does not end with a function brace, refusing to patch")

        text = text[:start] + SUSFS_SUCOMPAT_ABI_BLOCK + text[else_pos:]
        path.write_text(text, encoding="utf-8")
        print(f"patched: {path}: SUSFS faccessat/stat -> const char __user **")

    # The header declares the two hooks for both branches; without this the
    # new definitions conflict with the SUSFS-branch declarations and the
    # build fails with "conflicting types for 'ksu_handle_faccessat'".
    header = root_path / "feature" / "sucompat.h"
    if not header.exists():
        sys.exit(f"missing file: {header}")
    htext = header.read_text(encoding="utf-8")
    old_f = "int ksu_handle_faccessat(int *dfd, struct filename **filename, int *mode, int *__unused_flags);"
    old_s = "int ksu_handle_stat(int *dfd, struct filename **filename, int *flags);"
    new_f = "int ksu_handle_faccessat(int *dfd, const char __user **filename_user, int *mode, int *__unused_flags);"
    new_s = "int ksu_handle_stat(int *dfd, const char __user **filename_user, int *flags);"
    if old_f not in htext and old_s not in htext:
        print(f"skip (already fixed): {header}: SUSFS faccessat/stat declarations")
        return
    for old, new, what in ((old_f, new_f, "ksu_handle_faccessat"), (old_s, new_s, "ksu_handle_stat")):
        found = htext.count(old)
        if found != 1:
            sys.exit(f"{header}: {what} declaration found {found} times (expected 1)")
        htext = htext.replace(old, new, 1)
    header.write_text(htext, encoding="utf-8")
    print(f"patched: {header}: SUSFS faccessat/stat declarations -> const char __user **")


BATCH_SID_ANCHOR = "    smp_mb();\n    reset_avc_cache();\n#endif\n}"
BATCH_SID_BLOCK = (
    "    smp_mb();\n"
    "    reset_avc_cache();\n"
    "#ifdef CONFIG_KSU_SUSFS\n"
    "    susfs_set_batch_sid();\n"
    "#endif\n"
    "#endif\n"
    "}\n"
)


def fix_susfs_batch_sid(root_path: Path) -> None:
    """B2b: run SUSFS SID initialisation in the 4.14 apply_kernelsu_rules().

    Upstream only calls susfs_set_batch_sid() in the >= 5.10 branch; the 4.14
    branch never does, so susfs_ksu_sid/zygote_sid/init_sid stay 0 and
    SUS_MOUNT / OPEN_REDIRECT / setresuid-umount are inert.  Insert the call
    right before the 4.14 branch's closing #endif (guarded by
    CONFIG_KSU_SUSFS, matching the 5.10 branch; susfs_set_batch_sid() is
    declared in kernel/selinux/selinux.h under the same guard).
    """
    path = root_path / "selinux" / "rules.c"
    if not path.exists():
        sys.exit(f"missing file: {path}")
    text = path.read_text(encoding="utf-8")
    calls = text.count("susfs_set_batch_sid();")
    if calls == 2:
        print(f"skip (already fixed): {path}: 4.14 susfs_set_batch_sid()")
        return
    if calls != 1:
        sys.exit(f"{path}: susfs_set_batch_sid(); found {calls} times (expected 1 before patching)")
    anchor_count = text.count(BATCH_SID_ANCHOR)
    if anchor_count != 1:
        sys.exit(f"{path}: 4.14 apply_kernelsu_rules tail anchor found {anchor_count} times (expected 1)")
    text = text.replace(BATCH_SID_ANCHOR, BATCH_SID_BLOCK, 1)
    path.write_text(text, encoding="utf-8")
    print(f"patched: {path}: susfs_set_batch_sid() in 4.14 apply_kernelsu_rules")


def fix_user_arg_null(root_path: Path) -> None:
    """B3: non-SUSFS mode passes `struct user_arg_ptr` to sulog by value.

    `ksu_sulog_capture()` takes `const struct user_arg_ptr argv` in the
    non-SUSFS branch, but USER_ARG_NULL expands to a pointer
    (user_arg_null_ptr()), which is a type error.  Dereference it.  SUSFS
    mode takes `struct user_arg_ptr *`, so it must keep the pointer form
    (hence this fixer is skipped for mode=susfs).
    """
    path = root_path / "sulog" / "event.c"
    if not path.exists():
        sys.exit(f"missing file: {path}")
    text = path.read_text(encoding="utf-8")
    old = "    #define USER_ARG_NULL user_arg_null_ptr()"
    new = "    #define USER_ARG_NULL (*user_arg_null_ptr())"
    if new in text:
        print(f"skip (already fixed): {path}: USER_ARG_NULL")
        return
    count = text.count(old)
    if count != 1:
        sys.exit(f"{path}: USER_ARG_NULL anchor found {count} times (expected 1)")
    text = text.replace(old, new, 1)
    path.write_text(text, encoding="utf-8")
    print(f"patched: {path}: USER_ARG_NULL -> (*user_arg_null_ptr()) (non-SUSFS mode)")


def fix_susfs_new_symbols(root_path: Path) -> None:
    """Guard new SUSFS-2.x-only calls so mode=ksu still compiles.

    The current `builtin` branch calls susfs_parse_priority_app_strings()
    unconditionally from manager/pkg_observer.c.  In mode=ksu
    (CONFIG_KSU_SUSFS=n) the SUSFS kernel sources are not built, so the call
    would be an implicit declaration plus an undefined symbol.  SUSFS mode
    keeps the call (fs/susfs_compat.c provides it).
    """
    path = root_path / "manager" / "pkg_observer.c"
    if not path.exists():
        print(f"skip (absent): {path}: priority-filter refresh call")
        return
    text = path.read_text(encoding="utf-8")
    old = (
        "    // Renew the getpriority uid bitmap filter\n"
        "    susfs_parse_priority_app_strings();\n"
    )
    new = (
        "#ifdef CONFIG_KSU_SUSFS\n"
        "    // Renew the getpriority uid bitmap filter\n"
        "    susfs_parse_priority_app_strings();\n"
        "#endif\n"
    )
    if old not in text:
        print(f"skip (already fixed or absent): {path}: priority-filter refresh call")
        return
    path.write_text(text.replace(old, new, 1), encoding="utf-8")
    print(f"patched: {path}: guard susfs_parse_priority_app_strings() for mode=ksu")


def main(root: str, mode: str = "ksu") -> int:
    root_path = Path(root)
    for rel, old, new in FIXES:
        path = root_path / rel
        if not path.exists():
            sys.exit(f"missing file: {path}")
        text = path.read_text(encoding="utf-8")
        if old not in text:
            print(f"skip (already fixed or absent): {path}: {old}")
            continue
        if old in new and new in text:
            print(f"skip (already fixed): {path}: {old}")
            continue
        path.write_text(text.replace(old, new, 1), encoding="utf-8")
        print(f"patched: {path}: {old}")
    stub_cpu_spoof(root_path)
    fix_susfs_dispatch(root_path)
    fix_access_ok(root_path)
    fix_susfs_sucompat_abi(root_path)
    fix_susfs_batch_sid(root_path)
    fix_susfs_new_symbols(root_path)
    if mode == "susfs":
        print("skip: USER_ARG_NULL fix (SUSFS mode takes struct user_arg_ptr *)")
    else:
        fix_user_arg_null(root_path)
    return 0


if __name__ == "__main__":
    if len(sys.argv) not in (2, 3):
        sys.exit("usage: fix_builtin.py <drivers/kernelsu> [ksu|susfs]")
    mode_arg = sys.argv[2] if len(sys.argv) == 3 else "ksu"
    if mode_arg not in ("ksu", "susfs"):
        sys.exit(f"unknown mode: {mode_arg} (expected ksu or susfs)")
    sys.exit(main(sys.argv[1], mode_arg))
