#!/usr/bin/env python3
"""Rewrite SukiSU builtin sources for Linux 4.14 header paths.

SukiSU's `builtin` branch targets newer kernels; on 4.14 several
`<linux/...>` headers live under `<uapi/...>` and `static_call.h`
does not exist at all.  Keep the fixes in one place so the CI build
is reproducible.
"""
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
        if "access_ok(" not in text:
            continue
        path.write_text(text.replace("access_ok(", "ksu_access_ok("), encoding="utf-8")
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

def main(root: str) -> int:
    root_path = Path(root)
    for rel, old, new in FIXES:
        path = root_path / rel
        if not path.exists():
            sys.exit(f"missing file: {path}")
        text = path.read_text(encoding="utf-8")
        if old not in text:
            print(f"skip (already fixed or absent): {path}: {old}")
            continue
        path.write_text(text.replace(old, new, 1), encoding="utf-8")
        print(f"patched: {path}: {old}")
    stub_cpu_spoof(root_path)
    fix_susfs_dispatch(root_path)
    fix_access_ok(root_path)
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: fix_builtin.py <drivers/kernelsu>")
    sys.exit(main(sys.argv[1]))
