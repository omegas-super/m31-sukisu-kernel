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
        "sulog/event.c",
        "    #define USER_ARG_NULL user_arg_null_ptr()",
        "    #define USER_ARG_NULL (*user_arg_null_ptr())",
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
    fix_access_ok(root_path)
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: fix_builtin.py <drivers/kernelsu>")
    sys.exit(main(sys.argv[1]))
