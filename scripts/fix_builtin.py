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
]


def stub_cpu_spoof(root_path: Path) -> None:
    path = root_path / "extension/cpu_spoof.c"
    if not path.exists():
        sys.exit(f"missing file: {path}")
    text = path.read_text()
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
    path.write_text(text)
    print(f"patched: {path}: cpu_spoof 4.14 stub")


def fix_access_ok(root_path: Path) -> None:
    compat = root_path / "kernel_compat.h"
    if not compat.exists():
        sys.exit(f"missing file: {compat}")
    text = compat.read_text()
    if "ksu_access_ok" not in text:
        text += (
            "\n#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 0, 0)\n"
            "#define ksu_access_ok(addr, size) access_ok(VERIFY_READ, (addr), (size))\n"
            "#else\n"
            "#define ksu_access_ok(addr, size) access_ok((addr), (size))\n"
            "#endif\n"
        )
        compat.write_text(text)
        print(f"patched: {compat}: ksu_access_ok")
    for path in sorted((root_path / "extension/kpm").glob("*.c")):
        text = path.read_text()
        if "access_ok(" not in text:
            continue
        path.write_text(text.replace("access_ok(", "ksu_access_ok("))
        print(f"patched: {path}: access_ok -> ksu_access_ok")


def main(root: str) -> int:
    root_path = Path(root)
    for rel, old, new in FIXES:
        path = root_path / rel
        if not path.exists():
            sys.exit(f"missing file: {path}")
        text = path.read_text()
        if old not in text:
            print(f"skip (already fixed or absent): {path}: {old}")
            continue
        path.write_text(text.replace(old, new, 1))
        print(f"patched: {path}: {old}")
    stub_cpu_spoof(root_path)
    fix_access_ok(root_path)
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: fix_builtin.py <drivers/kernelsu>")
    sys.exit(main(sys.argv[1]))
