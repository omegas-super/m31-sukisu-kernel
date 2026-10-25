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
]


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
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: fix_builtin.py <drivers/kernelsu>")
    sys.exit(main(sys.argv[1]))
