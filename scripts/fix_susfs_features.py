#!/usr/bin/env python3
"""Enable the SUSFS 4.14 feature switches that SukiSU's `builtin` Kconfig lacks.

The 4.14 SUSFS sources (fs/susfs.c, fs/namespace.c overlay and the 50_
patch) test a number of ``CONFIG_KSU_SUSFS_*`` symbols that the vendored
SukiSU ``builtin`` Kconfig does not define at all.  An undefined symbol is
the same as "n" for the preprocessor, so those feature blocks are always
compiled out and cannot be enabled from the defconfig.

This script:
  1. inserts the missing ``config KSU_SUSFS_*`` entries into
     ``<kernel-root>/drivers/kernelsu/Kconfig`` (immediately before the
     ``endmenu`` that closes the "KernelSU - SUSFS" menu), and
  2. sets the matching switches in ``<defconfig-path>``.

Usage:
    python3 scripts/fix_susfs_features.py <kernel-root> <defconfig-path>

``<defconfig-path>`` may be absolute, relative to the current directory, or
relative to ``<kernel-root>``.

The script is idempotent: running it twice produces a byte-identical tree and
prints a no-op summary the second time.  It exits non-zero (and writes
nothing) when an anchor is missing or ambiguous, or when a symbol would end
up defined more than once.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

KCONFIG_REL = Path("drivers/kernelsu/Kconfig")
SUSFS_MENU = 'menu "KernelSU - SUSFS"'
SUS_MAP_CONFIG = "config KSU_SUSFS_SUS_MAP"
ENDMENU = "endmenu"

# The six entries `builtin` does not define.  Each is a bool gated on
# KSU_SUSFS; the extra dependency lines encode what the 4.14 source needs to
# link (fs/susfs.c declares ksu_try_umount() only under SUS_MOUNT, and the
# auto-add helpers live in the SUS_MOUNT / TRY_UMOUNT sections).
NEW_KCONFIG_ENTRIES = [
    (
        "KSU_SUSFS_TRY_UMOUNT",
        """\
config KSU_SUSFS_TRY_UMOUNT
\tbool "Enable to umount sus mounts"
\tdepends on KSU_SUSFS
\tdepends on KSU_SUSFS_SUS_MOUNT
\tdefault y
\thelp
\t  - Allow umounting the mounts that are added to the try_umount list.
\t  - Used by the automatic bind-mount / KSU default-mount helpers below.
\t  - Effective only on zygote/zygote_next spawned user app process that is marked with TIF_PROC_UMOUNTED.
""",
    ),
    (
        "KSU_SUSFS_AUTO_ADD_SUS_BIND_MOUNT",
        """\
config KSU_SUSFS_AUTO_ADD_SUS_BIND_MOUNT
\tbool "Enable to automatically add sus bind mounts"
\tdepends on KSU_SUSFS
\tdepends on KSU_SUSFS_SUS_MOUNT
\tdefault y
\thelp
\t  - Automatically mark the source mount of a bind mount done by the ksu process as a sus mount.
\t  - Effective only on zygote/zygote_next spawned user app process that is marked with TIF_PROC_UMOUNTED.
""",
    ),
    (
        "KSU_SUSFS_AUTO_ADD_SUS_KSU_DEFAULT_MOUNT",
        """\
config KSU_SUSFS_AUTO_ADD_SUS_KSU_DEFAULT_MOUNT
\tbool "Enable to automatically add sus mounts for KSU default mounts"
\tdepends on KSU_SUSFS
\tdepends on KSU_SUSFS_SUS_MOUNT
\tdefault y
\thelp
\t  - Automatically add the mounts created by KernelSU's default mount flow to the sus mount list.
\t  - Effective only on zygote/zygote_next spawned user app process that is marked with TIF_PROC_UMOUNTED.
""",
    ),
    (
        "KSU_SUSFS_AUTO_ADD_TRY_UMOUNT_FOR_BIND_MOUNT",
        """\
config KSU_SUSFS_AUTO_ADD_TRY_UMOUNT_FOR_BIND_MOUNT
\tbool "Enable to automatically add try_umount for bind mounts"
\tdepends on KSU_SUSFS
\tdepends on KSU_SUSFS_TRY_UMOUNT
\tdefault y
\thelp
\t  - Automatically add bind-mounted paths to the try_umount list so they are umounted for umounted app processes.
\t  - Effective only on zygote/zygote_next spawned user app process that is marked with TIF_PROC_UMOUNTED.
""",
    ),
    (
        "KSU_SUSFS_HAS_MAGIC_MOUNT",
        """\
config KSU_SUSFS_HAS_MAGIC_MOUNT
\tbool "Enable to support KernelSU magic mount"
\tdepends on KSU_SUSFS
\tdefault n
\thelp
\t  - Tell SUSFS that the KernelSU build uses the magic-mount workdir layout (/debug_ramdisk/workdir).
\t  - Only meaningful for the 5.10+ magic-mount implementation; keep it off on 4.14.
""",
    ),
    (
        "KSU_SUSFS_SUS_SU",
        """\
config KSU_SUSFS_SUS_SU
\tbool "Enable to support sus_su"
\tdepends on KSU_SUSFS
\tdefault n
\thelp
\t  - Build the sus_su FIFO device which provides an alternative su implementation.
\t  - Requires matching userspace (ksud) support; keep it off unless you need it.
""",
    ),
]

# Defconfig lines this script owns.  HAS_MAGIC_MOUNT is a 5.10+ concept and
# SUS_SU is an alternative su path; both stay off on this port.
#
# TRY_UMOUNT / AUTO_ADD_TRY_UMOUNT_FOR_BIND_MOUNT also stay OFF, deliberately:
# the 4.14 sources define susfs_add_try_umount()/susfs_try_umount() and the
# hand-ported fs/namespace.c defines susfs_run_try_umount_for_current_mnt_ns(),
# but NOTHING in this tree calls the runner and SukiSU builtin's dispatch.c has
# no CMD_SUSFS_ADD_TRY_UMOUNT/RUN_UMOUNT case.  Enabling them would add
# unbounded list growth with no drain path (a leak) and no hiding effect.
# AUTO_ADD_SUS_BIND_MOUNT / AUTO_ADD_SUS_KSU_DEFAULT_MOUNT DO have live callers
# in the hand-ported fs/namespace.c and are enabled.
DEFCONFIG_LINES = [
    "CONFIG_KSU_SUSFS_HIDE_KSU_SUSFS_SYMBOLS=y",
    "# CONFIG_KSU_SUSFS_TRY_UMOUNT is not set",
    "CONFIG_KSU_SUSFS_AUTO_ADD_SUS_BIND_MOUNT=y",
    "CONFIG_KSU_SUSFS_AUTO_ADD_SUS_KSU_DEFAULT_MOUNT=y",
    "# CONFIG_KSU_SUSFS_AUTO_ADD_TRY_UMOUNT_FOR_BIND_MOUNT is not set",
    "# CONFIG_KSU_SUSFS_HAS_MAGIC_MOUNT is not set",
    "# CONFIG_KSU_SUSFS_SUS_SU is not set",
]


class FixError(Exception):
    """Anchor/verification failure: abort with a non-zero exit code."""


def read_text(path: Path) -> tuple[str, str]:
    """Return (text with '\\n' newlines, original newline sequence)."""
    raw = path.read_bytes()
    newline = "\r\n" if b"\r\n" in raw else "\n"
    text = raw.decode("utf-8").replace("\r\n", "\n").replace("\r", "\n")
    return text, newline


def write_text(path: Path, text: str, newline: str) -> None:
    out = text if newline == "\n" else text.replace("\n", newline)
    path.write_bytes(out.encode("utf-8"))


def line_is_config(lines: list[str], symbol: str) -> bool:
    return any(line.strip() == f"config {symbol}" for line in lines)


def find_susfs_menu_end(lines: list[str], kconfig: Path) -> int:
    """Return the index of the endmenu closing the 'KernelSU - SUSFS' menu.

    The menu is located by its unique title; the closing endmenu is found by
    walking the menu nesting depth, so a future nested menu does not confuse
    the anchor.  ``config KSU_SUSFS_SUS_MAP`` must still be the last *config*
    entry of the menu (immediately before the closing endmenu); that is the
    anchor the SUSFS patch/Kconfig layout guarantees.
    """
    menu_idx = [i for i, line in enumerate(lines) if line.strip() == SUSFS_MENU]
    if len(menu_idx) != 1:
        raise FixError(
            f"{kconfig}: expected exactly one '{SUSFS_MENU}' anchor, "
            f"found {len(menu_idx)}")
    start = menu_idx[0]

    depth = 1
    end_idx = None
    for i in range(start + 1, len(lines)):
        stripped = lines[i].strip()
        if stripped.startswith("menu "):
            depth += 1
        elif stripped == ENDMENU:
            depth -= 1
            if depth == 0:
                end_idx = i
                break
    if end_idx is None:
        raise FixError(
            f"{kconfig}: no '{ENDMENU}' closing '{SUSFS_MENU}' found")

    sus_map_idx = [i for i in range(start, end_idx)
                   if lines[i].strip() == SUS_MAP_CONFIG]
    if len(sus_map_idx) != 1:
        raise FixError(
            f"{kconfig}: expected exactly one '{SUS_MAP_CONFIG}' anchor inside "
            f"'{SUSFS_MENU}', found {len(sus_map_idx)}")

    # The six new entries go after the current last entry (SUS_MAP).  A
    # partial previous run may already have some of them there; any *other*
    # config line after SUS_MAP means the layout drifted -> refuse to guess.
    ours = {symbol for symbol, _body in NEW_KCONFIG_ENTRIES}
    for i in range(sus_map_idx[0] + 1, end_idx):
        stripped = lines[i].strip()
        if stripped.startswith("config "):
            name = stripped.split(None, 1)[1]
            if name not in ours:
                raise FixError(
                    f"{kconfig}: unexpected config '{name}' after "
                    f"{SUS_MAP_CONFIG} inside '{SUSFS_MENU}'")
    return end_idx


def patch_kconfig(kconfig: Path) -> list[str]:
    """Insert the missing SUSFS feature entries; return inserted symbols."""
    text, newline = read_text(kconfig)
    lines = text.split("\n")

    missing = [(sym, body) for sym, body in NEW_KCONFIG_ENTRIES
               if not line_is_config(lines, sym)]
    if not missing:
        print("[kconfig] all 6 SUSFS feature symbols already defined; nothing to do")
        return []

    end_idx = find_susfs_menu_end(lines, kconfig)

    block: list[str] = []
    for _symbol, body in missing:
        block.extend(body.rstrip("\n").split("\n"))
        block.append("")

    lines = lines[:end_idx] + block + lines[end_idx:]
    write_text(kconfig, "\n".join(lines), newline)

    # Verify: every entry must now be defined exactly once.
    for symbol, _body in missing:
        count = sum(1 for line in lines if line.strip() == f"config {symbol}")
        if count != 1:
            raise FixError(
                f"{kconfig}: internal error, '{symbol}' defined {count} times")
    inserted = [symbol for symbol, _body in missing]
    print(f"[kconfig] inserted {len(inserted)} config entries before the "
          f"endmenu closing '{SUSFS_MENU}': {', '.join(inserted)}")
    return inserted


def symbol_of(defconfig_line: str) -> str:
    match = re.match(r"^(?:# )?CONFIG_([A-Za-z0-9_]+)(?:=| is not set)", defconfig_line)
    if not match:
        raise FixError(f"internal error: cannot parse defconfig line: {defconfig_line!r}")
    return match.group(1)


def patch_defconfig(defconfig: Path) -> tuple[list[str], list[str]]:
    """Set the SUSFS switches; return (replaced symbols, appended symbols)."""
    text, newline = read_text(defconfig)
    lines = text.split("\n")
    replaced: list[str] = []
    appended: list[str] = []

    for wanted in DEFCONFIG_LINES:
        symbol = symbol_of(wanted)
        pattern = re.compile(
            r"^(?:CONFIG_" + re.escape(symbol) + r"=.*|# CONFIG_"
            + re.escape(symbol) + r" is not set)$")
        hits = [i for i, line in enumerate(lines) if pattern.match(line.strip())]
        if hits:
            lines[hits[0]] = wanted
            # Drop duplicate occurrences so kconfig never sees the symbol twice.
            for extra in reversed(hits[1:]):
                del lines[extra]
            replaced.append(symbol)
        else:
            appended.append(wanted)

    if not replaced and not appended:
        print("[defconfig] all 7 SUSFS lines already correct; nothing to do")
        return [], []

    if appended:
        if text.endswith("\n"):
            body = lines[:-1]  # drop the split() sentinel after the last \n
            body.extend(appended)
            body.append("")
            lines = body
        else:
            lines.extend(appended)
            lines.append("")
    write_text(defconfig, "\n".join(lines), newline)

    # Verify: every owned symbol must occur exactly once now.
    for wanted in DEFCONFIG_LINES:
        symbol = symbol_of(wanted)
        pattern = re.compile(
            r"^(?:CONFIG_" + re.escape(symbol) + r"=.*|# CONFIG_"
            + re.escape(symbol) + r" is not set)$")
        count = sum(1 for line in lines if pattern.match(line.strip()))
        if count != 1:
            raise FixError(
                f"{defconfig}: internal error, CONFIG_{symbol} appears "
                f"{count} times after patching")

    if replaced:
        print(f"[defconfig] updated in place {len(replaced)} existing lines: "
              f"{', '.join(replaced)}")
    if appended:
        print(f"[defconfig] appended {len(appended)} lines: "
              f"{', '.join(symbol_of(line) for line in appended)}")
    return replaced, appended


def resolve_defconfig(kernel_root: Path, arg: str) -> Path:
    path = Path(arg)
    if path.is_absolute():
        return path
    cwd_candidate = Path.cwd() / path
    if cwd_candidate.exists():
        return cwd_candidate
    root_candidate = kernel_root / path
    if root_candidate.exists():
        return root_candidate
    raise FixError(
        f"defconfig not found: tried '{cwd_candidate}' and '{root_candidate}'")


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print(f"usage: {Path(argv[0]).name} <kernel-root> <defconfig-path>",
              file=sys.stderr)
        return 2

    kernel_root = Path(argv[1]).resolve()
    if not kernel_root.is_dir():
        print(f"ERROR: kernel root is not a directory: {kernel_root}", file=sys.stderr)
        return 1

    kconfig = kernel_root / KCONFIG_REL
    if not kconfig.is_file():
        print(f"ERROR: missing Kconfig: {kconfig}", file=sys.stderr)
        return 1

    try:
        defconfig = resolve_defconfig(kernel_root, argv[2])
        if not defconfig.is_file():
            raise FixError(f"defconfig is not a file: {defconfig}")

        print(f"fix_susfs_features: kernel root = {kernel_root}")
        inserted = patch_kconfig(kconfig)
        replaced, appended = patch_defconfig(defconfig)
    except FixError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    print(f"fix_susfs_features: OK "
          f"(Kconfig: {len(inserted)} entries added; "
          f"defconfig: {len(replaced)} lines replaced, {len(appended)} appended)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
