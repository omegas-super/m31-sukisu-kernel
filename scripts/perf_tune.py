#!/usr/bin/env python3
"""M31 / Exynos 9611 "Performance Edition" kernel tuning (opt-in: perf=1).

Performance Edition: kernel-controllable tuning only. CPU frequency/voltage is
ACPM firmware-owned; this is not a CPU overclock. GPU +99 MHz is an ACPM-gated
experiment.

CPU DVFS is owned by ACPM firmware (``cal_dfs_set_rate()``, cal-id
``ACPM_DVFS_CPUCL0``/``ACPM_DVFS_CPUCL1``): the kernel cannot add a CPU OPP,
a CPU voltage or a CPU clock.  What this script can do is raise the big-cluster
floor to an existing stock OPP, bias schedutil/freqvar for responsiveness, and
attempt one GPU row above the stock top (gated by ACPM/CAL at runtime).

The script edits exactly three files under <kernel-root>:

  arch/arm64/boot/dts/exynos/exynos9610.dts        -- 8 DTS edits
  arch/arm64/configs/exynos9611-m31_defconfig      -- 4 network edits (BBR + fq)
  drivers/gpu/arm/exynos/frontend/gpex_clock.c     -- 1 hardening edit

The gpex_clock.c edit is defensive: ``gpex_clock_init_time_in_state()`` indexes
``clk_info.table[gpex_clock_get_table_idx(gpu_max_clock)]`` and writes through
it; if ACPM/CAL does not expose the new 1152 MHz row the index is -1 and the
upstream loop would write ``table[-1]``.  The edit clamps both indices so an
unsupported overclock row can never corrupt memory at init.

DTS edits use anchors that must occur exactly once; any kernel-tree drift
aborts the run before either file is written.  The defconfig edits are
idempotent (an already-applied edit is skipped; a missing anchor whose tuned
value is also absent aborts loudly), so a re-run on a half-tuned tree is safe.

Deliberately NOT applied (they were dead or invalid in the 6d87180 script):

  * ``gpu_max_clock_limit`` -- the built bv_r38p1 driver takes the limit from
    CAL (``gpex_clock.c:89``); only the unbuilt b_r16p0 driver reads the DT
    property, and only with CONFIG_CAL_IF off.
  * ``gpu_temp_throttling`` -- not parsed by the built bv_r38p1 driver.
  * ``user-default-qos`` 702000 -> 806000 -- that property sits in a
    ``cpufreq-domain`` node that exynos-ufc never parses; the live little
    default is already 806000.
  * ``1014000`` -- not a big-core OPP (next stock step above 936000 is
    1040000); an invalid rate would be rejected or rounded by CAL.

usage: python3 perf_tune.py <kernel-root> [--check]
"""
import pathlib
import sys

DTS_REL = "arch/arm64/boot/dts/exynos/exynos9610.dts"
DEFCONFIG_REL = "arch/arm64/configs/exynos9611-m31_defconfig"
GPEX_REL = "drivers/gpu/arm/exynos/frontend/gpex_clock.c"

# gpex_clock_init_time_in_state() hardening (see the module docstring).  The
# anchor is the exact upstream block that indexes the CAL-built table with
# get_table_idx(); a missing clock yields -1 and table[-1] would be written.
GPEX_ANCHOR = (
    "\tint max_clk_idx = gpex_clock_get_table_idx(clk_info.gpu_max_clock);\n"
    "\tint min_clk_idx = gpex_clock_get_table_idx(clk_info.gpu_min_clock);\n"
    "\n"
    "\tfor (i = max_clk_idx; i <= min_clk_idx; i++) {\n"
)
GPEX_FIXED = (
    "\tint max_clk_idx = gpex_clock_get_table_idx(clk_info.gpu_max_clock);\n"
    "\tint min_clk_idx = gpex_clock_get_table_idx(clk_info.gpu_min_clock);\n"
    "\n"
    "\t/* Performance Edition hardening: if ACPM/CAL rejects the extra GPU\n"
    "\t * row, gpex_clock_get_table_idx() returns -1 and the loop below\n"
    "\t * would write table[-1].  Clamp to the valid range so an unsupported\n"
    "\t * OC row cannot corrupt memory during init. */\n"
    "\tif (max_clk_idx < 0)\n"
    "\t\tmax_clk_idx = 0;\n"
    "\tif (min_clk_idx < 0)\n"
    "\t\tmin_clk_idx = clk_info.table_size - 1;\n"
    "\n"
    "\tfor (i = max_clk_idx; i <= min_clk_idx; i++) {\n"
)
GPEX_MARKER = "Performance Edition hardening: if ACPM/CAL rejects"

# Second, same-class hardening: gpex_clock_update_time_in_state() also indexes
# the table with a raw get_table_idx() result; a rejected clock yields -1 and
# the (level >= idx(max)) && (level <= idx(min)) test can pass when both bounds
# are -1, writing table[-1].  Skip accounting for an unknown clock instead.
GPEX_UTIS_ANCHOR = (
    "\tint level = gpex_clock_get_table_idx(clock);\n"
    "\n"
    "\tif (clk_info.prev_time_in_state_time == 0)\n"
)
GPEX_UTIS_FIXED = (
    "\tint level = gpex_clock_get_table_idx(clock);\n"
    "\n"
    "\t/* Performance Edition hardening: an ACPM/CAL-rejected clock yields\n"
    "\t * level == -1; skip time-in-state accounting instead of indexing\n"
    "\t * table[-1]. */\n"
    "\tif (level < 0) {\n"
    "\t\tclk_info.prev_time_in_state_time = get_jiffies_64();\n"
    "\t\treturn 0;\n"
    "\t}\n"
    "\n"
    "\tif (clk_info.prev_time_in_state_time == 0)\n"
)
GPEX_UTIS_MARKER = "skip time-in-state accounting instead of indexing"

# (label, old, new) -- DTS, applied strictly, exactly-once anchors.
DTS_EDITS = [
    (
        "gpu_dvfs_table_size <11 7> -> <12 7>",
        "gpu_dvfs_table_size = <11 7>",
        "gpu_dvfs_table_size = <12 7>",
    ),
    (
        "gpu_dvfs_table: insert 1152 MHz row above 1053 MHz",
        "gpu_dvfs_table = <  1053000    95  100   1  2093000 1638000       0",
        "gpu_dvfs_table = <  1152000    95  100   1  2093000 1638000       0\n"
        "\t\t                     1053000    95  100   1  2093000 1638000       0",
    ),
    (
        "gpu_max_clock 1053000 -> 1152000",
        "gpu_max_clock = <1053000>",
        "gpu_max_clock = <1152000>",
    ),
    (
        "gpu interactive_info <764000 75 0> -> <839000 80 0>",
        "interactive_info = <764000 75 0>",
        "interactive_info = <839000 80 0>",
    ),
    (
        "big-cluster min-freq 936000 -> 1040000",
        "min-freq = <936000>",
        "min-freq = <1040000>",
    ),
    (
        "big-cluster user-default-qos 936000 -> 1040000",
        "user-default-qos = <936000>;",
        "user-default-qos = <1040000>;",
    ),
    (
        "schedutil big expired_time 80 -> 120 ms",
        "expired_time = <80>;    /* 80ms */",
        "expired_time = <120>;   /* 120ms */",
    ),
    (
        "big freqvar upscale_ratio_table <80> -> <90>",
        "upscale_ratio_table = < 80 >;",
        "upscale_ratio_table = < 90 >;",
    ),
]

# (label, old, new, applied-markers) -- defconfig, idempotent.
# NOTE on the qdisc edit: net/sched/Kconfig:349-355 makes DEFAULT_NET_SCH a
# non-prompt string derived from the "Default queuing discipline" choice, so the
# canonical symbol to select is CONFIG_DEFAULT_FQ (line 333).  Setting
# CONFIG_DEFAULT_FQ=y yields CONFIG_DEFAULT_NET_SCH="fq" in the generated
# .config; writing the derived string directly into a defconfig would be
# dropped by savedefconfig.
DEFCONFIG_EDITS = [
    (
        "CONFIG_TCP_CONG_BBR=y",
        "# CONFIG_TCP_CONG_BBR is not set",
        "CONFIG_TCP_CONG_BBR=y",
        ("CONFIG_TCP_CONG_BBR=y",),
    ),
    (
        'CONFIG_DEFAULT_TCP_CONG="bbr"',
        'CONFIG_DEFAULT_TCP_CONG="bic"',
        'CONFIG_DEFAULT_TCP_CONG="bbr"',
        ('CONFIG_DEFAULT_TCP_CONG="bbr"',),
    ),
    (
        "CONFIG_NET_SCH_FQ=y",
        "# CONFIG_NET_SCH_FQ is not set",
        "CONFIG_NET_SCH_FQ=y",
        ("CONFIG_NET_SCH_FQ=y",),
    ),
    (
        "CONFIG_NET_SCH_DEFAULT=y + CONFIG_DEFAULT_FQ=y",
        "# CONFIG_NET_SCH_DEFAULT is not set",
        "CONFIG_NET_SCH_DEFAULT=y\nCONFIG_DEFAULT_FQ=y",
        ("CONFIG_NET_SCH_DEFAULT=y", "CONFIG_DEFAULT_FQ=y"),
    ),
]


def die(msg):
    raise SystemExit("perf-tune: ABORT: " + msg)


def read_text(path):
    if not path.is_file():
        die("missing file: {}".format(path))
    with open(path, "r", encoding="utf-8", newline="") as fh:
        text = fh.read()
    if "\r" in text:
        die("unexpected CR line ending in {}".format(path))
    return text


def write_text(path, text):
    with open(path, "w", encoding="utf-8", newline="") as fh:
        fh.write(text)


def sub_dts(text, old, new, label):
    count = text.count(old)
    if count != 1:
        die(
            "{}: DTS anchor for '{}' found {} time(s), expected exactly 1 "
            "(kernel-tree drift); no files were written".format(DTS_REL, label, count)
        )
    print("  [applied] {}".format(label))
    return text.replace(old, new, 1)


def set_defconfig(text, old, new, markers, label):
    count = text.count(old)
    if count == 1:
        print("  [applied] {}".format(label))
        return text.replace(old, new, 1)
    if count == 0 and all(marker in text for marker in markers):
        print("  [skipped] {} (already applied)".format(label))
        return text
    die(
        "{}: defconfig anchor for '{}' found {} time(s) and the tuned value is "
        "not present (kernel-tree drift); no files were written".format(
            DEFCONFIG_REL, label, count
        )
    )


def validate_gpu_table(text):
    """Programmatic post-check: 12 rows x 7 cells, 1152 MHz on top."""
    marker = "gpu_dvfs_table = <"
    start = text.find(marker)
    if start < 0:
        die("gpu_dvfs_table not found after tuning")
    start += len(marker)
    end = text.find(">;", start)
    if end < 0:
        die("gpu_dvfs_table is not terminated by '>;' after tuning")
    rows = []
    for raw in text[start:end].splitlines():
        row = raw.strip()
        if row:
            rows.append([int(cell) for cell in row.split()])
    if len(rows) != 12:
        die("gpu_dvfs_table has {} rows after tuning, expected 12".format(len(rows)))
    for idx, cells in enumerate(rows):
        if len(cells) != 7:
            die(
                "gpu_dvfs_table row {} has {} cells, expected 7: {}".format(
                    idx, len(cells), cells
                )
            )
    if rows[0][0] != 1152000 or rows[1][0] != 1053000:
        die(
            "gpu_dvfs_table top rows unexpected: {} / {}".format(rows[0], rows[1])
        )
    print("  [verified] gpu_dvfs_table: 12 rows x 7 cells, 1152000 then 1053000")


def validate_defconfig(text):
    required = (
        "CONFIG_TCP_CONG_BBR=y",
        'CONFIG_DEFAULT_TCP_CONG="bbr"',
        "CONFIG_NET_SCH_FQ=y",
        "CONFIG_NET_SCH_DEFAULT=y",
        "CONFIG_DEFAULT_FQ=y",
    )
    missing = [line for line in required if line not in text]
    if missing:
        die("defconfig post-check failed, missing: {}".format(", ".join(missing)))
    print("  [verified] defconfig: BBR default + fq default symbols present")


def patch_gpex_bounds(text):
    """Clamp the time_in_state indices so a rejected GPU row cannot OOB-write."""
    if GPEX_MARKER in text:
        print("  [skipped] gpex_clock_init_time_in_state() hardening (already applied)")
    else:
        count = text.count(GPEX_ANCHOR)
        if count != 1:
            die(
                "{}: gpex_clock_init_time_in_state() anchor found {} time(s), "
                "expected exactly 1 (kernel-tree drift); no files were written".format(
                    GPEX_REL, count
                )
            )
        print("  [applied] gpex_clock_init_time_in_state() index clamp (GPU OC safety)")
        text = text.replace(GPEX_ANCHOR, GPEX_FIXED, 1)

    if GPEX_UTIS_MARKER in text:
        print("  [skipped] gpex_clock_update_time_in_state() guard (already applied)")
        return text
    count = text.count(GPEX_UTIS_ANCHOR)
    if count != 1:
        die(
            "{}: gpex_clock_update_time_in_state() anchor found {} time(s), "
            "expected exactly 1 (kernel-tree drift); no files were written".format(
                GPEX_REL, count
            )
        )
    print("  [applied] gpex_clock_update_time_in_state() level guard (GPU OC safety)")
    return text.replace(GPEX_UTIS_ANCHOR, GPEX_UTIS_FIXED, 1)


def main(argv):
    check_only = "--check" in argv
    args = [arg for arg in argv if not arg.startswith("--")]
    if len(args) != 1:
        raise SystemExit("usage: perf_tune.py <kernel-root> [--check]")

    root = pathlib.Path(args[0])
    dts_path = root / DTS_REL
    defconfig_path = root / DEFCONFIG_REL

    print("perf-tune: kernel root: {}".format(root))

    print("perf-tune: DTS: {}".format(DTS_REL))
    dts_text = read_text(dts_path)
    for label, old, new in DTS_EDITS:
        dts_text = sub_dts(dts_text, old, new, label)
    validate_gpu_table(dts_text)

    print("perf-tune: defconfig: {}".format(DEFCONFIG_REL))
    defconfig_text = read_text(defconfig_path)
    for label, old, new, markers in DEFCONFIG_EDITS:
        defconfig_text = set_defconfig(defconfig_text, old, new, markers, label)
    validate_defconfig(defconfig_text)

    print("perf-tune: driver hardening: {}".format(GPEX_REL))
    gpex_text = patch_gpex_bounds(read_text(root / GPEX_REL))

    if check_only:
        print("perf-tune: --check: all anchors resolved, nothing written")
        return

    write_text(dts_path, dts_text)
    write_text(defconfig_path, defconfig_text)
    write_text(root / GPEX_REL, gpex_text)
    print("perf-tune: wrote 3 files; rebuild required")
    print("perf-tune: NOTE: CPU frequency/voltage is ACPM firmware-owned (no CPU OC).")
    print(
        "perf-tune: NOTE: GPU 1152 MHz is an ACPM-gated, on-device-unverified "
        "experiment."
    )


if __name__ == "__main__":
    main(sys.argv[1:])
