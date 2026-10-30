#!/usr/bin/env python3
"""M31 / Exynos 9611 performance profiles (PERF_TUNE=1|2|3).

Three escalating profiles, all kernel-side and ACPM-safe:

  1  PERFORMANCE EDITION (safe)   -- GPU +99 MHz row, big-core floor at a valid
                                     stock OPP, schedutil/GPU-threshold tuning,
                                     BBR + fq.  Thermals untouched.
  2  EXTREME (OC)                 -- profile 1 plus: higher GPU floor, faster GPU
                                     DVFS polling, aggressive interactive
                                     thresholds, higher big/little floors,
                                     control-temp trips raised ~8 C.
  3  MAX 24/7                     -- profile 2 plus: CPU floor pinned to the TOP
                                     CAL OPP of both clusters (2.31 GHz big /
                                     1.74 GHz little), default governor
                                     `performance`, GPU floor 546 MHz, control
                                     temps raised ~15 C.  Sustained top clocks.

CPU frequency/voltage itself is ACPM firmware-owned: there is no CPU OPP table,
no CPU regulator and no `cal_dfs_set_rate()` path in this kernel, so a real
"more MHz than the top OPP" CPU overclock is impossible.  What these profiles do
is (a) raise the GPU table by one row above stock, (b) pin the CPU *floor* to the
highest existing CAL OPP so the governor cannot scale down, and (c) relax the
thermal control points.  Everything else (scheduler, network, GPU DVFS) is
tuning, not overclocking.

usage: perf_tune.py <kernel-root> [--profile N] [--check]
"""
import pathlib
import sys

DTS_REL = "arch/arm64/boot/dts/exynos/exynos9610.dts"
DEFCONFIG_REL = "arch/arm64/configs/exynos9611-m31_defconfig"
GPEX_REL = "drivers/gpu/arm/exynos/frontend/gpex_clock.c"

PROFILE_NAMES = {
    1: "PERFORMANCE EDITION (safe)",
    2: "EXTREME (GPU/CPU OC)",
    3: "MAX 24/7 (top clocks pinned)",
}

# --- gpex_clock.c hardening (needed by every profile that adds a GPU row) ----
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

# --- DTS edits shared by every profile --------------------------------------
DTS_EDITS_BASE = [
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

# profile -> list of (label, old, new) applied after DTS_EDITS_BASE
DTS_EDITS_BY_PROFILE = {
    1: [
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
    ],
    2: [
        (
            "gpu interactive_info <764000 75 0> -> <949000 90 0>",
            "interactive_info = <764000 75 0>",
            "interactive_info = <949000 90 0>",
        ),
        (
            "gpu_min_clock 260000 -> 385000",
            "gpu_min_clock = <260000>",
            "gpu_min_clock = <385000>",
        ),
        (
            "gpu_dvfs_start_clock 260000 -> 385000",
            "gpu_dvfs_start_clock = <260000>",
            "gpu_dvfs_start_clock = <385000>",
        ),
        (
            "gpu_dvfs_bl_config_clock 260000 -> 385000",
            "gpu_dvfs_bl_config_clock = <260000>",
            "gpu_dvfs_bl_config_clock = <385000>",
        ),
        (
            "gpu_dvfs_polling_time 10 -> 5",
            "gpu_dvfs_polling_time = <10>",
            "gpu_dvfs_polling_time = <5>",
        ),
        (
            "big-cluster min-freq 936000 -> 1456000",
            "min-freq = <936000>",
            "min-freq = <1456000>",
        ),
        (
            "little-cluster min-freq 403000 -> 806000",
            "min-freq = <403000>",
            "min-freq = <806000>",
        ),
        (
            "big-cluster user-default-qos 936000 -> 1456000",
            "user-default-qos = <936000>;",
            "user-default-qos = <1456000>;",
        ),
    ],
    3: [
        (
            "gpu interactive_info <764000 75 0> -> <1053000 95 0>",
            "interactive_info = <764000 75 0>",
            "interactive_info = <1053000 95 0>",
        ),
        (
            "gpu_min_clock 260000 -> 546000",
            "gpu_min_clock = <260000>",
            "gpu_min_clock = <546000>",
        ),
        (
            "gpu_dvfs_start_clock 260000 -> 546000",
            "gpu_dvfs_start_clock = <260000>",
            "gpu_dvfs_start_clock = <546000>",
        ),
        (
            "gpu_dvfs_bl_config_clock 260000 -> 546000",
            "gpu_dvfs_bl_config_clock = <260000>",
            "gpu_dvfs_bl_config_clock = <546000>",
        ),
        (
            "gpu_dvfs_polling_time 10 -> 5",
            "gpu_dvfs_polling_time = <10>",
            "gpu_dvfs_polling_time = <5>",
        ),
        (
            "big-cluster min-freq 936000 -> 2314000 (top CAL OPP)",
            "min-freq = <936000>",
            "min-freq = <2314000>",
        ),
        (
            "little-cluster min-freq 403000 -> 1742000 (top CAL OPP)",
            "min-freq = <403000>",
            "min-freq = <1742000>",
        ),
        (
            "big-cluster user-default-qos 936000 -> 2314000",
            "user-default-qos = <936000>;",
            "user-default-qos = <2314000>;",
        ),
    ],
}

# thermal: (zone marker, delta millicelsius, minimum trip to touch)
DTS_THERMAL = {
    1: [],
    2: [("big_thermal: BIG {", 8000, 83000), ("gpu_thermal: G3D {", 8000, 88000)],
    3: [("big_thermal: BIG {", 15000, 83000), ("gpu_thermal: G3D {", 15000, 88000)],
}

# --- defconfig edits --------------------------------------------------------
DEFCONFIG_NET = [
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

# profile 3 only: make `performance` the boot governor so both clusters sit on
# their top OPP from first boot (belt-and-braces with the pinned floor).
DEFCONFIG_PERF_GOV = [
    (
        "CONFIG_CPU_FREQ_DEFAULT_GOV_PERFORMANCE=y (default governor)",
        "CONFIG_CPU_FREQ_DEFAULT_GOV_SCHEDUTIL=y",
        "CONFIG_CPU_FREQ_DEFAULT_GOV_PERFORMANCE=y",
        ("CONFIG_CPU_FREQ_DEFAULT_GOV_PERFORMANCE=y",),
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
    if count == 1:
        print("  [applied] {}".format(label))
        return text.replace(old, new, 1)
    if count == 0 and new in text:
        print("  [skipped] {} (already applied)".format(label))
        return text
    die(
        "{}: DTS anchor for '{}' found {} time(s), expected exactly 1 "
        "(kernel-tree drift); no files were written".format(DTS_REL, label, count)
    )


def raise_zone_trips(text, zone_marker, delta, min_temp):
    """Add `delta` millicelsius to every >= min_temp trip inside one zone.

    Brace-scoped so the little/ISP zones are untouched even though several of
    them share the same trip temperatures.
    """
    start = text.find(zone_marker)
    if start < 0:
        die("{}: thermal zone '{}' not found".format(DTS_REL, zone_marker))
    open_at = text.find("{", start)
    if open_at < 0:
        die("{}: thermal zone '{}' has no body".format(DTS_REL, zone_marker))
    depth = 0
    end = None
    for idx in range(open_at, len(text)):
        ch = text[idx]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                end = idx + 1
                break
    if end is None:
        die("{}: unbalanced braces in thermal zone '{}'".format(DTS_REL, zone_marker))

    body = text[open_at:end]
    changed = 0

    def bump(match):
        nonlocal changed
        value = int(match.group(1))
        if value < min_temp:
            return match.group(0)
        changed += 1
        return "temperature = <{}>;".format(value + delta)

    import re

    new_body = re.sub(r"temperature = <(\d+)>;", bump, body)
    if not changed:
        die(
            "{}: no trip >= {} mC found in zone '{}'".format(
                DTS_REL, min_temp, zone_marker
            )
        )
    print(
        "  [applied] {}: {} trips raised by {} mC".format(
            zone_marker.strip(), changed, delta
        )
    )
    return text[:open_at] + new_body + text[end:]


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


def validate_gpu_table(text, expect_top):
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
    if rows[0][0] != expect_top or rows[1][0] != 1053000:
        die("gpu_dvfs_table top rows unexpected: {} / {}".format(rows[0], rows[1]))
    print(
        "  [verified] gpu_dvfs_table: 12 rows x 7 cells, {} then 1053000".format(
            expect_top
        )
    )


def validate_defconfig(text, profile):
    required = [
        "CONFIG_TCP_CONG_BBR=y",
        'CONFIG_DEFAULT_TCP_CONG="bbr"',
        "CONFIG_NET_SCH_FQ=y",
        "CONFIG_NET_SCH_DEFAULT=y",
        "CONFIG_DEFAULT_FQ=y",
    ]
    if profile >= 3:
        required.append("CONFIG_CPU_FREQ_DEFAULT_GOV_PERFORMANCE=y")
    missing = [line for line in required if line not in text]
    if missing:
        die("defconfig post-check failed, missing: {}".format(", ".join(missing)))
    print("  [verified] defconfig: {}".format(", ".join(required)))


def patch_gpex_bounds(text):
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


def parse_args(argv):
    profile = 1
    check_only = "--check" in argv
    rest = [arg for arg in argv if not arg.startswith("--")]
    root = None
    idx = 0
    while idx < len(rest):
        arg = rest[idx]
        if arg == "profile":
            idx += 1
            if idx >= len(rest):
                raise SystemExit("usage: perf_tune.py <kernel-root> [--profile N] [--check]")
            profile = int(rest[idx])
        elif arg.isdigit() and root is not None:
            profile = int(arg)
        elif root is None:
            root = arg
        idx += 1
    if root is None:
        raise SystemExit("usage: perf_tune.py <kernel-root> [--profile N] [--check]")
    if profile not in PROFILE_NAMES:
        raise SystemExit("unknown profile {} (expected 1, 2 or 3)".format(profile))
    return pathlib.Path(root), profile, check_only


def main(argv):
    root, profile, check_only = parse_args(argv)
    dts_path = root / DTS_REL
    defconfig_path = root / DEFCONFIG_REL

    print("perf-tune: kernel root: {}".format(root))
    print("perf-tune: profile {} = {}".format(profile, PROFILE_NAMES[profile]))

    print("perf-tune: DTS: {}".format(DTS_REL))
    dts_text = read_text(dts_path)
    for label, old, new in DTS_EDITS_BASE + DTS_EDITS_BY_PROFILE[profile]:
        dts_text = sub_dts(dts_text, old, new, label)
    validate_gpu_table(dts_text, 1152000)
    for zone, delta, min_temp in DTS_THERMAL[profile]:
        dts_text = raise_zone_trips(dts_text, zone, delta, min_temp)

    print("perf-tune: defconfig: {}".format(DEFCONFIG_REL))
    defconfig_text = read_text(defconfig_path)
    edits = list(DEFCONFIG_NET)
    if profile >= 3:
        edits += DEFCONFIG_PERF_GOV
    for label, old, new, markers in edits:
        defconfig_text = set_defconfig(defconfig_text, old, new, markers, label)
    validate_defconfig(defconfig_text, profile)

    print("perf-tune: driver hardening: {}".format(GPEX_REL))
    gpex_text = patch_gpex_bounds(read_text(root / GPEX_REL))

    if check_only:
        print("perf-tune: --check: all anchors resolved, nothing written")
        return

    write_text(dts_path, dts_text)
    write_text(defconfig_path, defconfig_text)
    write_text(root / GPEX_REL, gpex_text)
    print("perf-tune: wrote 3 files; rebuild required")
    print(
        "perf-tune: NOTE: CPU MHz/voltage is ACPM firmware-owned -- profiles 2/3 "
        "pin the CPU *floor* to existing CAL OPPs, they cannot add MHz."
    )
    print(
        "perf-tune: NOTE: GPU 1152 MHz and the raised thermal trips are "
        "ACPM-gated, on-device-unverified experiments."
    )


if __name__ == "__main__":
    main(sys.argv[1:])
