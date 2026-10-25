#!/usr/bin/env python3
"""Mild, reversible M31 (Exynos 9611) performance tuning.

GPU: add a 1152 MHz DVFS step above the stock 1053 MHz top, raise the
driver cap, and let the interactive governor ramp a little earlier.

CPU: the CPU OPP table is owned by ACPM firmware (cal-id ACPM_DVFS_CPUCL0/1),
so the kernel cannot add a frequency.  Instead raise the big-cluster floor
one step (936 -> 1014 MHz) and let schedutil hold boosts slightly longer.

Every edit is anchored exactly once; any drift aborts the build.
"""
import pathlib
import sys

if len(sys.argv) < 2:
    raise SystemExit("usage: perf_tune.py <kernel-root>")

DTS = pathlib.Path(sys.argv[1]) / "arch/arm64/boot/dts/exynos/exynos9610.dts"
text = DTS.read_text(encoding="utf-8")


def sub(old, new):
    global text
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"anchor count {count} (expected 1): {old!r}")
    text = text.replace(old, new, 1)


# --- GPU: add 1152 MHz step above the stock 1053 MHz top -------------------
sub("gpu_dvfs_table_size = <11 7>", "gpu_dvfs_table_size = <12 7>")
sub(
    "gpu_dvfs_table = <  1053000    95  100   1  2093000 1638000       0",
    """gpu_dvfs_table = <  1152000    95  100   1  2093000 1638000       0
		                     1053000    95  100   1  2093000 1638000       0""",
)
sub("gpu_max_clock = <1053000>", "gpu_max_clock = <1152000>")
sub("gpu_max_clock_limit = <1053000>", "gpu_max_clock_limit = <1152000>")
sub("interactive_info = <764000 75 0>", "interactive_info = <839000 80 0>")
sub(
    "gpu_temp_throttling = <764000 572000 455000 338000 260000 260000>",
    "gpu_temp_throttling = <839000 572000 455000 338000 260000 260000>",
)

# --- CPU: ACPM owns the OPP table; raise the big-cluster floor one step -----
sub("min-freq = <936000>", "min-freq = <1014000>")
sub("user-default-qos = <936000>;", "user-default-qos = <1014000>;")
sub("user-default-qos = <702000>;", "user-default-qos = <806000>;")
sub("expired_time = <80>;", "expired_time = <120>;")
sub("upscale_ratio_table = < 80 >;", "upscale_ratio_table = < 90 >;")

DTS.write_text(text, encoding="utf-8")
print(f"perf-tuned: {DTS}")
