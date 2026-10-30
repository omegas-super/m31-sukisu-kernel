# m31-sukisu-kernel

GitHub Actions build for the Exynos 9611 (**Galaxy M31 / `m31`**) LineageOS 24.0 kernel with
**SukiSU-Ultra** (`builtin` branch at `6397fcb5`, manual hooks), **SUSFS v1.5.5** (4.14 port) and an
optional **Performance Edition**.  It also backports the SUSFS 2.x **priority-UID filter**, the
SukiSU **SELinux-hide / AVC-spoof** features, and a kernel-level **bootloader-locked spoof**.

The runner clones the upstream kernel
[`Parbindar7/android_kernel_samsung_universal9611`](https://github.com/Parbindar7/android_kernel_samsung_universal9611)
(`lineage-24.0`, pinned), vendors SukiSU's `kernel/` directory as `drivers/kernelsu`, applies the
4.14 fixes + manual hooks, optionally applies the SUSFS 4.14 patch/overlay, and runs the tree's own
`build_kernel.py --target m31`. The result is an AnyKernel3 zip (writes `boot` only).

## Run

Actions -> **build-m31** -> *Run workflow*:

| input | values | meaning |
|---|---|---|
| `mode` | `stock` | unmodified kernel, pipeline sanity check |
| `mode` | `ksu` | SukiSU `builtin`, root only (no SUSFS) |
| `mode` | `susfs` | SukiSU `builtin` + SUSFS 4.14 (root + hiding) |
| `target` | `m31` (default), `m31s`, `a51`, `f41`, `m21` | device |
| `perf` | `0` (default) / `1` / `2` / `3` | performance profile: `0` stock, `1` Performance Edition (safe), `2` Extreme (GPU/CPU OC), `3` MAX 24/7 (top clocks pinned) |

Artifact name: `Everline-AOSP-<target>-<mode>[-perf<N>]`, plus a matching `-raw` artifact containing
the raw `Image`, `dtb` and `SHA256SUMS` for boot-image patchers (folpatch / Magisk-boot style).

Recommended order: `mode=susfs, perf=0` first (boot + root + hiding verification), then the perf
profiles one at a time (`perf=1` → `2` → `3`) as A/B experiments.

### Performance profiles

| perf | Name | What changes |
|---|---|---|
| `0` | stock | nothing |
| `1` | Performance Edition (safe) | GPU 1152 MHz row, big floor 1.04 GHz, schedutil + GPU-threshold tuning, BBR + fq |
| `2` | Extreme | + GPU floor 385 MHz, GPU DVFS polling 5 ms, interactive 949 MHz/90 %, big floor 1.456 GHz, little floor 806 MHz, big/G3D control-temp trips +8 °C |
| `3` | MAX 24/7 | + CPU floors pinned to the top CAL OPP of both clusters (2.314 / 1.742 GHz), default governor `performance`, GPU floor 546 MHz, control-temp trips +15 °C |

**CPU MHz/voltage is ACPM-firmware-owned** (`cal_id ACPM_DVFS_CPUCL0/1`, no CPU OPP table): profiles
2/3 pin the CPU *floor* to existing CAL OPPs so the governor cannot scale down — they cannot add MHz
above the stock top OPP. The GPU 1152 MHz row and all raised thermal trips are ACPM-gated
experiments.

## What the scripts do

- `scripts/build.sh` — clone + pin kernel and SukiSU, vendor, patch, build, package.
- `scripts/fix_builtin.py` — 4.14 header/API fixes; **B1**: rewrite the SUSFS-mode
  `faccessat`/`stat` hooks to the 4.14 `const char __user **` ABI (the struct-filename variant
  oopsed on boot); **B2b**: run `susfs_set_batch_sid()` from the 4.14 `apply_kernelsu_rules()`;
  **B3**: mode-aware `USER_ARG_NULL` fix so `mode=ksu` builds again.
- `scripts/patch_hooks.py` — idempotent manual hook insertion (`execveat`, `faccessat`, `stat`,
  `vfs_read`, `reboot`, `input`, plus `setresuid` for SUSFS).
- `scripts/fix_susfs_features.py` — adds the SUSFS 4.14 feature switches that SukiSU `builtin`'s
  Kconfig lacks (TRY_UMOUNT / auto-add / HAS_MAGIC_MOUNT / SUS_SU) and sets the safe subset in the
  defconfig (`AUTO_ADD_SUS_BIND_MOUNT`, `AUTO_ADD_SUS_KSU_DEFAULT_MOUNT`,
  `HIDE_KSU_SUSFS_SYMBOLS`; TRY_UMOUNT stays off — no drain path on this port).
- `scripts/perf_tune.py` — opt-in performance profiles (`perf=1|2|3`, see the table above). Profile 1
  is the safe Performance Edition (big-core floor 1040000, schedutil + GPU-threshold tuning, BBR + fq,
  experimental GPU 1152 MHz row); profile 2 adds a 385 MHz GPU floor, faster GPU DVFS polling,
  aggressive interactive thresholds, a 1.456 GHz big floor / 806 MHz little floor and +8 °C control
  temps; profile 3 pins both CPU floors to the top CAL OPP (2314000 / 1742000) with the
  `performance` governor as default, a 546 MHz GPU floor and +15 °C control temps. Thermal trips are
  raised brace-scoped per zone, so the little/ISP zones stay stock. Two `gpex_clock.c` index guards
  keep an ACPM-rejected GPU row from OOB-writing at init.
- `scripts/fix_selinux_features.py` — ports the two SukiSU manager kernel features that upstream
  only implements for >= 5.10 or via kprobes to this 4.14 tree, without kprobes:
  **`selinux_hide`** (id 4, "hide SELinux modifications") and **`avc_spoof`** (id 10003, "AVC log
  spoofing"). It patches `security/selinux/avc.c`, `selinuxfs.c`, `ss/services.c` and
  `fs/proc/base.c`, adds `security/selinux/ksu_selinux_hide.c`, and registers both feature handlers
  in the KernelSU tree. The SUSFS `CMD_SUSFS_ENABLE_AVC_LOG_SPOOFING` command drives the same
  toggle.
- `scripts/fix_best_spoof.py` — **bootloader-locked / verified-boot spoof** and the syscall hooks
  for the **priority-UID filter**:
  - new `fs/ksu_boot_spoof.c` rewrites `androidboot.verifiedbootstate=green`,
    `androidboot.flash.locked=1`, `androidboot.vbmeta.device_state=locked`,
    `androidboot.warranty_bit=0` (and `warranty_bit=0`) in `/proc/cmdline` before init derives
    `ro.boot.*` from it, and in the DT `/chosen/bootargs` property.  The real AVB decision is
    untouched; boot-critical tokens (`veritymode`, vbmeta metadata) are deliberately left to the
    manager's hide-BL userspace script.  Opt out with the `ksu_nobootspoof` kernel cmdline token.
  - adds the `getpriority`/`setpriority`/`ioprio_set`/`ioprio_get` hooks used by the SUSFS 2.x
    **priority-UID filter** (the filter itself lives in `fs/susfs_compat.c`; userspace ABI
    `CMD_SUSFS_SET_PRIORITY_UID_FILTER = 0x60030`, SukiSU manager's "Priority UID filter" tab).

## Layout

- `.github/workflows/build.yml` — Ubuntu 22.04 runner, clang-12/lld-12/llvm-12.
- `susfs/` — SUSFS 4.14 sources: `50_add_susfs_in_kernel-4.14.patch`, the 5 hand-ported overlay
  files (`overlay/`), the ported core sources + compat shim (`new/`).
- `.gitattributes` — forces LF in the repository (the scripts run on Linux).

## Pins

| Item | Value |
|---|---|
| Kernel | `Parbindar7/android_kernel_samsung_universal9611` @ `37341a80d83cfc71105eb80a3d56d403cf64a62d` (`lineage-24.0`) |
| SukiSU-Ultra | `builtin` @ `b16e899a555e9b96aa1225f049cd7274820ca5b8` |
| SUSFS | `susfs4ksu` `kernel-4.14`, v1.5.5 (NON-GKI) — unchanged upstream since the tag |

## Notes

- `CONFIG_KPROBES` is off in `exynos9611-m31_defconfig`; SukiSU `builtin` (manual hooks) is used
  because `main` needs kprobes.
- The zip writes the `boot` partition and replaces its DTB; it does **not** write `dtbo` and does
  **not** patch vbmeta. Match the ROM build to the kernel commit, keep an unlocked bootloader, and
  back up `boot` before flashing.
- **folpatch / boot-image patchers:** every build also publishes a `-raw` artifact with the raw
  `Image`, `dtb` and `SHA256SUMS`, so the boot image can be patched instead of flashing the AK3 zip.
- The kernel-level bootloader spoof is **opt-in** (`ksu_bootspoof` kernel cmdline token, default
  OFF) after the 2026-10-26 bootloop; the manager's Shamiko-derived Hide BL script is the safe path.
- Nothing here has been device-verified yet. See the workspace `docs/sukisu/MASTER.md` and
  `docs/sukisu/verification/IMPLEMENTATION_REVIEW.md` for the evidence and the open risks.
