# m31-sukisu-kernel

GitHub Actions build for the Exynos 9611 (**Galaxy M31 / `m31`**) LineageOS 24.0 kernel with
**SukiSU-Ultra** (`builtin` branch, manual hooks), **SUSFS v1.5.5** (4.14 port) and an optional
**Performance Edition**.

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
| `perf` | `0` (default) / `1` | `1` applies the M31 Performance Edition |

Artifact name: `Everline-AOSP-<target>-<mode>[-perf]`.

Recommended order: `mode=susfs, perf=0` first (boot + root + hiding verification), then
`mode=susfs, perf=1` as an A/B experiment.

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
- `scripts/perf_tune.py` — opt-in Performance Edition (`perf=1`): valid big-core floor (1040000),
  schedutil and GPU-threshold tuning, BBR + fq kernel defaults, experimental GPU 1152 MHz row, and
  two `gpx_clock.c` index guards so an ACPM-rejected GPU row cannot OOB-write at init.
- `scripts/fix_selinux_features.py` — ports the two SukiSU manager kernel features that upstream
  only implements for >= 5.10 or via kprobes to this 4.14 tree, without kprobes:
  **`selinux_hide`** (id 4, "hide SELinux modifications") and **`avc_spoof`** (id 10003, "AVC log
  spoofing"). It patches `security/selinux/avc.c`, `selinuxfs.c`, `ss/services.c` and
  `fs/proc/base.c`, adds `security/selinux/ksu_selinux_hide.c`, and registers both feature handlers
  in the KernelSU tree. The SUSFS `CMD_SUSFS_ENABLE_AVC_LOG_SPOOFING` command drives the same
  toggle.

## Layout

- `.github/workflows/build.yml` — Ubuntu 22.04 runner, clang-12/lld-12/llvm-12.
- `susfs/` — SUSFS 4.14 sources: `50_add_susfs_in_kernel-4.14.patch`, the 5 hand-ported overlay
  files (`overlay/`), the ported core sources + compat shim (`new/`).
- `.gitattributes` — forces LF in the repository (the scripts run on Linux).

## Pins

| Item | Value |
|---|---|
| Kernel | `Parbindar7/android_kernel_samsung_universal9611` @ `37341a80d83cfc71105eb80a3d56d403cf64a62d` (`lineage-24.0`) |
| SukiSU-Ultra | `builtin` @ `ce75122bec7423e0f1fa06e3e9a174085c5231ab` |
| SUSFS | `susfs4ksu` `kernel-4.14`, v1.5.5 (NON-GKI) |

## Notes

- `CONFIG_KPROBES` is off in `exynos9611-m31_defconfig`; SukiSU `builtin` (manual hooks) is used
  because `main` needs kprobes.
- The zip writes the `boot` partition and replaces its DTB; it does **not** write `dtbo` and does
  **not** patch vbmeta. Match the ROM build to the kernel commit, keep an unlocked bootloader, and
  back up `boot` before flashing.
- Nothing here has been device-verified yet. See the workspace `docs/sukisu/MASTER.md` and
  `docs/sukisu/verification/IMPLEMENTATION_REVIEW.md` for the evidence and the open risks.
