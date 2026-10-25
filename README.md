# m31-sukisu-kernel

GitHub Actions build for the Exynos 9611 (Galaxy M31 / `m31`) LineageOS 24.0
kernel with **SukiSU-Ultra** (`builtin` branch) integrated.

The runner clones the upstream kernel
[`Parbindar7/android_kernel_samsung_universal9611`](https://github.com/Parbindar7/android_kernel_samsung_universal9611)
(`lineage-24.0`), vendors SukiSU's `kernel/` directory as `drivers/kernelsu`,
inserts the manual hooks, and runs the tree's own `build_kernel.py --target m31`.
The resulting `Everline-AOSP_m31_<date>.zip` is an AnyKernel3 zip (boot + dtbo).

## Run

Actions -> **build-m31** -> Run workflow:

| input | values | meaning |
|---|---|---|
| `mode` | `stock` | unmodified kernel, pipeline sanity check |
| `mode` | `ksu` | SukiSU `builtin`, root only (no SUSFS yet) |
| `target` | `m31` | Galaxy M31 (SM-M315F) |

## Layout

- `.github/workflows/build.yml` — Ubuntu 22.04 runner, clang-12 toolchain.
- `scripts/build.sh` — clone kernel + SukiSU, vendor, patch, build.
- `scripts/patch_hooks.py` — idempotent manual-hook insertion for 4.14:
  `execveat`, `faccessat`, `vfs_statx`, `vfs_read`, `sys_reboot`
  (plus `setresuid` when SUSFS is enabled).

## Notes

- `CONFIG_KPROBES` is off in `exynos9611-m31_defconfig`; SukiSU `builtin`
  (manual hooks) is used because `main` needs kprobes.
- `CONFIG_KSU_SUSFS` is explicitly disabled for the root-only build.
- The zip flashes `boot`; `anykernel.sh` defines `dtboblock` but does not write
  it, so `dtbo` must already match the ROM (or be flashed separately).
