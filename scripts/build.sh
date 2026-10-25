#!/usr/bin/env bash
set -euo pipefail

MODE="${1:-stock}"
TARGET="${2:-m31}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SUSFS_DIR="$SCRIPT_DIR/../susfs"

KERNEL_REPO="${KERNEL_REPO:-https://github.com/Parbindar7/android_kernel_samsung_universal9611.git}"
KERNEL_BRANCH="${KERNEL_BRANCH:-lineage-24.0}"
KERNEL_SHA="${KERNEL_SHA:-37341a80d83cfc71105eb80a3d56d403cf64a62d}"
SUKISU_REPO="${SUKISU_REPO:-https://github.com/SukiSU-Ultra/SukiSU-Ultra.git}"
SUKISU_BRANCH="${SUKISU_BRANCH:-builtin}"
SUKISU_SHA="${SUKISU_SHA:-ce75122bec7423e0f1fa06e3e9a174085c5231ab}"
WORK="${WORK:-$PWD/work}"

log() { printf '\n[%s] %s\n' "$(date -u +%H:%M:%S)" "$*"; }

mkdir -p "$WORK"
cd "$WORK"

if [ ! -d kernel/.git ]; then
  log "Cloning $KERNEL_REPO ($KERNEL_BRANCH)"
  git clone --depth 1 -b "$KERNEL_BRANCH" "$KERNEL_REPO" kernel
fi

if [ -n "${KERNEL_SHA:-}" ]; then
  log "Pinning kernel to $KERNEL_SHA"
  git -C kernel fetch --depth 1 origin "$KERNEL_SHA" || true
  git -C kernel checkout "$KERNEL_SHA"
fi

cd kernel

# --- toolchain: clang-12 + lld-12 + llvm-12 from Ubuntu 22.04 ----------------
if [ ! -x toolchain/bin/clang ]; then
  log "Creating toolchain/bin symlinks"
  mkdir -p toolchain/bin
  for t in clang clang++ ld.lld llvm-ar llvm-nm llvm-objcopy llvm-objdump \
           llvm-readelf llvm-as llvm-strip; do
    if [ -x "/usr/bin/${t}-12" ]; then
      ln -sf "/usr/bin/${t}-12" "toolchain/bin/$t"
    elif command -v "$t" >/dev/null 2>&1; then
      ln -sf "$(command -v "$t")" "toolchain/bin/$t"
    else
      echo "ERROR: missing tool $t" >&2
      exit 1
    fi
  done
fi

# CI builds do not need debug info (saves ~10 GB and a lot of time)
if [ "${CI:-}" = "true" ]; then
  sed -i 's/^CONFIG_DEBUG_INFO=y/# CONFIG_DEBUG_INFO is not set/' \
    "arch/arm64/configs/exynos9611-${TARGET}_defconfig"
fi

if [ "$MODE" != "stock" ]; then
  log "Vendoring SukiSU ($SUKISU_BRANCH) into drivers/kernelsu"
  if [ ! -d "$WORK/sukisu/.git" ]; then
    git clone -b "$SUKISU_BRANCH" --single-branch "$SUKISU_REPO" "$WORK/sukisu"
  fi
  if [ -n "${SUKISU_SHA:-}" ]; then
    log "Pinning SukiSU to $SUKISU_SHA"
    git -C "$WORK/sukisu" checkout "$SUKISU_SHA"
  fi
  rm -rf drivers/kernelsu
  mkdir -p drivers/kernelsu
  cp -a "$WORK/sukisu/kernel/." drivers/kernelsu/
  python3 "$SCRIPT_DIR/fix_builtin.py" drivers/kernelsu

  grep -q 'source "drivers/kernelsu/Kconfig"' drivers/Kconfig || \
    echo 'source "drivers/kernelsu/Kconfig"' >> drivers/Kconfig
  grep -q 'kernelsu/' drivers/Makefile || \
    echo 'obj-$(CONFIG_KSU) += kernelsu/' >> drivers/Makefile

  printf '%s\n' \
    'CONFIG_KSU=y' \
    'CONFIG_KSU_FEATURE_ADBROOT=y' \
    '# CONFIG_KSU_DEBUG is not set' \
    '# CONFIG_KPM is not set' \
    >> "arch/arm64/configs/exynos9611-${TARGET}_defconfig"
fi

if [ "$MODE" = "susfs" ]; then
  log "Applying SUSFS 4.14 kernel patch"
  # 17 upstream files are patched; 5 of them carry Samsung/RKP
  # conditionals that the stock patch cannot apply cleanly.  Those 5 are
  # hand-ported under susfs/overlay and copied over the tree below.
  git apply --reject "$SUSFS_DIR/50_add_susfs_in_kernel-4.14.patch" || true
  cp -a "$SUSFS_DIR/overlay/." .

  log "Installing SUSFS core sources + compatibility shim"
  cp -a "$SUSFS_DIR/new/fs/." fs/
  cp -a "$SUSFS_DIR/new/include/linux/." include/linux/
  grep -q 'susfs_compat.o' fs/Makefile || \
    echo 'obj-$(CONFIG_KSU_SUSFS) += susfs_compat.o' >> fs/Makefile
  grep -q 'sus_su.o' fs/Makefile || \
    echo 'obj-$(CONFIG_KSU_SUSFS_SUS_SU) += sus_su.o' >> fs/Makefile

  # Rejects are expected only for the 5 overlaid files; anything else
  # means the pinned kernel tree drifted.  Show and remove them all.
  find . -name '*.rej' -not -path './.git/*' -print -delete

  sed -i '/^# CONFIG_KSU_SUSFS is not set$/d' \
    "arch/arm64/configs/exynos9611-${TARGET}_defconfig"
  printf '%s\n' \
    'CONFIG_KSU_SUSFS=y' \
    'CONFIG_KSU_SUSFS_SUS_PATH=y' \
    'CONFIG_KSU_SUSFS_SUS_MOUNT=y' \
    'CONFIG_KSU_SUSFS_SUS_KSTAT=y' \
    'CONFIG_KSU_SUSFS_SPOOF_UNAME=y' \
    'CONFIG_KSU_SUSFS_ENABLE_LOG=y' \
    'CONFIG_KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG=y' \
    'CONFIG_KSU_SUSFS_OPEN_REDIRECT=y' \
    '# CONFIG_KSU_SUSFS_SUS_MAP is not set' \
    >> "arch/arm64/configs/exynos9611-${TARGET}_defconfig"

  log "Applying SukiSU hooks (susfs mode adds setresuid)"
  python3 "$SCRIPT_DIR/patch_hooks.py" "$PWD" susfs
elif [ "$MODE" = "ksu" ]; then
  log "Applying SukiSU manual hooks"
  python3 "$SCRIPT_DIR/patch_hooks.py" "$PWD" ksu
fi

log "Building target=$TARGET mode=$MODE"
python3 build_kernel.py --target "$TARGET"

log "Build artifacts"
ls -l Everline-AOSP_"${TARGET}"_*.zip
