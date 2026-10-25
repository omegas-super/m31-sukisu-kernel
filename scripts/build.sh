#!/usr/bin/env bash
set -euo pipefail

MODE="${1:-stock}"
TARGET="${2:-m31}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

KERNEL_REPO="${KERNEL_REPO:-https://github.com/Parbindar7/android_kernel_samsung_universal9611.git}"
KERNEL_BRANCH="${KERNEL_BRANCH:-lineage-24.0}"
SUKISU_REPO="${SUKISU_REPO:-https://github.com/SukiSU-Ultra/SukiSU-Ultra.git}"
SUKISU_BRANCH="${SUKISU_BRANCH:-builtin}"
WORK="${WORK:-$PWD/work}"

log() { printf '\n[%s] %s\n' "$(date -u +%H:%M:%S)" "$*"; }

mkdir -p "$WORK"
cd "$WORK"

if [ ! -d kernel/.git ]; then
  log "Cloning $KERNEL_REPO ($KERNEL_BRANCH)"
  git clone --depth 1 -b "$KERNEL_BRANCH" "$KERNEL_REPO" kernel
fi

cd kernel

# --- toolchain: clang-12 + lld-12 + llvm-12 from Ubuntu 22.04 -----------------
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
    git clone --depth 1 -b "$SUKISU_BRANCH" "$SUKISU_REPO" "$WORK/sukisu"
  fi
  rm -rf drivers/kernelsu
  mkdir -p drivers/kernelsu
  cp -a "$WORK/sukisu/kernel/." drivers/kernelsu/
  python3 "$SCRIPT_DIR/fix_builtin.py" drivers/kernelsu

  grep -q 'source "drivers/kernelsu/Kconfig"' drivers/Kconfig || \
    echo 'source "drivers/kernelsu/Kconfig"' >> drivers/Kconfig
  grep -q 'kernelsu/' drivers/Makefile || \
    echo 'obj-$(CONFIG_KSU) += kernelsu/' >> drivers/Makefile

  cat >> "arch/arm64/configs/exynos9611-${TARGET}_defconfig" <<'EOF'
CONFIG_KSU=y
CONFIG_KSU_FEATURE_ADBROOT=y
# CONFIG_KSU_DEBUG is not set
# CONFIG_KPM is not set
# CONFIG_KSU_SUSFS is not set
EOF

  log "Applying SukiSU manual hooks"
  python3 "$SCRIPT_DIR/patch_hooks.py" "$PWD" "$MODE"
fi

if [ "$MODE" = "susfs" ]; then
  log "SUSFS mode is not wired yet"
  exit 2
fi

log "Building target=$TARGET mode=$MODE"
python3 build_kernel.py --target "$TARGET"

log "Build artifacts"
ls -l Everline-AOSP_"${TARGET}"_*.zip
