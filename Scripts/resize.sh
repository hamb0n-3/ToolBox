#!/bin/bash
# =============================================================================
# resize_vm_disk.sh — Resize a VM disk partition + filesystem after enlargement
# Tested on: Kali Linux (also works on Debian/Ubuntu-based VMs)
# Run as:    sudo bash resize_vm_disk.sh
# =============================================================================

set -euo pipefail

# ── Colour helpers ────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

info()    { echo -e "${CYAN}[INFO]${RESET}  $*"; }
success() { echo -e "${GREEN}[OK]${RESET}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${RESET}  $*"; }
error()   { echo -e "${RED}[ERROR]${RESET} $*" >&2; exit 1; }

# ── Root check ────────────────────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && error "This script must be run as root. Try: sudo bash $0"

echo -e "\n${BOLD}╔══════════════════════════════════════════╗"
echo -e "║      VM Disk Resize Utility (Kali)       ║"
echo -e "╚══════════════════════════════════════════╝${RESET}\n"

# ── Detect root disk and partition ───────────────────────────────────────────
info "Detecting root filesystem..."

ROOT_DEV=$(findmnt -n -o SOURCE /)           # e.g. /dev/sda1 or /dev/nvme0n1p1
FS_TYPE=$(findmnt -n -o FSTYPE /)            # e.g. ext4, xfs, btrfs

# Strip partition number to get the base disk
if [[ "$ROOT_DEV" =~ (nvme[0-9]+n[0-9]+)p([0-9]+)$ ]]; then
    DISK="/dev/${BASH_REMATCH[1]}"
    PART_NUM="${BASH_REMATCH[2]}"
elif [[ "$ROOT_DEV" =~ ([a-z]+)([0-9]+)$ ]]; then
    DISK="/dev/${BASH_REMATCH[1]}"
    PART_NUM="${BASH_REMATCH[2]}"
else
    error "Could not parse device: $ROOT_DEV"
fi

echo -e "  Root device : ${BOLD}$ROOT_DEV${RESET}"
echo -e "  Base disk   : ${BOLD}$DISK${RESET}"
echo -e "  Partition # : ${BOLD}$PART_NUM${RESET}"
echo -e "  Filesystem  : ${BOLD}$FS_TYPE${RESET}\n"

# ── Check for LVM ─────────────────────────────────────────────────────────────
IS_LVM=false
if command -v lvdisplay &>/dev/null && lvdisplay "$ROOT_DEV" &>/dev/null 2>&1; then
    IS_LVM=true
    LV_PATH="$ROOT_DEV"
    # Find the underlying PV/VG
    VG_NAME=$(lvdisplay "$LV_PATH" 2>/dev/null | awk '/VG Name/{print $3}')
    PV_DEV=$(pvdisplay 2>/dev/null | awk '/PV Name/{print $3}' | head -1)
    info "LVM detected — LV: $LV_PATH | VG: $VG_NAME | PV: $PV_DEV"
fi

# ── Install growpart if missing ───────────────────────────────────────────────
if ! command -v growpart &>/dev/null; then
    warn "growpart not found. Installing cloud-guest-utils..."
    apt-get update -qq && apt-get install -y cloud-guest-utils
fi

# ── Show current disk usage ───────────────────────────────────────────────────
info "Current disk layout:"
lsblk "$DISK" 2>/dev/null || lsblk
echo ""
info "Current filesystem usage:"
df -h /
echo ""

# ── Confirm before making changes ────────────────────────────────────────────
read -rp "$(echo -e "${YELLOW}Proceed with resize? [y/N]:${RESET} ")" CONFIRM
[[ "${CONFIRM,,}" != "y" ]] && { warn "Aborted by user."; exit 0; }
echo ""

# ── Step 1: Expand the partition to fill available disk space ─────────────────
info "Step 1/3 — Expanding partition $PART_NUM on $DISK..."
if growpart "$DISK" "$PART_NUM"; then
    success "Partition expanded."
else
    warn "growpart reported no change (partition may already be at max size)."
fi
echo ""

# ── Step 2: (LVM only) resize PV and LV ──────────────────────────────────────
if $IS_LVM; then
    info "Step 2/3 — Resizing LVM physical volume..."
    pvresize "$PV_DEV" && success "PV resized."

    info "         — Extending logical volume to 100% free..."
    lvextend -l +100%FREE "$LV_PATH" && success "LV extended."
    echo ""
fi

# ── Step 3: Resize the filesystem ────────────────────────────────────────────
info "Step 3/3 — Resizing $FS_TYPE filesystem on $ROOT_DEV..."

case "$FS_TYPE" in
    ext2|ext3|ext4)
        resize2fs "$ROOT_DEV" && success "ext filesystem resized."
        ;;
    xfs)
        xfs_growfs / && success "XFS filesystem resized."
        ;;
    btrfs)
        btrfs filesystem resize max / && success "Btrfs filesystem resized."
        ;;
    *)
        error "Unsupported filesystem type: $FS_TYPE. Resize it manually."
        ;;
esac
echo ""

# ── Final report ─────────────────────────────────────────────────────────────
success "All done! Updated disk usage:"
df -h /
echo ""
echo -e "${BOLD}${GREEN}Resize complete — no reboot required.${RESET}\n"s