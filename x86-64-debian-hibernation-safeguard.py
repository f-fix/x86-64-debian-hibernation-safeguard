#!/usr/bin/env python3
"""
x86-64-debian-hibernation-safeguard.py
Universal Dual-Stage Hardware Hibernation Safeguard for Debian on x86-64.

Provide a little added safety around hibernate/resume on Debian running on x86-64
(supports some USB key portable install scenarios).

Note: While this safeguard should work across various Debian derivatives and
Linux distributions on x86-64, it is currently only tested on Debian Forky/Sid
(Debian 14 / unstable).

Protects against resume state corruption across PCs, laptops, and portable USB installs.
Supports GRUB, systemd-boot, or both simultaneously.
Full support for plain partitions, LUKS, LVM, and LUKS+LVM swap configurations.
Non-clobbering configuration integration with sentinel markers.
Automatic cleanup of legacy artifacts and past guard comments from previous iterations.
Automatic privilege self-elevation (sudo/doas/pkexec).
Strict isolation of /boot and /boot/efi to eliminate post-resume filesystem corruption.
Comprehensive DMI/SMBIOS (vendor/model/bios/board/cpu) cross-validation across GRUB and initramfs without generic field filtering.
Seamless kernel rollback/override handling on systemd-boot and GRUB during hibernation resume with automatic restoration for future boots.
Strict bootloader isolation ensuring systemd-boot never hijacks resumption if the current session booted via GRUB or other loaders.
Interactive mismatch recovery menus:
  - GRUB: Pure ASCII menu with disabled countdown, safe Power Off default/preselected, Discard (clean boot), and Force Resume options.
  - Initramfs: Distinct non-password interactive prompt requiring fully typed words ('yes', 'no', 'force') to prevent accidental single-key passphrase triggers.
"""

import os
import sys
import re
import shutil
import argparse
import subprocess
from pathlib import Path

# Resolve installer script basename
INSTALLER_NAME = (
    Path(sys.argv[0]).name
    if sys.argv and sys.argv[0]
    else "x86-64-debian-hibernation-safeguard.py"
)
if not INSTALLER_NAME or INSTALLER_NAME.startswith("<"):
    INSTALLER_NAME = "x86-64-debian-hibernation-safeguard.py"

SAFEGUARD_MODULES = [
    "pci_hyperv",
    "pcie_hp",
    "iwlwifi",
    "iwlmvm",
    "mac80211",
    "cfg80211",
    "dm_mod",
]


def run_command(cmd, check=True, capture_output=False, text=True):
    try:
        return subprocess.run(
            cmd,
            shell=isinstance(cmd, str),
            check=check,
            capture_output=capture_output,
            text=text,
        )
    except subprocess.CalledProcessError as e:
        if capture_output:
            if e.stdout:
                sys.stdout.write(e.stdout)
            if e.stderr:
                sys.stderr.write(e.stderr)
        raise


def check_root():
    if os.geteuid() != 0:
        print("Non-root execution detected. Attempting privilege self-elevation...")
        elevation_tool = None
        for tool in ["sudo", "doas", "pkexec"]:
            if shutil.which(tool):
                elevation_tool = tool
                break

        if elevation_tool:
            cmd = [elevation_tool, sys.executable] + sys.argv
            try:
                os.execvp(elevation_tool, cmd)
            except OSError as e:
                sys.stderr.write(
                    f"ERROR: Failed to elevate privileges with {elevation_tool}: {e}\n"
                )
                sys.exit(1)
        else:
            sys.stderr.write(
                "ERROR: This command requires root privileges. Please run with sudo, doas, or as root.\n"
            )
            sys.exit(1)


def cleanup_legacy_artifacts():
    print(
        "=== Cleaning Up Artifacts and Legacy Guard Sections From Previous Iterations ==="
    )

    stale_paths = [
        Path("/etc/grub.d/08_hibernation_safeguard"),
        Path("/etc/default/grub.d/99-hibernation-safeguard.cfg"),
        Path("/usr/local/bin/gpd-machine-id"),
        Path("/lib/systemd/system-sleep/gpd-hibernation-hardware-tag"),
        Path("/etc/initramfs-tools/scripts/local-top/gpd_resume_check"),
        Path("/etc/initramfs-tools/conf.d/zz-gpd-hibernation.conf"),
        Path("/boot/grub_hib_id"),
        Path("/boot/initramfs_hib_id"),
        Path("/boot/loader/gpd_sdboot_hib_id"),
        Path("/boot/loader/sdboot_hib_id"),
        Path("/run/gpd/initramfs_id"),
        Path("/run/hibernation-safeguard/initramfs_id"),
        Path("/tmp/gpd_ply_key"),
        Path("/tmp/hib_ply_key"),
        Path("/root/deploy_adaptive_protection.py"),
        Path("/root/deploy_hibernation_safeguard.py"),
    ]

    for gpath in (
        list(Path("/etc/grub.d").glob("*hibernation_safeguard*"))
        + list(Path("/etc/grub.d").glob("*gpd*"))
        + list(Path("/etc/default/grub.d").glob("*hibernation*"))
        + list(Path("/etc/default/grub.d").glob("*gpd*"))
    ):
        stale_paths.append(gpath)

    for p in set(stale_paths):
        if p.exists() and p.is_file():
            try:
                p.unlink()
                print(f"Removed legacy/stale file: {p}")
            except OSError as e:
                sys.stderr.write(f"Warning: could not remove {p}: {e}\n")

    legacy_run_dir = Path("/run/gpd")
    if legacy_run_dir.exists() and legacy_run_dir.is_dir():
        try:
            shutil.rmtree(legacy_run_dir)
            print(f"Removed legacy directory: {legacy_run_dir}")
        except OSError as e:
            sys.stderr.write(
                f"Warning: could not remove directory {legacy_run_dir}: {e}\n"
            )

    modules_file = Path("/etc/initramfs-tools/modules")
    if modules_file.exists():
        content = modules_file.read_text()
        legacy_mod_pattern = r"### BEGIN (?:GPD )?HIBERNATION SAFEGUARD MODULES[^\n]*\n.*?### END (?:GPD )?HIBERNATION SAFEGUARD MODULES[^\n]*(?:\n|$)"
        if re.search(legacy_mod_pattern, content, flags=re.DOTALL):
            content = re.sub(legacy_mod_pattern, "", content, flags=re.DOTALL)
            modules_file.write_text(content)
            print("Purged legacy sentinel comments from /etc/initramfs-tools/modules")

    custom_path = Path("/etc/grub.d/40_custom")
    if custom_path.exists():
        content = custom_path.read_text()
        legacy_grub_pattern = r"### BEGIN (?:GPD )?HIBERNATION (?:HARDWARE )?SAFEGUARD[^\n]*\n.*?### END (?:GPD )?HIBERNATION (?:HARDWARE )?SAFEGUARD[^\n]*(?:\n|$)"
        if re.search(legacy_grub_pattern, content, flags=re.DOTALL):
            content = re.sub(legacy_grub_pattern, "", content, flags=re.DOTALL)
            custom_path.write_text(content)
            print("Purged legacy sentinel comments from /etc/grub.d/40_custom")


def gather_machine_layout():
    print("=== 1. Gathering Machine Layout Details ===")
    res = run_command(["df", "/boot"], capture_output=True)
    lines = res.stdout.strip().splitlines()
    if len(lines) < 2:
        sys.stderr.write("ERROR: Could not resolve block device for /boot\n")
        sys.exit(1)
    boot_dev = lines[1].split()[0]

    res_uuid = run_command(
        ["blkid", "-s", "UUID", "-o", "value", boot_dev], capture_output=True
    )
    boot_uuid = res_uuid.stdout.strip()
    if not boot_uuid:
        sys.stderr.write(f"ERROR: Could not fetch UUID for device {boot_dev}\n")
        sys.exit(1)
    print(f"Resolved /boot partition at {boot_dev} with UUID: {boot_uuid}")

    has_grub = Path("/etc/grub.d").is_dir() and shutil.which("update-grub") is not None

    has_systemd_boot = False
    esp_dir = ""
    for path in ["/boot/efi", "/efi", "/boot"]:
        if Path(f"{path}/loader/entries").is_dir():
            has_systemd_boot = True
            esp_dir = path
            break

    print(f"Detection Results -> GRUB: {has_grub} | systemd-boot: {has_systemd_boot}")
    return boot_dev, boot_uuid, has_grub, has_systemd_boot, esp_dir


def configure_initramfs_framework(installer_name=INSTALLER_NAME):
    print("=== 2. Configuring Initramfs Framework (Non-Clobbering) ===")
    modules_file = Path("/etc/initramfs-tools/modules")
    content = ""
    if modules_file.exists():
        content = modules_file.read_text()

    sentinel_start = (
        f"### BEGIN HIBERNATION SAFEGUARD MODULES (installed by {installer_name}) ###"
    )
    sentinel_end = (
        f"### END HIBERNATION SAFEGUARD MODULES (installed by {installer_name}) ###"
    )

    pat = r"### BEGIN (?:GPD )?HIBERNATION SAFEGUARD MODULES[^\n]*\n.*?### END (?:GPD )?HIBERNATION SAFEGUARD MODULES[^\n]*(?:\n|$)"
    base_content = re.sub(pat, "", content, flags=re.DOTALL)

    cleaned_base_lines = []
    for line in base_content.splitlines():
        stripped = line.strip()
        if stripped in SAFEGUARD_MODULES:
            continue
        cleaned_base_lines.append(line)

    base_clean = "\n".join(cleaned_base_lines).rstrip()

    safeguard_block = (
        f"{sentinel_start}\n" + "\n".join(SAFEGUARD_MODULES) + f"\n{sentinel_end}"
    )
    new_modules_content = (
        (base_clean + "\n\n" + safeguard_block + "\n")
        if base_clean
        else (safeguard_block + "\n")
    )

    modules_file.parent.mkdir(parents=True, exist_ok=True)
    modules_file.write_text(new_modules_content)

    conf_d = Path("/etc/initramfs-tools/conf.d")
    conf_d.mkdir(parents=True, exist_ok=True)
    dropin = conf_d / "zz-hibernation-safeguard.conf"
    dropin.write_text(
        f"# Configuration drop-in installed by {installer_name}\n"
        f"# Ensures firmware is available in early initramfs for hardware identification\n"
        f"# Note: Tested so far on Debian Forky/Sid (Debian 14 / unstable)\n"
        f"FIRMWARE=all\n"
    )


def write_machine_id_helper(installer_name=INSTALLER_NAME):
    print("=== 3. Creating Hardware Hibernation Machine ID Helper ===")
    helper_path = Path("/usr/local/bin/hibernation-machine-id")
    helper_template = r"""#!/bin/sh
# Installed and managed by __INSTALLER_NAME__
# Universal Hardware Hibernation Target and Identity Manager
# Note: Tested so far on Debian Forky/Sid (Debian 14 / unstable)

case "$1" in
    -h|--help|help)
        echo "Usage: $(basename "$0") [save-targets|clear-targets|status]"
        echo "Installed and managed by __INSTALLER_NAME__"
        echo "Universal Hardware Hibernation Target and Identity Manager."
        echo "Note: Tested so far on Debian Forky/Sid (Debian 14 / unstable); should work on other x86-64 Debian flavors."
        exit 0
        ;;
esac

is_permanent_hw_mac() {
    _mac="$1"
    case "$_mac" in
        [0-9a-fA-F][0-9a-fA-F]:[0-9a-fA-F][0-9a-fA-F]:[0-9a-fA-F][0-9a-fA-F]:[0-9a-fA-F][0-9a-fA-F]:[0-9a-fA-F][0-9a-fA-F]:[0-9a-fA-F][0-9a-fA-F]) ;;
        *) return 1 ;;
    esac
    [ "$_mac" = "00:00:00:00:00:00" ] && return 1
    [ "$_mac" = "ff:ff:ff:ff:ff:ff" ] && return 1
    [ "$_mac" = "FF:FF:FF:FF:FF:FF" ] && return 1
    _c2=$(echo "$_mac" | cut -c2)
    case "$_c2" in
        [048cC]) return 0 ;;
        *) return 1 ;;
    esac
}

was_booted_by_systemd_boot() {
    # Method 1: Check LoaderInfo EFI variable for systemd-boot
    for f in /sys/firmware/efi/efivars/LoaderInfo-*; do
        if [ -f "$f" ] && grep -qa "systemd-boot" "$f" 2>/dev/null; then
            return 0
        fi
    done
    # Method 2: Check bootctl status for active systemd-boot loader in current session
    if command -v bootctl >/dev/null 2>&1; then
        if bootctl status 2>/dev/null | grep -qE "Product:[[:space:]]+systemd-boot|Current Boot Loader:[[:space:]]*systemd-boot"; then
            return 0
        fi
    fi
    return 1
}

get_dmi_field() {
    _f="$1"
    _val=""
    if [ -f "/sys/class/dmi/id/$_f" ]; then
        _val=$(cat "/sys/class/dmi/id/$_f" 2>/dev/null | tr -d '\r\n' | sed -e 's/^[ \t]*//' -e 's/[ \t]*$//')
    fi
    echo "$_val"
}

# Collect Hardware Identifiers
CPU_STR=$(grep -m 1 "model name" /proc/cpuinfo | cut -d: -f2- | sed -e 's/^[ \t]*//' -e 's/[ \t]*$//')
RAM_STR=$(awk '/MemTotal/ {print $2$3}' /proc/meminfo 2>/dev/null | tr -d ' \r\n')
[ -z "$RAM_STR" ] && RAM_STR="$(grep -m 1 'MemTotal:' /proc/meminfo | tr -dc '0-9')kB"

# DMI / SMBIOS Identifiers (Preserve raw values without generic filtering)
SYS_VENDOR=$(get_dmi_field sys_vendor)
PRODUCT_NAME=$(get_dmi_field product_name)
PRODUCT_VERSION=$(get_dmi_field product_version)
BIOS_VENDOR=$(get_dmi_field bios_vendor)
BIOS_VERSION=$(get_dmi_field bios_version)
BOARD_VENDOR=$(get_dmi_field board_vendor)
BOARD_NAME=$(get_dmi_field board_name)
BOARD_VERSION=$(get_dmi_field board_version)
CHASSIS_VENDOR=$(get_dmi_field chassis_vendor)
PRODUCT_SERIAL=$(get_dmi_field product_serial)
PRODUCT_UUID=$(get_dmi_field product_uuid)

MAC_STR=""
IFACE_STR=""

for candidate_dir in /sys/class/net/w* /sys/class/net/e*; do
    [ ! -d "$candidate_dir" ] && continue
    iface_name=$(basename "$candidate_dir")
    [ "$iface_name" = "lo" ] && continue

    [ ! -e "$candidate_dir/device" ] && continue

    if [ -f "$candidate_dir/addr_assign_type" ]; then
        assign_type=$(cat "$candidate_dir/addr_assign_type" 2>/dev/null | tr -d '\r\n ')
        [ "$assign_type" != "0" ] && continue
    fi

    if [ -f "$candidate_dir/address" ]; then
        val=$(cat "$candidate_dir/address" 2>/dev/null | tr -d '\r\n ')
        if is_permanent_hw_mac "$val"; then
            MAC_STR="$val"
            IFACE_STR="$iface_name"
            break
        fi
    fi
done

CURRENT_KERNEL=$(uname -r)

mkdir -p /run/hibernation-safeguard
cat << EOF_RUN > /run/hibernation-safeguard/initramfs_id
# Generated by __INSTALLER_NAME__
SAVED_SYS_VENDOR="$SYS_VENDOR"
SAVED_PRODUCT_NAME="$PRODUCT_NAME"
SAVED_PRODUCT_VERSION="$PRODUCT_VERSION"
SAVED_BIOS_VENDOR="$BIOS_VENDOR"
SAVED_BIOS_VERSION="$BIOS_VERSION"
SAVED_BOARD_VENDOR="$BOARD_VENDOR"
SAVED_BOARD_NAME="$BOARD_NAME"
SAVED_BOARD_VERSION="$BOARD_VERSION"
SAVED_CHASSIS_VENDOR="$CHASSIS_VENDOR"
SAVED_PRODUCT_SERIAL="$PRODUCT_SERIAL"
SAVED_PRODUCT_UUID="$PRODUCT_UUID"
SAVED_CPU="$CPU_STR"
SAVED_RAM="$RAM_STR"
SAVED_MAC="$MAC_STR"
SAVED_MAC_IFACE="$IFACE_STR"
SAVED_KERNEL="$CURRENT_KERNEL"
EOF_RUN

if [ "$1" = "save-targets" ]; then
    cat << EOF_INIT > /boot/initramfs_hib_id
# Generated for hibernation by __INSTALLER_NAME__
SAVED_SYS_VENDOR="$SYS_VENDOR"
SAVED_PRODUCT_NAME="$PRODUCT_NAME"
SAVED_PRODUCT_VERSION="$PRODUCT_VERSION"
SAVED_BIOS_VENDOR="$BIOS_VENDOR"
SAVED_BIOS_VERSION="$BIOS_VERSION"
SAVED_BOARD_VENDOR="$BOARD_VENDOR"
SAVED_BOARD_NAME="$BOARD_NAME"
SAVED_BOARD_VERSION="$BOARD_VERSION"
SAVED_CHASSIS_VENDOR="$CHASSIS_VENDOR"
SAVED_PRODUCT_SERIAL="$PRODUCT_SERIAL"
SAVED_PRODUCT_UUID="$PRODUCT_UUID"
SAVED_CPU="$CPU_STR"
SAVED_RAM="$RAM_STR"
SAVED_MAC="$MAC_STR"
SAVED_MAC_IFACE="$IFACE_STR"
SAVED_KERNEL="$CURRENT_KERNEL"
EOF_INIT

    CURRENT_GRUB_ID=$(sed -n 's/.*grub_id="\([^"]*\)".*/\1/p' /proc/cmdline)
    if [ -z "$CURRENT_GRUB_ID" ]; then
        CURRENT_GRUB_ID=$(sed -n 's/.*grub_id=\([^ "]*\).*/\1/p' /proc/cmdline)
    fi
    if [ -z "$CURRENT_GRUB_ID" ]; then
        CURRENT_GRUB_ID="$CPU_STR"
    fi

    cat << EOF_GRUB > /boot/grub_hib_id
# Generated for hibernation by __INSTALLER_NAME__
SAVED_SYS_VENDOR="$SYS_VENDOR"
SAVED_PRODUCT_NAME="$PRODUCT_NAME"
SAVED_PRODUCT_VERSION="$PRODUCT_VERSION"
SAVED_BIOS_VENDOR="$BIOS_VENDOR"
SAVED_BIOS_VERSION="$BIOS_VERSION"
SAVED_BOARD_VENDOR="$BOARD_VENDOR"
SAVED_BOARD_NAME="$BOARD_NAME"
SAVED_BOARD_VERSION="$BOARD_VERSION"
SAVED_CHASSIS_VENDOR="$CHASSIS_VENDOR"
SAVED_GRUB_ID="$CURRENT_GRUB_ID"
SAVED_KERNEL_VERSION="$CURRENT_KERNEL"
EOF_GRUB

    # Only configure systemd-boot overrides IF the current session was actually booted by systemd-boot.
    # If the system was booted via GRUB or another loader, leave systemd-boot untouched so it never hijacks bootloader priority.
    if was_booted_by_systemd_boot; then
        if command -v bootctl >/dev/null 2>&1; then
            MATCHING_ENTRY=$(bootctl list --json=short 2>/dev/null | grep -o '"id":"[^"]*' | cut -d'"' -f4 | grep "$CURRENT_KERNEL" | head -n 1 || true)
            if [ -n "$MATCHING_ENTRY" ]; then
                bootctl set-oneshot "$MATCHING_ENTRY" 2>/dev/null || bootctl set-default "$MATCHING_ENTRY" 2>/dev/null || true
                mkdir -p /boot/loader
                touch /boot/loader/sdboot_hib_id
            fi
        fi
    fi
fi

if [ "$1" = "clear-targets" ]; then
    rm -f /boot/grub_hib_id /boot/initramfs_hib_id /boot/loader/sdboot_hib_id /boot/loader/gpd_sdboot_hib_id 2>/dev/null
    if was_booted_by_systemd_boot || [ -f /boot/loader/sdboot_hib_id ]; then
        if command -v bootctl >/dev/null 2>&1; then
            bootctl set-default "" 2>/dev/null || true
        fi
    fi
fi
"""
    helper_content = helper_template.replace("__INSTALLER_NAME__", installer_name)
    helper_path.parent.mkdir(parents=True, exist_ok=True)
    helper_path.write_text(helper_content)
    helper_path.chmod(0o755)

    legacy_helper = Path("/usr/local/bin/gpd-machine-id")
    if legacy_helper.exists() or legacy_helper.is_symlink():
        try:
            legacy_helper.unlink()
        except OSError:
            pass
    try:
        legacy_helper.symlink_to(helper_path)
    except OSError:
        pass


def write_systemd_sleep_hook(installer_name=INSTALLER_NAME):
    print("=== 4. Setting up Systemd Sleep Hooks (Clean /boot Unmount & Remount) ===")
    hook_path = Path("/lib/systemd/system-sleep/hibernation-hardware-tag")
    hook_path.parent.mkdir(parents=True, exist_ok=True)
    content_template = r"""#!/bin/bash
# Installed by __INSTALLER_NAME__
# Universal Pre- and Post-Sleep Hook for Hardware Hibernation Safeguard
# Protects /boot and /boot/efi from corruption by unmounting before hibernate snapshot
# and remounting after session restore.
# Note: Tested so far on Debian Forky/Sid (Debian 14 / unstable)

if [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
    echo "Usage: $(basename "$0") <pre|post> <hibernate>"
    echo "Installed by __INSTALLER_NAME__"
    echo "Systemd sleep hook for hardware hibernation safeguard."
    echo "Note: Tested so far on Debian Forky/Sid (Debian 14 / unstable); should work on other x86-64 Debian flavors."
    exit 0
fi

if [ "$1" = "pre" ] && [ "$2" = "hibernate" ]; then
    echo "Hibernation Safeguard (__INSTALLER_NAME__): Preparing system state for hibernation..."

    # 1. Save hardware targets to /boot while still mounted
    /usr/local/bin/hibernation-machine-id save-targets

    # 2. Flush dirty filesystem buffers to disk
    sync

    # 3. Unmount /boot/efi and /boot if they are separate mountpoints.
    # When unmounted before the kernel takes the hibernation snapshot, the memory snapshot
    # will contain NO active filesystem handles or stale superblocks for these volumes.
    if mountpoint -q /boot/efi 2>/dev/null; then
        echo "Hibernation Safeguard: Unmounting /boot/efi..."
        umount /boot/efi 2>/dev/null || { fuser -km /boot/efi 2>/dev/null; sleep 1; umount /boot/efi 2>/dev/null; }
    fi

    if mountpoint -q /boot 2>/dev/null; then
        echo "Hibernation Safeguard: Unmounting /boot..."
        umount /boot 2>/dev/null || { fuser -km /boot 2>/dev/null; sleep 1; umount /boot 2>/dev/null; }
    fi

    # 4. Strict Validation: Fail and abort hibernation if /boot or /boot/efi could not be unmounted
    FAILED_UNMOUNT=false
    if mountpoint -q /boot/efi 2>/dev/null; then
        echo "ERROR: /boot/efi could not be unmounted prior to hibernation!" >&2
        FAILED_UNMOUNT=true
    fi
    if mountpoint -q /boot 2>/dev/null; then
        echo "ERROR: /boot could not be unmounted prior to hibernation!" >&2
        FAILED_UNMOUNT=true
    fi

    if [ "$FAILED_UNMOUNT" = true ]; then
        echo "CRITICAL: Aborting hibernation to prevent filesystem corruption!" >&2
        mount /boot 2>/dev/null || true
        mount /boot/efi 2>/dev/null || true
        mount -a 2>/dev/null || true
        kill -9 "$PPID" 2>/dev/null || true
        exit 1
    fi

    # Optional safeguard against ACPI S4 poweroff hangs:
    if [ -f /sys/power/disk ]; then
        grep -q "shutdown" /sys/power/disk 2>/dev/null && echo "shutdown" > /sys/power/disk 2>/dev/null || true
    fi

elif [ "$1" = "post" ] && [ "$2" = "hibernate" ]; then
    echo "Hibernation Safeguard (__INSTALLER_NAME__): Resuming from hibernation, remounting boot filesystems..."

    # 1. Remount /boot and /boot/efi cleanly in userspace
    mount /boot 2>/dev/null || true
    mount /boot/efi 2>/dev/null || true
    mount -a 2>/dev/null || true

    # 2. Safely clean up targets in userspace after resume has succeeded
    /usr/local/bin/hibernation-machine-id clear-targets
fi
"""
    content = content_template.replace("__INSTALLER_NAME__", installer_name)
    hook_path.write_text(content)
    hook_path.chmod(0o755)


def write_grub_hooks(boot_uuid, installer_name=INSTALLER_NAME):
    print("=== 5. Writing GRUB Hook (Non-Clobbering 40_custom Integration) ===")
    grub_d = Path("/etc/grub.d")
    grub_d.mkdir(parents=True, exist_ok=True)

    custom_path = grub_d / "40_custom"
    content = ""
    if custom_path.exists():
        content = custom_path.read_text()

    sentinel_start = (
        f"### BEGIN HIBERNATION HARDWARE SAFEGUARD (installed by {installer_name}) ###"
    )
    sentinel_end = (
        f"### END HIBERNATION HARDWARE SAFEGUARD (installed by {installer_name}) ###"
    )

    template_block = r"""__SENTINEL_START__
insmod smbios
insmod echo
insmod search_fs_uuid
insmod test
insmod sleep
insmod halt

set target_boot_part=""
search --fs-uuid --set=target_boot_part __BOOT_UUID__

if [ -n "$target_boot_part" ]; then
    if [ -f ($target_boot_part)/grub_hib_id ]; then
        source ($target_boot_part)/grub_hib_id

        # Query live machine SMBIOS / DMI tables
        set curr_sys_vendor=""
        smbios --type 1 --get-string 1 --set=curr_sys_vendor
        set curr_product_name=""
        smbios --type 1 --get-string 2 --set=curr_product_name
        set curr_product_version=""
        smbios --type 1 --get-string 3 --set=curr_product_version
        set curr_bios_vendor=""
        smbios --type 0 --get-string 1 --set=curr_bios_vendor
        set curr_bios_version=""
        smbios --type 0 --get-string 2 --set=curr_bios_version
        set curr_board_vendor=""
        smbios --type 2 --get-string 1 --set=curr_board_vendor
        set curr_board_name=""
        smbios --type 2 --get-string 2 --set=curr_board_name
        set curr_cpu_model=""
        smbios --type 4 --get-string 3 --set=curr_cpu_model
        if [ -z "$curr_cpu_model" ]; then
            smbios --type 4 --get-string 5 --set=curr_cpu_model
        fi
        set current_grub_id="$curr_cpu_model"

        # Check for hardware and DMI mismatches
        set grub_mismatch="0"

        if [ -n "$SAVED_SYS_VENDOR" ]; then
            if [ "$curr_sys_vendor" != "$SAVED_SYS_VENDOR" ]; then
                set grub_mismatch="1"
            fi
        fi

        if [ -n "$SAVED_PRODUCT_NAME" ]; then
            if [ "$curr_product_name" != "$SAVED_PRODUCT_NAME" ]; then
                set grub_mismatch="1"
            fi
        fi

        if [ -n "$SAVED_PRODUCT_VERSION" ]; then
            if [ "$curr_product_version" != "$SAVED_PRODUCT_VERSION" ]; then
                set grub_mismatch="1"
            fi
        fi

        if [ -n "$SAVED_BIOS_VENDOR" ]; then
            if [ "$curr_bios_vendor" != "$SAVED_BIOS_VENDOR" ]; then
                set grub_mismatch="1"
            fi
        fi

        if [ -n "$SAVED_BIOS_VERSION" ]; then
            if [ "$curr_bios_version" != "$SAVED_BIOS_VERSION" ]; then
                set grub_mismatch="1"
            fi
        fi

        if [ -n "$SAVED_BOARD_VENDOR" ]; then
            if [ "$curr_board_vendor" != "$SAVED_BOARD_VENDOR" ]; then
                set grub_mismatch="1"
            fi
        fi

        if [ -n "$SAVED_BOARD_NAME" ]; then
            if [ "$curr_board_name" != "$SAVED_BOARD_NAME" ]; then
                set grub_mismatch="1"
            fi
        fi

        if [ -n "$SAVED_GRUB_ID" ]; then
            if [ "$current_grub_id" != "$SAVED_GRUB_ID" ]; then
                set grub_mismatch="1"
            fi
        fi

        if [ "$grub_mismatch" = "1" ]; then
            # Hardware Mismatch Flagged: Disable countdown timeout completely and force menu display
            set timeout=-1
            set timeout_style=menu

            echo "============================================================"
            echo "  [SAFEGUARD] HIBERNATION HARDWARE MISMATCH DETECTED!"
            echo "============================================================"
            echo "Environment change detected since hibernation:"
            if [ -n "$SAVED_SYS_VENDOR" ]; then
                echo "  System Vendor:  '$SAVED_SYS_VENDOR' -> '$curr_sys_vendor'"
            fi
            if [ -n "$SAVED_PRODUCT_NAME" ]; then
                echo "  Product Name:   '$SAVED_PRODUCT_NAME' -> '$curr_product_name'"
            fi
            if [ -n "$SAVED_BIOS_VENDOR" ]; then
                echo "  BIOS Vendor:    '$SAVED_BIOS_VENDOR' -> '$curr_bios_vendor'"
            fi
            if [ -n "$SAVED_BIOS_VERSION" ]; then
                echo "  BIOS Version:   '$SAVED_BIOS_VERSION' -> '$curr_bios_version'"
            fi
            if [ -n "$SAVED_BOARD_NAME" ]; then
                echo "  Board Name:     '$SAVED_BOARD_NAME' -> '$curr_board_name'"
            fi
            if [ -n "$SAVED_GRUB_ID" ]; then
                echo "  Processor / ID: '$SAVED_GRUB_ID' -> '$current_grub_id'"
            fi
            echo "============================================================"
            echo "Automatic countdown is DISABLED."
            echo "Select an option from the menu (Default: Safe Power Off):"
            echo "  1. Power Off Machine (Preserve Hibernation Session - Preselected)"
            echo "  2. Discard Hibernation Image & Boot Cleanly"
            echo "  3. Force Resume Anyway (Danger: Hardware Mismatch)"
            echo "============================================================"
            sleep 2

            # Dedicated Safeguard Menu Options in pure ASCII (Safe Power Off is Entry 1 and default)
            menuentry "[SAFEGUARD] 1. Power Off Machine (Preserve Hibernation Session - Default)" --id=safeguard_poweroff {
                echo "Safely powering off machine to preserve hibernated session..."
                halt
            }

            menuentry "[SAFEGUARD] 2. Discard Hibernation Image & Boot Cleanly" --id=safeguard_clean {
                set linux_resume_param=""
                set noresume="1"
                echo "Clean boot selected: resume parameters cleared."
            }

            menuentry "[SAFEGUARD] 3. Force Resume Anyway (Dangerous - May Panic)" --id=safeguard_force {
                echo "Proceeding with resume on mismatched hardware..."
            }

            # Enforce preselected default to safe power off
            set default="safeguard_poweroff"
        else
            # Kernel Rollback Automation on matching hardware
            if [ -n "$SAVED_KERNEL_VERSION" ]; then
                set default="Advanced options for Debian GNU/Linux>Debian GNU/Linux, with Linux $SAVED_KERNEL_VERSION"
            fi
        fi
    fi
fi
__SENTINEL_END__"""
    safeguard_block = (
        template_block.replace("__SENTINEL_START__", sentinel_start)
        .replace("__SENTINEL_END__", sentinel_end)
        .replace("__BOOT_UUID__", boot_uuid)
    )

    standard_header = """#!/bin/sh
exec tail -n +3 $0
# This file provides an easy way to add custom menu entries.  Simply type the
# menu entries you want to add after this comment.  Be careful not to change
# the 'exec tail' line above.
"""

    if not content.strip():
        new_content = standard_header + "\n" + safeguard_block + "\n"
    else:
        pat = r"### BEGIN (?:GPD )?HIBERNATION (?:HARDWARE )?SAFEGUARD[^\n]*\n.*?### END (?:GPD )?HIBERNATION (?:HARDWARE )?SAFEGUARD[^\n]*(?:\n|$)"
        cleaned = re.sub(pat, "", content, flags=re.DOTALL)

        legacy_unmarked = [
            r"insmod smbios.*?(?:set\s+linux_cmdline_extra=.*?|linux_cmdline_extra=.*?)(?:\n|$)",
            r"insmod smbios.*?set\s+default=.*?fi\s*\n\s*fi",
            r"insmod smbios.*?search --fs-uuid.*?fi\s*\n\s*fi",
        ]

        replaced = False
        for p in legacy_unmarked:
            if re.search(p, cleaned, flags=re.DOTALL):
                cleaned = re.sub(p, safeguard_block, cleaned, flags=re.DOTALL)
                replaced = True
                break

        if replaced:
            new_content = cleaned
        else:
            base_clean = cleaned.rstrip()
            new_content = base_clean + "\n\n" + safeguard_block + "\n"

    custom_path.write_text(new_content)
    custom_path.chmod(0o755)


def write_initramfs_hook(boot_uuid, installer_name=INSTALLER_NAME):
    print(
        "=== 6. Writing Initramfs Hook (Guaranteed /boot Unmount, Distinct Non-Password Prompt) ==="
    )
    hook_dir = Path("/etc/initramfs-tools/scripts/local-top")
    hook_dir.mkdir(parents=True, exist_ok=True)
    hook_path = hook_dir / "hibernation_resume_check"

    hook_template = r"""#!/bin/sh
# Installed by __INSTALLER_NAME__
# Universal Hardware Hibernation Resume Validation Hook
# Note: Tested so far on Debian Forky/Sid (Debian 14 / unstable)

PREREQ=""
prereqs() { echo "$PREREQ"; }
case $1 in
    -h|--help|help)
        echo "Usage: hibernation_resume_check [prereqs]"
        echo "Installed by __INSTALLER_NAME__"
        echo "Initramfs local-top hook for hardware hibernation validation."
        echo "Note: Tested so far on Debian Forky/Sid (Debian 14 / unstable); should work on other x86-64 Debian flavors."
        exit 0
        ;;
    prereqs) prereqs; exit 0;;
esac

. /scripts/functions

echo "=== Universal Hardware Hibernation Resume Validation ==="

BOOT_MNT="/tmp/boot_mnt"
mkdir -p "$BOOT_MNT"

cleanup_boot_mnt() {
    if [ -d "$BOOT_MNT" ]; then
        umount "$BOOT_MNT" 2>/dev/null || true
    fi
}
trap cleanup_boot_mnt EXIT INT TERM

modprobe ext4 2>/dev/null; modprobe vfat 2>/dev/null; modprobe usb_storage 2>/dev/null

TARGET_UUID="__BOOT_UUID__"
BOOT_DEV=""
count=0
while [ $count -lt 10 ]; do
    BOOT_DEV=$(blkid -U "$TARGET_UUID" 2>/dev/null)
    [ -n "$BOOT_DEV" ] && [ -b "$BOOT_DEV" ] && break
    sleep 1; count=$((count + 1))
done

SAVED_SYS_VENDOR=""
SAVED_PRODUCT_NAME=""
SAVED_PRODUCT_VERSION=""
SAVED_BIOS_VENDOR=""
SAVED_BIOS_VERSION=""
SAVED_BOARD_VENDOR=""
SAVED_BOARD_NAME=""
SAVED_BOARD_VERSION=""
SAVED_CHASSIS_VENDOR=""
SAVED_PRODUCT_SERIAL=""
SAVED_PRODUCT_UUID=""
SAVED_CPU=""
SAVED_RAM=""
SAVED_MAC=""
SAVED_MAC_IFACE=""
SAVED_KERNEL=""

if [ -n "$BOOT_DEV" ] && mount -o ro "$BOOT_DEV" "$BOOT_MNT" 2>/dev/null; then
    if [ -f "$BOOT_MNT/initramfs_hib_id" ]; then
        . "$BOOT_MNT/initramfs_hib_id"
    fi
    umount "$BOOT_MNT" 2>/dev/null || true
fi

get_curr_dmi() {
    _f="$1"
    _val=""
    if [ -f "/sys/class/dmi/id/$_f" ]; then
        _val=$(cat "/sys/class/dmi/id/$_f" 2>/dev/null | tr -d '\r\n' | sed -e 's/^[ \t]*//' -e 's/[ \t]*$//')
    fi
    echo "$_val"
}

# Read live DMI fields without generic string filtering
CURRENT_SYS_VENDOR=$(get_curr_dmi sys_vendor)
CURRENT_PRODUCT_NAME=$(get_curr_dmi product_name)
CURRENT_PRODUCT_VERSION=$(get_curr_dmi product_version)
CURRENT_BIOS_VENDOR=$(get_curr_dmi bios_vendor)
CURRENT_BIOS_VERSION=$(get_curr_dmi bios_version)
CURRENT_BOARD_VENDOR=$(get_curr_dmi board_vendor)
CURRENT_BOARD_NAME=$(get_curr_dmi board_name)
CURRENT_BOARD_VERSION=$(get_curr_dmi board_version)
CURRENT_CHASSIS_VENDOR=$(get_curr_dmi chassis_vendor)
CURRENT_PRODUCT_SERIAL=$(get_curr_dmi product_serial)
CURRENT_PRODUCT_UUID=$(get_curr_dmi product_uuid)

CURRENT_CPU=$(grep -m 1 "model name" /proc/cpuinfo | cut -d: -f2- | sed -e 's/^[ \t]*//' -e 's/[ \t]*$//')
CURRENT_RAM=$(awk '/MemTotal/ {print $2$3}' /proc/meminfo 2>/dev/null | tr -d ' \r\n')
[ -z "$CURRENT_RAM" ] && CURRENT_RAM="$(grep -m 1 'MemTotal:' /proc/meminfo | tr -dc '0-9')kB"

CURRENT_KERNEL=$(uname -r)

CURRENT_GRUB_ID=$(sed -n 's/.*grub_id="\([^"]*\)".*/\1/p' /proc/cmdline)
[ -z "$CURRENT_GRUB_ID" ] && CURRENT_GRUB_ID=$(sed -n 's/.*grub_id=\([^ "]*\).*/\1/p' /proc/cmdline)

is_permanent_hw_mac() {
    _mac="$1"
    case "$_mac" in
        [0-9a-fA-F][0-9a-fA-F]:[0-9a-fA-F][0-9a-fA-F]:[0-9a-fA-F][0-9a-fA-F]:[0-9a-fA-F][0-9a-fA-F]:[0-9a-fA-F][0-9a-fA-F]:[0-9a-fA-F][0-9a-fA-F]) ;;
        *) return 1 ;;
    esac
    [ "$_mac" = "00:00:00:00:00:00" ] && return 1
    [ "$_mac" = "ff:ff:ff:ff:ff:ff" ] && return 1
    [ "$_mac" = "FF:FF:FF:FF:FF:FF" ] && return 1
    _c2=$(echo "$_mac" | cut -c2)
    case "$_c2" in
        [048cC]) return 0 ;;
        *) return 1 ;;
    esac
}

HAS_MISMATCH=false
KERNEL_MISMATCH=false
CPU_MISMATCH=false
RAM_MISMATCH=false
MAC_MISMATCH=false
DMI_MISMATCH=false
DMI_MISMATCH_DETAILS=""
CURRENT_MAC=""

if [ -n "$SAVED_KERNEL" ] || [ -n "$SAVED_CPU" ] || [ -n "$SAVED_SYS_VENDOR" ] || [ -n "$SAVED_PRODUCT_NAME" ] || [ -n "$SAVED_BIOS_VENDOR" ]; then
    if [ -n "$SAVED_KERNEL" ] && [ "$SAVED_KERNEL" != "$CURRENT_KERNEL" ]; then
        KERNEL_MISMATCH=true
        HAS_MISMATCH=true
    fi

    if [ -n "$SAVED_CPU" ] && [ "$SAVED_CPU" != "$CURRENT_CPU" ]; then
        CPU_MISMATCH=true
        HAS_MISMATCH=true
    fi

    # DMI Field Cross-Checking (Direct string comparison)
    if [ -n "$SAVED_SYS_VENDOR" ] && [ "$SAVED_SYS_VENDOR" != "$CURRENT_SYS_VENDOR" ]; then
        DMI_MISMATCH=true
        HAS_MISMATCH=true
        DMI_MISMATCH_DETAILS="${DMI_MISMATCH_DETAILS}    System Vendor:  '$SAVED_SYS_VENDOR' -> '$CURRENT_SYS_VENDOR'\n"
    fi

    if [ -n "$SAVED_PRODUCT_NAME" ] && [ "$SAVED_PRODUCT_NAME" != "$CURRENT_PRODUCT_NAME" ]; then
        DMI_MISMATCH=true
        HAS_MISMATCH=true
        DMI_MISMATCH_DETAILS="${DMI_MISMATCH_DETAILS}    Product Name:   '$SAVED_PRODUCT_NAME' -> '$CURRENT_PRODUCT_NAME'\n"
    fi

    if [ -n "$SAVED_PRODUCT_VERSION" ] && [ "$SAVED_PRODUCT_VERSION" != "$CURRENT_PRODUCT_VERSION" ]; then
        DMI_MISMATCH=true
        HAS_MISMATCH=true
        DMI_MISMATCH_DETAILS="${DMI_MISMATCH_DETAILS}    Product Version: '$SAVED_PRODUCT_VERSION' -> '$CURRENT_PRODUCT_VERSION'\n"
    fi

    if [ -n "$SAVED_BIOS_VENDOR" ] && [ "$SAVED_BIOS_VENDOR" != "$CURRENT_BIOS_VENDOR" ]; then
        DMI_MISMATCH=true
        HAS_MISMATCH=true
        DMI_MISMATCH_DETAILS="${DMI_MISMATCH_DETAILS}    BIOS Vendor:    '$SAVED_BIOS_VENDOR' -> '$CURRENT_BIOS_VENDOR'\n"
    fi

    if [ -n "$SAVED_BIOS_VERSION" ] && [ "$SAVED_BIOS_VERSION" != "$CURRENT_BIOS_VERSION" ]; then
        DMI_MISMATCH=true
        HAS_MISMATCH=true
        DMI_MISMATCH_DETAILS="${DMI_MISMATCH_DETAILS}    BIOS Version:   '$SAVED_BIOS_VERSION' -> '$CURRENT_BIOS_VERSION'\n"
    fi

    if [ -n "$SAVED_BOARD_VENDOR" ] && [ "$SAVED_BOARD_VENDOR" != "$CURRENT_BOARD_VENDOR" ]; then
        DMI_MISMATCH=true
        HAS_MISMATCH=true
        DMI_MISMATCH_DETAILS="${DMI_MISMATCH_DETAILS}    Board Vendor:   '$SAVED_BOARD_VENDOR' -> '$CURRENT_BOARD_VENDOR'\n"
    fi

    if [ -n "$SAVED_BOARD_NAME" ] && [ "$SAVED_BOARD_NAME" != "$CURRENT_BOARD_NAME" ]; then
        DMI_MISMATCH=true
        HAS_MISMATCH=true
        DMI_MISMATCH_DETAILS="${DMI_MISMATCH_DETAILS}    Board Name:     '$SAVED_BOARD_NAME' -> '$CURRENT_BOARD_NAME'\n"
    fi

    saved_kb=$(echo "$SAVED_RAM" | tr -dc '0-9')
    curr_kb=$(echo "$CURRENT_RAM" | tr -dc '0-9')
    if [ -n "$saved_kb" ] && [ -n "$curr_kb" ]; then
        diff=$(( saved_kb > curr_kb ? saved_kb - curr_kb : curr_kb - saved_kb ))
        tol=$(( saved_kb / 20 ))
        [ $tol -lt 262144 ] && tol=262144
        if [ $diff -gt $tol ]; then
            RAM_MISMATCH=true
            HAS_MISMATCH=true
        fi
    fi

    if [ -n "$SAVED_MAC" ] && [ -n "$SAVED_MAC_IFACE" ]; then
        if [ -f "/sys/class/net/$SAVED_MAC_IFACE/address" ]; then
            curr_val=$(cat "/sys/class/net/$SAVED_MAC_IFACE/address" 2>/dev/null | tr -d '\r\n ')
            is_perm=true
            if [ -f "/sys/class/net/$SAVED_MAC_IFACE/addr_assign_type" ]; then
                assign_type=$(cat "/sys/class/net/$SAVED_MAC_IFACE/addr_assign_type" 2>/dev/null | tr -d '\r\n ')
                [ "$assign_type" != "0" ] && is_perm=false
            fi

            if [ "$is_perm" = true ] && is_permanent_hw_mac "$curr_val"; then
                CURRENT_MAC="$curr_val"
                if [ "$SAVED_MAC" != "$CURRENT_MAC" ]; then
                    MAC_MISMATCH=true
                    HAS_MISMATCH=true
                fi
            fi
        fi
    fi
fi

if [ "$HAS_MISMATCH" = true ]; then
    DETAILS=""
    if [ "$KERNEL_MISMATCH" = true ]; then
        DETAILS="${DETAILS}  [Kernel Version Mismatch]\n    Saved:   $SAVED_KERNEL\n    Current: $CURRENT_KERNEL\n"
    fi
    if [ "$DMI_MISMATCH" = true ]; then
        DETAILS="${DETAILS}  [DMI / SMBIOS Mismatch]\n${DMI_MISMATCH_DETAILS}"
    fi
    if [ "$CPU_MISMATCH" = true ]; then
        DETAILS="${DETAILS}  [CPU Model Mismatch]\n    Saved:   $SAVED_CPU\n    Current: $CURRENT_CPU\n"
    fi
    if [ "$RAM_MISMATCH" = true ]; then
        DETAILS="${DETAILS}  [RAM Size Mismatch]\n    Saved:   $SAVED_RAM\n    Current: $CURRENT_RAM\n"
    fi
    if [ "$MAC_MISMATCH" = true ]; then
        DETAILS="${DETAILS}  [MAC Address Mismatch (interface: $SAVED_MAC_IFACE)]\n    Saved:   $SAVED_MAC\n    Current: $CURRENT_MAC\n"
    fi

    echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
    echo "HIBERNATION RESUME SAFEGUARD: MISMATCH DETECTED!"
    printf "%b" "$DETAILS"
    echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"

    user_input=""

    # Interactive prompt via Plymouth if active
    if [ -x /bin/plymouth ] && plymouth --ping 2>/dev/null; then
        plymouth pause-progress 2>/dev/null || true
        plymouth message --text="=================================================="
        plymouth message --text="*** WARNING: ENVIRONMENT MISMATCH DETECTED ***"
        plymouth message --text="*** THIS IS NOT A DISK PASSPHRASE PROMPT ***"
        plymouth message --text="*** DO NOT ENTER YOUR LUKS / DISK PASSWORD ***"
        plymouth message --text="=================================================="
        if [ "$KERNEL_MISMATCH" = true ]; then
            plymouth message --text="Kernel update detected ($SAVED_KERNEL -> $CURRENT_KERNEL)"
        else
            plymouth message --text="Hardware / DMI environment change detected since hibernation."
        fi
        plymouth message --text="Type full word: 'yes' (clean boot) | 'no' (power off) | 'force' (resume anyway)"
        plymouth message --text="--------------------------------------------------"

        while true; do
            ans=$(plymouth ask-question --prompt="Type 'yes', 'no', or 'force' + Enter: " 2>/dev/null)
            clean_ans=$(echo "$ans" | tr -d '\r\n ' | tr 'A-Z' 'a-z')
            case "$clean_ans" in
                yes)
                    user_input="yes"
                    break
                    ;;
                no)
                    user_input="no"
                    break
                    ;;
                force)
                    user_input="force"
                    break
                    ;;
                *)
                    plymouth message --text="[INVALID] Single letters/passwords rejected. Type full word 'yes', 'no', or 'force'."
                    ;;
            esac
        done
        plymouth unpause-progress 2>/dev/null || true
    fi

    # Interactive prompt on text console (if plymouth was not used or did not resolve)
    if [ -z "$user_input" ]; then
        echo "" > /dev/console 2>/dev/null || echo ""
        echo "==================================================" > /dev/console 2>/dev/null || echo "=================================================="
        echo "*** NOTICE: THIS IS NOT A DISK PASSWORD PROMPT ***" > /dev/console 2>/dev/null || echo "*** NOTICE: THIS IS NOT A DISK PASSWORD PROMPT ***"
        echo "*** DO NOT TYPE YOUR DISK ENCRYPTION PASSWORD ***" > /dev/console 2>/dev/null || echo "*** DO NOT TYPE YOUR DISK ENCRYPTION PASSWORD ***"
        echo "==================================================" > /dev/console 2>/dev/null || echo "=================================================="
        echo "Options (must be fully typed out):" > /dev/console 2>/dev/null || echo "Options (must be fully typed out):"
        echo "  yes   - Discard hibernation snapshot and boot cleanly" > /dev/console 2>/dev/null || echo "  yes   - Discard hibernation snapshot and boot cleanly"
        echo "  no    - Power off immediately (preserves hibernated session)" > /dev/console 2>/dev/null || echo "  no    - Power off immediately (preserves hibernated session)"
        echo "  force - Force resume attempt anyway (risk of kernel panic/corruption)" > /dev/console 2>/dev/null || echo "  force - Force resume attempt anyway (risk of kernel panic/corruption)"
        echo "--------------------------------------------------" > /dev/console 2>/dev/null || echo "--------------------------------------------------"

        CONSOLE_IN=""
        if [ -c /dev/console ]; then
            CONSOLE_IN="/dev/console"
        elif [ -c /dev/tty0 ]; then
            CONSOLE_IN="/dev/tty0"
        fi

        while true; do
            printf "Confirm action (type full word 'yes', 'no', or 'force' + Enter): " > /dev/console 2>/dev/null || printf "Confirm action (type full word 'yes', 'no', or 'force' + Enter): "
            raw_ans=""
            if [ -n "$CONSOLE_IN" ]; then
                read raw_ans < "$CONSOLE_IN" 2>/dev/null || read raw_ans
            else
                read raw_ans
            fi

            clean_ans=$(echo "$raw_ans" | tr -d '\r\n ' | tr 'A-Z' 'a-z')
            case "$clean_ans" in
                yes)
                    user_input="yes"
                    echo "Selected: Discard hibernation snapshot and boot cleanly." > /dev/console 2>/dev/null || echo "Selected: Discard hibernation snapshot and boot cleanly."
                    break
                    ;;
                no)
                    user_input="no"
                    echo "Selected: Power off machine." > /dev/console 2>/dev/null || echo "Selected: Power off machine."
                    break
                    ;;
                force)
                    user_input="force"
                    echo "Selected: Force resume attempt anyway." > /dev/console 2>/dev/null || echo "Selected: Force resume attempt anyway."
                    break
                    ;;
                *)
                    echo "[INVALID INPUT] Single letters and unrecognized inputs are rejected. Please type the full word 'yes', 'no', or 'force' followed by Enter." > /dev/console 2>/dev/null || echo "[INVALID INPUT] Single letters and unrecognized inputs are rejected. Please type the full word 'yes', 'no', or 'force' followed by Enter."
                    ;;
            esac
        done
    fi

    if [ "$user_input" = "no" ]; then
        cleanup_boot_mnt
        echo "Powering off machine..."
        poweroff -f
    fi

    if [ "$user_input" = "force" ]; then
        echo "Forcing hibernation resume on mismatched hardware..."
        cleanup_boot_mnt
        exit 0
    fi

    # User selected 'yes' (clean boot / discard image)
    echo "Discarding hibernation image to enforce clean boot..."

    for rbin in /bin/resume /usr/lib/systemd/systemd-hibernate-resume /lib/systemd/systemd-hibernate-resume; do
        if [ -f "$rbin" ]; then
            rm -f "$rbin" 2>/dev/null || { echo '#!/bin/sh'; echo 'exit 0'; } > "$rbin"
        fi
    done

    rm -f /conf/conf.d/resume /conf/param.conf 2>/dev/null
    mkdir -p /conf/conf.d
    echo "RESUME=none" > /conf/conf.d/resume

    if [ -e /sys/power/resume ]; then
        echo "0:0" > /sys/power/resume 2>/dev/null || true
    fi

    mkdir -p /scripts/local-premount
    cat << 'EOF_SAN' > /scripts/local-premount/resume
#!/bin/sh
# Sanitizer installed dynamically by __INSTALLER_NAME__ during hibernation discard
PREREQ=""
prereqs() { echo "$PREREQ"; }
case $1 in prereqs) prereqs; exit 0;; esac

echo "Safeguard Discard: Sanitizing swap suspend signatures (LUKS/LVM/disk)..."
modprobe dm-mod 2>/dev/null
command -v lvm >/dev/null 2>&1 && lvm vgchange -ay 2>/dev/null

sanitize_dev() {
    dev="$1"
    [ ! -b "$dev" ] && return
    sig=$(dd if="$dev" bs=1 skip=4086 count=9 2>/dev/null)
    if [ "$sig" = "S1SUSPEND" ] || [ "$sig" = "S2SUSPEND" ]; then
        echo "Sanitizing swap suspend signature on $dev..."
        printf 'SWAPSPACE2' | dd of="$dev" bs=1 seek=4086 count=10 conv=notrunc 2>/dev/null
    fi
}

for d in $(awk '/\/dev\// {print $1}' /proc/swaps 2>/dev/null) \
         $(blkid -t TYPE=suspend -o device 2>/dev/null) \
         $(blkid -t TYPE=swsuspend -o device 2>/dev/null) \
         $(blkid -t TYPE=swap -o device 2>/dev/null) \
         /dev/mapper/* /dev/dm-*; do
    sanitize_dev "$d"
done

[ -e /sys/power/resume ] && echo "0:0" > /sys/power/resume 2>/dev/null
exit 0
EOF_SAN
    chmod +x /scripts/local-premount/resume

    for d in /dev/mapper/* /dev/dm-* $(awk '/\/dev\// {print $1}' /proc/swaps 2>/dev/null); do
        if [ -b "$d" ]; then
            sig=$(dd if="$d" bs=1 skip=4086 count=9 2>/dev/null)
            if [ "$sig" = "S1SUSPEND" ] || [ "$sig" = "S2SUSPEND" ]; then
                printf 'SWAPSPACE2' | dd of="$d" bs=1 seek=4086 count=10 conv=notrunc 2>/dev/null || true
            fi
        fi
    done

    if [ -n "$BOOT_DEV" ] && mount -o rw "$BOOT_DEV" "$BOOT_MNT" 2>/dev/null; then
        rm -f "$BOOT_MNT/initramfs_hib_id"
        rm -f "$BOOT_MNT/grub_hib_id"
        rm -f "$BOOT_MNT/loader/sdboot_hib_id"
        rm -f "$BOOT_MNT/loader/gpd_sdboot_hib_id"
        umount "$BOOT_MNT" 2>/dev/null || true
    fi
fi

cleanup_boot_mnt

exit 0
"""
    hook_content = hook_template.replace("__BOOT_UUID__", boot_uuid).replace(
        "__INSTALLER_NAME__", installer_name
    )
    hook_path.write_text(hook_content)
    hook_path.chmod(0o755)


def compile_images(has_grub):
    print("=== 7. Compiling Active Image Assets ===")
    if has_grub:
        run_command(["update-grub"], capture_output=False)
    run_command(["update-initramfs", "-u", "-k", "all"], capture_output=False)


def install(installer_name=INSTALLER_NAME):
    check_root()
    print(f"=== Deploying Hardware Hibernation Safeguard via {installer_name} ===")
    print(
        "Note: Tested so far on Debian Forky/Sid (Debian 14 / unstable); should work on other x86-64 Debian flavors."
    )
    print()
    cleanup_legacy_artifacts()
    boot_dev, boot_uuid, has_grub, has_systemd_boot, esp_dir = gather_machine_layout()
    configure_initramfs_framework(installer_name)
    write_machine_id_helper(installer_name)
    write_systemd_sleep_hook(installer_name)
    if has_grub:
        write_grub_hooks(boot_uuid, installer_name)
    write_initramfs_hook(boot_uuid, installer_name)
    compile_images(has_grub)
    print("=== SUCCESS ===")
    print(f"Hardware Hibernation Safeguard fully provisioned by {installer_name}.")
    print(
        "System will dynamically enforce hardware verification across GRUB and initramfs."
    )


def show_status(installer_name=INSTALLER_NAME):
    print(f"=== Hardware Hibernation Safeguard Status ({installer_name}) ===")
    print(
        "Note: Tested so far on Debian Forky/Sid (Debian 14 / unstable); should work on other x86-64 Debian flavors."
    )
    print()

    helper = Path("/usr/local/bin/hibernation-machine-id")
    helper_ok = helper.is_file() and os.access(helper, os.X_OK)

    sleep_hook = Path("/lib/systemd/system-sleep/hibernation-hardware-tag")
    sleep_hook_ok = sleep_hook.is_file() and os.access(sleep_hook, os.X_OK)

    init_hook = Path("/etc/initramfs-tools/scripts/local-top/hibernation_resume_check")
    init_hook_ok = init_hook.is_file() and os.access(init_hook, os.X_OK)

    modules_file = Path("/etc/initramfs-tools/modules")
    modules_ok = False
    if modules_file.is_file():
        m_txt = modules_file.read_text()
        modules_ok = "### BEGIN HIBERNATION SAFEGUARD MODULES" in m_txt

    dropin = Path("/etc/initramfs-tools/conf.d/zz-hibernation-safeguard.conf")
    dropin_ok = dropin.is_file()

    custom_grub = Path("/etc/grub.d/40_custom")
    grub_hook_ok = False
    if custom_grub.is_file():
        g_txt = custom_grub.read_text()
        grub_hook_ok = "### BEGIN HIBERNATION HARDWARE SAFEGUARD" in g_txt

    def badge(ok):
        return "[INSTALLED]" if ok else "[MISSING]"

    def cfg_badge(ok):
        return "[CONFIGURED]" if ok else "[NOT CONFIGURED]"

    print("Components:")
    print(
        f"  - Machine ID helper (/usr/local/bin/hibernation-machine-id)        : {badge(helper_ok)}"
    )
    print(
        f"  - Systemd sleep hook (/lib/systemd/system-sleep/...)               : {badge(sleep_hook_ok)}"
    )
    print(
        f"  - Initramfs check hook (/etc/initramfs-tools/scripts/local-top/..): {badge(init_hook_ok)}"
    )
    print(
        f"  - Initramfs modules config (sentinel block in /etc/.../modules)    : {cfg_badge(modules_ok)}"
    )
    print(
        f"  - Initramfs firmware config (zz-hibernation-safeguard.conf)        : {cfg_badge(dropin_ok)}"
    )
    print(
        f"  - GRUB safeguard hook (sentinel block in /etc/grub.d/40_custom)    : {cfg_badge(grub_hook_ok)}"
    )
    print()

    print("Live System Hardware Identity:")

    # Read raw DMI values from sysfs
    def read_dmi(name):
        p = Path(f"/sys/class/dmi/id/{name}")
        if p.is_file():
            val = p.read_text().strip()
            if val:
                return val
        return None

    sys_vendor = read_dmi("sys_vendor")
    product_name = read_dmi("product_name")
    bios_vendor = read_dmi("bios_vendor")
    bios_version = read_dmi("bios_version")
    board_vendor = read_dmi("board_vendor")
    board_name = read_dmi("board_name")

    if sys_vendor or product_name:
        print(
            f"  - System / Model  : {sys_vendor or 'Unknown'} {product_name or ''}".strip()
        )
    if bios_vendor or bios_version:
        print(f"  - BIOS Details    : {bios_vendor or ''} {bios_version or ''}".strip())
    if board_name:
        print(f"  - Baseboard       : {board_vendor or ''} {board_name}".strip())

    cpu = "Unknown"
    cpuinfo = Path("/proc/cpuinfo")
    if cpuinfo.is_file():
        for line in cpuinfo.read_text().splitlines():
            if line.startswith("model name"):
                cpu = line.split(":", 1)[1].strip()
                break
    print(f"  - CPU Model       : {cpu}")

    ram = "Unknown"
    meminfo = Path("/proc/meminfo")
    if meminfo.is_file():
        for line in meminfo.read_text().splitlines():
            if line.startswith("MemTotal:"):
                ram = "".join(line.split()[1:3])
                break
    print(f"  - Memory          : {ram}")

    kernel = os.uname().release
    print(f"  - Active Kernel   : {kernel}")

    mac = "None"
    mac_iface = "None"
    net_dir = Path("/sys/class/net")
    if net_dir.is_dir():
        for candidate in sorted(list(net_dir.glob("w*")) + list(net_dir.glob("e*"))):
            if not (candidate / "device").exists():
                continue
            addr_file = candidate / "address"
            assign_file = candidate / "addr_assign_type"
            if assign_file.is_file() and assign_file.read_text().strip() != "0":
                continue
            if addr_file.is_file():
                val = addr_file.read_text().strip()
                if (
                    len(val) == 17
                    and val[1].lower() in "048c"
                    and val != "00:00:00:00:00:00"
                ):
                    mac = val
                    mac_iface = candidate.name
                    break
    print(f"  - Permanent MAC   : {mac} (interface: {mac_iface})")
    print()

    print("Saved Hibernation Targets:")
    grub_id_file = Path("/boot/grub_hib_id")
    init_id_file = Path("/boot/initramfs_hib_id")
    print(
        f"  - /boot/grub_hib_id      : {'[PRESENT]' if grub_id_file.is_file() else '[NONE] (clean / not hibernated)'}"
    )
    if grub_id_file.is_file():
        for line in grub_id_file.read_text().splitlines():
            print(f"      {line}")
    print(
        f"  - /boot/initramfs_hib_id : {'[PRESENT]' if init_id_file.is_file() else '[NONE] (clean / not hibernated)'}"
    )
    if init_id_file.is_file():
        for line in init_id_file.read_text().splitlines():
            print(f"      {line}")
    print()

    pwr_disk = Path("/sys/power/disk")
    disk_val = pwr_disk.read_text().strip() if pwr_disk.is_file() else "unsupported"
    print(f"Power Management Configuration:")
    print(f"  - /sys/power/disk        : {disk_val}")
    print()

    all_ok = all(
        [helper_ok, sleep_hook_ok, init_hook_ok, modules_ok, dropin_ok, grub_hook_ok]
    )
    any_ok = any(
        [helper_ok, sleep_hook_ok, init_hook_ok, modules_ok, dropin_ok, grub_hook_ok]
    )
    if all_ok:
        print(
            f"Safeguard Overall Status   : [ACTIVE & FULLY INSTALLED by {installer_name}]"
        )
    elif any_ok:
        print(
            f"Safeguard Overall Status   : [PARTIALLY INSTALLED - run '{installer_name} --install' to fix]"
        )
    else:
        print(
            f"Safeguard Overall Status   : [NOT INSTALLED - run '{installer_name} --install' to deploy]"
        )


def main():
    parser = argparse.ArgumentParser(
        prog=INSTALLER_NAME,
        description=(
            f"Universal Dual-Stage Hardware Hibernation Safeguard ({INSTALLER_NAME}).\n"
            f"Provide a little added safety around hibernate/resume on Debian running on x86-64\n"
            f"(supports some USB key portable install scenarios).\n\n"
            f"Note: While this safeguard should work across other flavors and distributions on x86-64,\n"
            f"it is currently only tested on Debian Forky/Sid (Debian 14 / unstable)."
        ),
        epilog=(
            f"Examples:\n"
            f"  {INSTALLER_NAME} --status     # Inspect components and live hardware identity\n"
            f"  sudo {INSTALLER_NAME} --install  # Deploy safeguard hooks and update boot images\n\n"
            f"Repository: https://github.com/f-fix/x86-64-debian-hibernation-safeguard\n"
            f"Note: Only tested so far on Debian Forky/Sid (Debian 14 / unstable)."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--install",
        action="store_true",
        help=f"Deploy and configure the hardware hibernation safeguard using {INSTALLER_NAME}.",
    )
    group.add_argument(
        "--status",
        action="store_true",
        help=f"Check and display the current safeguard installation status and hardware targets.",
    )

    args = parser.parse_args()

    if args.install:
        install(INSTALLER_NAME)
    elif args.status:
        show_status(INSTALLER_NAME)


if __name__ == "__main__":
    main()
