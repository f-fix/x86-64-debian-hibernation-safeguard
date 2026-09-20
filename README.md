# x86-64-debian-hibernation-safeguard

> Provide a little added safety around hibernate/resume on Debian running on x86-64 (supports some USB key portable install scenarios).

Repository: [https://github.com/f-fix/x86-64-debian-hibernation-safeguard](https://github.com/f-fix/x86-64-debian-hibernation-safeguard)

---

## Overview

Hibernating Linux writes the complete active memory state and kernel registers to swap storage. When using portable installations (e.g., Debian installed on an external USB SSD, thumb drive, or external NVMe enclosure) or moving drives between different machines, resuming on mismatched physical hardware results in driver hangs, memory map corruption, and kernel panics.

`x86-64-debian-hibernation-safeguard` provides an automated **dual-stage hardware verification and isolation framework**:
1. **Early Bootloader Validation (GRUB / systemd-boot):** Compares the machine's SMBIOS DMI information (vendor, model, BIOS version, baseboard, and processor) against the saved hibernation record before the kernel boots. Disables automatic timer countdowns, displays changed hardware attributes, and presents safe recovery options (Safe Power Off preselected, Clean Boot, and Force Resume).
2. **Early Initramfs Validation:** Mounts `/boot` strictly read-only for a few milliseconds, immediately unmounts it, and validates Kernel version, DMI parameters, CPU model, numeric RAM capacity (with dynamic tolerance for stolen memory), and permanent hardware MAC addresses.
3. **Safe Interactive Confirmation (Anti-Passphrase Leak):** Uses a dedicated compiled C evdev micro-daemon (`hibernation-resume-prompt`) as the primary interactive prompt in early initramfs, supporting both Plymouth splash screens (live in-place prompt line updates) and text consoles. Requires full words (`yes`, `no`, `force`) with **zero plaintext echoing** of passwords typed in error. If the C binary is missing, non-executable, or exits abnormally/crashes, a compact shell-based fallback (using `plymouth ask-question` or regular console input with normal text echo) prompts the user until a valid confirmation is entered.
4. **Resilient Discard (LUKS, LVM, and Plain Swap):** Selecting discard neutralizes resume binaries, zeroes `/sys/power/resume`, and sanitizes swap suspend signatures (`S1SUSPEND`/`S2SUSPEND` -> `SWAPSPACE2`) on plain partitions and inside LUKS/LVM volumes once unlocked.
5. **Boot Mount Isolation & Strict Early Read-Only:** Attempts to sync dirty buffers and unmount `/boot/efi` (if present) and `/boot` immediately prior to hibernation, and attempts to remount them immediately after resumption. Strictly isolates `/boot` as read-only during GRUB and initramfs (never mounting rw or writing in early boot), and communicates state transitions safely via `/run` tmpfs.

---

## Compatibility & Tested Platforms

* **Tested Platform:** **Debian Forky/Sid (Debian 14 / unstable)** on `x86_64`.
* **Other Flavors:** While architected using standard Linux kernel, procfs, sysfs, and `initramfs-tools` primitives that should work across other Debian versions and derivatives on `x86_64`, it is **currently only tested on Debian Forky/Sid**.
* **Bootloaders:** GRUB 2 and/or `systemd-boot` (`bootctl`).
* **Storage Configurations:** Plain swap partitions, swap on LUKS, swap on LVM, or swap on LUKS+LVM.

---

## Usage

### 1. Check Installation Status (`--status`)
To inspect your current system hardware identity and check which safeguard components and hooks are installed without making any modifications:

```bash
python3 x86-64-debian-hibernation-safeguard.py --status
```

### 2. Deploy the Safeguard (`--install`)
To install the hooks, compile the C evdev prompt binary, configure bootloader integration, and update initramfs/boot images:

```bash
sudo python3 x86-64-debian-hibernation-safeguard.py --install
```

*(Note: If executed without root, the script automatically attempts privilege self-elevation via `sudo`, `doas`, or `pkexec`).*

### 3. Completely Uninstall the Safeguard (`--uninstall`)
To completely and surgically uninstall all safeguard hooks, native prompt binaries, systemd services, and configuration blocks (including any legacy artifacts from previous versions), and recompile clean boot images:

```bash
sudo python3 x86-64-debian-hibernation-safeguard.py --uninstall
```

*(Note: If executed without root, the script automatically attempts privilege self-elevation via `sudo`, `doas`, or `pkexec`).*

### 4. Display Documentation / Help (`--help` or `-h`)
To display this full manual using the standard Python help pager:

```bash
python3 x86-64-debian-hibernation-safeguard.py --help
```

---

## Architecture & Installed Files

All installed scripts, configuration drop-ins, and guard blocks are traceable back to `x86-64-debian-hibernation-safeguard.py`:

* **`/usr/local/bin/hibernation-machine-id`**: Helper that discovers permanent hardware identity (DMI strings, CPU, MemTotal, physical MAC), saves targets on hibernate, and clears them on resume. Includes a `--help` option identifying `x86-64-debian-hibernation-safeguard.py`.
* **`/lib/systemd/system-sleep/hibernation-hardware-tag`**: Systemd sleep hook that saves target parameters prior to hibernation and cleans them up upon restore.
* **`/lib/systemd/system/hibernation-safeguard-cleanup.service`**: Oneshot systemd service running at `basic.target` on every cold boot and clean startup to guarantee stale target records are cleared.
* **`/usr/local/bin/hibernation-resume-prompt`**: Compiled native C micro-daemon for direct evdev, tty, and console input handling with live Plymouth bootsplash message line updates.
* **`/etc/initramfs-tools/scripts/local-top/hibernation_resume_check`**: Early initramfs hook that mounts `/boot` strictly read-only, checks hardware parameters, and executes the interactive prompt if a mismatch is detected.
* **`/etc/initramfs-tools/modules`**: Bounded by sentinel comments:
  ```text
  ### BEGIN HIBERNATION SAFEGUARD MODULES (installed by x86-64-debian-hibernation-safeguard.py) ###
  ...
  ### END HIBERNATION SAFEGUARD MODULES (installed by x86-64-debian-hibernation-safeguard.py) ###
  ```
* **`/etc/grub.d/40_custom`**: Bounded by sentinel comments:
  ```text
  ### BEGIN HIBERNATION HARDWARE SAFEGUARD (installed by x86-64-debian-hibernation-safeguard.py) ###
  ...
  ### END HIBERNATION HARDWARE SAFEGUARD (installed by x86-64-debian-hibernation-safeguard.py) ###
  ```
* **`/etc/initramfs-tools/conf.d/zz-hibernation-safeguard.conf`**: Drop-in configuration ensuring all necessary firmware is bundled into the initramfs.

---

## Troubleshooting Hibernation Hangs

If your machine fails to complete hibernation (e.g. screen turns black, system freezes with cooling fans spinning at 100%), isolate the failing subsystem using the kernel power management testing interface:

```bash
# Test driver suspend/resume without powering down
sudo bash -c 'echo devices > /sys/power/pm_test'
sudo systemctl hibernate

# Reset test mode back to normal
sudo bash -c 'echo none > /sys/power/pm_test'
```

If the hang occurs during final power-down, `x86-64-debian-hibernation-safeguard.py` automatically configures `/sys/power/disk` to `shutdown` rather than `platform`, bypassing problematic BIOS ACPI S4 sleep routines.

---

## 🤖 Note on the code and the tools used to write it
Parts of this code were written (including some initial ones that began in other, separate projects) with assistance from LLM-integrated coding tools. If you don't like it, feel free to use other software or rewrite parts you dislike. PRs are welcome!
