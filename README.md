# x86-64-debian-hibernation-safeguard

> Provide a little added safety around hibernate/resume on Debian running on x86-64 (supports some USB key portable install scenarios).

Repository: [https://github.com/f-fix/x86-64-debian-hibernation-safeguard](https://github.com/f-fix/x86-64-debian-hibernation-safeguard)

---

## 🎯 Overview

Hibernating Linux writes the complete active memory state and kernel registers to swap storage. When using portable installations (e.g., Debian installed on an external USB SSD, thumb drive, or external NVMe enclosure) or moving drives between different machines, resuming on mismatched physical hardware results in driver hangs, memory map corruption, and kernel panics.

Furthermore, standard Linux hibernation workflows risk filesystem corruption if `/boot` or `/boot/efi` remain mounted when the memory snapshot is taken, or if early boot resume prompts leak full disk encryption passphrases.

`x86-64-debian-hibernation-safeguard` provides an automated **dual-stage hardware verification and isolation framework**:
1. **Early Bootloader Validation (GRUB / systemd-boot):** Compares the machine's SMBIOS Processor Information against the saved hibernation record before the kernel boots. Disables resume parameters and triggers kernel rollback if a mismatch is detected.
2. **Early Initramfs Validation:** Mounts `/boot` strictly read-only, immediately unmounts it, and validates Kernel version, CPU model, numeric RAM capacity (with dynamic tolerance for Intel GPU / EFI stolen memory), and permanent hardware MAC addresses (filtering out randomized/locally-administered MACs).
3. **Safe Interactive Confirmation (Anti-Passphrase Leak):** Uses a dedicated non-password interactive filter loop in both Plymouth and text consoles. Keystrokes are filtered to accept only `yes`+Enter or `no`+Enter with live visual feedback (`> `, `> y`, `> ye`, `> yes`), backspace/delete editing, and **zero plaintext echoing** of passwords typed in error.
4. **Resilient Discard (LUKS, LVM, and Plain Swap):** Selecting discard neutralizes resume binaries, zeroes `/sys/power/resume`, and sanitizes swap suspend signatures (`S1SUSPEND`/`S2SUSPEND` -> `SWAPSPACE2`) on plain partitions and inside LUKS/LVM volumes once unlocked.
5. **Pre-Hibernation Filesystem Isolation:** Unmounts `/boot` and `/boot/efi` before taking the memory snapshot (aborting hibernation if unmount fails), and cleanly remounts them in userspace upon resume.

---

## 💻 Compatibility & Tested Platforms

* **Tested Platform:** **Debian Forky/Sid (Debian 14 / unstable)** on `x86_64`.
* **Other Flavors:** While architected using standard Linux kernel, procfs, sysfs, and `initramfs-tools` primitives that should work across other Debian versions and derivatives on `x86_64`, it is **currently only tested on Debian Forky/Sid**.
* **Bootloaders:** GRUB 2 and/or `systemd-boot` (`bootctl`).
* **Storage Configurations:** Plain swap partitions, swap on LUKS, swap on LVM, or swap on LUKS+LVM.

---

## 🛠️ Usage

### 1. Check Installation Status (`--status`)
To inspect your current system hardware identity and check which safeguard components and hooks are installed without making any modifications:

```bash
python3 x86-64-debian-hibernation-safeguard.py --status
```

Example status output:
```text
=== Hardware Hibernation Safeguard Status (x86-64-debian-hibernation-safeguard.py) ===
Note: Tested so far on Debian Forky/Sid (Debian 14 / unstable); should work on other x86-64 Debian flavors.

Components:
  - Machine ID helper (/usr/local/bin/hibernation-machine-id)        : [INSTALLED]
  - Systemd sleep hook (/lib/systemd/system-sleep/...)               : [INSTALLED]
  - Initramfs check hook (/etc/initramfs-tools/scripts/local-top/..): [INSTALLED]
  - Initramfs modules config (sentinel block in /etc/.../modules)    : [CONFIGURED]
  - Initramfs firmware config (zz-hibernation-safeguard.conf)        : [CONFIGURED]
  - GRUB safeguard hook (sentinel block in /etc/grub.d/40_custom)    : [CONFIGURED]

Live System Hardware Identity:
  - CPU Model       : Intel(R) Core(TM) m3-7Y30 CPU @ 1.00GHz
  - Memory          : 8047040kB
  - Active Kernel   : 6.12.107+deb13-amd64
  - Permanent MAC   : b4:69:21:a8:12:6d (interface: wlan0)

Saved Hibernation Targets:
  - /boot/grub_hib_id      : [NONE] (clean / not hibernated)
  - /boot/initramfs_hib_id : [NONE] (clean / not hibernated)

Power Management Configuration:
  - /sys/power/disk        : shutdown

Safeguard Overall Status   : [ACTIVE & FULLY INSTALLED by x86-64-debian-hibernation-safeguard.py]
```

### 2. Deploy the Safeguard (`--install`)
To install the hooks, purge legacy artifacts, configure bootloader integration, and update initramfs/boot images:

```bash
sudo python3 x86-64-debian-hibernation-safeguard.py --install
```

*(Note: If executed without root, the script automatically attempts privilege self-elevation via `sudo`, `doas`, or `pkexec`).*

---

## 🔍 Architecture & Installed Files

All installed scripts, configuration drop-ins, and guard blocks are traceable back to `x86-64-debian-hibernation-safeguard.py`:

* **`/usr/local/bin/hibernation-machine-id`**: Helper that discovers permanent hardware identity (SMBIOS Processor string, MemTotal, physical MAC), saves targets on hibernate, and clears them on resume. Includes a `--help` option identifying `x86-64-debian-hibernation-safeguard.py`.
* **`/lib/systemd/system-sleep/hibernation-hardware-tag`**: Systemd sleep hook that saves target parameters, cleanly unmounts `/boot` and `/boot/efi` prior to memory snapshotting, and remounts them upon restore. Includes `--help` documentation.
* **`/etc/initramfs-tools/scripts/local-top/hibernation_resume_check`**: Early initramfs hook that mounts `/boot` strictly read-only, checks hardware parameters, and executes the non-password interactive prompt if a mismatch is detected.
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

## 🔧 Troubleshooting Hibernation Hangs

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
