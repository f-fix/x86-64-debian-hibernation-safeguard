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
Strict read-only isolation of /boot in GRUB and initramfs (no rw mounting or writing in early boot).
Clean userspace management of /boot and /boot/efi target files, attempting pre-sleep sync/unmount and post-resume remount.
Inter-stage communication via /run tmpfs and kernel boot parameters.
Comprehensive DMI/SMBIOS (vendor/model/bios/board/cpu) cross-validation across GRUB and initramfs.
Standard SMBIOS byte-offset retrieval in GRUB with automatic skip on unretrievable/empty fields.
GRUB mismatch screen with 30-second interruptible reading pause and display of changed fields only.
Functional GRUB menu entries preserving full default hardware kernel parameters and resume= targets with explicit boot commands.
Automatic handling of read-only /boot and /boot/efi filesystems in userspace (remount rw for updates/cleanup with ro restoration).
Userspace cleanup service and post-sleep hooks guaranteeing deletion of leftover hibernation files.
Seamless kernel rollback/override handling on systemd-boot and GRUB during hibernation resume with automatic restoration for future boots.
Strict bootloader isolation ensuring systemd-boot never hijacks resumption if the current session booted via GRUB or other loaders.
Robust physical MAC address discovery supporting Ethernet, Wi-Fi, and userspace-configured links with IEEE 802 universal/local bit validation.
Dedicated compiled C micro-daemon for direct evdev, console, and tty keyboard capture in early initramfs with live Plymouth bootsplash message updates.
Automatic bundling of ethtool and C resume prompt binary into initramfs.
Integrated README.md documentation paged via python's standard help pager (pydoc.pager).
Interactive mismatch recovery menus:
  - GRUB: Pure ASCII menu with disabled countdown, safe Power Off default/preselected, Discard (clean boot), and Force Resume options.
  - Initramfs: Distinct non-password interactive prompt requiring fully typed words ('yes', 'no', 'force') with live typing echo on both Plymouth and text consoles.
"""

import os
import sys
import re
import shutil
import pydoc
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
    "evdev",
    "atkbd",
    "i8042",
    "button",
    "hid_generic",
    "usbhid",
]

README_DOC = r"""# x86-64-debian-hibernation-safeguard

> Provide a little added safety around hibernate/resume on Debian running on x86-64 (supports some USB key portable install scenarios).

Repository: [https://github.com/f-fix/x86-64-debian-hibernation-safeguard](https://github.com/f-fix/x86-64-debian-hibernation-safeguard)

---

## Overview

Hibernating Linux writes the complete active memory state and kernel registers to swap storage. When using portable installations (e.g., Debian installed on an external USB SSD, thumb drive, or external NVMe enclosure) or moving drives between different machines, resuming on mismatched physical hardware results in driver hangs, memory map corruption, and kernel panics.

`x86-64-debian-hibernation-safeguard` provides an automated **dual-stage hardware verification and isolation framework**:
1. **Early Bootloader Validation (GRUB / systemd-boot):** Compares the machine's SMBIOS DMI information (vendor, model, BIOS version, baseboard, and processor) against the saved hibernation record before the kernel boots. Disables automatic timer countdowns, displays changed hardware attributes, and presents safe recovery options (Safe Power Off preselected, Clean Boot, and Force Resume).
2. **Early Initramfs Validation:** Mounts `/boot` strictly read-only for a few milliseconds, immediately unmounts it, and validates Kernel version, DMI parameters, CPU model, numeric RAM capacity (with dynamic tolerance for stolen memory), and permanent hardware MAC addresses.
3. **Safe Interactive Confirmation (Anti-Passphrase Leak):** Uses a dedicated compiled C evdev micro-daemon (`hibernation-resume-prompt`) as the primary interactive prompt in early initramfs, supporting both Plymouth splash screens (live in-place prompt line updates) and text consoles. Requires full words (`yes`, `no`, `force`) with **zero plaintext echoing** of passwords typed in error (any input that is not a case-insensitive prefix of `yes`, `no`, or `force` is masked as `*`, and Enter discards invalid input). If the C binary is missing, non-executable, or exits abnormally/crashes, a compact shell-based fallback (using `plymouth ask-question` or regular console input with normal text echo) prompts the user until a valid confirmation is entered.
4. **Resilient Discard (LUKS, LVM, and Plain Swap):** Selecting discard neutralizes resume binaries, zeroes `/sys/power/resume`, and sanitizes swap suspend signatures (`S1SUSPEND`/`S2SUSPEND` -> `SWAPSPACE2`) on plain partitions and inside LUKS/LVM volumes once unlocked. Additionally, if the kernel command line flag `noresume` (or `resume=none`) is passed at boot (such as via GRUB's clean boot entry), the initramfs validation stage immediately inhibits/bypasses all hardware checks and prompts, sanitizes swap signatures, and executes a clean boot.
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
"""

C_PROMPT_SOURCE = r"""
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <glob.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/reboot.h>
#include <sys/ioctl.h>
#include <linux/input.h>

#define MAX_EV_FDS 32
#define PROMPT_PREFIX "Lose unmatched hibernation? Yes=new/No=off/Force=resume: > "

static int plymouth_active = 0;
static char input_buf[64];
static int buf_len = 0;
static int shift_down = 0;

static int check_plymouth(void) {
    if (access("/bin/plymouth", X_OK) == 0 || access("/usr/bin/plymouth", X_OK) == 0) {
        if (system("plymouth --ping 2>/dev/null") == 0) {
            return 1;
        }
    }
    return 0;
}

static int is_valid_prefix_or_match(const char *s) {
    if (!s || !*s) return 1;
    size_t len = strlen(s);
    if (len <= 3 && strncasecmp(s, "yes", len) == 0) return 1;
    if (len <= 2 && strncasecmp(s, "no", len) == 0) return 1;
    if (len <= 5 && strncasecmp(s, "force", len) == 0) return 1;
    return 0;
}

static void get_display_string(char *out, size_t max_out) {
    if (is_valid_prefix_or_match(input_buf)) {
        snprintf(out, max_out, "%s", input_buf);
    } else {
        size_t len = strlen(input_buf);
        if (len >= max_out) len = max_out - 1;
        for (size_t i = 0; i < len; i++) {
            out[i] = '*';
        }
        out[len] = '\0';
    }
}

static void update_display(void) {
    char disp[64];
    get_display_string(disp, sizeof(disp));

    char full_prompt[160];
    snprintf(full_prompt, sizeof(full_prompt), "%s%s", PROMPT_PREFIX, disp);

    if (plymouth_active) {
        char cmd[256];
        snprintf(cmd, sizeof(cmd), "plymouth message --text=\"%s\" 2>/dev/null", full_prompt);
        int r = system(cmd);
        (void)r;
    }

    // Also write to /dev/console for direct text console visibility
    int cfd = open("/dev/console", O_WRONLY | O_NOCTTY);
    if (cfd >= 0) {
        char line[200];
        snprintf(line, sizeof(line), "\r\033[K%s", full_prompt);
        ssize_t w = write(cfd, line, strlen(line));
        (void)w;
        close(cfd);
    }
}

static int scan_inputs(struct pollfd *fds, int max_fds) {
    for (int i = 0; i < max_fds; i++) {
        if (fds[i].fd >= 0) {
            close(fds[i].fd);
            fds[i].fd = -1;
        }
    }
    glob_t g;
    int num_fds = 0;
    if (glob("/dev/input/event*", 0, NULL, &g) == 0) {
        for (size_t i = 0; i < g.gl_pathc && num_fds < max_fds; i++) {
            int fd = open(g.gl_pathv[i], O_RDONLY | O_NONBLOCK);
            if (fd >= 0) {
                fds[num_fds].fd = fd;
                fds[num_fds].events = POLLIN;
                num_fds++;
            }
        }
        globfree(&g);
    }
    return num_fds;
}

static char keycode_to_ascii(int code, int shift) {
    switch (code) {
        case KEY_A: return shift ? 'A' : 'a';
        case KEY_B: return shift ? 'B' : 'b';
        case KEY_C: return shift ? 'C' : 'c';
        case KEY_D: return shift ? 'D' : 'd';
        case KEY_E: return shift ? 'E' : 'e';
        case KEY_F: return shift ? 'F' : 'f';
        case KEY_G: return shift ? 'G' : 'g';
        case KEY_H: return shift ? 'H' : 'h';
        case KEY_I: return shift ? 'I' : 'i';
        case KEY_J: return shift ? 'J' : 'j';
        case KEY_K: return shift ? 'K' : 'k';
        case KEY_L: return shift ? 'L' : 'l';
        case KEY_M: return shift ? 'M' : 'm';
        case KEY_N: return shift ? 'N' : 'n';
        case KEY_O: return shift ? 'O' : 'o';
        case KEY_P: return shift ? 'P' : 'p';
        case KEY_Q: return shift ? 'Q' : 'q';
        case KEY_R: return shift ? 'R' : 'r';
        case KEY_S: return shift ? 'S' : 's';
        case KEY_T: return shift ? 'T' : 't';
        case KEY_U: return shift ? 'U' : 'u';
        case KEY_V: return shift ? 'V' : 'v';
        case KEY_W: return shift ? 'W' : 'w';
        case KEY_X: return shift ? 'X' : 'x';
        case KEY_Y: return shift ? 'Y' : 'y';
        case KEY_Z: return shift ? 'Z' : 'z';
        case KEY_1: return '1';
        case KEY_2: return '2';
        case KEY_3: return '3';
        case KEY_4: return '4';
        case KEY_5: return '5';
        case KEY_6: return '6';
        case KEY_7: return '7';
        case KEY_8: return '8';
        case KEY_9: return '9';
        case KEY_0: return '0';
        case KEY_KP1: return '1';
        case KEY_KP2: return '2';
        case KEY_KP3: return '3';
        case KEY_KP4: return '4';
        case KEY_KP5: return '5';
        case KEY_KP6: return '6';
        case KEY_KP7: return '7';
        case KEY_KP8: return '8';
        case KEY_KP9: return '9';
        case KEY_KP0: return '0';
        case KEY_SPACE: return ' ';
        default: return 0;
    }
}

int main(int argc, char **argv) {
    plymouth_active = check_plymouth();

    struct pollfd fds[MAX_EV_FDS];
    for (int i = 0; i < MAX_EV_FDS; i++) fds[i].fd = -1;

    int num_fds = scan_inputs(fds, MAX_EV_FDS);

    // Initial prompt display
    memset(input_buf, 0, sizeof(input_buf));
    buf_len = 0;
    update_display();

    while (1) {
        if (num_fds == 0) {
            usleep(250000);
            num_fds = scan_inputs(fds, MAX_EV_FDS);
            continue;
        }

        int ret = poll(fds, num_fds, 500);

        if (ret < 0) {
            if (errno == EINTR) continue;
            break;
        }

        // Periodically verify plymouth state
        plymouth_active = check_plymouth();

        if (ret == 0) {
            // Periodic rescan for newly attached USB keyboards
            int new_fds = scan_inputs(fds, MAX_EV_FDS);
            num_fds = new_fds;
            continue;
        }

        struct input_event ev;
        for (int i = 0; i < num_fds; i++) {
            if (fds[i].revents & POLLIN) {
                while (read(fds[i].fd, &ev, sizeof(ev)) == sizeof(ev)) {
                    if (ev.type != EV_KEY) continue;

                    // Track Shift key
                    if (ev.code == KEY_LEFTSHIFT || ev.code == KEY_RIGHTSHIFT) {
                        shift_down = (ev.value != 0);
                        continue;
                    }

                    // Key down or repeat
                    if (ev.value == 1 || ev.value == 2) {
                        // Power button press -> Safe power off
                        if (ev.code == KEY_POWER || ev.code == KEY_POWER2) {
                            if (plymouth_active) system("plymouth message --text=\"[POWER] Powering off machine...\" 2>/dev/null");
                            int cfd = open("/dev/console", O_WRONLY | O_NOCTTY);
                            if (cfd >= 0) {
                                ssize_t w = write(cfd, "\nPower button pressed. Powering off...\n", 39);
                                (void)w;
                                close(cfd);
                            }
                            sync();
                            reboot(RB_POWER_OFF);
                            return 1;
                        }

                        // Escape key -> Discard input buffer and re-prompt
                        if (ev.code == KEY_ESC) {
                            buf_len = 0;
                            input_buf[0] = '\0';
                            update_display();
                            continue;
                        }

                        // Enter key -> Submit answer if match; otherwise discard input string
                        if (ev.code == KEY_ENTER || ev.code == KEY_KPENTER) {
                            if (strcasecmp(input_buf, "yes") == 0) {
                                if (plymouth_active) system("plymouth message --text=\"[CONFIRMED] Clean boot (discard snapshot)...\" 2>/dev/null");
                                int cfd = open("/dev/console", O_WRONLY | O_NOCTTY);
                                if (cfd >= 0) {
                                    ssize_t w = write(cfd, "\nConfirmed: Discard snapshot and clean boot.\n", 45);
                                    (void)w;
                                    close(cfd);
                                }
                                return 0; // 0 = yes (discard / clean boot)
                            } else if (strcasecmp(input_buf, "no") == 0) {
                                if (plymouth_active) system("plymouth message --text=\"[CONFIRMED] Powering off machine...\" 2>/dev/null");
                                int cfd = open("/dev/console", O_WRONLY | O_NOCTTY);
                                if (cfd >= 0) {
                                    ssize_t w = write(cfd, "\nConfirmed: Power off machine.\n", 31);
                                    (void)w;
                                    close(cfd);
                                }
                                return 1; // 1 = no (power off)
                            } else if (strcasecmp(input_buf, "force") == 0) {
                                if (plymouth_active) system("plymouth message --text=\"[CONFIRMED] Forcing resume anyway...\" 2>/dev/null");
                                int cfd = open("/dev/console", O_WRONLY | O_NOCTTY);
                                if (cfd >= 0) {
                                    ssize_t w = write(cfd, "\nConfirmed: Forcing resume anyway.\n", 35);
                                    (void)w;
                                    close(cfd);
                                }
                                return 2; // 2 = force resume
                            } else {
                                // Enter discards the input string if it doesn't match yes/no/force
                                int cfd = open("/dev/console", O_WRONLY | O_NOCTTY);
                                if (cfd >= 0) {
                                    ssize_t w = write(cfd, "\n", 1);
                                    (void)w;
                                    close(cfd);
                                }
                                buf_len = 0;
                                input_buf[0] = '\0';
                                update_display();
                            }
                        } else if (ev.code == KEY_BACKSPACE || ev.code == KEY_DELETE) {
                            if (buf_len > 0) {
                                buf_len--;
                                input_buf[buf_len] = '\0';
                                update_display();
                            }
                        } else {
                            char c = keycode_to_ascii(ev.code, shift_down);
                            if (c != 0 && buf_len < (int)sizeof(input_buf) - 1) {
                                input_buf[buf_len++] = c;
                                input_buf[buf_len] = '\0';
                                update_display();
                            }
                        }
                    }
                }
            }
        }
    }

    for (int i = 0; i < num_fds; i++) {
        if (fds[i].fd >= 0) close(fds[i].fd);
    }
    return 1;
}
"""


PROTECTED_FAN_DAEMON_PATTERNS = [
    "gpd-win-2",
    "gpd_win_2",
    "gpd-pocket-3",
    "gpd_pocket_3",
    "nbfc",
    "gpd-win-2-governor",
    "gpd-pocket-3-i7-1195G7-governor",
    "gpd-win-2-lowpower",
    "gpd-pocket-3-i7-1195G7-lowpower",
    "gpd-win-2-power-watchdog",
    "gpd-pocket-3-power-watchdog",
    "gpd-win-2-sleep",
    "gpd-win-2-nbfc-prestart",
    "coretemp",
    "ec_sys",
]


def is_protected_fan_daemon_path(path):
    p_str = str(path).lower()
    return any(pat.lower() in p_str for pat in PROTECTED_FAN_DAEMON_PATTERNS)


GRUBENV_HEADER = b"# GRUB Environment Block\n"
GRUBENV_SIZE = 1024


def is_valid_grubenv(raw: bytes) -> bool:
    return len(raw) == GRUBENV_SIZE and raw.startswith(GRUBENV_HEADER)


def repair_grub_environment_block():
    """Validates and restores any corrupted GRUB environment blocks across standard paths."""
    candidates = [
        Path("/boot/grub/grubenv"),
        Path("/boot/grub2/grubenv"),
        Path("/boot/efi/EFI/debian/grubenv"),
        Path("/efi/EFI/debian/grubenv"),
        Path("/boot/efi/EFI/BOOT/grubenv"),
    ]

    for genv in candidates:
        needs_repair = False
        raw = b""
        if genv.exists():
            try:
                raw = genv.read_bytes()
                if not is_valid_grubenv(raw):
                    needs_repair = True
            except Exception:
                needs_repair = True
        elif (
            genv.parent.is_dir()
            and genv.name == "grubenv"
            and genv.parent.name in ["grub", "grub2"]
        ):
            needs_repair = True

        if needs_repair:
            print(
                f"  [GRUBENV] Repairing corrupted or missing GRUB environment block at {genv}..."
            )
            ensure_boot_rw()
            genv.parent.mkdir(parents=True, exist_ok=True)

            repaired_with_tool = False
            if shutil.which("grub-editenv"):
                try:
                    subprocess.run(
                        ["grub-editenv", str(genv), "create"],
                        check=True,
                        capture_output=True,
                    )
                    repaired_with_tool = True
                except Exception:
                    repaired_with_tool = False

            if not repaired_with_tool:
                salvaged = []
                if raw:
                    for line in raw.splitlines():
                        sline = line.strip()
                        if sline and not sline.startswith(b"#") and b"=" in sline:
                            salvaged.append(sline)

                content = GRUBENV_HEADER
                for v in salvaged:
                    if len(content) + len(v) + 1 <= GRUBENV_SIZE:
                        content += v + b"\n"

                if len(content) < GRUBENV_SIZE:
                    content += b"#" * (GRUBENV_SIZE - len(content))

                try:
                    genv.write_bytes(content[:GRUBENV_SIZE])
                    genv.chmod(0o644)
                    print(
                        f"  [GRUBENV] Successfully restored valid 1024-byte environment block at {genv}."
                    )
                except Exception as e:
                    sys.stderr.write(
                        f"Warning: could not write repaired grubenv at {genv}: {e}\n"
                    )


def ensure_boot_rw():
    for mount_target in ["/boot", "/boot/efi", "/efi"]:
        if Path(mount_target).is_mount() or Path(mount_target).is_dir():
            try:
                subprocess.run(
                    ["mount", "-o", "remount,rw", mount_target],
                    check=False,
                    capture_output=True,
                )
            except Exception:
                pass


def get_default_kernel_cmdline():
    raw_tokens = []
    default_grub = Path("/etc/default/grub")
    if default_grub.is_file():
        txt = default_grub.read_text()
        m_linux = re.search(
            r'^\s*GRUB_CMDLINE_LINUX=["\'](.*?)["\']', txt, re.MULTILINE
        )
        m_def = re.search(
            r'^\s*GRUB_CMDLINE_LINUX_DEFAULT=["\'](.*?)["\']', txt, re.MULTILINE
        )
        if m_linux and m_linux.group(1).strip():
            raw_tokens.extend(m_linux.group(1).strip().split())
        if m_def and m_def.group(1).strip():
            raw_tokens.extend(m_def.group(1).strip().split())

    grub_d = Path("/etc/default/grub.d")
    if grub_d.is_dir():
        for cfg in sorted(grub_d.glob("*.cfg")):
            txt = cfg.read_text()
            m_linux = re.search(
                r'^\s*GRUB_CMDLINE_LINUX=["\'](.*?)["\']', txt, re.MULTILINE
            )
            m_def = re.search(
                r'^\s*GRUB_CMDLINE_LINUX_DEFAULT=["\'](.*?)["\']', txt, re.MULTILINE
            )
            if m_linux and m_linux.group(1).strip():
                raw_tokens.extend(m_linux.group(1).strip().split())
            if m_def and m_def.group(1).strip():
                raw_tokens.extend(m_def.group(1).strip().split())

    cmdline_file = Path("/proc/cmdline")
    if cmdline_file.is_file():
        cmd_tokens = cmdline_file.read_text().strip().split()
        for token in cmd_tokens:
            if (
                token.startswith("BOOT_IMAGE=")
                or token.startswith("root=")
                or token.startswith("resume=")
                or token.startswith("grub_id=")
            ):
                continue
            if token in ["ro", "rw", "noresume"]:
                continue
            raw_tokens.append(token)

    seen = set()
    cleaned_tokens = []
    for t in raw_tokens:
        if t.startswith("resume=") or t == "noresume":
            continue
        if t not in seen:
            seen.add(t)
            cleaned_tokens.append(t)

    result = " ".join(cleaned_tokens).strip()
    return result if result else "quiet"


def get_resume_param():
    resume_target = ""
    resume_offset = ""

    # 1. Check /proc/cmdline
    cmdline_file = Path("/proc/cmdline")
    if cmdline_file.is_file():
        for token in cmdline_file.read_text().strip().split():
            if token.startswith("resume="):
                resume_target = token
            elif token.startswith("resume_offset="):
                resume_offset = token

    # 2. Check /etc/initramfs-tools/conf.d/resume
    if not resume_target:
        conf_resume = Path("/etc/initramfs-tools/conf.d/resume")
        if conf_resume.is_file():
            txt = conf_resume.read_text()
            m = re.search(r'^\s*RESUME=["\']?([^"\']+)["\']?', txt, re.MULTILINE)
            if m and m.group(1).strip() and m.group(1).strip().lower() != "none":
                val = m.group(1).strip()
                resume_target = f"resume={val}"

    # 3. Check /etc/default/grub & /etc/default/grub.d/*.cfg
    if not resume_target:
        for grub_cfg in [Path("/etc/default/grub")] + list(
            Path("/etc/default/grub.d").glob("*.cfg")
        ):
            if grub_cfg.is_file():
                txt = grub_cfg.read_text()
                for line in txt.splitlines():
                    if "GRUB_CMDLINE_LINUX" in line:
                        for token in line.split():
                            if token.startswith("resume="):
                                resume_target = token.strip("\"'")
                            elif token.startswith("resume_offset="):
                                resume_offset = token.strip("\"'")

    # 4. Check /proc/swaps
    if not resume_target:
        swaps_file = Path("/proc/swaps")
        if swaps_file.is_file():
            lines = swaps_file.read_text().splitlines()
            for line in lines[1:]:
                parts = line.split()
                if parts and parts[0].startswith("/dev/"):
                    swap_dev = parts[0]
                    res = subprocess.run(
                        ["blkid", "-s", "UUID", "-o", "value", swap_dev],
                        check=False,
                        capture_output=True,
                        text=True,
                    )
                    s_uuid = res.stdout.strip()
                    if s_uuid:
                        resume_target = f"resume=UUID={s_uuid}"
                    else:
                        resume_target = f"resume={swap_dev}"
                    break

    parts = []
    if resume_target:
        parts.append(resume_target)
    if resume_offset:
        parts.append(resume_offset)
    return " ".join(parts).strip()


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
    ensure_boot_rw()
    repair_grub_environment_block()

    # Explicit legacy files from previous iterations of this hibernation safeguard ONLY
    stale_paths = [
        Path("/etc/grub.d/08_hibernation_safeguard"),
        Path("/etc/default/grub.d/99-hibernation-safeguard.cfg"),
        Path("/usr/local/bin/gpd-machine-id"),
        Path("/lib/systemd/system-sleep/gpd-hibernation-hardware-tag"),
        Path("/etc/initramfs-tools/scripts/local-top/gpd_resume_check"),
        Path("/etc/initramfs-tools/conf.d/zz-gpd-hibernation.conf"),
        Path("/etc/initramfs-tools/hooks/gpd_include_script"),
        Path("/boot/grub_hib_id"),
        Path("/boot/initramfs_hib_id"),
        Path("/boot/loader/gpd_sdboot_hib_id"),
        Path("/boot/loader/sdboot_hib_id"),
        Path("/run/hibernation-safeguard"),
        Path("/tmp/gpd_ply_key"),
        Path("/tmp/hib_ply_key"),
        Path("/root/deploy_adaptive_protection.py"),
        Path("/root/deploy_hibernation_safeguard.py"),
    ]

    # Only glob safeguard-specific names; NEVER glob generic *gpd* which breaks fan control daemons
    for gpath in (
        list(Path("/etc/grub.d").glob("*hibernation_safeguard*"))
        + list(Path("/etc/grub.d").glob("*hibernation-safeguard*"))
        + list(Path("/etc/default/grub.d").glob("*hibernation_safeguard*"))
        + list(Path("/etc/default/grub.d").glob("*hibernation-safeguard*"))
        + list(Path("/etc/initramfs-tools/hooks").glob("*hibernation_safeguard*"))
        + list(
            Path("/etc/initramfs-tools/scripts/local-top").glob(
                "*hibernation_resume_check*"
            )
        )
    ):
        stale_paths.append(gpath)

    for p in set(stale_paths):
        # Strict safety check: Never delete or touch files belonging to fan control daemons
        if is_protected_fan_daemon_path(p):
            continue

        if p.exists():
            if p.is_file() or p.is_symlink():
                try:
                    p.unlink()
                    print(f"Removed legacy/stale file: {p}")
                except OSError:
                    ensure_boot_rw()
                    try:
                        p.unlink()
                        print(f"Removed legacy/stale file: {p}")
                    except OSError as e2:
                        sys.stderr.write(f"Warning: could not remove {p}: {e2}\n")
            elif p.is_dir():
                try:
                    shutil.rmtree(p)
                    print(f"Removed legacy directory: {p}")
                except OSError as e:
                    sys.stderr.write(f"Warning: could not remove directory {p}: {e}\n")

    # Purge safeguard sentinel comments from /etc/initramfs-tools/modules without touching fan control blocks
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
    res_boot = run_command(["df", "/boot"], capture_output=True)
    lines_boot = res_boot.stdout.strip().splitlines()
    if len(lines_boot) < 2:
        sys.stderr.write("ERROR: Could not resolve block device for /boot\n")
        sys.exit(1)
    boot_dev = lines_boot[1].split()[0]

    res_root = run_command(["df", "/"], capture_output=True)
    lines_root = res_root.stdout.strip().splitlines()
    if len(lines_root) < 2:
        sys.stderr.write("ERROR: Could not resolve block device for /\n")
        sys.exit(1)
    root_dev = lines_root[1].split()[0]

    res_boot_uuid = run_command(
        ["blkid", "-s", "UUID", "-o", "value", boot_dev],
        check=False,
        capture_output=True,
    )
    boot_uuid = res_boot_uuid.stdout.strip()
    if not boot_uuid:
        boot_uuid = ""

    res_root_uuid = run_command(
        ["blkid", "-s", "UUID", "-o", "value", root_dev],
        check=False,
        capture_output=True,
    )
    root_uuid = res_root_uuid.stdout.strip()

    is_separate_boot = (boot_dev != root_dev) and (Path("/boot").is_mount())
    kernel_dir = "" if is_separate_boot else "/boot"
    root_spec = f"UUID={root_uuid}" if root_uuid else root_dev

    default_cmdline = get_default_kernel_cmdline()
    resume_param = get_resume_param()

    has_grub = Path("/etc/grub.d").is_dir() and shutil.which("update-grub") is not None

    has_systemd_boot = False
    esp_dir = ""
    for path in ["/boot/efi", "/efi", "/boot"]:
        if Path(f"{path}/loader/entries").is_dir():
            has_systemd_boot = True
            esp_dir = path
            break

    print(
        f"Resolved /boot partition at {boot_dev} (UUID: {boot_uuid or 'unknown'}, separate: {is_separate_boot})"
    )
    print(f"Resolved / (root) partition at {root_dev} (root_spec: {root_spec})")
    print(f"Hardware Kernel Cmdline Parameters: '{default_cmdline}'")
    print(f"Resolved Resume Parameter: '{resume_param or 'none'}'")
    print(f"Detection Results -> GRUB: {has_grub} | systemd-boot: {has_systemd_boot}")
    return (
        boot_dev,
        boot_uuid,
        root_dev,
        root_uuid,
        root_spec,
        kernel_dir,
        default_cmdline,
        resume_param,
        has_grub,
        has_systemd_boot,
        esp_dir,
    )


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

    # Install initramfs hook to bundle ethtool binary and C interactive prompt into initramfs
    hooks_d = Path("/etc/initramfs-tools/hooks")
    hooks_d.mkdir(parents=True, exist_ok=True)
    tool_hook = hooks_d / "hibernation_safeguard_tools"
    tool_hook_content = f"""#!/bin/sh
# Installed by {installer_name}
# Bundles ethtool binary and C interactive prompt into initramfs
PREREQ=""
prereqs() {{ echo "$PREREQ"; }}
case $1 in prereqs) prereqs; exit 0;; esac

. /usr/share/initramfs-tools/hook-functions

if command -v ethtool >/dev/null 2>&1; then
    copy_exec $(command -v ethtool) /sbin
fi

if [ -x /usr/local/bin/hibernation-resume-prompt ]; then
    copy_exec /usr/local/bin/hibernation-resume-prompt /bin/hibernation-resume-prompt
    copy_exec /usr/local/bin/hibernation-resume-prompt /usr/bin/hibernation-resume-prompt
fi
"""
    tool_hook.write_text(tool_hook_content)
    tool_hook.chmod(0o755)


def write_c_prompt_daemon(installer_name=INSTALLER_NAME):
    print("=== 2b. Compiling Native C Initramfs evdev Interactive Prompt ===")
    src_dir = Path("/usr/local/src")
    src_dir.mkdir(parents=True, exist_ok=True)
    c_path = src_dir / "hibernation-resume-prompt.c"
    c_path.write_text(C_PROMPT_SOURCE)

    bin_path = Path("/usr/local/bin/hibernation-resume-prompt")
    bin_path.parent.mkdir(parents=True, exist_ok=True)

    if not shutil.which("gcc") and shutil.which("apt-get"):
        print("Checking for gcc compiler package...")
        try:
            run_command(
                ["apt-get", "install", "-y", "-qq", "gcc", "build-essential"],
                check=False,
            )
        except Exception:
            pass

    if shutil.which("gcc"):
        try:
            run_command(
                ["gcc", "-O2", str(c_path), "-o", str(bin_path)],
                check=True,
            )
            bin_path.chmod(0o755)
            print(f"  [OK] Compiled {bin_path} successfully.")
        except Exception as e:
            sys.stderr.write(f"Warning: Failed to compile {c_path}: {e}\n")
            sys.stderr.write(
                "  Safeguard will rely on the initramfs shell prompt fallback.\n"
            )
    else:
        sys.stderr.write(
            "Warning: gcc compiler not found. Safeguard will rely on the initramfs shell prompt fallback.\n"
        )


def write_machine_id_helper(boot_uuid, installer_name=INSTALLER_NAME):
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

    # Reject kernel-randomized addresses (type 1)
    if [ -f "$candidate_dir/addr_assign_type" ]; then
        assign_type=$(cat "$candidate_dir/addr_assign_type" 2>/dev/null | tr -d '\r\n ')
        [ "$assign_type" = "1" ] && continue
    fi

    # Query ethtool permanent hardware address if available
    if command -v ethtool >/dev/null 2>&1; then
        perm_val=$(ethtool -P "$iface_name" 2>/dev/null | awk '/Permanent address:/ {print $3}' | tr -d '\r\n ')
        if is_permanent_hw_mac "$perm_val"; then
            MAC_STR="$perm_val"
            IFACE_STR="$iface_name"
            break
        fi
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

repair_grubenv_if_corrupted() {
    for _genv in /boot/grub/grubenv /boot/grub2/grubenv /boot/efi/EFI/debian/grubenv /efi/EFI/debian/grubenv; do
        if [ -f "$_genv" ]; then
            _sz=$(wc -c < "$_genv" 2>/dev/null | tr -d ' ')
            _hdr=$(head -n 1 "$_genv" 2>/dev/null)
            if [ "$_sz" != "1024" ] || [ "$_hdr" != "# GRUB Environment Block" ]; then
                if command -v grub-editenv >/dev/null 2>&1; then
                    grub-editenv "$_genv" create 2>/dev/null || true
                else
                    printf "# GRUB Environment Block\n" > "$_genv" 2>/dev/null
                    awk 'BEGIN { for (i = 25; i < 1024; i++) printf "#"; }' >> "$_genv" 2>/dev/null || true
                fi
            fi
        fi
    done
}

if [ "$1" = "save-targets" ]; then
    repair_grubenv_if_corrupted
    _was_ro=0
    if mountpoint -q /boot 2>/dev/null; then
        if grep -qE '[[:space:]]/boot[[:space:]]+[^ ]+[[:space:]]+([^ ]*,)?ro[, ]' /proc/mounts 2>/dev/null; then
            _was_ro=1
        fi
        mount -o remount,rw /boot 2>/dev/null || true
    fi

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

    if [ "$_was_ro" = "1" ] && mountpoint -q /boot 2>/dev/null; then
        mount -o remount,ro /boot 2>/dev/null || true
    fi

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
    repair_grubenv_if_corrupted
    _was_ro=0
    if mountpoint -q /boot 2>/dev/null; then
        if grep -qE '[[:space:]]/boot[[:space:]]+[^ ]+[[:space:]]+([^ ]*,)?ro[, ]' /proc/mounts 2>/dev/null; then
            _was_ro=1
        fi
        mount -o remount,rw /boot 2>/dev/null || true
    fi

    rm -f /boot/grub_hib_id /boot/initramfs_hib_id /boot/loader/sdboot_hib_id /boot/loader/gpd_sdboot_hib_id 2>/dev/null
    rm -rf /run/hibernation-safeguard 2>/dev/null

    # If /boot is a separate partition, check if target partition holds uncleaned files
    _boot_uuid="__BOOT_UUID__"
    if [ -n "$_boot_uuid" ]; then
        _bdev=$(blkid -U "$_boot_uuid" 2>/dev/null)
        if [ -n "$_bdev" ] && [ -b "$_bdev" ]; then
            if ! mountpoint -q /boot 2>/dev/null; then
                _tmp_c="/tmp/clear_boot_target_mnt"
                mkdir -p "$_tmp_c"
                if mount -o rw "$_bdev" "$_tmp_c" 2>/dev/null; then
                    rm -f "$_tmp_c/grub_hib_id" "$_tmp_c/initramfs_hib_id" "$_tmp_c/loader/sdboot_hib_id" "$_tmp_c/loader/gpd_sdboot_hib_id" 2>/dev/null
                    umount "$_tmp_c" 2>/dev/null || true
                fi
                rmdir "$_tmp_c" 2>/dev/null || true
            fi
        fi
    fi

    if [ "$_was_ro" = "1" ] && mountpoint -q /boot 2>/dev/null; then
        mount -o remount,ro /boot 2>/dev/null || true
    fi

    if was_booted_by_systemd_boot || [ -f /boot/loader/sdboot_hib_id ]; then
        if command -v bootctl >/dev/null 2>&1; then
            bootctl set-default "" 2>/dev/null || true
        fi
    fi
fi
"""
    helper_content = helper_template.replace(
        "__INSTALLER_NAME__", installer_name
    ).replace("__BOOT_UUID__", boot_uuid)
    helper_path.parent.mkdir(parents=True, exist_ok=True)
    helper_path.write_text(helper_content)
    helper_path.chmod(0o755)

    # Only remove legacy helper symlink if it was an artifact pointing to our helper
    legacy_helper = Path("/usr/local/bin/gpd-machine-id")
    if legacy_helper.is_symlink():
        try:
            if "hibernation-machine-id" in str(legacy_helper.resolve()):
                legacy_helper.unlink()
        except OSError:
            pass


def write_systemd_sleep_hook(installer_name=INSTALLER_NAME):
    print(
        "=== 4. Setting up Systemd Sleep Hooks (Clean Userspace Target Management) ==="
    )
    hook_path = Path("/lib/systemd/system-sleep/hibernation-hardware-tag")
    hook_path.parent.mkdir(parents=True, exist_ok=True)
    content_template = r"""#!/bin/bash
# Installed by __INSTALLER_NAME__
# Universal Pre- and Post-Sleep Hook for Hardware Hibernation Safeguard
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

    # 1. Save hardware targets to /boot
    /usr/local/bin/hibernation-machine-id save-targets

    # 2. Flush dirty filesystem buffers to disk
    sync

    # 3. Attempt to sync and then unmount /boot/efi (if it exists) and /boot immediately prior to hibernation
    if [ -d /boot/efi ] && mountpoint -q /boot/efi 2>/dev/null; then
        umount /boot/efi 2>/dev/null || true
    fi
    if [ -d /boot ] && mountpoint -q /boot 2>/dev/null; then
        umount /boot 2>/dev/null || true
    fi

    # 4. Flush dirty buffers again
    sync

    # 5. Optional safeguard against ACPI S4 poweroff hangs:
    if [ -f /sys/power/disk ]; then
        grep -q "shutdown" /sys/power/disk 2>/dev/null && echo "shutdown" > /sys/power/disk 2>/dev/null || true
    fi

elif [ "$1" = "post" ] && [ "$2" = "hibernate" ]; then
    echo "Hibernation Safeguard (__INSTALLER_NAME__): Resuming from hibernation, clearing target records..."

    # 1. Attempt to mount /boot and /boot/efi (if they exist) immediately after resumption
    if [ -d /boot ] && ! mountpoint -q /boot 2>/dev/null; then
        mount /boot 2>/dev/null || true
    fi
    if [ -d /boot/efi ] && ! mountpoint -q /boot/efi 2>/dev/null; then
        mount /boot/efi 2>/dev/null || true
    fi

    # 2. Safely clean up targets in userspace after resume has succeeded
    /usr/local/bin/hibernation-machine-id clear-targets
fi
"""
    content = content_template.replace("__INSTALLER_NAME__", installer_name)
    hook_path.write_text(content)
    hook_path.chmod(0o755)


def write_boot_cleanup_service(installer_name=INSTALLER_NAME):
    print("=== 4b. Setting up Boot Target Cleanup Service (Normal Boot Cleanup) ===")
    service_path = Path("/lib/systemd/system/hibernation-safeguard-cleanup.service")
    service_path.parent.mkdir(parents=True, exist_ok=True)
    content = f"""[Unit]
Description=Hibernation Safeguard Target Cleanup on Normal Boot
Documentation=https://github.com/f-fix/x86-64-debian-hibernation-safeguard
DefaultDependencies=no
After=local-fs.target
Before=basic.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/hibernation-machine-id clear-targets
RemainAfterExit=yes

[Install]
WantedBy=basic.target
"""
    service_path.write_text(content)
    service_path.chmod(0o644)

    wants_dir = Path("/etc/systemd/system/basic.target.wants")
    wants_dir.mkdir(parents=True, exist_ok=True)
    wants_link = wants_dir / "hibernation-safeguard-cleanup.service"
    if wants_link.exists() or wants_link.is_symlink():
        try:
            wants_link.unlink()
        except OSError:
            pass
    try:
        wants_link.symlink_to(service_path)
    except OSError:
        pass


def write_grub_hooks(
    boot_uuid,
    root_spec,
    kernel_dir,
    default_cmdline,
    resume_param,
    installer_name=INSTALLER_NAME,
):
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

    # Discover installed versioned kernels in /boot to ensure versioned GRUB references
    installed_versions = []
    curr_k = os.uname().release
    if curr_k:
        installed_versions.append(curr_k)

    boot_dir = Path("/boot")
    if boot_dir.is_dir():
        for kfile in sorted(boot_dir.glob("vmlinuz-*"), reverse=True):
            if kfile.is_file() and not kfile.is_symlink():
                v = kfile.name[len("vmlinuz-") :].strip()
                if v and v not in installed_versions:
                    installed_versions.append(v)

    # Order oldest to newest so newest installed kernel wins if saved kernel is absent
    sorted_versions = list(reversed(installed_versions))

    def generate_kernel_selector(extra_arg):
        lines = []
        lines.append('                chosen_kernel=""')
        lines.append('                chosen_initrd=""')
        lines.append("")
        lines.append(
            "                # 1. Unversioned fallback (lowest priority, only if file exists)"
        )
        lines.append("                if [ -f /vmlinuz ]; then")
        lines.append('                    chosen_kernel="/vmlinuz"')
        lines.append('                    chosen_initrd="/initrd.img"')
        lines.append("                fi")
        lines.append("                if [ -f /boot/vmlinuz ]; then")
        lines.append('                    chosen_kernel="/boot/vmlinuz"')
        lines.append('                    chosen_initrd="/boot/initrd.img"')
        lines.append("                fi")
        lines.append("")
        lines.append(
            "                # 2. Installed versioned kernels (ordered oldest to newest so newest wins)"
        )
        for v in sorted_versions:
            lines.append(f"                if [ -f /vmlinuz-{v} ]; then")
            lines.append(f'                    chosen_kernel="/vmlinuz-{v}"')
            lines.append(f'                    chosen_initrd="/initrd.img-{v}"')
            lines.append("                fi")
            lines.append(f"                if [ -f /boot/vmlinuz-{v} ]; then")
            lines.append(f'                    chosen_kernel="/boot/vmlinuz-{v}"')
            lines.append(f'                    chosen_initrd="/boot/initrd.img-{v}"')
            lines.append("                fi")
        lines.append("")
        lines.append(
            "                # 3. Saved hibernation kernel from previous session (highest priority)"
        )
        lines.append('                if [ -n "$SAVED_KERNEL_VERSION" ]; then')
        lines.append(
            "                    if [ -f /vmlinuz-$SAVED_KERNEL_VERSION ]; then"
        )
        lines.append(
            '                        chosen_kernel="/vmlinuz-$SAVED_KERNEL_VERSION"'
        )
        lines.append(
            '                        chosen_initrd="/initrd.img-$SAVED_KERNEL_VERSION"'
        )
        lines.append("                    fi")
        lines.append(
            "                    if [ -f /boot/vmlinuz-$SAVED_KERNEL_VERSION ]; then"
        )
        lines.append(
            '                        chosen_kernel="/boot/vmlinuz-$SAVED_KERNEL_VERSION"'
        )
        lines.append(
            '                        chosen_initrd="/boot/initrd.img-$SAVED_KERNEL_VERSION"'
        )
        lines.append("                    fi")
        lines.append("                fi")
        lines.append("")
        lines.append('                if [ -n "$chosen_kernel" ]; then')
        lines.append(
            f"                    linux $chosen_kernel root={root_spec} ro {default_cmdline} {extra_arg}"
        )
        lines.append('                    if [ -n "$chosen_initrd" ]; then')
        lines.append("                        initrd $chosen_initrd")
        lines.append("                    fi")
        lines.append("                    boot")
        lines.append("                fi")
        return "\n".join(lines)

    clean_selector = generate_kernel_selector("noresume")
    force_selector = generate_kernel_selector(resume_param)

    template_block = r"""__SENTINEL_START__
insmod smbios
insmod echo
insmod search_fs_uuid
insmod test
insmod sleep
insmod halt

set target_boot_part=""
search --no-floppy --fs-uuid --set=target_boot_part __BOOT_UUID__

if [ -n "$target_boot_part" ]; then
    if [ -f ($target_boot_part)/grub_hib_id ]; then
        source ($target_boot_part)/grub_hib_id

        # Query live machine SMBIOS / DMI tables using standard structure byte offsets
        set curr_sys_vendor=""
        smbios --type 1 --get-string 4 --set=curr_sys_vendor
        set curr_product_name=""
        smbios --type 1 --get-string 5 --set=curr_product_name
        set curr_product_version=""
        smbios --type 1 --get-string 6 --set=curr_product_version
        set curr_bios_vendor=""
        smbios --type 0 --get-string 4 --set=curr_bios_vendor
        set curr_bios_version=""
        smbios --type 0 --get-string 5 --set=curr_bios_version
        set curr_board_vendor=""
        smbios --type 2 --get-string 4 --set=curr_board_vendor
        set curr_board_name=""
        smbios --type 2 --get-string 5 --set=curr_board_name
        set curr_cpu_model=""
        smbios --type 4 --get-string 16 --set=curr_cpu_model
        if [ -z "$curr_cpu_model" ]; then
            smbios --type 4 --get-string 5 --set=curr_cpu_model
        fi
        set current_grub_id="$curr_cpu_model"

        # Check for hardware and DMI mismatches ONLY when fields resolved non-empty
        set grub_mismatch="0"
        set sys_vendor_mismatch="0"
        set product_name_mismatch="0"
        set product_version_mismatch="0"
        set bios_vendor_mismatch="0"
        set bios_version_mismatch="0"
        set board_vendor_mismatch="0"
        set board_name_mismatch="0"
        set grub_id_mismatch="0"

        if [ -n "$SAVED_SYS_VENDOR" ]; then
            if [ -n "$curr_sys_vendor" ]; then
                if [ "$curr_sys_vendor" != "$SAVED_SYS_VENDOR" ]; then
                    set grub_mismatch="1"
                    set sys_vendor_mismatch="1"
                fi
            fi
        fi

        if [ -n "$SAVED_PRODUCT_NAME" ]; then
            if [ -n "$curr_product_name" ]; then
                if [ "$curr_product_name" != "$SAVED_PRODUCT_NAME" ]; then
                    set grub_mismatch="1"
                    set product_name_mismatch="1"
                fi
            fi
        fi

        if [ -n "$SAVED_PRODUCT_VERSION" ]; then
            if [ -n "$curr_product_version" ]; then
                if [ "$curr_product_version" != "$SAVED_PRODUCT_VERSION" ]; then
                    set grub_mismatch="1"
                    set product_version_mismatch="1"
                fi
            fi
        fi

        if [ -n "$SAVED_BIOS_VENDOR" ]; then
            if [ -n "$curr_bios_vendor" ]; then
                if [ "$curr_bios_vendor" != "$SAVED_BIOS_VENDOR" ]; then
                    set grub_mismatch="1"
                    set bios_vendor_mismatch="1"
                fi
            fi
        fi

        if [ -n "$SAVED_BIOS_VERSION" ]; then
            if [ -n "$curr_bios_version" ]; then
                if [ "$curr_bios_version" != "$SAVED_BIOS_VERSION" ]; then
                    set grub_mismatch="1"
                    set bios_version_mismatch="1"
                fi
            fi
        fi

        if [ -n "$SAVED_BOARD_VENDOR" ]; then
            if [ -n "$curr_board_vendor" ]; then
                if [ "$curr_board_vendor" != "$SAVED_BOARD_VENDOR" ]; then
                    set grub_mismatch="1"
                    set board_vendor_mismatch="1"
                fi
            fi
        fi

        if [ -n "$SAVED_BOARD_NAME" ]; then
            if [ -n "$curr_board_name" ]; then
                if [ "$curr_board_name" != "$SAVED_BOARD_NAME" ]; then
                    set grub_mismatch="1"
                    set board_name_mismatch="1"
                fi
            fi
        fi

        if [ -n "$SAVED_GRUB_ID" ]; then
            if [ -n "$current_grub_id" ]; then
                if [ "$current_grub_id" != "$SAVED_GRUB_ID" ]; then
                    set grub_mismatch="1"
                    set grub_id_mismatch="1"
                fi
            fi
        fi

        if [ "$grub_mismatch" = "1" ]; then
            # Hardware Mismatch Flagged: Disable countdown timeout completely and force menu display
            set timeout=-1
            set timeout_style=menu

            echo "============================================================"
            echo "  [SAFEGUARD] HIBERNATION HARDWARE MISMATCH DETECTED!"
            echo "============================================================"
            echo "Hardware changes detected since hibernation:"
            if [ "$sys_vendor_mismatch" = "1" ]; then
                echo "  System Vendor:   '$SAVED_SYS_VENDOR' -> '$curr_sys_vendor'"
            fi
            if [ "$product_name_mismatch" = "1" ]; then
                echo "  Product Name:    '$SAVED_PRODUCT_NAME' -> '$curr_product_name'"
            fi
            if [ "$product_version_mismatch" = "1" ]; then
                echo "  Product Version: '$SAVED_PRODUCT_VERSION' -> '$curr_product_version'"
            fi
            if [ "$bios_vendor_mismatch" = "1" ]; then
                echo "  BIOS Vendor:     '$SAVED_BIOS_VENDOR' -> '$curr_bios_vendor'"
            fi
            if [ "$bios_version_mismatch" = "1" ]; then
                echo "  BIOS Version:    '$SAVED_BIOS_VERSION' -> '$curr_bios_version'"
            fi
            if [ "$board_name_mismatch" = "1" ]; then
                echo "  Board Name:      '$SAVED_BOARD_NAME' -> '$curr_board_name'"
            fi
            if [ "$grub_id_mismatch" = "1" ]; then
                echo "  Processor / ID:  '$SAVED_GRUB_ID' -> '$current_grub_id'"
            fi
            echo "============================================================"
            echo "Automatic countdown is DISABLED."
            echo "Available options in the menu (Default: Safe Power Off):"
            echo "  * Power Off Machine (Preserve Hibernation Session - Preselected)"
            echo "  * Discard Hibernation Image & Boot Cleanly"
            echo "  * Force Resume Anyway (Danger: Hardware Mismatch)"
            echo "============================================================"
            echo ""
            echo "Press ESC or wait for timer to proceed to menu..."
            sleep --verbose --interruptible 30

            # Dedicated Safeguard Menu Options in pure ASCII (Safe Power Off is Entry 1 and default)
            menuentry "[SAFEGUARD] 1. Power Off Machine (Preserve Hibernation Session - Default)" --id=safeguard_poweroff {
                echo "Safely powering off machine to preserve hibernated session..."
                halt
            }

            menuentry "[SAFEGUARD] 2. Discard Hibernation Image & Boot Cleanly" --id=safeguard_clean {
                echo "Loading kernel for clean boot (noresume)..."
                search --no-floppy --fs-uuid --set=root __BOOT_UUID__
__CLEAN_BOOT_SELECTOR__
            }

            menuentry "[SAFEGUARD] 3. Force Resume Anyway (Dangerous - May Panic)" --id=safeguard_force {
                echo "Loading kernel for forced resume..."
                search --no-floppy --fs-uuid --set=root __BOOT_UUID__
__FORCE_BOOT_SELECTOR__
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
        .replace("__CLEAN_BOOT_SELECTOR__", clean_selector)
        .replace("__FORCE_BOOT_SELECTOR__", force_selector)
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

PREREQ="udev"
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

[ -f /scripts/functions ] && . /scripts/functions || true

echo "=== Universal Hardware Hibernation Resume Validation ==="

# 0. Check if resume is inhibited via kernel command line (noresume or resume=none/0:0)
no_resume_requested=false
for arg in $(cat /proc/cmdline 2>/dev/null); do
    case "$arg" in
        noresume|resume=none|resume=0:0)
            no_resume_requested=true
            ;;
    esac
done

if [ "$no_resume_requested" = true ]; then
    echo "Safeguard: 'noresume' detected on kernel command line. Bypassing hardware checks for clean boot."

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
# Sanitizer installed dynamically by __INSTALLER_NAME__ during clean boot / noresume
PREREQ="udev"
prereqs() { echo "$PREREQ"; }
case $1 in prereqs) prereqs; exit 0;; esac

echo "Safeguard Clean Boot: Sanitizing swap suspend signatures (LUKS/LVM/disk)..."
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

    mkdir -p /run/hibernation-safeguard
    echo "discard" > /run/hibernation-safeguard/action

    exit 0
fi

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

# Strictly READ-ONLY mount, read targets into memory, immediately unmount
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
        DMI_MISMATCH_DETAILS="${DMI_MISMATCH_DETAILS}    System Vendor:   '$SAVED_SYS_VENDOR' -> '$CURRENT_SYS_VENDOR'\n"
    fi

    if [ -n "$SAVED_PRODUCT_NAME" ] && [ "$SAVED_PRODUCT_NAME" != "$CURRENT_PRODUCT_NAME" ]; then
        DMI_MISMATCH=true
        HAS_MISMATCH=true
        DMI_MISMATCH_DETAILS="${DMI_MISMATCH_DETAILS}    Product Name:    '$SAVED_PRODUCT_NAME' -> '$CURRENT_PRODUCT_NAME'\n"
    fi

    if [ -n "$SAVED_PRODUCT_VERSION" ] && [ "$SAVED_PRODUCT_VERSION" != "$CURRENT_PRODUCT_VERSION" ]; then
        DMI_MISMATCH=true
        HAS_MISMATCH=true
        DMI_MISMATCH_DETAILS="${DMI_MISMATCH_DETAILS}    Product Version: '$SAVED_PRODUCT_VERSION' -> '$CURRENT_PRODUCT_VERSION'\n"
    fi

    if [ -n "$SAVED_BIOS_VENDOR" ] && [ "$SAVED_BIOS_VENDOR" != "$CURRENT_BIOS_VENDOR" ]; then
        DMI_MISMATCH=true
        HAS_MISMATCH=true
        DMI_MISMATCH_DETAILS="${DMI_MISMATCH_DETAILS}    BIOS Vendor:     '$SAVED_BIOS_VENDOR' -> '$CURRENT_BIOS_VENDOR'\n"
    fi

    if [ -n "$SAVED_BIOS_VERSION" ] && [ "$SAVED_BIOS_VERSION" != "$CURRENT_BIOS_VERSION" ]; then
        DMI_MISMATCH=true
        HAS_MISMATCH=true
        DMI_MISMATCH_DETAILS="${DMI_MISMATCH_DETAILS}    BIOS Version:    '$SAVED_BIOS_VERSION' -> '$CURRENT_BIOS_VERSION'\n"
    fi

    if [ -n "$SAVED_BOARD_VENDOR" ] && [ "$SAVED_BOARD_VENDOR" != "$CURRENT_BOARD_VENDOR" ]; then
        DMI_MISMATCH=true
        HAS_MISMATCH=true
        DMI_MISMATCH_DETAILS="${DMI_MISMATCH_DETAILS}    Board Vendor:    '$SAVED_BOARD_VENDOR' -> '$CURRENT_BOARD_VENDOR'\n"
    fi

    if [ -n "$SAVED_BOARD_NAME" ] && [ "$SAVED_BOARD_NAME" != "$CURRENT_BOARD_NAME" ]; then
        DMI_MISMATCH=true
        HAS_MISMATCH=true
        DMI_MISMATCH_DETAILS="${DMI_MISMATCH_DETAILS}    Board Name:      '$SAVED_BOARD_NAME' -> '$CURRENT_BOARD_NAME'\n"
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
        curr_val=""
        if command -v ethtool >/dev/null 2>&1; then
            perm_val=$(ethtool -P "$SAVED_MAC_IFACE" 2>/dev/null | awk '/Permanent address:/ {print $3}' | tr -d '\r\n ')
            if is_permanent_hw_mac "$perm_val"; then
                curr_val="$perm_val"
            fi
        fi

        if [ -z "$curr_val" ] && [ -f "/sys/class/net/$SAVED_MAC_IFACE/address" ]; then
            val=$(cat "/sys/class/net/$SAVED_MAC_IFACE/address" 2>/dev/null | tr -d '\r\n ')
            is_perm=true
            if [ -f "/sys/class/net/$SAVED_MAC_IFACE/addr_assign_type" ]; then
                assign_type=$(cat "/sys/class/net/$SAVED_MAC_IFACE/addr_assign_type" 2>/dev/null | tr -d '\r\n ')
                [ "$assign_type" = "1" ] && is_perm=false
            fi
            if [ "$is_perm" = true ] && is_permanent_hw_mac "$val"; then
                curr_val="$val"
            fi
        fi

        if [ -n "$curr_val" ]; then
            CURRENT_MAC="$curr_val"
            if [ "$SAVED_MAC" != "$CURRENT_MAC" ]; then
                MAC_MISMATCH=true
                HAS_MISMATCH=true
            fi
        fi
    fi
fi

if [ "$HAS_MISMATCH" = true ]; then
    CONSOLE_OUT="/dev/console"
    [ ! -c "$CONSOLE_OUT" ] && CONSOLE_OUT="/dev/tty0"
    [ ! -c "$CONSOLE_OUT" ] && CONSOLE_OUT=""

    print_console() {
        if [ -n "$CONSOLE_OUT" ]; then
            printf "%b\n" "$1" > "$CONSOLE_OUT" 2>/dev/null || printf "%b\n" "$1"
        else
            printf "%b\n" "$1"
        fi
    }

    print_console "============================================================"
    print_console "  [SAFEGUARD] HIBERNATION HARDWARE MISMATCH DETECTED!"
    print_console "============================================================"
    print_console "Hardware changes detected since hibernation:"
    if [ "$KERNEL_MISMATCH" = true ]; then
        print_console "  Kernel Version:  '$SAVED_KERNEL' -> '$CURRENT_KERNEL'"
    fi
    if [ "$CPU_MISMATCH" = true ]; then
        print_console "  Processor / CPU: '$SAVED_CPU' -> '$CURRENT_CPU'"
    fi
    if [ "$RAM_MISMATCH" = true ]; then
        print_console "  Memory Total:    '$SAVED_RAM' -> '$CURRENT_RAM'"
    fi
    if [ "$MAC_MISMATCH" = true ]; then
        print_console "  Permanent MAC:   '$SAVED_MAC' -> '$CURRENT_MAC' ($SAVED_MAC_IFACE)"
    fi
    if [ -n "$DMI_MISMATCH_DETAILS" ]; then
        printf "%b" "$DMI_MISMATCH_DETAILS" > "$CONSOLE_OUT" 2>/dev/null || printf "%b" "$DMI_MISMATCH_DETAILS"
    fi
    print_console "============================================================"

    user_input=""

    # Interactive prompt via compiled native C micro-daemon
    PROMPT_BIN=""
    if [ -x /bin/hibernation-resume-prompt ]; then
        PROMPT_BIN="/bin/hibernation-resume-prompt"
    elif [ -x /usr/bin/hibernation-resume-prompt ]; then
        PROMPT_BIN="/usr/bin/hibernation-resume-prompt"
    elif command -v hibernation-resume-prompt >/dev/null 2>&1; then
        PROMPT_BIN=$(command -v hibernation-resume-prompt)
    fi

    if [ -n "$PROMPT_BIN" ] && [ -x "$PROMPT_BIN" ]; then
        "$PROMPT_BIN"
        prompt_rc=$?
        case "$prompt_rc" in
            0) user_input="yes" ;;
            1) user_input="no" ;;
            2) user_input="force" ;;
            *)
                echo "[WARNING] C prompt binary exited with status $prompt_rc." > /dev/console 2>/dev/null || true
                user_input=""
                ;;
        esac
    fi

    # Fallback to shell-based interactive prompt if C binary was missing, non-executable, or exited abnormally
    if [ -z "$user_input" ]; then
        PROMPT_STR="Lose unmatched hibernation? Yes=new/No=off/Force=resume: > "

        while [ -z "$user_input" ]; do
            raw_ans=""
            if command -v plymouth >/dev/null 2>&1 && plymouth --ping 2>/dev/null; then
                raw_ans=$(plymouth ask-question --prompt="$PROMPT_STR" 2>/dev/null)
                if ! plymouth --ping 2>/dev/null; then
                    plymouth quit 2>/dev/null || true
                fi
            else
                CONSOLE_IN=""
                if [ -c /dev/console ] && [ -r /dev/console ]; then
                    CONSOLE_IN="/dev/console"
                elif [ -c /dev/tty0 ] && [ -r /dev/tty0 ]; then
                    CONSOLE_IN="/dev/tty0"
                fi

                if [ -n "$CONSOLE_OUT" ]; then
                    printf "%s" "$PROMPT_STR" > "$CONSOLE_OUT" 2>/dev/null || printf "%s" "$PROMPT_STR"
                else
                    printf "%s" "$PROMPT_STR"
                fi

                if [ -n "$CONSOLE_IN" ]; then
                    read -r raw_ans < "$CONSOLE_IN" 2>/dev/null || read -r raw_ans
                else
                    read -r raw_ans
                fi
            fi

            clean_ans=$(echo "$raw_ans" | tr -d '\r\n ' | tr 'A-Z' 'a-z')
            case "$clean_ans" in
                yes)
                    user_input="yes"
                    ;;
                no)
                    user_input="no"
                    ;;
                force)
                    user_input="force"
                    ;;
                *)
                    # Invalid answer: re-prompt until an acceptable answer is provided
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
        mkdir -p /run/hibernation-safeguard
        echo "force" > /run/hibernation-safeguard/action
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
PREREQ="udev"
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

    mkdir -p /run/hibernation-safeguard
    echo "discard" > /run/hibernation-safeguard/action
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
    ensure_boot_rw()
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
    ensure_boot_rw()

    # Ensure ethtool is available if apt-get is accessible
    if not shutil.which("ethtool") and shutil.which("apt-get"):
        print("Checking for ethtool package...")
        try:
            run_command(["apt-get", "install", "-y", "-qq", "ethtool"], check=False)
        except Exception:
            pass

    cleanup_legacy_artifacts()
    repair_grub_environment_block()
    (
        boot_dev,
        boot_uuid,
        root_dev,
        root_uuid,
        root_spec,
        kernel_dir,
        default_cmdline,
        resume_param,
        has_grub,
        has_systemd_boot,
        esp_dir,
    ) = gather_machine_layout()
    write_c_prompt_daemon(installer_name)
    configure_initramfs_framework(installer_name)
    write_machine_id_helper(boot_uuid, installer_name)
    write_systemd_sleep_hook(installer_name)
    write_boot_cleanup_service(installer_name)
    if has_grub:
        write_grub_hooks(
            boot_uuid,
            root_spec,
            kernel_dir,
            default_cmdline,
            resume_param,
            installer_name,
        )
    write_initramfs_hook(boot_uuid, installer_name)
    compile_images(has_grub)
    print("=== SUCCESS ===")
    print(f"Hardware Hibernation Safeguard fully provisioned by {installer_name}.")
    print(
        "System will dynamically enforce hardware verification across GRUB and initramfs."
    )


def uninstall(installer_name=INSTALLER_NAME):
    check_root()
    print(
        f"=== Surgically Uninstalling Hardware Hibernation Safeguard ({installer_name}) ==="
    )
    print("Purging all active components, legacy artifacts, and configuration blocks.")
    print()
    ensure_boot_rw()

    # 1. Clean up legacy artifacts from previous iterations (strictly avoiding fan control daemons)
    cleanup_legacy_artifacts()

    # 2. Repair any corrupted GRUB environment block so uninstallation leaves GRUB in clean working order
    repair_grub_environment_block()

    # 3. Remove only safeguard installed files
    active_paths = [
        Path("/usr/local/bin/hibernation-machine-id"),
        Path("/lib/systemd/system-sleep/hibernation-hardware-tag"),
        Path("/lib/systemd/system/hibernation-safeguard-cleanup.service"),
        Path(
            "/etc/systemd/system/basic.target.wants/hibernation-safeguard-cleanup.service"
        ),
        Path("/usr/local/bin/hibernation-resume-prompt"),
        Path("/usr/local/src/hibernation-resume-prompt.c"),
        Path("/etc/initramfs-tools/scripts/local-top/hibernation_resume_check"),
        Path("/etc/initramfs-tools/hooks/hibernation_safeguard_tools"),
        Path("/etc/initramfs-tools/conf.d/zz-hibernation-safeguard.conf"),
        Path("/boot/grub_hib_id"),
        Path("/boot/initramfs_hib_id"),
        Path("/boot/loader/sdboot_hib_id"),
        Path("/run/hibernation-safeguard"),
    ]

    for p in active_paths:
        if is_protected_fan_daemon_path(p):
            continue

        if p.exists() or p.is_symlink():
            if p.is_dir():
                try:
                    shutil.rmtree(p)
                    print(f"Removed safeguard directory: {p}")
                except OSError as e:
                    sys.stderr.write(f"Warning: could not remove directory {p}: {e}\n")
            else:
                try:
                    p.unlink()
                    print(f"Removed safeguard file: {p}")
                except OSError:
                    ensure_boot_rw()
                    try:
                        p.unlink()
                        print(f"Removed safeguard file: {p}")
                    except OSError as e2:
                        sys.stderr.write(f"Warning: could not remove file {p}: {e2}\n")

    # 4. Clean sentinel blocks from /etc/initramfs-tools/modules (safeguard blocks ONLY)
    modules_file = Path("/etc/initramfs-tools/modules")
    if modules_file.exists():
        content = modules_file.read_text()
        pat = r"### BEGIN (?:GPD )?HIBERNATION SAFEGUARD MODULES[^\n]*\n.*?### END (?:GPD )?HIBERNATION SAFEGUARD MODULES[^\n]*(?:\n|$)"
        if re.search(pat, content, flags=re.DOTALL):
            content = re.sub(pat, "", content, flags=re.DOTALL)
            modules_file.write_text(content)
            print(
                "Purged safeguard sentinel comments from /etc/initramfs-tools/modules"
            )

    # 5. Clean sentinel and legacy blocks from /etc/grub.d/40_custom
    custom_path = Path("/etc/grub.d/40_custom")
    if custom_path.exists():
        content = custom_path.read_text()
        pat = r"### BEGIN (?:GPD )?HIBERNATION (?:HARDWARE )?SAFEGUARD[^\n]*\n.*?### END (?:GPD )?HIBERNATION (?:HARDWARE )?SAFEGUARD[^\n]*(?:\n|$)"
        cleaned = re.sub(pat, "", content, flags=re.DOTALL)

        legacy_unmarked = [
            r"insmod smbios.*?(?:set\s+linux_cmdline_extra=.*?|linux_cmdline_extra=.*?)(?:\n|$)",
            r"insmod smbios.*?set\s+default=.*?fi\s*\n\s*fi",
            r"insmod smbios.*?search --fs-uuid.*?fi\s*\n\s*fi",
        ]
        for p in legacy_unmarked:
            cleaned = re.sub(p, "", cleaned, flags=re.DOTALL)

        if cleaned != content:
            custom_path.write_text(cleaned)
            print("Purged safeguard configuration blocks from /etc/grub.d/40_custom")

    # 6. Reset systemd-boot default if needed
    if shutil.which("bootctl"):
        try:
            run_command(
                ["bootctl", "set-default", ""], check=False, capture_output=True
            )
        except Exception:
            pass

    # 7. Recompile bootloader and initramfs images
    has_grub = Path("/etc/grub.d").is_dir() and shutil.which("update-grub") is not None
    compile_images(has_grub)

    print()
    print("=== SUCCESS ===")
    print(
        f"Hardware Hibernation Safeguard completely and surgically uninstalled by {installer_name}."
    )
    print("Boot images and bootloader configuration have been restored to default.")


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

    cleanup_svc = Path("/lib/systemd/system/hibernation-safeguard-cleanup.service")
    cleanup_svc_ok = cleanup_svc.is_file()

    c_prompt_bin = Path("/usr/local/bin/hibernation-resume-prompt")
    c_prompt_ok = c_prompt_bin.is_file() and os.access(c_prompt_bin, os.X_OK)

    init_hook = Path("/etc/initramfs-tools/scripts/local-top/hibernation_resume_check")
    init_hook_ok = init_hook.is_file() and os.access(init_hook, os.X_OK)

    tool_hook = Path("/etc/initramfs-tools/hooks/hibernation_safeguard_tools")
    tool_hook_ok = tool_hook.is_file() and os.access(tool_hook, os.X_OK)

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
        f"  - Boot cleanup service (hibernation-safeguard-cleanup.service)     : {badge(cleanup_svc_ok)}"
    )
    print(
        f"  - C evdev prompt binary (/usr/local/bin/hibernation-resume-prompt) : {badge(c_prompt_ok)}"
    )
    print(
        f"  - Initramfs check hook (/etc/initramfs-tools/scripts/local-top/..): {badge(init_hook_ok)}"
    )
    print(
        f"  - Initramfs tool hook (/etc/initramfs-tools/hooks/...)            : {badge(tool_hook_ok)}"
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
        sys_str = f"{sys_vendor or ''} {product_name or ''}".strip() or "Unknown"
        print(f"  - System / Model  : {sys_str}")
    if bios_vendor or bios_version:
        bios_str = f"{bios_vendor or ''} {bios_version or ''}".strip()
        print(f"  - BIOS Details    : {bios_str}")
    if board_vendor or board_name:
        board_str = f"{board_vendor or ''} {board_name or ''}".strip()
        print(f"  - Baseboard       : {board_str}")

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
            if assign_file.is_file() and assign_file.read_text().strip() == "1":
                continue

            perm_mac = None
            if shutil.which("ethtool"):
                try:
                    res_eth = subprocess.run(
                        ["ethtool", "-P", candidate.name],
                        capture_output=True,
                        text=True,
                        timeout=1,
                    )
                    for line in res_eth.stdout.splitlines():
                        if "Permanent address:" in line:
                            pval = line.split("Permanent address:", 1)[1].strip()
                            if (
                                len(pval) == 17
                                and pval[1].lower() in "048c"
                                and pval != "00:00:00:00:00:00"
                            ):
                                perm_mac = pval
                                break
                except Exception:
                    pass

            if perm_mac:
                mac = perm_mac
                mac_iface = candidate.name
                break

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

    grubenv_path = Path("/boot/grub/grubenv")
    grubenv_ok = False
    if grubenv_path.is_file():
        try:
            grubenv_ok = is_valid_grubenv(grubenv_path.read_bytes())
        except Exception:
            grubenv_ok = False
    print(
        f"  - GRUB environment block (/boot/grub/grubenv)            : {'[VALID 1024B]' if grubenv_ok else '[MISSING/CORRUPTED]'}"
    )
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
        [
            helper_ok,
            sleep_hook_ok,
            cleanup_svc_ok,
            c_prompt_ok,
            init_hook_ok,
            tool_hook_ok,
            modules_ok,
            dropin_ok,
            grub_hook_ok,
        ]
    )
    any_ok = any(
        [
            helper_ok,
            sleep_hook_ok,
            cleanup_svc_ok,
            c_prompt_ok,
            init_hook_ok,
            tool_hook_ok,
            modules_ok,
            dropin_ok,
            grub_hook_ok,
        ]
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
    # Handle help requests by paging the full embedded README.md via pydoc.pager
    if len(sys.argv) > 1 and sys.argv[1] in ["-h", "--help", "help"]:
        pydoc.pager(README_DOC)
        sys.exit(0)

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
        "--uninstall",
        action="store_true",
        help=f"Completely and surgically uninstall the hardware hibernation safeguard and any previous versions.",
    )
    group.add_argument(
        "--status",
        action="store_true",
        help=f"Check and display the current safeguard installation status and hardware targets.",
    )

    args = parser.parse_args()

    if args.install:
        install(INSTALLER_NAME)
    elif args.uninstall:
        uninstall(INSTALLER_NAME)
    elif args.status:
        show_status(INSTALLER_NAME)


if __name__ == "__main__":
    main()
