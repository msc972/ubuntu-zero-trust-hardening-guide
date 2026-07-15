# Ubuntu Zero-Trust Hardening Guide

A comprehensive, tested security hardening guide for (K)Ubuntu-based systems with KDE Plasma and Wayland. Every command has been verified on a live system.

This guide implements a **deny-by-default, zero-trust** approach across twelve layers of defense. Steps are ordered as a logical progression for hardening a freshly installed Kubuntu system, from hardware and boot security through to application-level controls and ongoing monitoring.

*Tested on: Kubuntu 24.04 LTS, KDE Plasma 5.27 (Wayland). Last reviewed: July 2026.*

*Version sensitivity: hardening guides rot fast. Package names, sysctl keys, and tool commands change between releases (for example, `kwriteconfig5` becomes `kwriteconfig6` on KDE Plasma 6, which ships in Kubuntu 24.10 and later). This guide targets Ubuntu-based KDE systems broadly but was verified only on the versions above. Re-check any version-sensitive step before relying on it.*

> **⚠️ Back up before you start.** Several steps here can lock you out of your machine if done wrong: LUKS, the NVMe firmware password (Step 4), GRUB and boot changes (Step 4), USBGuard (Step 11), and PAM faillock (Step 12). Before changing anything: (1) confirm you have a working backup of your personal files on a **separate** drive, (2) create a Timeshift snapshot (Step 2), (3) back up your LUKS header (Step 3), and (4) keep a live USB (a Kubuntu installer) handy to boot from for recovery. Steps that carry a lock-out risk include an "If this locks you out" recovery note.

---

## Table of Contents

- [Motivation](#motivation)
- [Scope, Audience & Tiers](#scope-audience--tiers)
- [Threat Model & Attack Surfaces](#threat-model--attack-surfaces)
- [Architecture Overview](#architecture-overview)
- [Where This Sits: Zero Trust & Prior Art](#where-this-sits-zero-trust--prior-art)
- [Prerequisites](#prerequisites)
- [Conventions & Placeholders](#conventions--placeholders)
- [Step 1: System Update & Cleanup](#step-1-system-update--cleanup)
- [Step 2: System Snapshots (Timeshift)](#step-2-system-snapshots-timeshift)
- [Step 3: LUKS Header Backup](#step-3-luks-header-backup)
- [Step 4: Boot & Hardware Security](#step-4-boot--hardware-security)
- [Step 5: Kernel Hardening](#step-5-kernel-hardening)
- [Step 6: AppArmor](#step-6-apparmor)
- [Step 7: Disabled Services](#step-7-disabled-services)
- [Step 8: DNS Configuration](#step-8-dns-configuration)
- [Step 9: UFW Firewall (Zero Trust)](#step-9-ufw-firewall-zero-trust-deny-by-default)
- [Step 10: OpenSnitch (Application Firewall)](#step-10-opensnitch-application-firewall)
- [Step 11: USBGuard](#step-11-usbguard)
- [Step 12: PAM Hardening & Screen Lock](#step-12-pam-hardening--screen-lock)
- [Step 13: Install Applications](#step-13-install-applications)
- [Step 14: Flatseal (Flatpak Permission Hardening)](#step-14-flatseal-flatpak-permission-hardening)
- [Step 15: Browser Hardening (Firefox)](#step-15-browser-hardening-firefox)
- [Step 16: Malware & Rootkit Scanning](#step-16-malware--rootkit-scanning)
- [Physical Attack Vectors & Defenses](#physical-attack-vectors--defenses)
- [Troubleshooting](#troubleshooting)
- [Regular Maintenance](#regular-maintenance)
- [Glossary](#glossary)
- [Sources](#sources)

---

## Motivation
In a world of growing mass surveillance and aggressive profiling by big tech and e-commerce companies, it is becoming harder for average users to protect their privacy. There are many excellent guides online that explain how to configure LUKS, firewalls, and browsers for secure and private use. However, users who do not know what to search for often cannot find the right information.

Some Linux distributions are designed specifically for privacy and security. However, they often reduce usability. Gaming may not work properly, and hardened browsers can break e-payment systems or websites. These distributions are useful, but they are usually focused on very specific use cases.

This guide hardens a daily-driver Ubuntu-based distribution while keeping it practical for everyday use. It provides strong (though not ultimate) protection against data theft and user profiling. Ultimately it depends on your web habits.

If you use big tech services or social media, I recommend creating a separate Firefox profile for them, or using a second browser entirely.

By following this guide, you will get a hardened Linux system that still supports smooth gaming, browsing, and daily work. It was created as the result of many years of experience hardening Windows and Linux systems for personal use. I hope you find it useful. Please feel free to contact me with any feedback or questions.

---

## Scope, Audience & Tiers

**Who this is for.** Intermediate to advanced users who are comfortable in a terminal and understand what LUKS, `sudo`, and editing system configuration files do. You do not need to be a security professional, but you should be willing to read each step, keep backups, and recover if something breaks. A motivated newcomer can follow along, but this guide favours thoroughness over hand-holding.

**What this covers.** Hardening a daily-driver Kubuntu / KDE Plasma (Wayland) laptop against data theft, network attackers, tracking, malware, and physical or USB attacks, while keeping the system usable for gaming, browsing, and everyday work. It does not cover servers, enterprise fleet management, or anonymity against a nation-state adversary. See the [Threat Model](#threat-model--attack-surfaces) for exactly who this defends against.

**Two tiers.** There is no "basic" tier here: a maintained, updated Linux install with full-disk encryption is already a reasonable baseline, and this guide starts above that.

- **Hardened** (default): everything in this guide unless a step or setting is marked otherwise. Strong, practical protection with acceptable day-to-day friction. Follow the guide top to bottom, skip the Paranoid items, and you have the Hardened tier.
- **Paranoid** (marked **Tier: Paranoid**): extra measures against strong, targeted, or physical adversaries that cost real effort, add friction, or carry a bricking or lockout risk. Adopt these only if your threat model justifies the trade-off. The Paranoid items are the NVMe firmware password and LUKS two-factor unlock (Step 4), USBGuard (Step 11), and disabling Firefox Safe Browsing (Step 15).

Pick the tier that matches your threat model and stop where the effort stops being worth it.

---

## Threat Model & Attack Surfaces

This guide defends against the following threat actors and attack surfaces. Each hardening step maps to one or more of these threats.

### Threat Actors

| Actor | Motivation | Capability |
|-------|-----------|------------|
| **Opportunistic thief** | Steal hardware, access data | Physical access to laptop (café, office, travel) |
| **Network attacker** | Intercept traffic, inject malware | Same WiFi network (public hotspots, hotel, airport) |
| **Malicious software** | Exfiltrate data, establish persistence | Bundled in downloads, browser exploits, email attachments |
| **Corporate/advertising tracking** | Profile behavior, sell data | Browser fingerprinting, cookies, telemetry, DNS snooping |
| **Rogue USB device** | Execute commands, exfiltrate data | Physical access for 5-30 seconds (rubber ducky, BadUSB) |
| **Insider/physical access** | Tamper with boot, install rootkit | Prolonged physical access (evil maid attack) |

### Attack Surfaces & Mitigations

| Attack Surface | Threat | Mitigation Layer |
|---------------|--------|-----------------|
| Unencrypted disk | Data theft from stolen/removed drive | LUKS full disk encryption |
| Boot process | Bootloader tampering, root shell via GRUB | GRUB password, BIOS password, LUKS encrypted BOOT partition |
| Kernel | Privilege escalation, information leaks | sysctl hardening, ASLR, ptrace restriction |
| Network (outbound) | Malware phoning home, data exfiltration | UFW deny-by-default, OpenSnitch per-app control |
| Network (public WiFi) | MITM, traffic sniffing, DNS poisoning | WireGuard VPN, encrypted DNS, ICMP redirect blocking |
| DNS | Query snooping, DNS hijacking | Quad9 + DNSSEC + DNS-over-TLS, VPN DNS |
| USB ports | Rubber ducky, BadUSB, malicious firmware | USBGuard strict whitelist |
| Thunderbolt ports | DMA attacks (direct memory read/write) | IOMMU (VT-d), Thunderbolt user authorization |
| Applications | Malware, excessive permissions, tracking | Flatpak sandboxing, Flatseal, AppArmor |
| Browser | Fingerprinting, tracking, WebRTC IP leaks | Firefox hardening, container isolation |
| Login/authentication | Brute-force password attacks | PAM faillock, screen lock, LUKS |
| Unnecessary services | Expanded attack surface | Disable unused daemons and discovery protocols |
| File system tampering | Rootkits, modified system binaries | rkhunter, ClamAV |
| System misconfiguration | Broken hardening locking out user | Timeshift snapshots, LUKS header backup |

The hardening steps below address each surface systematically, starting from the hardware layer and working up through the OS, network, and application layers.

---

## Architecture Overview

Twelve layers of defense, ordered from hardware to application level:

| # | Layer | Purpose |
|---|-------|---------|
| 1 | LUKS | Full disk encryption |
| 2 | GRUB + BIOS | Boot security, passwords, hardware disables |
| 3 | Kernel | sysctl settings reducing attack surface |
| 4 | AppArmor | Mandatory access control |
| 5 | USBGuard | USB device whitelisting (BadUSB protection) |
| 6 | UFW | Network-level deny-by-default firewall |
| 7 | OpenSnitch | Application-level firewall with per-process visibility |
| 8 | DNS | Quad9 + DNSSEC + DoT for bootstrap, VPN DNS in tunnel |
| 9 | WireGuard VPN | All traffic encrypted through VPN tunnel |
| 10 | Flatseal | Flatpak permission hardening |
| 11 | rkhunter + ClamAV | Rootkit and malware scanning |
| 12 | Timeshift | System snapshots for safe rollback |

![Ubuntu zero-trust hardening reference architecture: five defence layers from devices and disk up through kernel, network egress, and application, over a deny-by-default zero-trust egress flow (OpenSnitch to UFW to WireGuard to the internet) and cross-cutting recovery tools; Paranoid items are marked](reference-architecture.png)

*The whole stack at a glance. [Open the HTML version](reference-architecture.html). Hardened is the entire stack; the marked items are Paranoid opt-ins.*

---

## Where This Sits: Zero Trust & Prior Art

This guide did not invent its ideas; it collects and applies established ones. Naming the sources it draws on makes its choices auditable and shows where it sits.

**Zero trust, applied to one laptop.** The guiding idea is *zero trust*: never trust by default, verify explicitly, assume breach, and grant the least access needed. The reference definition is NIST SP 800-207 (Rose et al., 2020). That document describes an *enterprise network* architecture, with a policy engine and enforcement points deciding every access request dynamically. A single personal laptop is not that, and this guide does not pretend to implement it. What it borrows are the zero-trust *principles*, applied at the endpoint:

- **Deny by default.** UFW drops all traffic, inbound and outbound, until a rule allows it (Step 9). OpenSnitch extends this to per-application decisions (Step 10). USBGuard denies unknown USB devices (Step 11).
- **Least privilege.** AppArmor confines processes (Step 6), Flatseal strips Flatpak apps to the permissions they actually need (Step 14), and unnecessary services are disabled (Step 7).
- **Assume breach.** Kernel hardening limits what a compromised process can reach (Step 5); rkhunter, ClamAV, and Timeshift assume something may already be wrong (Steps 2, 16).

**Related, heavier standards.** For a system-wide, auditable baseline, the CIS Ubuntu Linux Benchmark (CIS, 2024) is the community-consensus reference, and the Kernel Self-Protection Project (KSPP) publishes the recommended kernel and sysctl settings that ground Step 5. This guide is lighter and more opinionated than CIS: it targets a specific daily-driver desktop rather than a certifiable server baseline, and it deliberately relaxes a few KSPP recommendations (for example it keeps `ptrace_scope = 2` rather than `3`, and leaves unprivileged user namespaces enabled) because a usable Flatpak desktop needs them. Where a choice departs from the stricter reference, the reason is stated next to it.

---

## Prerequisites

- Kubuntu installed with **LUKS full disk encryption** enabled during installation
- KDE Plasma with Wayland session
- A WireGuard-based VPN provider
- A YubiKey or FIDO2 security key (optional but recommended)

See [Conventions & Placeholders](#conventions--placeholders) for the interface names and device placeholders used throughout this guide.

---

## Conventions & Placeholders

Commands assume a `sudo`-capable user on Kubuntu 24.04 LTS with the KDE Plasma (Wayland) session and the Bash shell. Replace these placeholders with values from your own system before running a command:

| Placeholder | Meaning | Find it with |
|---|---|---|
| `wlp1234` | Your WiFi interface name | `ip link show` |
| `ifvpn0` | Your VPN tunnel interface name | `ip a \| grep -E "tun\|wg\|vpn"` |
| `YOUR_DEVICE` | Your encrypted disk or partition (for example `/dev/nvme0n1p3`) | `lsblk -f \| grep crypto` |
| `nvme0n1` | Your NVMe disk | `lsblk -d` |
| `192.168.0.1` | Your router's LAN address | `ip route \| grep default` |
| `YOUR_HASH_HERE`, `YOUR_USER`, `<ID>`, `<SOURCE_NAME>`, `<profile>` | Values produced or shown by the command just above them | (context-specific) |

- Comment lines (`# ...`) inside code blocks are explanatory and are not required.
- A `> **⚠️ WARNING**` block flags a step that can lock you out or lose data. Read it before running the commands beneath it.

---

## Step 1: System Update & Cleanup

Start with a clean, updated, minimal system before any hardening.

### Update

```bash
sudo apt update
sudo apt full-upgrade -y
```

### Pin KDE core packages

Prevents KDE essentials from being auto-removed when purging apps:

```bash
sudo apt-mark manual plasma-desktop plasma-workspace kde-plasma-desktop \
  kde-baseapps kwin dolphin konsole
```

### Purge telemetry

```bash
sudo apt purge whoopsie apport ubuntu-report popularity-contest -y
```

### Purge unnecessary software

Adjust this list to your needs:

```bash
sudo apt purge konversation kmail ktorrent korganizer juk dragonplayer \
  kamoso elisa vlc zutty isoimagewriter firefox thunderbird khelpcenter \
  kmahjongg kpat ksudoku kmines irssi transmission-common postfix -y
```

### Prevent reinstallation with update

```bash
sudo apt-mark hold whoopsie apport ubuntu-report popularity-contest \
  konversation kmail ktorrent korganizer juk dragonplayer kamoso elisa \
  vlc zutty isoimagewriter firefox thunderbird khelpcenter kmahjongg \
  kpat ksudoku kmines irssi transmission-common postfix
```

### Install security and system tools

```bash
sudo apt install -y \
  apparmor-utils apparmor-profiles apparmor-profiles-extra \
  usbguard \
  rkhunter \
  timeshift \
  bolt \
  yubikey-manager libpam-u2f \
  clamav clamav-freshclam
```

### Enable essential services

```bash
sudo systemctl enable --now cron              # Some distros ship with cron disabled
sudo systemctl enable --now clamav-freshclam  # ClamAV auto-updates
sudo systemctl enable --now apparmor
sudo aa-enforce /etc/apparmor.d/systemd-coredump
sudo systemctl reload apparmor
```

> **⚠️ WARNING:** Do NOT enforce AppArmor profiles for Flatpak apps (Firefox, Chromium, etc.). They are intentionally unconfined because Flatpak uses Bubblewrap sandboxing. Enforcing AppArmor on top of Bubblewrap causes conflicts and breakage.

### Clean up and reboot

```bash
sudo apt autoremove --purge -y
sudo apt clean
sudo apt autoclean
sudo apt update
sudo reboot
```

---

## Step 2: System Snapshots (Timeshift)

Set up Timeshift **before** any hardening changes. If something breaks, snapshots allow rollback in minutes.

```bash
sudo timeshift-gtk
```

- Snapshot type: **RSYNC** (for ext4 filesystems)
- Snapshot location: a **separate drive** if available (survives system drive failure)
- Schedule: daily keep 5, weekly keep 3
- Home directories: **EXCLUDE** (Timeshift is for system recovery; back up personal files separately)
- `/var/lib/libvirt`: **EXCLUDE** (VM images are large)
- `/root`: **INCLUDE** (small, contains root config)

Create the first snapshot:

```bash
sudo timeshift --create --comments "Fresh install before hardening"
```

Create a snapshot before every significant change from this point forward.

---

## Step 3: LUKS Header Backup

If the LUKS header gets corrupted, all data is permanently lost, even with the correct password. Back this up immediately.

```bash
lsblk -f | grep crypto    # Find encrypted partition
sudo cryptsetup luksHeaderBackup /dev/YOUR_DEVICE \
  --header-backup-file /tmp/luks-header-backup.bin
sudo cryptsetup luksDump /tmp/luks-header-backup.bin    # Verify
```

Store on an **encrypted USB drive** kept physically secure. Do NOT store on the encrypted drive itself or in unencrypted cloud storage.

```bash
shred -u /tmp/luks-header-backup.bin    # Delete temporary copy
```

Update the backup after adding/removing LUKS key slots or changing the LUKS password.

---

## Step 4: Boot & Hardware Security

### GRUB Password

Prevents editing boot parameters to get a root shell:

```bash
grub-mkpasswd-pbkdf2
```

Enter a password. Copy the hash. Edit `/etc/grub.d/40_custom` and add:

```
set superusers="admin"
password_pbkdf2 admin grub.pbkdf2.sha512.10000.YOUR_HASH_HERE
```

Apply:

```bash
sudo update-grub
sudo chmod 600 /boot/grub/grub.cfg
```

Normal booting works without the password. Only editing GRUB entries or recovery mode requires it.

> **Note:** Some distributions require adding `--unrestricted` to menuentry lines in `/etc/grub.d/10_linux` to prevent the password prompt on every boot. Test after applying.

> **If this locks you out.** A wrong hash, or forgetting `--unrestricted`, can make GRUB demand the password at every boot or refuse to boot. Recovery: boot a live USB (you may need the BIOS admin password to re-enable USB boot), mount your root and `/boot`, `chroot` in, fix or remove your edits to `/etc/grub.d/40_custom`, and run `sudo update-grub`. Since `grub.cfg` is regenerated, this is reversible as long as you can boot external media.

### BIOS/UEFI Settings

- Set BIOS **ADMIN** password (protects settings from being changed)
- Set BIOS **BOOT** password (required every time machine powers on)
- Boot order: internal disk only
- Disable: USB boot, Network/PXE boot, Wake on LAN
- Disable: webcam, microphone (hardware-level, cannot be bypassed by software)
- Disable: Bluetooth, fingerprint reader, SD card reader (if unused)
- Enable: Intel VT-d (IOMMU) for DMA protection
- Thunderbolt security: set to "User Authorization" or higher

### Microphone (Software Fallback)

If BIOS doesn't support disabling the mic:

```bash
pactl list sources short
pactl set-source-mute <SOURCE_NAME> 1

# Persist across reboots:
mkdir -p ~/.config/autostart
cat > ~/.config/autostart/disable-mic.desktop << 'EOF'
[Desktop Entry]
Type=Application
Name=Disable Microphone
Exec=pactl set-source-mute @DEFAULT_SOURCE@ 1
X-KDE-autostart-after=pulseaudio
EOF
```

### Secure Boot

If available, Secure Boot ensures only signed kernels and bootloaders can run. Enabling requires care with NVIDIA proprietary drivers and DKMS modules. Check status: `mokutil --sb-state`.

If Secure Boot is not available, the boot chain is protected by: BIOS boot password → GRUB password → LUKS encryption.

### NVMe Password / TCG Opal (Optional)

**Tier: Paranoid**

**Attack vector:** An attacker physically removes the NVMe drive and clones the LUKS-encrypted partition for offline brute-force.

**Remedy:** NVMe password locks the drive at firmware level. Check support:

```bash
sudo nvme id-ctrl /dev/nvme0n1 -H | grep -i opal
```

> **⚠️ WARNING:** If you forget the NVMe password, the drive is permanently bricked. No recovery possible.

> **Cost & residual.** You enter the drive's firmware password at every cold boot, on top of the LUKS passphrase. It defends only against an attacker who removes the drive to clone it offline; it does nothing against a running or suspended machine, and it does not replace LUKS. Record the password in a separate password manager, since a forgotten password bricks the drive.

### 2FA for LUKS (Optional Enhancement)

**Tier: Paranoid**

**Attack vector:** If an attacker obtains the LUKS password (cold boot, shoulder surfing, keylogger, coercion), they can decrypt the drive with the password alone.

**Remedy:** Add a physical security key (YubiKey, FIDO2) as a second factor.

**Approach 1: Full disk 2FA**

```bash
systemd-cryptenroll --fido2-device=list
sudo systemd-cryptenroll /dev/YOUR_DEVICE --fido2-device=auto
```

**Approach 2: Separate encrypted container with 2FA**

Keep main boot as password-only. Create a separate LUKS2 container for sensitive files that requires YubiKey to open:

```bash
dd if=/dev/zero of=~/secure-vault.img bs=1M count=1024
sudo cryptsetup luksFormat --type luks2 ~/secure-vault.img
sudo systemd-cryptenroll ~/secure-vault.img --fido2-device=auto

# Open (requires password + YubiKey)
sudo cryptsetup open ~/secure-vault.img secure-vault
sudo mkfs.ext4 /dev/mapper/secure-vault
sudo mount /dev/mapper/secure-vault /mnt/secure-vault
```

> **⚠️ WARNING:** Keep a backup YubiKey enrolled, or maintain a password-only key slot as fallback. Two YubiKeys are recommended.

> **Cost & residual.** You need the security key present at every unlock. It raises the bar against an attacker who has only your passphrase (keylogger, shoulder-surfing, coercion of the password alone), but not against one who captures an already-unlocked session. **If you lose the key:** unlock with the fallback password slot or a backup key, then re-enroll. Losing every enrolled key with no password slot means the data is unrecoverable.

---

## Step 5: Kernel Hardening

Create `/etc/sysctl.d/99-hardening.conf`:

```ini
# === NETWORK - IPv6 ===
# Disable IPv6. All traffic goes through IPv4 VPN tunnel.
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1

# === NETWORK - ICMP Redirects ===
# Prevent MITM on public WiFi via ICMP redirect spoofing.
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# === NETWORK - Source Routing ===
# Prevent attackers from specifying packet routes to bypass firewalls.
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0

# === NETWORK - Spoofing Protection ===
# Drop packets with spoofed source addresses.
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# === NETWORK - Broadcast Protection ===
net.ipv4.icmp_echo_ignore_broadcasts = 1

# === NETWORK - Suspicious Packet Logging ===
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# === NETWORK - SYN Flood Protection ===
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2

# === NETWORK - IP Forwarding ===
net.ipv4.ip_forward = 0

# === KERNEL - Information Leaks ===
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2

# === KERNEL - Process Isolation ===
kernel.yama.ptrace_scope = 2

# === KERNEL - Physical Attack Prevention ===
kernel.sysrq = 0

# === KERNEL - Exploit Mitigation ===
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_harden = 2
# Set to 1 (not 0) because Flatpak needs user namespaces for Bubblewrap.
kernel.unprivileged_userns_clone = 1
kernel.perf_event_paranoid = 3

# === MEMORY ===
kernel.randomize_va_space = 2
fs.suid_dumpable = 0
```

Apply:

```bash
sudo sysctl -p /etc/sysctl.d/99-hardening.conf
```

Survives reboot. Verify after kernel updates: `sysctl kernel.dmesg_restrict`

> **Trade-off & recovery.** These keys shrink the attack surface but some have side effects: disabling IPv6 breaks IPv6-only networks; `rp_filter = 1` can drop traffic on asymmetric-routing setups; `ptrace_scope = 2` stops user-space debuggers (gdb, strace) from attaching to running processes; and unprivileged user namespaces are left enabled on purpose because Flatpak's Bubblewrap sandbox needs them. These settings follow the Kernel Self-Protection Project's recommendations, relaxed where a desktop needs it. If a key breaks something, edit or delete `/etc/sysctl.d/99-hardening.conf` and run `sudo sysctl --system`; nothing here is compiled into the kernel, so removing the file fully reverts it.

---

## Step 6: AppArmor

AppArmor provides mandatory access control, restricting what files, directories, and capabilities each process can access.

```bash
sudo aa-status
```

Enforced profiles from `apparmor-profiles-extra`: systemd-coredump, plasmashell, dnsmasq, avahi-daemon, ping, nscd, nvidia_modprobe, samba services.

> **⚠️ WARNING:** Do NOT enforce Flatpak app profiles (Firefox, Chromium, etc.). They are intentionally unconfined; Bubblewrap handles sandboxing.

```bash
sudo aa-enforce /etc/apparmor.d/<profile>   # Enforce a profile
sudo aa-complain /etc/apparmor.d/<profile>  # Complain mode (log only)
sudo systemctl reload apparmor              # Reload after changes
```

---

## Step 7: Disabled Services

Reduce attack surface by disabling unnecessary services:

```bash
sudo systemctl disable --now cups-browsed     # Network printer discovery
sudo systemctl disable --now avahi-daemon     # mDNS/Bonjour discovery
```

Disable KDE Connect (if unused):

```bash
sudo systemctl disable --now kdeconnect
cp /etc/xdg/autostart/org.kde.kdeconnect.daemon.desktop ~/.config/autostart/ 2>/dev/null
echo "Hidden=true" >> ~/.config/autostart/org.kde.kdeconnect.daemon.desktop
```

Disable KDE Discover Notifier (background update checks):

```bash
cp /etc/xdg/autostart/org.kde.discover.notifier.desktop ~/.config/autostart/
echo "Hidden=true" >> ~/.config/autostart/org.kde.discover.notifier.desktop
```

---

## Step 8: DNS Configuration

### /etc/systemd/resolved.conf

```ini
[Resolve]
DNS=9.9.9.9#dns.quad9.net 149.112.112.112#dns.quad9.net
FallbackDNS=1.1.1.2#security.cloudflare-dns.com 1.0.0.2#security.cloudflare-dns.com
DNSOverTLS=opportunistic
DNSSEC=yes
Cache=no-negative
MulticastDNS=no
LLMNR=no
ReadEtcHosts=yes
```

`DNSOverTLS=opportunistic` uses TLS when available, falls back when not. Quad9 supports DoT so bootstrap DNS is encrypted. The VPN's DNS may not support DoT, but `opportunistic` falls back silently and traffic is already inside the WireGuard tunnel. Check Cloudflare for Malware filtered DNS 1.1.1.2 at https://one.one.one.one/family/

### /etc/NetworkManager/conf.d/dns.conf

```ini
[main]
dns=systemd-resolved
```

Ensures NetworkManager defers all DNS to systemd-resolved. Works on any network.

### DNS Flow

| Phase | DNS Server | Interface | Encrypted by |
|-------|-----------|-----------|-------------|
| Before VPN | Quad9 (9.9.9.9) | wlp1234 | DNS-over-TLS |
| After VPN | VPN provider DNS | ifvpn0 | WireGuard |

```bash
sudo systemctl restart systemd-resolved
sudo systemctl restart NetworkManager
```

> **If DNS breaks.** Check `resolvectl status` (per-interface servers) and `resolvectl query example.com`. `DNSSEC=yes` rejects some misconfigured domains; if that bites, `DNSSEC=allow-downgrade` is a softer setting. Revert by restoring the original `resolved.conf` and running `sudo systemctl restart systemd-resolved`.

---

## Step 9: UFW Firewall (Zero Trust, Deny by Default)

### Disable IPv6 in UFW
```
echo 'IPV6=no' | sudo tee -a /etc/ufw/ufw.conf
```

### Setup

```bash
sudo ufw reset
sudo ufw default deny incoming
sudo ufw default deny outgoing
sudo ufw default deny routed
```

### Block Google Analytics IP range (inbound)

```bash
sudo ufw insert 1 deny in on wlp1234 from 34.107.0.0/16    # Block GA on WiFi
sudo ufw insert 2 deny in on ifvpn0 from 34.107.0.0/16     # Block GA on VPN
```
 
### Block Google Analytics IP range (outbound)
```bash
sudo ufw insert 3 deny out on wlp1234 to 34.107.0.0/16      # Block GA on WiFi
sudo ufw insert 4 deny out on ifvpn0 to 34.107.0.0/16       # Block GA on VPN
```

### VPN Tunnel Interface: Internet Traffic

Replace `ifvpn0` with your VPN tunnel interface (`ip a | grep -E "tun|wg|vpn"`):

```bash
# DNS
sudo ufw allow out on ifvpn0 to any port 53 proto udp       # DNS lookups (UDP)
sudo ufw allow out on ifvpn0 to any port 53 proto tcp        # DNS lookups (TCP, zone transfers)
 
# Web browsing
sudo ufw allow out on ifvpn0 to any port 80 proto tcp        # HTTP
sudo ufw allow out on ifvpn0 to any port 443 proto tcp       # HTTPS
sudo ufw allow out on ifvpn0 to any port 443 proto udp       # QUIC / HTTP3
 
# Email
sudo ufw allow out on ifvpn0 to any port 993 proto tcp       # IMAP over SSL (mail fetch)
sudo ufw allow out on ifvpn0 to any port 465 proto tcp       # SMTPS (mail send)
 
# SSH
sudo ufw allow out on ifvpn0 to any port 22 proto tcp        # SSH
 
# VPN internal control channel
sudo ufw allow out on ifvpn0 to any port 65432 proto tcp     # VPN app <-> gateway
 
# Alternate HTTPS
sudo ufw allow out on ifvpn0 to any port 8443 proto tcp      # Alt HTTPS (VPN/services)
 
# NTP
sudo ufw allow out on ifvpn0 to any port 123 proto udp       # Time sync through VPN
 
# Steam
sudo ufw allow out on ifvpn0 to any port 27000:27050 proto udp  # Steam game traffic
 
# Blizzard / Battle.net
sudo ufw allow out on ifvpn0 to any port 1119 proto tcp      # Battle.net login
sudo ufw allow out on ifvpn0 to any port 1119 proto udp      # Battle.net login
sudo ufw allow out on ifvpn0 to any port 1120 proto tcp      # Battle.net login (alt)
sudo ufw allow out on ifvpn0 to any port 1120 proto udp      # Battle.net login (alt)
sudo ufw allow out on ifvpn0 to any port 3724 proto tcp      # WoW / Battle.net game
sudo ufw allow out on ifvpn0 to any port 3724 proto udp      # WoW / Battle.net game
sudo ufw allow out on ifvpn0 to any port 6012 proto tcp      # Battle.net voice/game
sudo ufw allow out on ifvpn0 to any port 6012 proto udp      # Battle.net voice/game
 
# Project Gorgon
sudo ufw allow out on ifvpn0 to 64.187.238.75 port 9002 proto tcp
```

| Port | Proto | Purpose |
|------|-------|---------|
| 53 | udp/tcp | DNS (TCP needed for DNSSEC large responses) |
| 80 | tcp | HTTP |
| 443 | tcp | HTTPS |
| 443 | udp | QUIC / HTTP/3 |
| 465 | tcp | SMTPS (sending email) |
| 993 | tcp | IMAP (receiving email) |
| 8443 | tcp | VPN internal API |
| 65432 | tcp | VPN health check |

> **Note:** Ports 8443 and 65432 may be specific to certain VPN providers. Adjust based on `sudo dmesg | grep -i ufw` output.

### WiFi Interface: VPN Bootstrap Only

Replace `wlp1234` with your WiFi interface (`ip link show`):

```bash
# VPN tunnel establishment
sudo ufw allow out on wlp1234 to any port 443 proto udp      # WireGuard (Proton VPN tunnel)
 
# Alternate HTTPS (VPN setup)
sudo ufw allow out on wlp1234 to any port 8443 proto tcp      # Alt HTTPS (Proton/Ubiquiti)
 
# Ubiquiti network management
sudo ufw allow out on wlp1234 to any port 10001 proto udp     # UniFi device discovery
 
# Fallback DNS (before VPN is up)
sudo ufw allow out on wlp1234 to 9.9.9.9 port 53 proto udp   # Quad9 DNS
sudo ufw allow out on wlp1234 to 1.1.1.2 port 53 proto udp   # Cloudflare Privacy DNS primary
sudo ufw allow out on wlp1234 to 1.0.0.2 port 53 proto udp   # Cloudflare Privacy DNS secondary
sudo ufw allow out on wlp1234 to 1.1.1.1 port 53 proto udp   # Cloudflare DNS primary as fallback
sudo ufw allow out on wlp1234 to 1.0.0.1 port 53 proto udp   # Cloudflare DNS secondary as fallback 
# NTP (before VPN is up)
sudo ufw allow out on wlp1234 to any port 123 proto udp       # Time sync
 
# Router admin
sudo ufw allow out on wlp1234 to 192.168.0.1 port 80 proto tcp  # Router web interface
```

| Port | Proto | Destination | Purpose |
|------|-------|-------------|---------|
| 53 | udp | Quad9/Cloudflare | DNS bootstrap |
| 123 | udp | Anywhere | NTP time sync |
| 443 | udp | Anywhere | WireGuard alt handshake |
| 8443 | tcp | Anywhere | VPN API auth |
| 10001 | udp | Anywhere | WireGuard primary handshake |

> **Note:** WireGuard ports vary by VPN provider. Connect the VPN and check `sudo dmesg | grep -i ufw` to identify blocked ports, then add rules accordingly.

### Enable UFW firewall now
```bash
sudo ufw enable
```

### Also block analytics/tracking domains in hosts file
 
```bash
sudo vim /etc/hosts
# Add these lines:
0.0.0.0 safebrowsing.google.com
0.0.0.0 www.google-analytics.com
0.0.0.0 google-analytics.com
0.0.0.0 ssl.google-analytics.com
0.0.0.0 analytics.google.com
0.0.0.0 www.googletagmanager.com
0.0.0.0 googletagmanager.com
```

### Enable built-in Kill Switch if available

If the VPN drops, the tunnel interface disappears. The physical interface only allows VPN handshake ports. No browsing traffic can leak. UFW settings should deny leak as well.

> **Trade-off & recovery.** `default deny outgoing` is the strongest part of this setup and the most disruptive: anything without an explicit allow rule (a new app, a new port, a LAN service) fails, often silently. Expect to add rules as you go, using `sudo dmesg | grep -i ufw` to see what was blocked. If it locks you out of your own network, run `sudo ufw disable` from a local terminal to drop all rules at once, then re-enable after fixing them. The port list above is specific to the author's applications (Steam, Battle.net, one VPN provider); treat it as an example, not a template.

---

## Step 10: OpenSnitch (Application Firewall)

OpenSnitch prompts for allow/deny every time a process makes a network connection.

Download `.deb` packages from [github.com/evilsocket/opensnitch/releases](https://github.com/evilsocket/opensnitch/releases):

```bash
sudo dpkg -i opensnitch_*.deb python3-opensnitch-ui_*.deb
sudo apt -f install
sudo systemctl enable --now opensnitch
```

### System Rules

Disable all default nftables-level system rules. UFW and OpenSnitch app rules handle all traffic decisions.

### App Rules

Rules are stored in `/etc/opensnitchd/rules/`. Build organically from pop-up prompts:

**Allow always:** systemd-resolved, systemd-timesyncd, NetworkManager, kernel connections, VPN client, Firefox, Flatpak, apt, freshclam.

**Deny always:** avahi-daemon, cups-browsed, KDE Discover Notifier, KDE Connect (if unused), KDE kioworker (Dolphin network discovery).

### Tips

- Use duration `always` for system services. Temporary durations on critical services cause failures when they expire.
- **Deny** (DROP) silently drops packets. **Reject** sends "connection refused." Use Deny by default.
- If the VPN client runs as Python, restrict the OpenSnitch rule to match only the VPN command, not all Python scripts.

---

## Step 11: USBGuard

**Tier: Paranoid**

Whitelists known USB devices and blocks everything else. Strict mode: all new devices are blocked until manually approved.

```bash
sudo apt install usbguard -y
```

Plug in all regularly used USB devices (keyboard, mouse, YubiKey), then:

```bash
sudo usbguard generate-policy | sudo tee /etc/usbguard/rules.conf
sudo systemctl enable --now usbguard
```

Hotplug devices may need permanent approval:

```bash
sudo usbguard list-devices | grep block
sudo usbguard allow-device <ID> -p
```

### Day-to-day Workflow

1. Plug in new USB device: blocked silently
2. `sudo usbguard list-devices | grep block`
3. Temporary: `sudo usbguard allow-device <ID>`
4. Permanent: `sudo usbguard allow-device <ID> -p`

**Recovery if keyboard blocked:** Reboot → GRUB recovery mode → `sudo systemctl stop usbguard` → regenerate policy.

> **Cost & residual.** Every new USB device is blocked until you approve it by ID, which is real daily friction (docks, hubs, and re-enumerated internal devices included). It stops BadUSB and rubber-ducky devices at enumeration, but not a device that spoofs an already-whitelisted ID. Approve your keyboard and mouse first, and keep the recovery path above in mind before enabling strict mode on a machine whose only input is USB.

---

## Step 12: PAM Hardening & Screen Lock

### Screen Lock (KDE)

```bash
kwriteconfig5 --file kscreenlockerrc --group "Daemon" --key "Autolock" --type bool true
kwriteconfig5 --file kscreenlockerrc --group "Daemon" --key "Timeout" 5
kwriteconfig5 --file kscreenlockerrc --group "Daemon" --key "LockOnResume" --type bool true
kwriteconfig5 --file kscreenlockerrc --group "Daemon" --key "LockGrace" 0
```

Locks after 5 minutes idle, locks on lid close/sleep, zero grace period.

### PAM Faillock

Locks accounts after repeated failed password attempts. Create `/usr/share/pam-configs/faillock`:

```
Name: Faillock
Default: yes
Priority: 0
Auth-Type: Primary
Auth:
	required			pam_faillock.so preauth
Auth-Initial:
	required			pam_faillock.so preauth
Auth-Final:
	[default=die]			pam_faillock.so authfail
Account-Type: Primary
Account:
	required			pam_faillock.so
```

> **Important:** Indentation must be tabs, not spaces.

Configure (uncomment/add) `/etc/security/faillock.conf`:

```
deny = 5
unlock_time = 600
fail_interval = 900
silent
even_deny_root = no
```

Enable:

```bash
sudo pam-auth-update
```

> **⚠️ WARNING:** Keep a root terminal open during testing. Test with `su - YOUR_USER` using wrong passwords before closing the safety terminal.

> **Note:** KDE's screen locker counts faillock attempts but does not enforce lockout (KDE-specific behavior). Terminal-based authentication (su, sudo, SSH) IS locked after 5 failures. Failed attempts expire after the `fail_interval` (15 minutes).

> **If this locks you out.** Reset a locked account as root with `faillock --user YOUR_USER --reset`, or wait out the `unlock_time` (10 minutes). With no root shell available, boot to recovery mode from GRUB and run the reset there. This is why you keep a root terminal open while testing.

---

## Step 13: Install Applications

### Steam (optional) for Gaming support

```bash
sudo dpkg --add-architecture i386
sudo add-apt-repository multiverse
sudo apt update
sudo apt install steam-installer mesa-vulkan-drivers mesa-vulkan-drivers:i386
```

### Flatpak Applications

```bash
flatpak install flathub -y \
  com.github.tchx84.Flatseal \
  org.mozilla.firefox

flatpak update -y
```

---

## Step 14: Flatseal (Flatpak Permission Hardening)

Permissions are stored in `~/.local/share/flatpak/overrides/`. Principle: deny everything the app does not need.

### Firefox

```bash
flatpak override --user org.mozilla.firefox \
  --device=dri \
  --device=all \
  --no-feature=devel \
  --talk-name=org.kde.plasma.browser.integration
```

GPU access (`dri`) for hardware acceleration. Full device access (`all`) needed for YubiKey USB communication. Re-enable smart card socket (`--socket=pcsc`) if using FIDO2/YubiKey in Firefox.

> **Note:** `--device=all` also grants webcam and other devices. On Flatpak 1.15.11 and newer, the narrower `--device=usb` (raw USB only) is preferable where your Flatpak version supports it. Kubuntu 24.04 ships an older Flatpak, so `--device=all` is used here.

### General Principles

- **No network needed:** `flatpak override --user APP_ID --unshare=network`
- **No home access:** `flatpak override --user APP_ID --nofilesystem=home --nofilesystem=host`
- **Disable everywhere:** `--nosocket=cups --nosocket=pcsc --no-feature=bluetooth`
- **Downloads only:** `--filesystem=xdg-download:ro`

### Verify

```bash
for f in ~/.local/share/flatpak/overrides/*; do
  echo "=== $(basename $f) ==="
  cat "$f"
  echo ""
done
```

---

## Step 15: Browser Hardening (Firefox)

### about:config

```
privacy.resistFingerprinting = true
privacy.firstparty.isolate = true
media.peerconnection.enabled = false
network.dns.disablePrefetch = true
network.dns.disablePrefetchFromHTTPS = true
network.prefetch-next = false
browser.urlbar.speculativeConnect.enabled = false
network.trr.mode = 5
network.http.referer.XOriginPolicy = 2
network.cookie.cookieBehavior = 5
privacy.trackingprotection.enabled = true
privacy.trackingprotection.socialtracking.enabled = true
geo.enabled = false
dom.event.clipboardevents.enabled = false
dom.battery.enabled = false
media.navigator.enabled = false
webgl.disabled = true
browser.send_pings = false
browser.casting.enabled = false
browser.search.suggest.enabled = false
browser.urlbar.suggest.searches = false
network.connectivity-service.enabled = false
extensions.pocket.enabled = false
toolkit.telemetry.enabled = false
toolkit.telemetry.unified = false
toolkit.telemetry.archive.enabled = false
datareporting.healthreport.uploadEnabled = false
datareporting.policy.dataSubmissionEnabled = false
browser.discovery.enabled = false
browser.newtabpage.activity-stream.feeds.telemetry = false
browser.newtabpage.activity-stream.telemetry = false
browser.newtabpage.activity-stream.feeds.section.topstories = false
browser.crashReports.unsubmittedCheck.autoSubmit2 = false
browser.tabs.crashReporting.sendReport = false
```

### Disable Safe Browsing (Paranoid)

**Tier: Paranoid**

**How it works.** Firefox's Safe Browsing (phishing and malware protection) does **not** send every URL you visit to Google. It downloads a local database of 32-bit hash *prefixes* of known-bad URLs and checks each page against that list locally. Only when a page's hash matches a prefix in the local list (a rare collision, and only for suspected-bad URLs) does Firefox send the 4-byte prefix, without cookies, to confirm the full hash. Google's own documentation states: "At no point does Google learn about the URLs you are examining."

**Why disable it anyway.** It is not zero-contact. Firefox periodically downloads list updates from Google's servers, so Google sees your IP address and the timing of those requests. And because URLs are low-entropy, a 32-bit prefix is guessable: an observer holding the known-bad hash list can narrow what a prefix implies, so a prefix collision leaks *some* signal. If your bar is "no contact with Google's servers at all," disabling Safe Browsing removes both the periodic list downloads and the prefix lookups.

**Cost.** You lose real protection: Firefox will no longer warn you before known phishing and malware sites. **Most users on the Hardened tier should leave Safe Browsing on.** Disable it only if the Paranoid trade-off is right for you.

```
browser.safebrowsing.malware.enabled = false
browser.safebrowsing.phishing.enabled = false
services.sync.prefs.sync.browser.safebrowsing.malware.enabled = false
services.sync.prefs.sync.browser.safebrowsing.phishing.enabled = false
```

### about:preferences → Privacy & Security

- Enhanced Tracking Protection → **Strict**
- Do Not Track → **Always**
- HTTPS-Only Mode → **Enable in all windows**
- Permissions: Location, Camera, Mic, Notifications, Autoplay, VR → **Block new requests**
- Firefox Data Collection → **All unchecked**

### Recommended Extensions

- **uBlock Origin**: ad and tracker blocker
- **Skip Redirect**: bypasses tracking redirects
- **Multi-Account Containers**: isolate sites in permanent containers
- **Temporary Containers**: disposable containers for one-off links

---

## Step 16: Malware & Rootkit Scanning

Two complementary tools: ClamAV catches malware files, rkhunter catches system-level compromises.

### ClamAV

Weekly scan cron job (`/etc/cron.weekly/clamav-scan`):

```bash
#!/bin/bash
LOGFILE="/var/log/clamav/weekly-scan.log"
mkdir -p /var/log/clamav
echo "ClamAV scan started: $(date)" > "$LOGFILE"
clamscan -r --infected --exclude-dir="^/sys" --exclude-dir="^/proc" \
  --exclude-dir="^/dev" --exclude-dir="^/snap" \
  /home /etc /tmp /var >> "$LOGFILE" 2>&1
echo "ClamAV scan finished: $(date)" >> "$LOGFILE"
```

```bash
sudo chmod 755 /etc/cron.weekly/clamav-scan
```

### rkhunter

During install, if Postfix configuration appears, select **No configuration** and remove Postfix:

```bash
sudo apt purge postfix -y
```

Set baseline:

```bash
sudo rkhunter --propupd
sudo rkhunter --check --skip-keypress
```

Whitelist known false positives in `/etc/rkhunter.conf`:

```
SCRIPTWHITELIST=/usr/bin/lwp-request
ALLOWHIDDENFILE=/etc/.updated
ALLOWDEVFILE=/dev/shm/qb-*/*
WEB_CMD=""
IPC_SEG_SIZE=268435456
```

rkhunter signature updates are handled by `apt`, not `rkhunter --update` (Debian disables self-update by design).

Weekly cron job (`/etc/cron.weekly/rkhunter-scan`):

```bash
#!/bin/bash
LOGFILE="/var/log/rkhunter/weekly-scan.log"
mkdir -p /var/log/rkhunter
echo "rkhunter scan started: $(date)" > "$LOGFILE"
rkhunter --check --skip-keypress >> "$LOGFILE" 2>&1
echo "rkhunter scan finished: $(date)" >> "$LOGFILE"
```

```bash
sudo chmod 755 /etc/cron.weekly/rkhunter-scan
```

### AIDE (File Integrity Monitoring): Not Recommended for Daily Drivers

AIDE flags all changed system files. On a desktop with frequent apt and flatpak upgrades, it produces excessive noise. rkhunter + ClamAV + Timeshift provide sufficient protection without the maintenance overhead.

---

## Physical Attack Vectors & Defenses

### Attack 1: USB Rubber Ducky (Fake Keyboard)

A USB device registers as a keyboard and types pre-programmed commands.

- **Via KDE lock screen:** Very slow (10-15 attempts/min). Impractical.
- **Via virtual terminal (Ctrl+Alt+F3):** Fast, hundreds of attempts/min. **PAM faillock blocks after 5.**

**Defense:** USBGuard blocks before enumeration. PAM faillock locks terminals.

### Attack 2: USB Network Adapter (Traffic Hijack)

Registers as a network adapter, intercepts all traffic.

**Defense:** USBGuard blocks it. VPN encrypts all traffic. UFW blocks unexpected interfaces.

### Attack 3: Thunderbolt DMA (Direct Memory Access)

The most dangerous physical attack. Thunderbolt devices get direct memory access, bypassing all software protections. Can read LUKS keys, passwords, and session data from RAM.

**Defense:** Thunderbolt "User Authorization" policy + IOMMU (VT-d). Check: `cat /sys/bus/thunderbolt/devices/*/security` and `dmesg | grep -i iommu`.

### Attack 4: Evil Maid (Boot Tamper)

Attacker reboots and modifies bootloader to capture LUKS password.

**Defense:** GRUB password + LUKS + BIOS boot password. Full protection requires Secure Boot.

### Attack 5: USB Killer

High voltage through USB. No software protection exists.

### Attack 6: Network Brute-Force

Attacker brute-forces login credentials remotely or on the same network.

**Defense:** No SSH server. UFW blocks all incoming. PAM faillock. VPN hides real IP.

| Attack | USBGuard | PAM | VPN | Status |
|--------|----------|-----|-----|--------|
| Rubber Ducky | BLOCKS | LOCKS | n/a | ✅ |
| USB Network | BLOCKS | n/a | ENCRYPTS | ✅ |
| Thunderbolt DMA | n/a | n/a | n/a | ⚠️ Needs IOMMU |
| Evil Maid | n/a | n/a | n/a | ✅ Mostly |
| USB Killer | n/a | n/a | n/a | ❌ No fix |
| Network Brute-Force | n/a | LOCKS | HIDES | ✅ |

---

## Troubleshooting

### Network connectivity

```bash
sudo dmesg | grep -i ufw | tail -30          # UFW blocked packets
grep -l "deny" /etc/opensnitchd/rules/*.json  # OpenSnitch denials
resolvectl query google.com                   # Test DNS
resolvectl status                             # DNS per interface
```

### VPN won't connect

```bash
ip a | grep -E "tun|wg|vpn"                 # Check tunnel interface
sudo dmesg | grep -i ufw | tail -30          # Check blocked ports
```

### Browser issues

- Blocked UDP 443 on tunnel → QUIC/HTTP3 needed
- Blocked TCP 53 on tunnel → DNSSEC needs TCP
- Check browser secure DNS is disabled (VPN handles DNS)

### USB device not recognized

```bash
sudo usbguard list-devices | grep block       # Check if blocked
sudo usbguard allow-device <ID> -p            # Allow permanently
```

### After system updates

```bash
sudo rkhunter --propupd                       # Update rkhunter baseline
sysctl kernel.dmesg_restrict                  # Verify kernel hardening
sudo aa-status                                # Check AppArmor
```

---

## Regular Maintenance

```bash
sudo apt update && sudo apt full-upgrade -y   # System updates
flatpak update -y                             # Flatpak updates
sudo rkhunter --check --skip-keypress         # Rootkit scan
cat /var/log/clamav/weekly-scan.log            # Review ClamAV results
grep "Warning" /var/log/rkhunter.log           # Review rkhunter warnings
sudo timeshift --create --comments "routine"  # Snapshot before changes
```

---

## Glossary

- **AppArmor** - A Linux mandatory access control (MAC) system that confines each program to a set of files and capabilities defined in a profile.
- **BadUSB / rubber ducky** - A malicious USB device that pretends to be a keyboard (or other trusted device) to inject commands or payloads.
- **ClamAV** - An open-source antivirus engine, used here for on-demand malware file scanning.
- **DNSSEC** - DNS Security Extensions: cryptographic signatures that let a resolver verify a DNS answer was not forged.
- **DNS-over-TLS (DoT)** - DNS queries sent inside a TLS connection so the network cannot read or tamper with them.
- **Evil maid** - A physical attack in which someone with brief access to a powered-off machine tampers with the bootloader or firmware to capture your password later.
- **FIDO2 / security key** - A hardware authentication device (such as a YubiKey), used here as a second factor for disk unlock.
- **Flatpak / Bubblewrap** - Flatpak packages desktop apps in a sandbox; Bubblewrap is the engine that isolates them from the rest of the system.
- **Flatseal** - A GUI for viewing and tightening Flatpak app permissions.
- **IOMMU (VT-d)** - Hardware that restricts which memory a device can reach over DMA, defending against Thunderbolt/DMA attacks.
- **LUKS** - Linux Unified Key Setup, the standard full-disk encryption format on Linux. The **LUKS header** holds the key slots; lose or corrupt it and the data is unrecoverable.
- **MAC (mandatory access control)** - Access rules enforced by the kernel that even the file owner cannot override (see AppArmor).
- **OpenSnitch** - An application-level firewall that prompts to allow or deny each program's outbound connections.
- **PAM / faillock** - PAM is Linux's pluggable authentication framework; faillock is the module that locks an account after repeated failed logins.
- **sysctl** - The interface for reading and setting kernel parameters at runtime, used here for kernel hardening.
- **TCG Opal / NVMe password** - Self-encrypting-drive features that lock the drive at the firmware level, separate from LUKS.
- **Timeshift** - A snapshot tool that lets you roll the system back to an earlier state.
- **UFW** - Uncomplicated Firewall, a front end for the kernel's netfilter packet filter.
- **USBGuard** - A daemon that whitelists known USB devices and blocks the rest.
- **WireGuard** - A modern, fast VPN protocol built on current cryptography.
- **Zero trust** - A security model that trusts nothing by default and verifies every access explicitly (see [Where This Sits](#where-this-sits-zero-trust--prior-art)).

---

## Sources

External standards, tools, and factual claims are cited here; the design choices and the specific configuration are the author's own. Cited Harvard-style (author, year). Every link was checked at the time of writing.

- Center for Internet Security (2024) *CIS Ubuntu Linux Benchmark*. Available at: https://www.cisecurity.org/benchmark/ubuntu_linux
- Flatpak (no date) *Sandbox Permissions*. Flatpak documentation. Available at: https://docs.flatpak.org/en/latest/sandbox-permissions.html
- Google (2024) *Safe Browsing Update API (v4)*. Google for Developers. Available at: https://developers.google.com/safe-browsing/v4/update-api
- Kernel Self-Protection Project (no date) *Recommended Settings*. Available at: https://kspp.github.io/Recommended_Settings
- Linux kernel documentation (no date) *Yama*. Available at: https://www.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html
- OpenSnitch (no date) *OpenSnitch: an application firewall*. Available at: https://github.com/evilsocket/opensnitch
- Quad9 (no date) *Quad9: a free, recursive, anycast DNS platform with security and privacy*. Available at: https://quad9.net/
- Rose, S., Borchert, O., Mitchell, S. and Connelly, S. (2020) *Zero Trust Architecture* (NIST Special Publication 800-207). National Institute of Standards and Technology. Available at: https://doi.org/10.6028/NIST.SP.800-207
- USBGuard (no date) *USBGuard*. Available at: https://usbguard.github.io/
- WireGuard (no date) *WireGuard: fast, modern, secure VPN tunnel*. Available at: https://www.wireguard.com/

---

## License

Copyright © 2026 msc972.

This guide (this `README.md` and its reference-architecture diagram) is licensed under the [Creative Commons Attribution 4.0 International License (CC BY 4.0)](https://creativecommons.org/licenses/by/4.0/): you may share and adapt it, including commercially, as long as you give attribution. See [LICENSE](LICENSE) for details.

The author retains copyright and full rights to reuse this material in later academic work (a paper or thesis).

**Suggested citation:** msc972 (2026) *Ubuntu Zero-Trust Hardening Guide*. Available at: https://github.com/msc972/ubuntu-zero-trust-hardening-guide (Accessed: DD Month YYYY).

---

## Disclaimer

This guide is provided as-is for educational purposes and is **not** professional security advice. Test all changes in a safe environment before applying them, and make sure you have working backups, a Timeshift snapshot, and a recovery path first (see the backup note at the top). Understand each command before you run it. The author is not responsible for any data loss, lockout, or system damage resulting from following this guide.
