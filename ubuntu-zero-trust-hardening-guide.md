# Ubuntu Zero-Trust Hardening Guide

A comprehensive and tested security hardening guide for (K)Ubuntu based system + KDE Plasma with Wayland. Every command has been verified on a live system.

This guide implements a **deny-by-default, zero-trust** approach across twelve layers of defense. Steps are ordered as a logical progression for hardening a freshly installed Kubuntu system — from hardware and boot security through to application-level controls and ongoing monitoring.

---

## Table of Contents

- [Threat Model & Attack Surfaces](#threat-model--attack-surfaces)
- [Architecture Overview](#architecture-overview)
- [Prerequisites](#prerequisites)
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

---

## Motivation
In a world of growing mass surveillance and aggressive profiling by big tech and e-commerce companies, it is becoming harder for average users to protect their privacy. There are many excellent guides online that explain how to configure LUKS, firewalls, and browsers for secure and private use. However, users who do not know what to search for often cannot find the right information.

Some Linux distributions are designed specifically for privacy and security. However, they often reduce usability. Gaming may not work properly, and hardened browsers can break e-payment systems or websites. These distributions are useful, but they are usually focused on very specific use cases.

This guide hardens a daily-driver Ubuntu-based distribution while keeping it practical for everyday use. It provides strong — though not ultimate — protection against data theft and user profiling. Ultimately it depends on users web habbits.

If you use big tech services or social media, I recommend creating a separate Firefox profile for them, or using a second browser entirely.

By following this guide, you will get a hardened Linux system that still supports smooth gaming, browsing, and daily work. It was created as the result of many years of experience hardening Windows and Linux systems for personal use. I hope you find it useful. Please feel free to contact me with any feedback or questions.

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

---

## Prerequisites

- Kubuntu installed with **LUKS full disk encryption** enabled during installation
- KDE Plasma with Wayland session
- A WireGuard-based VPN provider
- This guide uses `ifvpn0` as the VPN tunnel interface name and `wlp1234` as the WiFi interface name — replace these with actual interface names from `ip link show` and `ip a | grep -E "tun|wg|vpn"`
- A YubiKey or FIDO2 security key (optional but recommended)

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

If the LUKS header gets corrupted, all data is permanently lost — even with the correct password. Back this up immediately.

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

**Attack vector:** An attacker physically removes the NVMe drive and clones the LUKS-encrypted partition for offline brute-force.

**Remedy:** NVMe password locks the drive at firmware level. Check support:

```bash
sudo nvme id-ctrl /dev/nvme0n1 -H | grep -i opal
```

> **⚠️ WARNING:** If you forget the NVMe password, the drive is permanently bricked. No recovery possible.

### 2FA for LUKS (Optional Enhancement)

**Attack vector:** If an attacker obtains the LUKS password (cold boot, shoulder surfing, keylogger, coercion), they can decrypt the drive with the password alone.

**Remedy:** Add a physical security key (YubiKey, FIDO2) as a second factor.

**Approach 1 — Full disk 2FA:**

```bash
systemd-cryptenroll --fido2-device=list
sudo systemd-cryptenroll /dev/YOUR_DEVICE --fido2-device=auto
```

**Approach 2 — Separate encrypted container with 2FA:**

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

---

## Step 5: Kernel Hardening

Create `/etc/sysctl.d/99-hardening.conf`:

```ini
# === NETWORK — IPv6 ===
# Disable IPv6. All traffic goes through IPv4 VPN tunnel.
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1

# === NETWORK — ICMP Redirects ===
# Prevent MITM on public WiFi via ICMP redirect spoofing.
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# === NETWORK — Source Routing ===
# Prevent attackers from specifying packet routes to bypass firewalls.
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0

# === NETWORK — Spoofing Protection ===
# Drop packets with spoofed source addresses.
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# === NETWORK — Broadcast Protection ===
net.ipv4.icmp_echo_ignore_broadcasts = 1

# === NETWORK — Suspicious Packet Logging ===
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# === NETWORK — SYN Flood Protection ===
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2

# === NETWORK — IP Forwarding ===
net.ipv4.ip_forward = 0

# === KERNEL — Information Leaks ===
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2

# === KERNEL — Process Isolation ===
kernel.yama.ptrace_scope = 2

# === KERNEL — Physical Attack Prevention ===
kernel.sysrq = 0

# === KERNEL — Exploit Mitigation ===
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

---

## Step 6: AppArmor

AppArmor provides mandatory access control — restricting what files, directories, and capabilities each process can access.

```bash
sudo aa-status
```

Enforced profiles from `apparmor-profiles-extra`: systemd-coredump, plasmashell, dnsmasq, avahi-daemon, ping, nscd, nvidia_modprobe, samba services.

> **⚠️ WARNING:** Do NOT enforce Flatpak app profiles (Firefox, Chromium, etc.). They are intentionally unconfined — Bubblewrap handles sandboxing.

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
FallbackDNS=1.1.1.1#cloudflare-dns.com 1.0.0.1#cloudflare-dns.com
DNSOverTLS=opportunistic
DNSSEC=yes
Cache=no-negative
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

---

## Step 9: UFW Firewall (Zero Trust, Deny by Default)

### Disable IPv6 in UFW

Edit `/etc/default/ufw`:

```
IPV6=no
```

### Setup

```bash
sudo ufw reset
sudo ufw default deny incoming
sudo ufw default deny outgoing
```

### WiFi Interface — VPN Bootstrap Only

Replace `wlp1234` with your WiFi interface (`ip link show`):

```bash
sudo ufw allow out on wlp1234 to 9.9.9.9 port 53 proto udp
sudo ufw allow out on wlp1234 to 1.1.1.1 port 53 proto udp
sudo ufw allow out on wlp1234 to 1.0.0.1 port 53 proto udp
sudo ufw allow out on wlp1234 to any port 123 proto udp
sudo ufw allow out on wlp1234 to any port 443 proto udp
sudo ufw allow out on wlp1234 to any port 8443 proto tcp
sudo ufw allow out on wlp1234 to any port 10001 proto udp
```

| Port | Proto | Destination | Purpose |
|------|-------|-------------|---------|
| 53 | udp | Quad9/Cloudflare | DNS bootstrap |
| 123 | udp | Anywhere | NTP time sync |
| 443 | udp | Anywhere | WireGuard alt handshake |
| 8443 | tcp | Anywhere | VPN API auth |
| 10001 | udp | Anywhere | WireGuard primary handshake |

> **Note:** WireGuard ports vary by VPN provider. Connect the VPN and check `sudo dmesg | grep -i ufw` to identify blocked ports, then add rules accordingly.

### VPN Tunnel Interface — Internet Traffic

Replace `ifvpn0` with your VPN tunnel interface (`ip a | grep -E "tun|wg|vpn"`):

```bash
sudo ufw allow out on ifvpn0 to any port 53 proto udp
sudo ufw allow out on ifvpn0 to any port 53 proto tcp
sudo ufw allow out on ifvpn0 to any port 80 proto tcp
sudo ufw allow out on ifvpn0 to any port 443 proto tcp
sudo ufw allow out on ifvpn0 to any port 443 proto udp
sudo ufw allow out on ifvpn0 to any port 465 proto tcp
sudo ufw allow out on ifvpn0 to any port 993 proto tcp
sudo ufw allow out on ifvpn0 to any port 8443 proto tcp
sudo ufw allow out on ifvpn0 to any port 65432 proto tcp
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

```bash
sudo ufw enable
```

### Enable built-in Kill Switch if available

If the VPN drops, the tunnel interface disappears. The physical interface only allows VPN handshake ports. No browsing traffic can leak. UFW settings should deny leak as well.

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

Whitelists known USB devices and blocks everything else. Strict mode — all new devices blocked until manually approved.

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

1. Plug in new USB device — blocked silently
2. `sudo usbguard list-devices | grep block`
3. Temporary: `sudo usbguard allow-device <ID>`
4. Permanent: `sudo usbguard allow-device <ID> -p`

**Recovery if keyboard blocked:** Reboot → GRUB recovery mode → `sudo systemctl stop usbguard` → regenerate policy.

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
browser.safebrowsing.malware.enabled = false
browser.safebrowsing.phishing.enabled = false
services.sync.prefs.sync.browser.safebrowsing.malware.enabled = false
services.sync.prefs.sync.browser.safebrowsing.phishing.enabled = false
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

### about:preferences → Privacy & Security

- Enhanced Tracking Protection → **Strict**
- Do Not Track → **Always**
- HTTPS-Only Mode → **Enable in all windows**
- Permissions: Location, Camera, Mic, Notifications, Autoplay, VR → **Block new requests**
- Firefox Data Collection → **All unchecked**

### Recommended Extensions

- **uBlock Origin** — ad and tracker blocker
- **Skip Redirect** — bypasses tracking redirects
- **Multi-Account Containers** — isolate sites in permanent containers
- **Temporary Containers** — disposable containers for one-off links

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

### AIDE (File Integrity Monitoring) — Not Recommended for Daily Drivers

AIDE flags all changed system files. On a desktop with frequent apt and flatpak upgrades, it produces excessive noise. rkhunter + ClamAV + Timeshift provide sufficient protection without the maintenance overhead.

---

## Physical Attack Vectors & Defenses

### Attack 1: USB Rubber Ducky (Fake Keyboard)

A USB device registers as a keyboard and types pre-programmed commands.

- **Via KDE lock screen:** Very slow (10-15 attempts/min). Impractical.
- **Via virtual terminal (Ctrl+Alt+F3):** Fast — hundreds of attempts/min. **PAM faillock blocks after 5.**

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

## License

This guide is provided as-is for educational purposes. Test all changes in a safe environment before applying to production systems. The author is not responsible for any data loss or system issues resulting from following this guide.
