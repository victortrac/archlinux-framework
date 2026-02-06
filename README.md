# Arch Linux Installer for Framework 13" (AMD)

Automated installation script for Arch Linux on Framework 13" AMD laptop with full disk encryption.

## Features

- **Full disk encryption** with LUKS2 (argon2id)
- **BTRFS** with subvolumes (@, @home, @var, @snapshots)
- **systemd-boot** bootloader with automatic kernel updates
- **Hyprland** Wayland compositor with full configuration
- **Framework-specific** optimizations (power management, fingerprint)
- **Ubuntu live CD support** - better WiFi hardware compatibility

## Partition Layout

| Partition | Size | Type | Mount |
|-----------|------|------|-------|
| nvme0n1p1 | 1GB | EFI (FAT32) | /boot/efi |
| nvme0n1p2 | 32GB | Swap | swap |
| nvme0n1p3 | Rest | LUKS2 > BTRFS | / |

## Usage

### Option A: Ubuntu Live USB (Recommended)

Ubuntu's live environment has better WiFi driver support for Framework laptops out of the box.

#### 1. Create Ubuntu Live USB

Download Ubuntu Desktop ISO from https://ubuntu.com/download/desktop and create a bootable USB:

```bash
# On Linux/macOS
sudo dd if=ubuntu-24.04-desktop-amd64.iso of=/dev/sdX bs=4M status=progress
sync
```

Or use [Balena Etcher](https://etcher.balena.io/) or [Rufus](https://rufus.ie/) (Windows).

#### 2. Add the Install Script to USB

After creating the bootable USB, mount it and copy the install script:

```bash
# Mount the USB (it will have a writable partition)
# The USB will appear as a drive in your file manager

# Copy install.py to the USB root or a folder
cp install.py /media/your-usb-drive/
```

**Alternative: Download on boot**
You can also download the script after booting (requires internet):

```bash
wget https://raw.githubusercontent.com/yourusername/archlinux-framework/main/install.py
```

#### 3. Boot from Ubuntu USB

Boot your Framework laptop from the USB and select "Try Ubuntu" (do not install Ubuntu).

#### 4. Connect to WiFi

Use the NetworkManager GUI in the top-right corner, or use the terminal:

```bash
# List available networks
nmcli device wifi list

# Connect to WiFi
nmcli device wifi connect "YOUR_SSID" password "YOUR_PASSWORD"

# Verify connection
ping -c 3 1.1.1.1
```

#### 5. Run the Install Script

```bash
# Open a terminal and navigate to where you saved the script
cd /media/ubuntu/YOUR_USB_DRIVE  # or wherever you saved it

# Or download it:
# wget https://raw.githubusercontent.com/victortrac/archlinux-framework/main/install.py

# Make executable and run as root
chmod +x install.py
sudo python3 install.py
```

The script will automatically detect Ubuntu and download the necessary Arch Linux bootstrap tools.

---

### Option B: Arch Linux Live USB

If you prefer the native Arch experience or the WiFi works for you:

#### 1. Boot from Arch Linux USB

Download the ISO from https://archlinux.org/download/ and create a bootable USB.

#### 2. Connect to Internet

```bash
# For WiFi
iwctl
[iwd]# station wlan0 connect YOUR_SSID

# Verify connection
ping archlinux.org
```

#### 3. Download and Run Script

```bash
# Install git if needed
pacman -Sy git

# Clone this repo (or download the script)
git clone https://github.com/yourusername/archlinux-framework
cd archlinux-framework

# Make executable and run
chmod +x install.py
python install.py
```

---

## Configuration Wizard

The script will guide you through an interactive configuration:

**System Configuration:**
- Target disk (auto-detected NVMe drives)
- Hostname
- Timezone (common options + custom)
- Locale
- Keyboard layout

**Partition Sizing:**
- Swap size (recommended: match RAM for hibernation)
- EFI size (recommended: 1GB)

**User Accounts:**
- LUKS encryption password (required at every boot)
- Root password
- Username and user password

## Post-Installation

### Start Hyprland

After rebooting and logging in:

```bash
Hyprland
```

### Key Bindings (Hyprland)

| Key | Action |
|-----|--------|
| Super + Return | Terminal (kitty) |
| Super + D | App launcher (wofi) |
| Super + Q | Close window |
| Super + F | Fullscreen |
| Super + V | Toggle floating |
| Super + L | Lock screen |
| Super + 1-0 | Switch workspace |
| Super + Shift + 1-0 | Move to workspace |
| Super + Shift + E | Exit Hyprland |
| Print | Screenshot (region) |
| Shift + Print | Screenshot (full) |

### Install AUR Helper

```bash
git clone https://aur.archlinux.org/yay-bin.git
cd yay-bin
makepkg -si
```

### Recommended AUR Packages

```bash
yay -S \
  visual-studio-code-bin \
  google-chrome \
  fw-ectool-git  # Framework EC tool
```

## Troubleshooting

### WiFi Not Working on Arch Live USB

This is why we recommend Ubuntu live USB - it has better out-of-box WiFi support. If you must use Arch:

1. Try connecting via ethernet or USB tethering from phone
2. Check if the driver is loading: `dmesg | grep -i wifi`
3. Try loading the driver manually: `modprobe mt7921e` (for MediaTek)

### Can't Boot After Install

1. Boot from USB again (Ubuntu or Arch)
2. Decrypt and mount:
   ```bash
   cryptsetup open /dev/nvme0n1p3 cryptroot
   mount -o subvol=@ /dev/mapper/cryptroot /mnt
   mount /dev/nvme0n1p1 /mnt/boot/efi

   # If using Ubuntu:
   chroot /mnt /bin/bash

   # If using Arch:
   arch-chroot /mnt
   ```
3. Reinstall bootloader:
   ```bash
   bootctl install --esp-path=/boot/efi
   ```

### Hyprland Won't Start

Check for errors:
```bash
Hyprland 2>&1 | tee hyprland.log
```

Common fixes:
- Ensure you're logged in on a TTY (not via display manager)
- Check GPU drivers: `lspci -k | grep -A 3 VGA`

## How It Works (Ubuntu Live)

When running from Ubuntu, the script:

1. Detects it's running on Ubuntu/Debian
2. Installs required packages (`wget`, `tar`, `zstd`)
3. Attempts to use `arch-install-scripts` from Ubuntu repos (if available)
4. If not available, downloads the official Arch Linux bootstrap tarball
5. Uses the bootstrap tools (`pacstrap`, `genfstab`, `arch-chroot`) to install Arch
6. All system configuration happens inside chroot, so the result is identical to native Arch installation

## License

MIT
