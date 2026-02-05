#!/usr/bin/env python3
"""
Arch Linux Installation Script for Framework 13" (AMD)

Requirements:
- Boot from Arch Linux live USB or Ubuntu live USB
- Internet connection (use `iwctl` for WiFi on Arch, or NetworkManager on Ubuntu)
- Run as root

Supports:
- Arch Linux live environment (native tools)
- Ubuntu live environment (downloads Arch bootstrap tools)

Partitioning scheme:
- /dev/nvme0n1p1: 1GB EFI System Partition (FAT32)
- /dev/nvme0n1p2: 32GB Swap (matches RAM for hibernation)
- /dev/nvme0n1p3: Remaining space, LUKS2 encrypted BTRFS

BTRFS subvolumes:
- @        -> /
- @home    -> /home
- @var     -> /var
- @snapshots -> /.snapshots
"""

import subprocess
import sys
import os
import getpass
import shutil
import tempfile
import time
import urllib.request
import tarfile
from pathlib import Path

# Live environment detection
LIVE_ENV = None  # Will be set to "arch" or "ubuntu"
ARCH_BOOTSTRAP_DIR = None  # Path to Arch bootstrap if on Ubuntu

# Default Configuration (will be overridden by user input)
DISK = "/dev/nvme0n1"
EFI_SIZE = "1G"
SWAP_SIZE = "32G"
HOSTNAME = "framework"
TIMEZONE = "America/Los_Angeles"
LOCALE = "en_US.UTF-8"
KEYMAP = "us"

# Common timezones for quick selection
COMMON_TIMEZONES = [
    "America/New_York",
    "America/Chicago",
    "America/Denver",
    "America/Los_Angeles",
    "America/Phoenix",
    "America/Anchorage",
    "Pacific/Honolulu",
    "Europe/London",
    "Europe/Paris",
    "Europe/Berlin",
    "Europe/Amsterdam",
    "Asia/Tokyo",
    "Asia/Shanghai",
    "Asia/Singapore",
    "Asia/Kolkata",
    "Australia/Sydney",
    "Australia/Melbourne",
]

# Common locales
COMMON_LOCALES = [
    "en_US.UTF-8",
    "en_GB.UTF-8",
    "de_DE.UTF-8",
    "fr_FR.UTF-8",
    "es_ES.UTF-8",
    "it_IT.UTF-8",
    "pt_BR.UTF-8",
    "ja_JP.UTF-8",
    "zh_CN.UTF-8",
    "ko_KR.UTF-8",
]

# Common keyboard layouts
COMMON_KEYMAPS = [
    "us",
    "uk",
    "de",
    "fr",
    "es",
    "it",
    "dvorak",
    "colemak",
]

# Partition paths
EFI_PART = f"{DISK}p1"
SWAP_PART = f"{DISK}p2"
ROOT_PART = f"{DISK}p3"
CRYPT_NAME = "cryptroot"
CRYPT_PATH = f"/dev/mapper/{CRYPT_NAME}"

# Mount point
MOUNT_POINT = "/mnt"


def detect_live_environment() -> str:
    """Detect if running from Arch or Ubuntu live environment."""
    global LIVE_ENV

    # Check for Arch
    if Path("/etc/arch-release").exists():
        LIVE_ENV = "arch"
        print("Detected: Arch Linux live environment")
        return "arch"

    # Check for Ubuntu/Debian
    if Path("/etc/lsb-release").exists() or Path("/etc/debian_version").exists():
        LIVE_ENV = "ubuntu"
        print("Detected: Ubuntu/Debian live environment")
        return "ubuntu"

    # Check for pacman (might be Arch-based)
    if shutil.which("pacman"):
        LIVE_ENV = "arch"
        print("Detected: Arch-based live environment (has pacman)")
        return "arch"

    # Check for apt (might be Debian-based)
    if shutil.which("apt"):
        LIVE_ENV = "ubuntu"
        print("Detected: Debian-based live environment (has apt)")
        return "ubuntu"

    # Default to assuming we need to set up tools
    LIVE_ENV = "ubuntu"
    print("Warning: Could not detect live environment, assuming Ubuntu-like")
    return "ubuntu"


def setup_arch_tools_on_ubuntu():
    """Download and set up Arch Linux bootstrap tools on Ubuntu."""
    global ARCH_BOOTSTRAP_DIR

    print("\n=== Setting Up Arch Linux Bootstrap Tools ===")

    # Install required packages on Ubuntu
    print("Installing required packages on Ubuntu...")
    subprocess.run("apt-get update", shell=True, check=True)
    subprocess.run(
        "apt-get install -y wget tar zstd arch-install-scripts 2>/dev/null || "
        "apt-get install -y wget tar zstd",
        shell=True,
        check=True
    )

    # Check if arch-install-scripts is available (provides pacstrap, genfstab, arch-chroot)
    if shutil.which("pacstrap"):
        print("arch-install-scripts is available from Ubuntu repos")
        return

    # If arch-install-scripts not available, download Arch bootstrap
    print("Downloading Arch Linux bootstrap...")
    ARCH_BOOTSTRAP_DIR = "/tmp/arch-bootstrap"
    Path(ARCH_BOOTSTRAP_DIR).mkdir(parents=True, exist_ok=True)

    # Download the bootstrap tarball
    mirror = "https://geo.mirror.pkgbuild.com"
    bootstrap_url = f"{mirror}/iso/latest/archlinux-bootstrap-x86_64.tar.zst"

    bootstrap_tar = f"{ARCH_BOOTSTRAP_DIR}/archlinux-bootstrap.tar.zst"

    print(f"Downloading from {bootstrap_url}...")
    subprocess.run(f"wget -O {bootstrap_tar} {bootstrap_url}", shell=True, check=True)

    print("Extracting bootstrap...")
    subprocess.run(f"tar -xf {bootstrap_tar} -C {ARCH_BOOTSTRAP_DIR} --strip-components=1", shell=True, check=True)

    # Initialize pacman keyring in bootstrap
    print("Initializing pacman keyring in bootstrap environment...")
    subprocess.run(f"{ARCH_BOOTSTRAP_DIR}/bin/arch-chroot {ARCH_BOOTSTRAP_DIR} pacman-key --init", shell=True, check=False)
    subprocess.run(f"{ARCH_BOOTSTRAP_DIR}/bin/arch-chroot {ARCH_BOOTSTRAP_DIR} pacman-key --populate archlinux", shell=True, check=False)

    print("Arch bootstrap tools ready.")


def manual_chroot_setup(mount_point: str):
    """Set up mount points for manual chroot (when arch-chroot not available)."""
    # Mount necessary filesystems for chroot
    subprocess.run(f"mount --bind /dev {mount_point}/dev", shell=True, check=True)
    subprocess.run(f"mount --bind /dev/pts {mount_point}/dev/pts", shell=True, check=True)
    subprocess.run(f"mount -t proc proc {mount_point}/proc", shell=True, check=True)
    subprocess.run(f"mount -t sysfs sys {mount_point}/sys", shell=True, check=True)
    subprocess.run(f"mount --bind /sys/firmware/efi/efivars {mount_point}/sys/firmware/efi/efivars 2>/dev/null || true", shell=True, check=False)
    subprocess.run(f"mount -t tmpfs tmpfs {mount_point}/tmp", shell=True, check=True)

    # Copy resolv.conf for DNS resolution
    subprocess.run(f"cp /etc/resolv.conf {mount_point}/etc/resolv.conf", shell=True, check=True)


def manual_chroot_cleanup(mount_point: str):
    """Clean up manual chroot mounts."""
    for mp in ["tmp", "sys/firmware/efi/efivars", "sys", "proc", "dev/pts", "dev"]:
        subprocess.run(f"umount {mount_point}/{mp} 2>/dev/null || true", shell=True, check=False)


def run(cmd: str, check: bool = True, capture: bool = False, chroot: bool = False) -> subprocess.CompletedProcess:
    """Execute a shell command."""
    if chroot:
        # Prefer arch-chroot if available
        if shutil.which("arch-chroot"):
            cmd = f"arch-chroot {MOUNT_POINT} {cmd}"
        elif ARCH_BOOTSTRAP_DIR and Path(f"{ARCH_BOOTSTRAP_DIR}/bin/arch-chroot").exists():
            cmd = f"{ARCH_BOOTSTRAP_DIR}/bin/arch-chroot {MOUNT_POINT} {cmd}"
        else:
            # Fallback to manual chroot
            cmd = f"chroot {MOUNT_POINT} /bin/bash -c '{cmd}'"
    print(f">>> {cmd}")
    return subprocess.run(cmd, shell=True, check=check, capture_output=capture, text=True)


def confirm(prompt: str) -> bool:
    """Ask for user confirmation."""
    response = input(f"{prompt} [y/N]: ").strip().lower()
    return response == 'y'


def prompt_with_default(prompt: str, default: str) -> str:
    """Prompt for input with a default value."""
    response = input(f"{prompt} [{default}]: ").strip()
    return response if response else default


def normalize_size(size_str: str) -> str:
    """Normalize a size string to ensure it has a valid unit suffix for sgdisk.

    Accepts formats like: "32", "32G", "32GB", "32g", "32gb", "512M", etc.
    Returns normalized format like "32G" or "512M".
    """
    size_str = size_str.strip().upper()

    # Remove trailing 'B' if present (e.g., "32GB" -> "32G")
    if size_str.endswith('B') and len(size_str) > 1:
        size_str = size_str[:-1]

    # If it's just a number, assume gigabytes
    if size_str.isdigit():
        return f"{size_str}G"

    # Validate the format: should be number followed by K, M, G, or T
    import re
    match = re.match(r'^(\d+)([KMGT])$', size_str)
    if match:
        return size_str

    # If we can't parse it, return as-is and let sgdisk handle the error
    return size_str


def select_from_list(prompt: str, options: list, default: str = None) -> str:
    """Let user select from a numbered list or enter custom value."""
    print(f"\n{prompt}")
    print("-" * 40)

    for i, option in enumerate(options, 1):
        marker = " (default)" if option == default else ""
        print(f"  {i:2}. {option}{marker}")
    print(f"  {len(options) + 1:2}. Enter custom value")

    while True:
        if default:
            choice = input(f"\nSelect [1-{len(options) + 1}] or press Enter for default: ").strip()
        else:
            choice = input(f"\nSelect [1-{len(options) + 1}]: ").strip()

        # Default selection
        if not choice and default:
            return default

        try:
            num = int(choice)
            if 1 <= num <= len(options):
                return options[num - 1]
            elif num == len(options) + 1:
                custom = input("Enter custom value: ").strip()
                if custom:
                    return custom
                print("Value cannot be empty.")
            else:
                print(f"Please enter a number between 1 and {len(options) + 1}")
        except ValueError:
            print("Please enter a valid number")


def detect_system_info() -> dict:
    """Detect system information for smart defaults."""
    info = {}

    # Detect available NVMe drives
    nvme_drives = []
    for path in Path("/dev").glob("nvme*n1"):
        if path.is_block_device():
            nvme_drives.append(str(path))
    info['nvme_drives'] = sorted(nvme_drives)

    # Detect RAM for swap recommendation
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemTotal:"):
                    mem_kb = int(line.split()[1])
                    info['ram_gb'] = round(mem_kb / 1024 / 1024)
                    break
    except:
        info['ram_gb'] = 32  # Default assumption

    return info


def get_configuration() -> dict:
    """Interactive configuration wizard."""
    global DISK, EFI_SIZE, SWAP_SIZE, HOSTNAME, TIMEZONE, LOCALE, KEYMAP
    global EFI_PART, SWAP_PART, ROOT_PART

    print("\n" + "=" * 60)
    print("            CONFIGURATION WIZARD")
    print("=" * 60)

    config = {}

    # Detect system info
    sys_info = detect_system_info()

    # === Disk Selection ===
    print("\n--- Disk Selection ---")
    if sys_info['nvme_drives']:
        print(f"Detected NVMe drives: {', '.join(sys_info['nvme_drives'])}")
        if len(sys_info['nvme_drives']) == 1:
            config['disk'] = prompt_with_default("Target disk", sys_info['nvme_drives'][0])
        else:
            config['disk'] = select_from_list(
                "Select target disk:",
                sys_info['nvme_drives'],
                default=sys_info['nvme_drives'][0]
            )
    else:
        config['disk'] = prompt_with_default("Target disk", DISK)

    # Update global partition paths
    DISK = config['disk']
    EFI_PART = f"{DISK}p1"
    SWAP_PART = f"{DISK}p2"
    ROOT_PART = f"{DISK}p3"

    # === Hostname ===
    print("\n--- System Identity ---")
    config['hostname'] = prompt_with_default("Hostname", "framework")
    HOSTNAME = config['hostname']

    # === Timezone ===
    config['timezone'] = select_from_list(
        "Select your timezone:",
        COMMON_TIMEZONES,
        default="America/Los_Angeles"
    )
    TIMEZONE = config['timezone']

    # === Locale ===
    config['locale'] = select_from_list(
        "Select your locale:",
        COMMON_LOCALES,
        default="en_US.UTF-8"
    )
    LOCALE = config['locale']

    # === Keyboard Layout ===
    config['keymap'] = select_from_list(
        "Select keyboard layout:",
        COMMON_KEYMAPS,
        default="us"
    )
    KEYMAP = config['keymap']

    # === Partition Sizes ===
    print("\n--- Partition Configuration ---")
    print(f"Detected RAM: {sys_info['ram_gb']}GB")

    # Recommend swap = RAM for hibernation support
    recommended_swap = f"{sys_info['ram_gb']}G"
    print(f"\nRecommended swap size: {recommended_swap} (matches RAM for hibernation)")
    print("  - For hibernation support: swap >= RAM")
    print("  - Without hibernation: 4-8GB is usually sufficient")

    swap_input = prompt_with_default("Swap partition size", recommended_swap)
    config['swap_size'] = normalize_size(swap_input)
    SWAP_SIZE = config['swap_size']
    if swap_input != config['swap_size']:
        print(f"  (normalized to: {config['swap_size']})")

    print(f"\nRecommended EFI size: 1G (sufficient for multiple kernels)")
    efi_input = prompt_with_default("EFI partition size", "1G")
    config['efi_size'] = normalize_size(efi_input)
    EFI_SIZE = config['efi_size']
    if efi_input != config['efi_size']:
        print(f"  (normalized to: {config['efi_size']})")

    # === Summary ===
    print("\n" + "=" * 60)
    print("            CONFIGURATION SUMMARY")
    print("=" * 60)
    print(f"""
  Target Disk:    {config['disk']}
  Hostname:       {config['hostname']}
  Timezone:       {config['timezone']}
  Locale:         {config['locale']}
  Keyboard:       {config['keymap']}

  Partitions:
    EFI:          {config['efi_size']} (FAT32)
    Swap:         {config['swap_size']}
    Root:         Remaining space (LUKS2 encrypted BTRFS)

  BTRFS Subvolumes:
    @             -> /
    @home         -> /home
    @var          -> /var
    @snapshots    -> /.snapshots
""")

    return config


def get_password(prompt: str) -> str:
    """Get password with confirmation."""
    while True:
        password = getpass.getpass(f"{prompt}: ")
        confirm_pass = getpass.getpass("Confirm password: ")
        if password == confirm_pass:
            return password
        print("Passwords do not match. Try again.")


def check_requirements():
    """Verify we're running in the right environment."""
    if os.geteuid() != 0:
        print("Error: This script must be run as root")
        sys.exit(1)

    if not Path(DISK).exists():
        print(f"Error: Disk {DISK} not found")
        sys.exit(1)

    # Check for UEFI
    if not Path("/sys/firmware/efi").exists():
        print("Error: System must be booted in UEFI mode")
        sys.exit(1)

    # Check internet connectivity (use a reliable target)
    result = run("ping -c 1 -W 5 1.1.1.1", check=False, capture=True)
    if result.returncode != 0:
        # Try DNS-based check as fallback
        result = run("ping -c 1 -W 5 google.com", check=False, capture=True)
        if result.returncode != 0:
            print("Error: No internet connection.")
            if LIVE_ENV == "arch":
                print("Use 'iwctl' for WiFi setup.")
            else:
                print("Use NetworkManager (nmcli/nmtui) or the network settings GUI for WiFi setup.")
            sys.exit(1)

    print("All requirements met.")


def reload_partition_table(disk: str):
    """Reload the partition table using multiple methods with fallbacks.

    partprobe can fail with 'Device or resource busy' if the kernel still
    has references to old partitions. This is common when running from a
    live environment. We try multiple methods and ultimately verify that
    the partition devices actually exist.
    """
    print("\n--- Reloading Partition Table ---")

    # Method 1: partprobe on specific disk
    result = run(f"partprobe {disk}", check=False)
    if result.returncode == 0:
        print("partprobe succeeded")
        time.sleep(2)
        return

    print("partprobe returned non-zero, trying alternative methods...")

    # Method 2: blockdev --rereadpt
    result = run(f"blockdev --rereadpt {disk}", check=False)
    if result.returncode == 0:
        print("blockdev --rereadpt succeeded")
        time.sleep(2)
        # Still verify partitions exist below

    # Method 3: partx -u (update partition table)
    result = run(f"partx -u {disk}", check=False)
    if result.returncode == 0:
        print("partx -u succeeded")
        time.sleep(2)

    # Give the kernel time to process
    time.sleep(2)

    # Verify partition devices actually exist - this is the real test
    # Even if partprobe fails, the partitions may have been created
    partitions_exist = True
    for part in [f"{disk}p1", f"{disk}p2", f"{disk}p3"]:
        if not Path(part).exists():
            partitions_exist = False
            print(f"Warning: {part} does not exist yet")

    if partitions_exist:
        print("All partition devices exist - continuing installation")
        return

    # Final fallback: trigger udev and wait
    print("Partitions not yet visible, triggering udev...")
    run("udevadm settle --timeout=10", check=False)
    time.sleep(2)

    # Final verification
    missing = []
    for part in [f"{disk}p1", f"{disk}p2", f"{disk}p3"]:
        if not Path(part).exists():
            missing.append(part)

    if missing:
        print(f"\nERROR: Partition devices not found: {', '.join(missing)}")
        print("\nThis can happen when running from a live environment that")
        print("has mounted or used the target disk previously.")
        print("\nPossible solutions:")
        print("  1. Reboot into the live environment and try again")
        print("  2. Ensure no partitions from this disk are mounted")
        print("  3. Check 'lsblk' to see current disk state")
        sys.exit(1)

    print("All partition devices exist - continuing installation")


def partition_disk():
    """Create GPT partitions on the disk."""
    print("\n=== Partitioning Disk ===")

    # Wipe existing partitions
    run(f"wipefs -af {DISK}")
    run(f"sgdisk -Z {DISK}")

    # Create GPT partition table
    run(f"sgdisk -o {DISK}")

    # Create partitions
    # EFI System Partition
    run(f"sgdisk -n 1:0:+{EFI_SIZE} -t 1:ef00 -c 1:'EFI' {DISK}")
    # Swap partition
    run(f"sgdisk -n 2:0:+{SWAP_SIZE} -t 2:8200 -c 2:'Swap' {DISK}")
    # Root partition (remaining space)
    run(f"sgdisk -n 3:0:0 -t 3:8309 -c 3:'Linux LUKS' {DISK}")

    # Reload partition table - try multiple methods as partprobe can fail
    # when the kernel has stale references to old partitions
    reload_partition_table(DISK)

    # Verify partitions were created correctly
    verify_partitions()

    print("Partitioning complete.")


def verify_partitions():
    """Verify that partitions were created with reasonable sizes."""
    print("\n--- Verifying Partitions ---")

    # Use lsblk to get partition sizes in bytes
    result = run(f"lsblk -b -n -o SIZE {SWAP_PART}", capture=True, check=False)
    if result.returncode != 0:
        print(f"Warning: Could not verify partition {SWAP_PART}")
        return

    try:
        swap_bytes = int(result.stdout.strip())
        swap_mb = swap_bytes / (1024 * 1024)
        swap_gb = swap_bytes / (1024 * 1024 * 1024)

        print(f"  EFI partition:  {EFI_PART}")
        print(f"  Swap partition: {SWAP_PART} ({swap_gb:.1f} GB)")
        print(f"  Root partition: {ROOT_PART}")

        # Swap should be at least 1GB for any reasonable use
        min_swap_mb = 1024  # 1GB minimum
        if swap_mb < min_swap_mb:
            print(f"\nERROR: Swap partition is too small ({swap_mb:.1f} MB)!")
            print(f"Expected at least 1GB. Got {swap_mb:.1f} MB.")
            print(f"This usually means the size format was incorrect.")
            print(f"Use format like '32G' for 32 gigabytes, not just '32'.")
            sys.exit(1)

    except (ValueError, AttributeError) as e:
        print(f"Warning: Could not parse partition size: {e}")


def setup_encryption(luks_password: str):
    """Set up LUKS encryption on root partition."""
    print("\n=== Setting Up Encryption ===")

    # Format with LUKS2 (using argon2id for better security)
    # Note: Using pbkdf2 for GRUB compatibility if needed later
    run(f"echo -n '{luks_password}' | cryptsetup luksFormat --type luks2 "
        f"--cipher aes-xts-plain64 --key-size 512 --hash sha512 "
        f"--pbkdf argon2id {ROOT_PART} -")

    # Open the encrypted volume
    run(f"echo -n '{luks_password}' | cryptsetup open {ROOT_PART} {CRYPT_NAME} -")

    print("Encryption setup complete.")


def format_filesystems():
    """Format partitions with appropriate filesystems."""
    print("\n=== Formatting Filesystems ===")

    # EFI partition (FAT32)
    run(f"mkfs.fat -F32 -n EFI {EFI_PART}")

    # Swap
    run(f"mkswap -L swap {SWAP_PART}")

    # BTRFS on encrypted volume
    run(f"mkfs.btrfs -f -L archroot {CRYPT_PATH}")

    print("Filesystems formatted.")


def create_btrfs_subvolumes():
    """Create BTRFS subvolumes for flexible snapshots."""
    print("\n=== Creating BTRFS Subvolumes ===")

    # Mount root temporarily
    run(f"mount {CRYPT_PATH} {MOUNT_POINT}")

    # Create subvolumes
    subvolumes = ["@", "@home", "@var", "@snapshots"]
    for sv in subvolumes:
        run(f"btrfs subvolume create {MOUNT_POINT}/{sv}")

    # Unmount
    run(f"umount {MOUNT_POINT}")

    print("Subvolumes created.")


def mount_filesystems():
    """Mount all filesystems for installation."""
    print("\n=== Mounting Filesystems ===")

    # Mount options for BTRFS (optimized for NVMe SSD)
    btrfs_opts = "noatime,compress=zstd:1,ssd,discard=async,space_cache=v2"

    # Mount root subvolume
    run(f"mount -o {btrfs_opts},subvol=@ {CRYPT_PATH} {MOUNT_POINT}")

    # Create mount points
    for d in ["home", "var", ".snapshots", "boot"]:
        Path(f"{MOUNT_POINT}/{d}").mkdir(parents=True, exist_ok=True)

    # Mount other subvolumes
    run(f"mount -o {btrfs_opts},subvol=@home {CRYPT_PATH} {MOUNT_POINT}/home")
    run(f"mount -o {btrfs_opts},subvol=@var {CRYPT_PATH} {MOUNT_POINT}/var")
    run(f"mount -o {btrfs_opts},subvol=@snapshots {CRYPT_PATH} {MOUNT_POINT}/.snapshots")

    # Mount EFI partition
    Path(f"{MOUNT_POINT}/boot/efi").mkdir(parents=True, exist_ok=True)
    run(f"mount {EFI_PART} {MOUNT_POINT}/boot/efi")

    # Enable swap
    run(f"swapon {SWAP_PART}")

    print("Filesystems mounted.")


def install_base_system():
    """Install base Arch Linux system."""
    print("\n=== Installing Base System ===")

    # Update pacman mirrors (only on Arch live environment)
    if LIVE_ENV == "arch":
        run("pacman -Sy --noconfirm archlinux-keyring")

    # Base packages
    packages = [
        # Base system
        "base",
        "base-devel",
        "linux",
        "linux-headers",
        "linux-firmware",
        "amd-ucode",

        # Filesystem tools
        "btrfs-progs",
        "dosfstools",
        "e2fsprogs",

        # Boot and encryption
        "systemd",
        "efibootmgr",
        "cryptsetup",

        # Networking
        "networkmanager",
        "iwd",
        "wireless-regdb",

        # Essential tools
        "sudo",
        "vim",
        "git",
        "wget",
        "curl",
        "htop",
        "man-db",
        "man-pages",

        # Hardware support for Framework
        "fwupd",  # Firmware updates
        "power-profiles-daemon",
        "thermald",
        "fprintd",  # Fingerprint reader
    ]

    # Use pacstrap (either native or from bootstrap)
    if shutil.which("pacstrap"):
        run(f"pacstrap -K {MOUNT_POINT} {' '.join(packages)}")
    elif ARCH_BOOTSTRAP_DIR and Path(f"{ARCH_BOOTSTRAP_DIR}/bin/pacstrap").exists():
        run(f"{ARCH_BOOTSTRAP_DIR}/bin/pacstrap -K {MOUNT_POINT} {' '.join(packages)}")
    else:
        print("Error: pacstrap not found. Cannot install base system.")
        sys.exit(1)

    print("Base system installed.")


def generate_fstab():
    """Generate fstab file."""
    print("\n=== Generating fstab ===")

    # Use genfstab (either native or from bootstrap)
    if shutil.which("genfstab"):
        run(f"genfstab -U {MOUNT_POINT} >> {MOUNT_POINT}/etc/fstab")
    elif ARCH_BOOTSTRAP_DIR and Path(f"{ARCH_BOOTSTRAP_DIR}/bin/genfstab").exists():
        run(f"{ARCH_BOOTSTRAP_DIR}/bin/genfstab -U {MOUNT_POINT} >> {MOUNT_POINT}/etc/fstab")
    else:
        # Manual fstab generation as fallback
        print("genfstab not found, generating fstab manually...")
        generate_fstab_manual()
        return

    # Display for verification
    print("Generated fstab:")
    with open(f"{MOUNT_POINT}/etc/fstab") as f:
        print(f.read())


def generate_fstab_manual():
    """Manually generate fstab when genfstab is not available."""
    btrfs_opts = "noatime,compress=zstd:1,ssd,discard=async,space_cache=v2"

    # Get UUIDs
    crypt_uuid = get_uuid(CRYPT_PATH)
    efi_uuid = get_uuid(EFI_PART)
    swap_uuid = get_uuid(SWAP_PART)

    fstab_content = f"""# /etc/fstab - Static filesystem information
# Generated by archlinux-framework installer

# Root subvolume
UUID={crypt_uuid}  /  btrfs  {btrfs_opts},subvol=@  0  0

# Home subvolume
UUID={crypt_uuid}  /home  btrfs  {btrfs_opts},subvol=@home  0  0

# Var subvolume
UUID={crypt_uuid}  /var  btrfs  {btrfs_opts},subvol=@var  0  0

# Snapshots subvolume
UUID={crypt_uuid}  /.snapshots  btrfs  {btrfs_opts},subvol=@snapshots  0  0

# EFI System Partition
UUID={efi_uuid}  /boot/efi  vfat  umask=0077  0  2

# Swap
UUID={swap_uuid}  none  swap  defaults  0  0
"""

    with open(f"{MOUNT_POINT}/etc/fstab", "w") as f:
        f.write(fstab_content)

    print("Generated fstab:")
    print(fstab_content)


def configure_system(root_password: str, username: str, user_password: str):
    """Configure the installed system."""
    print("\n=== Configuring System ===")

    # Timezone
    run(f"ln -sf /usr/share/zoneinfo/{TIMEZONE} /etc/localtime", chroot=True)
    run("hwclock --systohc", chroot=True)

    # Locale
    with open(f"{MOUNT_POINT}/etc/locale.gen", "a") as f:
        f.write(f"{LOCALE} UTF-8\n")
    run("locale-gen", chroot=True)
    with open(f"{MOUNT_POINT}/etc/locale.conf", "w") as f:
        f.write(f"LANG={LOCALE}\n")

    # Keymap
    with open(f"{MOUNT_POINT}/etc/vconsole.conf", "w") as f:
        f.write(f"KEYMAP={KEYMAP}\n")

    # Hostname
    with open(f"{MOUNT_POINT}/etc/hostname", "w") as f:
        f.write(f"{HOSTNAME}\n")

    # Hosts file
    with open(f"{MOUNT_POINT}/etc/hosts", "w") as f:
        f.write(f"""127.0.0.1   localhost
::1         localhost
127.0.1.1   {HOSTNAME}.localdomain {HOSTNAME}
""")

    # Set root password
    run(f"echo 'root:{root_password}' | chpasswd", chroot=True)

    # Create user
    run(f"useradd -m -G wheel,video,audio,input -s /bin/bash {username}", chroot=True)
    run(f"echo '{username}:{user_password}' | chpasswd", chroot=True)

    # Enable sudo for wheel group
    with open(f"{MOUNT_POINT}/etc/sudoers.d/wheel", "w") as f:
        f.write("%wheel ALL=(ALL:ALL) ALL\n")
    os.chmod(f"{MOUNT_POINT}/etc/sudoers.d/wheel", 0o440)

    print("System configured.")


def configure_mkinitcpio():
    """Configure mkinitcpio for encryption."""
    print("\n=== Configuring mkinitcpio ===")

    # Use systemd-based initramfs for better LUKS2/BTRFS support
    mkinitcpio_conf = f"""\
# mkinitcpio configuration for encrypted BTRFS root
MODULES=(amdgpu)
BINARIES=()
FILES=()
HOOKS=(base systemd autodetect microcode modconf kms keyboard sd-vconsole block sd-encrypt filesystems fsck)
"""

    with open(f"{MOUNT_POINT}/etc/mkinitcpio.conf", "w") as f:
        f.write(mkinitcpio_conf)

    # Regenerate initramfs
    run("mkinitcpio -P", chroot=True)

    print("mkinitcpio configured.")


def get_uuid(device: str) -> str:
    """Get UUID of a device."""
    result = run(f"blkid -s UUID -o value {device}", capture=True)
    return result.stdout.strip()


def install_bootloader():
    """Install and configure systemd-boot."""
    print("\n=== Installing Bootloader (systemd-boot) ===")

    # Install systemd-boot
    run("bootctl install --esp-path=/boot/efi", chroot=True)

    # Get UUIDs
    root_uuid = get_uuid(ROOT_PART)

    # Create loader configuration
    loader_conf = """\
default arch.conf
timeout 3
console-mode max
editor no
"""

    Path(f"{MOUNT_POINT}/boot/efi/loader").mkdir(parents=True, exist_ok=True)
    with open(f"{MOUNT_POINT}/boot/efi/loader/loader.conf", "w") as f:
        f.write(loader_conf)

    # Create boot entry
    # Using rd.luks for systemd-based initramfs
    boot_entry = f"""\
title   Arch Linux
linux   /vmlinuz-linux
initrd  /amd-ucode.img
initrd  /initramfs-linux.img
options rd.luks.name={root_uuid}={CRYPT_NAME} root=/dev/mapper/{CRYPT_NAME} rootflags=subvol=@ rw quiet splash
"""

    Path(f"{MOUNT_POINT}/boot/efi/loader/entries").mkdir(parents=True, exist_ok=True)
    with open(f"{MOUNT_POINT}/boot/efi/loader/entries/arch.conf", "w") as f:
        f.write(boot_entry)

    # Copy kernel and initramfs to EFI partition
    # systemd-boot looks for these in the ESP
    shutil.copy(f"{MOUNT_POINT}/boot/vmlinuz-linux", f"{MOUNT_POINT}/boot/efi/")
    shutil.copy(f"{MOUNT_POINT}/boot/initramfs-linux.img", f"{MOUNT_POINT}/boot/efi/")
    shutil.copy(f"{MOUNT_POINT}/boot/amd-ucode.img", f"{MOUNT_POINT}/boot/efi/")

    # Create pacman hook to update ESP on kernel updates
    hooks_dir = Path(f"{MOUNT_POINT}/etc/pacman.d/hooks")
    hooks_dir.mkdir(parents=True, exist_ok=True)

    kernel_hook = """\
[Trigger]
Type = Path
Operation = Install
Operation = Upgrade
Target = usr/lib/modules/*/vmlinuz
Target = usr/lib/initcpio/*
Target = boot/*

[Action]
Description = Copying kernel and initramfs to EFI partition...
When = PostTransaction
Exec = /usr/bin/sh -c 'cp /boot/vmlinuz-linux /boot/efi/ && cp /boot/initramfs-linux.img /boot/efi/ && cp /boot/amd-ucode.img /boot/efi/'
"""

    with open(f"{hooks_dir}/95-systemd-boot.hook", "w") as f:
        f.write(kernel_hook)

    print("Bootloader installed.")


def install_desktop():
    """Install Wayland and Hyprland."""
    print("\n=== Installing Desktop Environment ===")

    packages = [
        # Wayland essentials
        "wayland",
        "wayland-protocols",
        "xorg-xwayland",
        "wl-clipboard",

        # Hyprland and ecosystem
        "hyprland",
        "hyprpaper",      # Wallpaper
        "hypridle",       # Idle daemon
        "hyprlock",       # Lock screen
        "xdg-desktop-portal-hyprland",

        # Terminal and shell
        "kitty",          # GPU-accelerated terminal
        "zsh",

        # Application launcher and bar
        "wofi",           # App launcher
        "waybar",         # Status bar

        # Audio (PipeWire)
        "pipewire",
        "pipewire-alsa",
        "pipewire-pulse",
        "pipewire-jack",
        "wireplumber",
        "pavucontrol",

        # Display/screen tools
        "brightnessctl",  # Brightness control
        "kanshi",         # Display configuration
        "grim",           # Screenshot
        "slurp",          # Region selection

        # Notifications
        "mako",           # Notification daemon

        # File manager
        "thunar",
        "gvfs",

        # Fonts
        "ttf-dejavu",
        "ttf-liberation",
        "noto-fonts",
        "noto-fonts-emoji",
        "ttf-font-awesome",

        # GTK theming
        "gtk3",
        "gtk4",
        "gnome-themes-extra",
        "adwaita-icon-theme",

        # Polkit for authentication
        "polkit-gnome",

        # Qt Wayland support
        "qt5-wayland",
        "qt6-wayland",
    ]

    run(f"pacman -S --noconfirm {' '.join(packages)}", chroot=True)

    print("Desktop environment installed.")


def create_hyprland_config(username: str):
    """Create basic Hyprland configuration."""
    print("\n=== Creating Hyprland Configuration ===")

    config_dir = Path(f"{MOUNT_POINT}/home/{username}/.config/hypr")
    config_dir.mkdir(parents=True, exist_ok=True)

    hyprland_conf = """\
# Hyprland configuration for Framework 13" AMD

# Monitor configuration (Framework 13.5" 2256x1504)
monitor=eDP-1,2256x1504@60,0x0,1.5

# Execute at launch
exec-once = waybar
exec-once = hyprpaper
exec-once = mako
exec-once = /usr/lib/polkit-gnome/polkit-gnome-authentication-agent-1
exec-once = hypridle

# Environment variables
env = XCURSOR_SIZE,24
env = QT_QPA_PLATFORM,wayland
env = XDG_CURRENT_DESKTOP,Hyprland
env = XDG_SESSION_TYPE,wayland
env = XDG_SESSION_DESKTOP,Hyprland
env = GDK_BACKEND,wayland,x11

# Input configuration
input {
    kb_layout = us
    follow_mouse = 1
    touchpad {
        natural_scroll = true
        tap-to-click = true
        disable_while_typing = true
    }
    sensitivity = 0
}

# General appearance
general {
    gaps_in = 5
    gaps_out = 10
    border_size = 2
    col.active_border = rgba(33ccffee) rgba(00ff99ee) 45deg
    col.inactive_border = rgba(595959aa)
    layout = dwindle
}

# Decorations
decoration {
    rounding = 10
    blur {
        enabled = true
        size = 3
        passes = 1
    }
    shadow {
        enabled = true
        range = 4
        render_power = 3
        color = rgba(1a1a1aee)
    }
}

# Animations
animations {
    enabled = true
    bezier = myBezier, 0.05, 0.9, 0.1, 1.05
    animation = windows, 1, 7, myBezier
    animation = windowsOut, 1, 7, default, popin 80%
    animation = border, 1, 10, default
    animation = fade, 1, 7, default
    animation = workspaces, 1, 6, default
}

# Layout
dwindle {
    pseudotile = true
    preserve_split = true
}

# Gestures
gestures {
    workspace_swipe = true
}

# Key bindings
$mainMod = SUPER

bind = $mainMod, Return, exec, kitty
bind = $mainMod, Q, killactive,
bind = $mainMod SHIFT, E, exit,
bind = $mainMod, E, exec, thunar
bind = $mainMod, V, togglefloating,
bind = $mainMod, D, exec, wofi --show drun
bind = $mainMod, P, pseudo,
bind = $mainMod, J, togglesplit,
bind = $mainMod, F, fullscreen,
bind = $mainMod, L, exec, hyprlock

# Move focus
bind = $mainMod, left, movefocus, l
bind = $mainMod, right, movefocus, r
bind = $mainMod, up, movefocus, u
bind = $mainMod, down, movefocus, d

# Workspaces
bind = $mainMod, 1, workspace, 1
bind = $mainMod, 2, workspace, 2
bind = $mainMod, 3, workspace, 3
bind = $mainMod, 4, workspace, 4
bind = $mainMod, 5, workspace, 5
bind = $mainMod, 6, workspace, 6
bind = $mainMod, 7, workspace, 7
bind = $mainMod, 8, workspace, 8
bind = $mainMod, 9, workspace, 9
bind = $mainMod, 0, workspace, 10

# Move to workspace
bind = $mainMod SHIFT, 1, movetoworkspace, 1
bind = $mainMod SHIFT, 2, movetoworkspace, 2
bind = $mainMod SHIFT, 3, movetoworkspace, 3
bind = $mainMod SHIFT, 4, movetoworkspace, 4
bind = $mainMod SHIFT, 5, movetoworkspace, 5
bind = $mainMod SHIFT, 6, movetoworkspace, 6
bind = $mainMod SHIFT, 7, movetoworkspace, 7
bind = $mainMod SHIFT, 8, movetoworkspace, 8
bind = $mainMod SHIFT, 9, movetoworkspace, 9
bind = $mainMod SHIFT, 0, movetoworkspace, 10

# Scroll through workspaces
bind = $mainMod, mouse_down, workspace, e+1
bind = $mainMod, mouse_up, workspace, e-1

# Move/resize with mouse
bindm = $mainMod, mouse:272, movewindow
bindm = $mainMod, mouse:273, resizewindow

# Media keys
bind = , XF86AudioRaiseVolume, exec, wpctl set-volume @DEFAULT_AUDIO_SINK@ 5%+
bind = , XF86AudioLowerVolume, exec, wpctl set-volume @DEFAULT_AUDIO_SINK@ 5%-
bind = , XF86AudioMute, exec, wpctl set-mute @DEFAULT_AUDIO_SINK@ toggle
bind = , XF86AudioMicMute, exec, wpctl set-mute @DEFAULT_AUDIO_SOURCE@ toggle
bind = , XF86MonBrightnessUp, exec, brightnessctl set +5%
bind = , XF86MonBrightnessDown, exec, brightnessctl set 5%-

# Screenshot
bind = , Print, exec, grim -g "$(slurp)" - | wl-copy
bind = SHIFT, Print, exec, grim - | wl-copy

# Window rules
windowrulev2 = float, class:^(pavucontrol)$
windowrulev2 = float, class:^(thunar)$,title:^(File Operation Progress)$
"""

    with open(f"{config_dir}/hyprland.conf", "w") as f:
        f.write(hyprland_conf)

    # Create hypridle config
    hypridle_conf = """\
general {
    lock_cmd = pidof hyprlock || hyprlock
    before_sleep_cmd = loginctl lock-session
    after_sleep_cmd = hyprctl dispatch dpms on
}

listener {
    timeout = 300
    on-timeout = brightnessctl -s set 10%
    on-resume = brightnessctl -r
}

listener {
    timeout = 600
    on-timeout = loginctl lock-session
}

listener {
    timeout = 900
    on-timeout = hyprctl dispatch dpms off
    on-resume = hyprctl dispatch dpms on
}

listener {
    timeout = 1800
    on-timeout = systemctl suspend
}
"""

    with open(f"{config_dir}/hypridle.conf", "w") as f:
        f.write(hypridle_conf)

    # Create hyprlock config
    hyprlock_conf = """\
general {
    disable_loading_bar = false
    hide_cursor = true
    grace = 0
}

background {
    monitor =
    path = screenshot
    blur_passes = 3
    blur_size = 8
}

input-field {
    monitor =
    size = 200, 50
    outline_thickness = 3
    dots_size = 0.33
    dots_spacing = 0.15
    dots_center = true
    outer_color = rgb(151515)
    inner_color = rgb(200, 200, 200)
    font_color = rgb(10, 10, 10)
    fade_on_empty = true
    placeholder_text = <i>Password...</i>
    hide_input = false
    position = 0, -20
    halign = center
    valign = center
}
"""

    with open(f"{config_dir}/hyprlock.conf", "w") as f:
        f.write(hyprlock_conf)

    # Fix ownership
    run(f"chown -R {username}:{username} /home/{username}/.config", chroot=True)

    print("Hyprland configuration created.")


def enable_services():
    """Enable systemd services."""
    print("\n=== Enabling Services ===")

    services = [
        "NetworkManager",
        "bluetooth",
        "fstrim.timer",
        "power-profiles-daemon",
    ]

    for service in services:
        run(f"systemctl enable {service}", chroot=True)

    # Enable user services
    print("User services (PipeWire, etc.) will start automatically via socket activation.")

    print("Services enabled.")


def cleanup():
    """Unmount filesystems and close encrypted volume."""
    print("\n=== Cleanup ===")

    # Clean up manual chroot mounts if they were set up
    if not shutil.which("arch-chroot") and not (ARCH_BOOTSTRAP_DIR and Path(f"{ARCH_BOOTSTRAP_DIR}/bin/arch-chroot").exists()):
        manual_chroot_cleanup(MOUNT_POINT)

    run("swapoff -a", check=False)
    run(f"umount -R {MOUNT_POINT}", check=False)
    run(f"cryptsetup close {CRYPT_NAME}", check=False)

    print("Cleanup complete.")


def main():
    print("""
╔═══════════════════════════════════════════════════════════════╗
║     Arch Linux Installer for Framework 13" (AMD Edition)      ║
╠═══════════════════════════════════════════════════════════════╣
║  This script will:                                            ║
║  1. Partition and encrypt your NVMe drive                     ║
║  2. Install Arch Linux with AMD drivers                       ║
║  3. Configure systemd-boot with LUKS2 encryption              ║
║  4. Install Hyprland (Wayland compositor)                     ║
║                                                               ║
║  Supports: Arch Linux or Ubuntu live environments             ║
╚═══════════════════════════════════════════════════════════════╝
""")

    # Detect live environment
    detect_live_environment()

    print("\nThis installer will guide you through the configuration process.")
    print("You'll be asked for timezone, hostname, and other settings.\n")

    if not confirm("Do you want to continue?"):
        print("Aborted.")
        sys.exit(0)

    # Set up Arch tools if running from Ubuntu
    if LIVE_ENV == "ubuntu":
        print("\nRunning from Ubuntu live environment.")
        print("Will download and set up Arch Linux bootstrap tools...")
        if not confirm("Continue with Ubuntu live setup?"):
            print("Aborted.")
            sys.exit(0)
        setup_arch_tools_on_ubuntu()

    # Interactive configuration
    config = get_configuration()

    print(f"\nWARNING: ALL DATA ON {DISK} WILL BE DESTROYED!")

    if not confirm("Is this configuration correct?"):
        print("Aborted. Please run the installer again.")
        sys.exit(0)

    # Check requirements
    check_requirements()

    # Get passwords
    print("\n" + "=" * 60)
    print("            USER ACCOUNT SETUP")
    print("=" * 60)

    print("\n--- Encryption Password ---")
    print("This password will be required every time you boot.")
    luks_password = get_password("Enter LUKS encryption password")

    print("\n--- Root Account ---")
    root_password = get_password("Enter root password")

    print("\n--- User Account ---")
    username = input("Enter username for new user: ").strip()
    if not username:
        print("Username cannot be empty.")
        sys.exit(1)
    user_password = get_password(f"Enter password for {username}")

    # Final confirmation
    print("\n" + "=" * 60)
    print("            FINAL CONFIRMATION")
    print("=" * 60)
    print(f"""
  Target Disk:    {DISK}
  Hostname:       {HOSTNAME}
  Timezone:       {TIMEZONE}
  Locale:         {LOCALE}
  Keyboard:       {KEYMAP}
  Username:       {username}

  Partitions:
    {EFI_PART}:  {EFI_SIZE} EFI
    {SWAP_PART}:  {SWAP_SIZE} Swap
    {ROOT_PART}:  Remaining (encrypted BTRFS)
""")

    print("WARNING: This will ERASE ALL DATA on the target disk!")

    if not confirm("\nProceed with installation?"):
        print("Aborted.")
        sys.exit(0)

    try:
        partition_disk()
        setup_encryption(luks_password)
        format_filesystems()
        create_btrfs_subvolumes()
        mount_filesystems()
        install_base_system()

        # Set up chroot environment if arch-chroot is not available
        if not shutil.which("arch-chroot") and not (ARCH_BOOTSTRAP_DIR and Path(f"{ARCH_BOOTSTRAP_DIR}/bin/arch-chroot").exists()):
            print("\n=== Setting Up Chroot Environment ===")
            manual_chroot_setup(MOUNT_POINT)
        generate_fstab()
        configure_system(root_password, username, user_password)
        configure_mkinitcpio()
        install_bootloader()
        install_desktop()
        create_hyprland_config(username)
        enable_services()

        print("\n" + "=" * 60)
        print("Installation complete!")
        print("=" * 60)
        print(f"""
Next steps:
1. Review the installation: chroot {MOUNT_POINT} /bin/bash
2. Exit chroot: exit
3. Reboot: reboot

After reboot:
- Login as {username}
- Start Hyprland: Hyprland

Key bindings (in Hyprland):
- Super + Return: Open terminal (kitty)
- Super + D: App launcher (wofi)
- Super + Q: Close window
- Super + L: Lock screen
- Super + Shift + E: Exit Hyprland
""")

        if confirm("Unmount and reboot now?"):
            cleanup()
            run("reboot")
        else:
            if shutil.which("arch-chroot"):
                print(f"\nYou can manually chroot with: arch-chroot {MOUNT_POINT}")
            else:
                print(f"\nYou can manually chroot with: chroot {MOUNT_POINT} /bin/bash")
            print("When done, run: umount -R /mnt && reboot")

    except subprocess.CalledProcessError as e:
        print(f"\nError during installation: {e}")
        print("Installation failed. You may need to manually clean up.")
        if confirm("Attempt cleanup?"):
            cleanup()
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n\nInstallation interrupted.")
        if confirm("Attempt cleanup?"):
            cleanup()
        sys.exit(1)


if __name__ == "__main__":
    main()
