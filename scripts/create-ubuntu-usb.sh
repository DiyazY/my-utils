#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════
#  Ubuntu Headless Server — Fully Automated USB Installer Creator
#  (macOS edition)
# ══════════════════════════════════════════════════════════════════════
#  Creates a hands-off USB installer for Ubuntu Server.
#  After booting from the USB, the target machine installs Ubuntu
#  automatically, configures SSH with key-only auth (password disabled),
#  and powers off. Just unplug the USB, boot, and SSH in.
#
#  Usage:  sudo ./create-ubuntu-usb.sh
#
#  Customize via environment variables (optional):
#    TARGET_HOSTNAME=mybox  TARGET_USERNAME=myuser  sudo ./create-ubuntu-usb.sh
#
#  Requirements (install via Homebrew):
#    brew install xorriso wget python3 coreutils
# ══════════════════════════════════════════════════════════════════════
set -Eeuo pipefail

# ─── Defaults ─────────────────────────────────────────────────────────
TARGET_HOSTNAME="${TARGET_HOSTNAME:-ubuntu-nuc}"
TARGET_USERNAME="${TARGET_USERNAME:-nuc}"

# Resolve real user's home even under sudo
if [[ -n "${SUDO_USER:-}" ]]; then
    REAL_HOME=$(dscl . -read "/Users/$SUDO_USER" NFSHomeDirectory 2>/dev/null \
                | awk '{print $2}')
    [[ -z "$REAL_HOME" ]] && REAL_HOME="/Users/$SUDO_USER"
else
    REAL_HOME="$HOME"
fi
CACHE_DIR="${CACHE_DIR:-${REAL_HOME}/.cache/ubuntu-autoinstall-creator}"
WORK_DIR=""

# ─── Available OS versions ────────────────────────────────────────────
OS_NAMES=(
    "Ubuntu 24.04.3 LTS (Noble Numbat)"
    "Ubuntu 22.04.5 LTS (Jammy Jellyfish)"
)
OS_URLS=(
    "https://releases.ubuntu.com/noble/ubuntu-24.04.3-live-server-amd64.iso"
    "https://releases.ubuntu.com/jammy/ubuntu-22.04.5-live-server-amd64.iso"
)
OS_FILES=(
    "ubuntu-24.04.3-live-server-amd64.iso"
    "ubuntu-22.04.5-live-server-amd64.iso"
)
OS_SHA_URLS=(
    "https://releases.ubuntu.com/noble/SHA256SUMS"
    "https://releases.ubuntu.com/jammy/SHA256SUMS"
)

# ─── Colours ──────────────────────────────────────────────────────────
R=$'\033[0;31m'  G=$'\033[0;32m'  Y=$'\033[1;33m'
B=$'\033[0;34m'  C=$'\033[0;36m'  BOLD=$'\033[1m'  NC=$'\033[0m'

info() { printf '%s\n' "${B}▸${NC} $*"; }
ok()   { printf '%s\n' "${G}✓${NC} $*"; }
warn() { printf '%s\n' "${Y}⚠${NC} $*"; }
err()  { printf '%s\n' "${R}✗${NC} $*" >&2; }
die()  { err "$@"; exit 1; }
hr()   { printf '%s\n' "${C}────────────────────────────────────────────────${NC}"; }

# Portable lowercase (works on bash 3.2 which ships with macOS)
to_lower() { printf '%s' "$1" | tr '[:upper:]' '[:lower:]'; }

# ─── Cleanup ──────────────────────────────────────────────────────────
cleanup() {
    if [[ -n "${WORK_DIR:-}" && -d "${WORK_DIR:-}" ]]; then
        rm -rf "$WORK_DIR"
    fi
}
trap cleanup EXIT
trap 'echo ""; die "Interrupted."' INT TERM

# ─── Pre-flight checks ───────────────────────────────────────────────
preflight() {
    if [[ "$(uname)" != "Darwin" ]]; then
        die "This script is designed for macOS.  Detected: $(uname)"
    fi

    if (( EUID != 0 )); then
        die "Root required (for writing to USB).  Run:  sudo $0"
    fi

    local missing=()
    for cmd in xorriso wget dd python3; do
        command -v "$cmd" &>/dev/null || missing+=("$cmd")
    done
    # Check for diskutil (built-in on macOS, but just in case)
    command -v diskutil &>/dev/null || missing+=("diskutil")

    if (( ${#missing[@]} )); then
        err "Missing tools: ${missing[*]}"
        echo ""
        echo "  Install via Homebrew:"
        echo "    brew install xorriso wget python3"
        echo ""
        exit 1
    fi

    WORK_DIR=$(mktemp -d)
    mkdir -p "$CACHE_DIR"
}

# ══════════════════════════════════════════════════════════════════════
#  Step 1 — Select OS
# ══════════════════════════════════════════════════════════════════════
select_os() {
    echo ""
    printf '%s\n' "${BOLD}Select Ubuntu Server version:${NC}"
    echo ""
    for i in "${!OS_NAMES[@]}"; do
        printf '  %s\n' "${C}$((i + 1)))${NC} ${OS_NAMES[$i]}"
    done
    echo ""

    while true; do
        read -rp "  Your choice [1-${#OS_NAMES[@]}]: " choice
        if [[ "$choice" =~ ^[0-9]+$ ]] && (( choice >= 1 && choice <= ${#OS_NAMES[@]} )); then
            OS_IDX=$((choice - 1))
            break
        fi
        warn "Invalid — try again"
    done
    ok "Selected: ${OS_NAMES[$OS_IDX]}"
}

# ══════════════════════════════════════════════════════════════════════
#  Step 2 — Download ISO (with cache)
# ══════════════════════════════════════════════════════════════════════
download_iso() {
    ISO_PATH="${CACHE_DIR}/${OS_FILES[$OS_IDX]}"

    if [[ -f "$ISO_PATH" ]]; then
        ok "Found cached: ${OS_FILES[$OS_IDX]}"
        read -rp "  Use cached ISO? [Y/n]: " yn
        if [[ "$(to_lower "${yn:-y}")" != "n" ]]; then
            return 0
        fi
    fi

    info "Downloading ${OS_FILES[$OS_IDX]} …"
    wget --progress=bar:force:noscroll -O "$ISO_PATH" "${OS_URLS[$OS_IDX]}"
    ok "Download complete"

    # Checksum verification  (macOS uses shasum, not sha256sum)
    info "Verifying SHA-256 checksum …"
    local sha_file="$WORK_DIR/SHA256SUMS"
    if wget -q -O "$sha_file" "${OS_SHA_URLS[$OS_IDX]}" 2>/dev/null; then
        local expect actual
        expect=$(grep "${OS_FILES[$OS_IDX]}" "$sha_file" | awk '{print $1}')
        actual=$(shasum -a 256 "$ISO_PATH" | awk '{print $1}')
        if [[ "$expect" == "$actual" ]]; then
            ok "Checksum OK"
        else
            die "Checksum MISMATCH — download may be corrupt."
        fi
    else
        warn "SHA256SUMS not available — skipping verification"
    fi
}

# ══════════════════════════════════════════════════════════════════════
#  Step 3 — Select USB drive  (macOS: diskutil)
# ══════════════════════════════════════════════════════════════════════
select_usb() {
    echo ""
    printf '%s\n' "${BOLD}Select target USB drive:${NC}"
    echo ""

    local -a devs=() descs=()

    # Parse diskutil list to find external, physical disks
    # diskutil list external → shows only externally-connected disks
    while IFS= read -r line; do
        # Lines that start /dev/disk are disk headers
        if [[ "$line" == /dev/disk* ]]; then
            local disk_id disk_info
            disk_id=$(echo "$line" | awk '{print $1}')

            # Get human-readable info via diskutil info
            local d_size d_name d_removable d_protocol
            d_size=$(diskutil info "$disk_id" 2>/dev/null | grep "Disk Size" \
                     | sed 's/.*: *//' | sed 's/ (.*//')
            d_name=$(diskutil info "$disk_id" 2>/dev/null | grep "Media Name" \
                     | sed 's/.*: *//')
            d_removable=$(diskutil info "$disk_id" 2>/dev/null | grep "Removable Media" \
                          | sed 's/.*: *//')
            d_protocol=$(diskutil info "$disk_id" 2>/dev/null | grep "Protocol" \
                         | sed 's/.*: *//')

            # Only show USB / external disks — skip internal drives
            if [[ "$d_protocol" == *USB* ]] || [[ "$d_removable" == *Yes* ]]; then
                devs+=("$disk_id")
                descs+=("$disk_id  ${d_size:-??}  ${d_name:-Unknown device}")
            fi
        fi
    done < <(diskutil list 2>/dev/null)

    if (( ${#devs[@]} == 0 )); then
        die "No USB drives found. Plug one in and retry."
    fi

    for i in "${!descs[@]}"; do
        printf '  %s\n' "${C}$((i + 1)))${NC} ${descs[$i]}"
    done
    echo ""

    while true; do
        read -rp "  Your choice [1-${#devs[@]}]: " choice
        if [[ "$choice" =~ ^[0-9]+$ ]] && (( choice >= 1 && choice <= ${#devs[@]} )); then
            USB_DEV="${devs[$((choice - 1))]}"
            break
        fi
        warn "Invalid — try again"
    done

    echo ""
    printf '  %s\n' "${R}${BOLD}⚠  ALL DATA ON ${USB_DEV} WILL BE DESTROYED  ⚠${NC}"
    printf '  %s\n' "${descs[$((choice - 1))]}"
    echo ""
    read -rp "  Type YES to confirm: " confirm
    [[ "$confirm" == "YES" ]] || die "Aborted by user."
    ok "Target: $USB_DEV"

    # Derive the raw device path for faster dd writes
    # /dev/disk4 → /dev/rdisk4   (character device, much faster on macOS)
    USB_RAW_DEV="${USB_DEV/disk/rdisk}"
}

# ══════════════════════════════════════════════════════════════════════
#  Step 4 — SSH public key
# ══════════════════════════════════════════════════════════════════════
get_ssh_key() {
    echo ""
    printf '%s\n' "${BOLD}SSH public key:${NC}"
    echo ""

    local default_key=""
    for kf in "$REAL_HOME/.ssh/id_ed25519.pub" \
              "$REAL_HOME/.ssh/id_rsa.pub" \
              "$REAL_HOME/.ssh/id_ecdsa.pub"; do
        if [[ -f "$kf" ]]; then default_key="$kf"; break; fi
    done

    if [[ -n "$default_key" ]]; then
        info "Found: $default_key"
        read -rp "  Use this key? [Y/n]: " yn
        if [[ "$(to_lower "${yn:-y}")" != "n" ]]; then
            SSH_KEY_PATH="$default_key"
        else
            read -rp "  Path to .pub file: " SSH_KEY_PATH
        fi
    else
        read -rp "  Path to .pub file: " SSH_KEY_PATH
    fi

    SSH_KEY_PATH="${SSH_KEY_PATH/#\~/$REAL_HOME}"
    [[ -f "$SSH_KEY_PATH" ]] || die "File not found: $SSH_KEY_PATH"

    SSH_PUB_KEY=$(<"$SSH_KEY_PATH")
    [[ "$SSH_PUB_KEY" == ssh-* || "$SSH_PUB_KEY" == ecdsa-* ]] \
        || die "Does not look like an SSH public key"

    ok "Key loaded  (${SSH_PUB_KEY:0:40}…)"
}

# ══════════════════════════════════════════════════════════════════════
#  Step 5 — Generate cloud-init / autoinstall config
# ══════════════════════════════════════════════════════════════════════
generate_autoinstall() {
    info "Generating autoinstall configuration …"

    # Write the SSH key to a temp file so Python reads it cleanly
    echo -n "$SSH_PUB_KEY" > "$WORK_DIR/.ssh_key"

    # Use Python for everything sensitive: password hash generation
    # (macOS LibreSSL doesn't support openssl passwd -6) and YAML
    # templating (avoids bash $ expansion in hash strings).
    python3 - "$TARGET_HOSTNAME" "$TARGET_USERNAME" "$WORK_DIR" <<'PYEOF'
import sys, os, secrets, subprocess, textwrap

hostname  = sys.argv[1]
username  = sys.argv[2]
work_dir  = sys.argv[3]

# ── Generate SHA-512 password hash ($6$) ─────────────────────────────
# Random password — user will only ever use SSH keys, but Ubuntu
# autoinstall requires a password hash in the identity block.
# We try multiple methods for maximum macOS compatibility.

def generate_sha512_hash(password):
    salt = secrets.token_hex(8)

    # Method 1: Python crypt module (Python < 3.13)
    try:
        import crypt
        result = crypt.crypt(password, f"$6${salt}$")
        if result and result.startswith("$6$"):
            return result
    except (ImportError, Exception):
        pass

    # Method 2: Homebrew openssl (supports passwd -6)
    for ossl in [
        "/opt/homebrew/bin/openssl",
        "/usr/local/bin/openssl",
        "/opt/homebrew/opt/openssl/bin/openssl",
        "/usr/local/opt/openssl/bin/openssl",
    ]:
        if os.path.isfile(ossl):
            try:
                r = subprocess.run(
                    [ossl, "passwd", "-6", "-salt", salt, "-stdin"],
                    input=password, capture_output=True, text=True, timeout=10,
                )
                if r.returncode == 0 and r.stdout.strip().startswith("$6$"):
                    return r.stdout.strip()
            except Exception:
                pass

    # Method 3: system openssl (might work on some setups)
    try:
        r = subprocess.run(
            ["openssl", "passwd", "-6", "-salt", salt, "-stdin"],
            input=password, capture_output=True, text=True, timeout=10,
        )
        if r.returncode == 0 and r.stdout.strip().startswith("$6$"):
            return r.stdout.strip()
    except Exception:
        pass

    # Method 4: perl (usually pre-installed on macOS)
    try:
        # Perl's crypt() uses the system C library which supports $6$
        r = subprocess.run(
            ["perl", "-e",
             f'print crypt("{password}", "\\$6\\${salt}\\$")'],
            capture_output=True, text=True, timeout=10,
        )
        if r.returncode == 0 and r.stdout.strip().startswith("$6$"):
            return r.stdout.strip()
    except Exception:
        pass

    # Method 5: passlib (pip install passlib)
    try:
        from passlib.hash import sha512_crypt
        return sha512_crypt.using(salt=salt, rounds=5000).hash(password)
    except ImportError:
        pass

    print("ERROR: Could not generate SHA-512 password hash.", file=sys.stderr)
    print("Fix: brew install openssl", file=sys.stderr)
    sys.exit(1)

random_pw = secrets.token_urlsafe(32)
pw_hash   = generate_sha512_hash(random_pw)

# ── Read SSH public key ──────────────────────────────────────────────
with open(os.path.join(work_dir, ".ssh_key"), "r") as f:
    ssh_key = f.read().strip()

# ── Build autoinstall YAML ───────────────────────────────────────────
config = textwrap.dedent(f"""\
    #cloud-config
    autoinstall:
      version: 1
      locale: en_US.UTF-8
      keyboard:
        layout: us
      refresh-installer:
        update: false
      network:
        version: 2
        ethernets:
          any-en:
            match:
              name: "en*"
            dhcp4: true
          any-eth:
            match:
              name: "eth*"
            dhcp4: true
      storage:
        layout:
          name: lvm
      identity:
        hostname: {hostname}
        username: {username}
        password: "{pw_hash}"
      ssh:
        install-server: true
        authorized-keys:
          - "{ssh_key}"
        allow-pw: false
      packages:
        - openssh-server
        - avahi-daemon
        - curl
        - wget
        - net-tools
      late-commands:
        - echo 'PasswordAuthentication no' > /target/etc/ssh/sshd_config.d/99-autoinstall.conf
        - echo 'PubkeyAuthentication yes' >> /target/etc/ssh/sshd_config.d/99-autoinstall.conf
        - echo 'PermitRootLogin no' >> /target/etc/ssh/sshd_config.d/99-autoinstall.conf
        - echo 'ChallengeResponseAuthentication no' >> /target/etc/ssh/sshd_config.d/99-autoinstall.conf
        - echo 'KbdInteractiveAuthentication no' >> /target/etc/ssh/sshd_config.d/99-autoinstall.conf
        - echo '{username} ALL=(ALL) NOPASSWD:ALL' > /target/etc/sudoers.d/90-autoinstall
        - chmod 440 /target/etc/sudoers.d/90-autoinstall
        - curtin in-target --target=/target -- systemctl enable ssh
        - curtin in-target --target=/target -- systemctl enable avahi-daemon
      shutdown: poweroff
""")

with open(os.path.join(work_dir, "user-data"), "w") as f:
    f.write(config)

with open(os.path.join(work_dir, "meta-data"), "w") as f:
    f.write("")

print("done")
PYEOF

    ok "Autoinstall config written"
}

# ══════════════════════════════════════════════════════════════════════
#  Step 6 — Repack ISO with autoinstall baked in
# ══════════════════════════════════════════════════════════════════════
repack_iso() {
    info "Building custom ISO (this takes a moment) …"

    local src="$WORK_DIR/iso-src"
    mkdir -p "$src"

    # ── Extract original ISO ──────────────────────────────────────────
    info "  Extracting ISO contents …"
    xorriso -osirrox on -indev "$ISO_PATH" -extract / "$src/" 2>/dev/null
    chmod -R u+w "$src"

    # ── Extract MBR (first 432 bytes) for hybrid BIOS boot ───────────
    dd if="$ISO_PATH" bs=1 count=432 of="$WORK_DIR/mbr.img" 2>/dev/null

    # ── Inject autoinstall data ───────────────────────────────────────
    mkdir -p "$src/nocloud"
    cp "$WORK_DIR/user-data" "$src/nocloud/"
    cp "$WORK_DIR/meta-data" "$src/nocloud/"

    # ── Patch GRUB config ─────────────────────────────────────────────
    #  • Add  autoinstall ds=nocloud\;s=/cdrom/nocloud/  to every
    #    kernel command line (handles vmlinuz and hwe-vmlinuz).
    #  • Set timeout to 3 s so it auto-boots without waiting.
    local patched=0
    while IFS= read -r -d '' grub_cfg; do
        # macOS BSD sed: -i requires a backup suffix ('' = no backup file)
        sed -i '' '/linux.*vmlinuz/s# ---# autoinstall ds=nocloud\\;s=/cdrom/nocloud/ ---#' \
            "$grub_cfg"
        sed -i '' 's/^set timeout=.*/set timeout=3/' "$grub_cfg"
        patched=1
    done < <(find "$src" -name grub.cfg -print0)

    if (( patched )); then
        ok "  GRUB patched (autoinstall + 3 s timeout)"
    else
        warn "  No grub.cfg found — the USB may require manual boot-param editing"
    fi

    # ── Locate boot images ────────────────────────────────────────────
    local efi_img="" bios_img=""
    [[ -f "$src/boot/grub/efi.img"             ]] && efi_img="$src/boot/grub/efi.img"
    [[ -f "$src/boot/grub/i386-pc/eltorito.img" ]] && bios_img="$src/boot/grub/i386-pc/eltorito.img"

    # ── Re-assemble ISO ───────────────────────────────────────────────
    local -a cmd=(
        xorriso -as mkisofs
        -r
        -V "UBUNTU-AUTOINSTALL"
        -o "$WORK_DIR/custom.iso"
        --grub2-mbr "$WORK_DIR/mbr.img"
        -partition_offset 16
        --mbr-force-bootable
    )

    if [[ -n "$efi_img" ]]; then
        cmd+=(
            -append_partition 2 28732ac11ff8d211ba4b00a0c93ec93b "$efi_img"
            -appended_part_as_gpt
            -iso_mbr_part_type a2a0d0ebe5b9334487c068b6b72699c7
        )
    fi

    if [[ -n "$bios_img" ]]; then
        cmd+=(
            -c '/boot.catalog'
            -b '/boot/grub/i386-pc/eltorito.img'
            -no-emul-boot -boot-load-size 4
            -boot-info-table --grub2-boot-info
        )
    fi

    if [[ -n "$efi_img" ]]; then
        cmd+=(
            -eltorito-alt-boot
            -e '--interval:appended_partition_2:::'
            -no-emul-boot
        )
    fi

    cmd+=("$src/")

    info "  Packing ISO …"
    "${cmd[@]}" 2>/dev/null

    CUSTOM_ISO="$WORK_DIR/custom.iso"
    local iso_size
    iso_size=$(du -h "$CUSTOM_ISO" | awk '{print $1}')
    ok "  Custom ISO ready  (${iso_size})"
}

# ══════════════════════════════════════════════════════════════════════
#  Step 7 — Write to USB  (macOS: diskutil + rdisk)
# ══════════════════════════════════════════════════════════════════════
write_usb() {
    info "Writing custom ISO → ${USB_DEV} …"

    # Unmount all volumes on this disk (macOS way)
    diskutil unmountDisk "$USB_DEV" 2>/dev/null || true

    # Use the raw device (/dev/rdiskN) for ~10× faster writes on macOS.
    # macOS dd: bs uses lowercase 'm', no status=progress, no conv=fsync.
    info "  (Using raw device ${USB_RAW_DEV} for speed)"
    info "  This will take a few minutes — no progress bar on macOS dd."
    info "  You can press Ctrl+T to check progress."
    dd if="$CUSTOM_ISO" of="$USB_RAW_DEV" bs=4m
    sync

    # Eject cleanly so macOS doesn't complain
    diskutil eject "$USB_DEV" 2>/dev/null || true

    ok "USB write complete"
}

# ══════════════════════════════════════════════════════════════════════
#  Main
# ══════════════════════════════════════════════════════════════════════
echo ""
printf '%s\n' "${BOLD}${C}┌──────────────────────────────────────────────────┐${NC}"
printf '%s\n' "${BOLD}${C}│  Ubuntu Headless Server — USB Installer Creator  │${NC}"
printf '%s\n' "${BOLD}${C}│  (macOS edition)                                 │${NC}"
printf '%s\n' "${BOLD}${C}└──────────────────────────────────────────────────┘${NC}"

preflight

# 1) Pick OS
select_os

# 2) Download / cache ISO
download_iso

# 3) Pick USB
select_usb

# 4) SSH key
get_ssh_key

# 5) Generate autoinstall YAML
generate_autoinstall

# 6) Repack ISO
repack_iso

# 7) Burn to USB
write_usb

# ── Summary ───────────────────────────────────────────────────────────
hr
echo ""
printf '  %s\n' "${G}${BOLD}USB installer is ready!${NC}"
echo ""
printf '  %s\n' "${BOLD}Next steps:${NC}"
printf '    %s\n' "1.  Plug the USB into your NUC"
printf '    %s\n' "2.  Boot from USB  (set USB first in BIOS boot order)"
printf '    %s\n' "3.  Sit back — installation is fully automatic  (~5–15 min)"
printf '    %s\n' "4.  NUC powers off when finished"
printf '    %s\n' "5.  Remove USB → power on the NUC"
printf '    %s\n' "6.  SSH in:"
echo ""
printf '        %s\n' "${G}ssh ${TARGET_USERNAME}@${TARGET_HOSTNAME}.local${NC}"
printf '        %s\n' "${G}ssh ${TARGET_USERNAME}@<ip-address>${NC}"
echo ""
printf '  %s\n' "${BOLD}Credentials:${NC}"
printf '    %s\n' "User ............. ${C}${TARGET_USERNAME}${NC}"
printf '    %s\n' "Hostname ......... ${C}${TARGET_HOSTNAME}${NC}"
printf '    %s\n' "SSH key .......... ${C}${SSH_KEY_PATH}${NC}"
printf '    %s\n' "Password auth .... ${C}disabled${NC}"
printf '    %s\n' "sudo ............. ${C}passwordless${NC}"
echo ""
printf '  %s\n' "${BOLD}Tip:${NC}  If ${TARGET_HOSTNAME}.local doesn't resolve,"
printf '  %s\n' "check your router's DHCP leases for the NUC's IP."
echo ""
hr
