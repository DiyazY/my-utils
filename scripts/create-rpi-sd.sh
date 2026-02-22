#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════
#  Raspberry Pi Headless Server — Automated SD Card Creator
#  (macOS edition)
# ══════════════════════════════════════════════════════════════════════
#  Creates a ready-to-boot SD card for Raspberry Pi headless servers.
#  Insert the SD card, power on, wait ~2 min for cloud-init, SSH in.
#
#  Supported boards:
#    • Pi 3 / 3B+          (Ubuntu Server arm64)
#    • Pi 4 / 4 Model B    (Ubuntu Server arm64)
#    • Pi 5                 (Ubuntu Server arm64)
#    • Pi Zero (original)   (Raspberry Pi OS Lite armhf — see note)
#
#  NOTE: Original Pi Zero is ARMv6 — Ubuntu does not support it.
#        The script uses Raspberry Pi OS Lite 32-bit for Pi Zero,
#        with the same SSH-key-only, no-password hardening.
#
#  Usage:  sudo ./create-rpi-sd.sh
#
#  Customize via environment variables (optional):
#    TARGET_HOSTNAME=mypi  TARGET_USERNAME=pi  sudo ./create-rpi-sd.sh
#
#  Requirements (install via Homebrew):
#    brew install xz wget python3
# ══════════════════════════════════════════════════════════════════════
set -Eeuo pipefail

# ─── Defaults ─────────────────────────────────────────────────────────
TARGET_HOSTNAME="${TARGET_HOSTNAME:-rpi}"
TARGET_USERNAME="${TARGET_USERNAME:-pi}"

# Resolve real user's home even under sudo
if [[ -n "${SUDO_USER:-}" ]]; then
    REAL_HOME=$(dscl . -read "/Users/$SUDO_USER" NFSHomeDirectory 2>/dev/null \
                | awk '{print $2}')
    [[ -z "$REAL_HOME" ]] && REAL_HOME="/Users/$SUDO_USER"
else
    REAL_HOME="$HOME"
fi
CACHE_DIR="${CACHE_DIR:-${REAL_HOME}/.cache/rpi-sd-creator}"
WORK_DIR=""

# ─── Pi Models ────────────────────────────────────────────────────────
PI_MODELS=(
    "Raspberry Pi 3 / 3B+"
    "Raspberry Pi 4 / 4 Model B"
    "Raspberry Pi 5"
    "Raspberry Pi Zero (original — ARMv6)"
)
# arch: arm64 for all except Pi Zero
PI_ARCH=("arm64" "arm64" "arm64" "armhf")
# has_wifi: all modern Pis have wifi; Zero original does NOT (Zero W does)
PI_WIFI=(1 1 1 0)
# needs_gadget: Pi Zero can use USB OTG ethernet
PI_GADGET=(0 0 0 1)

# ─── OS images ────────────────────────────────────────────────────────
# Ubuntu Server arm64 for Pi 3/4/5
UBUNTU_URL="https://cdimage.ubuntu.com/releases/noble/release/ubuntu-24.04.4-preinstalled-server-arm64+raspi.img.xz"
UBUNTU_FILE="ubuntu-24.04.4-preinstalled-server-arm64+raspi.img.xz"
UBUNTU_SHA_URL="https://cdimage.ubuntu.com/releases/noble/release/SHA256SUMS"
UBUNTU_LABEL="Ubuntu 24.04.4 LTS (Noble Numbat) arm64"

# Raspberry Pi OS Lite 32-bit for Pi Zero
PIOS_URL="https://downloads.raspberrypi.com/raspios_lite_armhf_latest"
PIOS_FILE="raspios-lite-armhf-latest.img.xz"
PIOS_LABEL="Raspberry Pi OS Lite (Bookworm) armhf"

# ─── Colours ──────────────────────────────────────────────────────────
R=$'\033[0;31m'  G=$'\033[0;32m'  Y=$'\033[1;33m'
B=$'\033[0;34m'  C=$'\033[0;36m'  BOLD=$'\033[1m'  NC=$'\033[0m'

info() { printf '%s\n' "${B}▸${NC} $*"; }
ok()   { printf '%s\n' "${G}✓${NC} $*"; }
warn() { printf '%s\n' "${Y}⚠${NC} $*"; }
err()  { printf '%s\n' "${R}✗${NC} $*" >&2; }
die()  { err "$@"; exit 1; }
hr()   { printf '%s\n' "${C}────────────────────────────────────────────────${NC}"; }

to_lower() { printf '%s' "$1" | tr '[:upper:]' '[:lower:]'; }

# ─── Cleanup ──────────────────────────────────────────────────────────
cleanup() {
    if [[ -n "${WORK_DIR:-}" && -d "${WORK_DIR:-}" ]]; then
        rm -rf "$WORK_DIR"
    fi
}
trap cleanup EXIT
trap 'echo ""; die "Interrupted."' INT TERM

# ─── Pre-flight ───────────────────────────────────────────────────────
preflight() {
    if [[ "$(uname)" != "Darwin" ]]; then
        die "This script is designed for macOS.  Detected: $(uname)"
    fi
    if (( EUID != 0 )); then
        die "Root required.  Run:  sudo $0"
    fi

    local missing=()
    for cmd in wget xz python3; do
        command -v "$cmd" &>/dev/null || missing+=("$cmd")
    done
    command -v diskutil &>/dev/null || missing+=("diskutil")

    if (( ${#missing[@]} )); then
        err "Missing tools: ${missing[*]}"
        echo ""
        echo "  Install via Homebrew:"
        echo "    brew install xz wget python3"
        echo ""
        exit 1
    fi

    WORK_DIR=$(mktemp -d)
    mkdir -p "$CACHE_DIR"
}

# ══════════════════════════════════════════════════════════════════════
#  Step 1 — Select Pi model
# ══════════════════════════════════════════════════════════════════════
select_model() {
    echo ""
    printf '%s\n' "${BOLD}Select your Raspberry Pi model:${NC}"
    echo ""
    for i in "${!PI_MODELS[@]}"; do
        local note=""
        if [[ "${PI_ARCH[$i]}" == "armhf" ]]; then
            note="  ${Y}← Raspberry Pi OS (Ubuntu not supported)${NC}"
        fi
        printf '  %s%s\n' "${C}$((i + 1)))${NC} ${PI_MODELS[$i]}" "$note"
    done
    echo ""

    while true; do
        read -rp "  Your choice [1-${#PI_MODELS[@]}]: " choice
        if [[ "$choice" =~ ^[0-9]+$ ]] && (( choice >= 1 && choice <= ${#PI_MODELS[@]} )); then
            MODEL_IDX=$((choice - 1))
            break
        fi
        warn "Invalid — try again"
    done

    ARCH="${PI_ARCH[$MODEL_IDX]}"
    HAS_WIFI="${PI_WIFI[$MODEL_IDX]}"
    NEEDS_GADGET="${PI_GADGET[$MODEL_IDX]}"

    if [[ "$ARCH" == "armhf" ]]; then
        OS_TYPE="pios"
        IMG_URL="$PIOS_URL"
        IMG_FILE="$PIOS_FILE"
        IMG_LABEL="$PIOS_LABEL"
        ok "Selected: ${PI_MODELS[$MODEL_IDX]}  →  ${PIOS_LABEL}"
        warn "Pi Zero original cannot run Ubuntu (ARMv6)."
        warn "Using Raspberry Pi OS Lite with identical SSH-key-only hardening."
    else
        OS_TYPE="ubuntu"
        IMG_URL="$UBUNTU_URL"
        IMG_FILE="$UBUNTU_FILE"
        IMG_LABEL="$UBUNTU_LABEL"
        ok "Selected: ${PI_MODELS[$MODEL_IDX]}  →  ${UBUNTU_LABEL}"
    fi
}

# ══════════════════════════════════════════════════════════════════════
#  Step 2 — Download image (with cache)
# ══════════════════════════════════════════════════════════════════════
download_image() {
    IMG_PATH="${CACHE_DIR}/${IMG_FILE}"

    if [[ -f "$IMG_PATH" ]]; then
        ok "Found cached: ${IMG_FILE}"
        read -rp "  Use cached image? [Y/n]: " yn
        if [[ "$(to_lower "${yn:-y}")" != "n" ]]; then
            return 0
        fi
    fi

    info "Downloading ${IMG_LABEL} …"
    wget --progress=bar:force:noscroll -O "$IMG_PATH" "$IMG_URL"
    ok "Download complete"

    # Checksum (Ubuntu only — Pi OS redirect URL doesn't have easy SHA)
    if [[ "$OS_TYPE" == "ubuntu" ]]; then
        info "Verifying SHA-256 checksum …"
        local sha_file="$WORK_DIR/SHA256SUMS"
        if wget -q -O "$sha_file" "$UBUNTU_SHA_URL" 2>/dev/null; then
            local expect actual base_file
            base_file=$(basename "$IMG_FILE")
            expect=$(grep "$base_file" "$sha_file" | awk '{print $1}')
            actual=$(shasum -a 256 "$IMG_PATH" | awk '{print $1}')
            if [[ -n "$expect" && "$expect" == "$actual" ]]; then
                ok "Checksum OK"
            elif [[ -z "$expect" ]]; then
                warn "File not found in SHA256SUMS — skipping verification"
            else
                die "Checksum MISMATCH — download may be corrupt."
            fi
        else
            warn "SHA256SUMS not available — skipping verification"
        fi
    fi
}

# ══════════════════════════════════════════════════════════════════════
#  Step 3 — Select SD card (macOS: diskutil)
# ══════════════════════════════════════════════════════════════════════
select_sd() {
    echo ""
    printf '%s\n' "${BOLD}Select target SD card:${NC}"
    echo ""

    local -a devs=() descs=()

    while IFS= read -r line; do
        if [[ "$line" == /dev/disk* ]]; then
            local disk_id
            disk_id=$(echo "$line" | awk '{print $1}')

            local d_size d_name d_removable d_protocol
            d_size=$(diskutil info "$disk_id" 2>/dev/null | grep "Disk Size" \
                     | sed 's/.*: *//' | sed 's/ (.*//')
            d_name=$(diskutil info "$disk_id" 2>/dev/null | grep "Media Name" \
                     | sed 's/.*: *//')
            d_removable=$(diskutil info "$disk_id" 2>/dev/null | grep "Removable Media" \
                          | sed 's/.*: *//')
            d_protocol=$(diskutil info "$disk_id" 2>/dev/null | grep "Protocol" \
                         | sed 's/.*: *//')

            if [[ "$d_protocol" == *USB* ]] || [[ "$d_removable" == *Yes* ]]; then
                devs+=("$disk_id")
                descs+=("$disk_id  ${d_size:-??}  ${d_name:-Unknown device}")
            fi
        fi
    done < <(diskutil list 2>/dev/null)

    if (( ${#devs[@]} == 0 )); then
        die "No SD cards / USB drives found. Insert one and retry."
    fi

    for i in "${!descs[@]}"; do
        printf '  %s\n' "${C}$((i + 1)))${NC} ${descs[$i]}"
    done
    echo ""

    while true; do
        read -rp "  Your choice [1-${#devs[@]}]: " choice
        if [[ "$choice" =~ ^[0-9]+$ ]] && (( choice >= 1 && choice <= ${#devs[@]} )); then
            SD_DEV="${devs[$((choice - 1))]}"
            break
        fi
        warn "Invalid — try again"
    done

    echo ""
    printf '  %s\n' "${R}${BOLD}⚠  ALL DATA ON ${SD_DEV} WILL BE DESTROYED  ⚠${NC}"
    printf '  %s\n' "${descs[$((choice - 1))]}"
    echo ""
    read -rp "  Type YES to confirm: " confirm
    [[ "$confirm" == "YES" ]] || die "Aborted by user."
    ok "Target: $SD_DEV"

    SD_RAW_DEV="${SD_DEV/disk/rdisk}"
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
#  Step 5 — WiFi (optional)
# ══════════════════════════════════════════════════════════════════════
get_wifi() {
    WIFI_SSID=""
    WIFI_PASS=""
    WIFI_COUNTRY=""

    if (( HAS_WIFI )); then
        echo ""
        printf '%s\n' "${BOLD}WiFi configuration (optional):${NC}"
        info "Skip if connecting via Ethernet."
        echo ""
        read -rp "  WiFi SSID (blank to skip): " WIFI_SSID

        if [[ -n "$WIFI_SSID" ]]; then
            read -rsp "  WiFi password: " WIFI_PASS
            echo ""
            read -rp "  Country code [US]: " WIFI_COUNTRY
            WIFI_COUNTRY="${WIFI_COUNTRY:-US}"
            ok "WiFi: ${WIFI_SSID}  (${WIFI_COUNTRY})"
        else
            info "Skipping WiFi — will use Ethernet"
        fi
    else
        echo ""
        warn "Pi Zero (original) has no built-in WiFi or Ethernet."
        info "USB gadget ethernet (OTG) will be configured automatically."
        info "Connect the Pi Zero to your Mac via its data USB port."
    fi
}

# ══════════════════════════════════════════════════════════════════════
#  Step 6 — Flash image to SD card
# ══════════════════════════════════════════════════════════════════════
flash_image() {
    info "Flashing ${IMG_LABEL} → ${SD_DEV} …"

    diskutil unmountDisk "$SD_DEV" 2>/dev/null || true

    info "  (Using raw device ${SD_RAW_DEV} for speed)"
    info "  Decompressing and writing — this takes a few minutes."
    info "  Press Ctrl+T to check progress."

    xzcat "$IMG_PATH" | dd of="$SD_RAW_DEV" bs=4m
    sync

    ok "Flash complete"

    # Give macOS time to detect the new partition table
    sleep 3
    diskutil mountDisk "$SD_DEV" 2>/dev/null || true
    sleep 2
}

# ══════════════════════════════════════════════════════════════════════
#  Step 7a — Configure Ubuntu (cloud-init)
# ══════════════════════════════════════════════════════════════════════
configure_ubuntu() {
    info "Configuring Ubuntu via cloud-init …"

    # Find the boot partition (Ubuntu labels it "system-boot")
    local boot_mnt=""
    for label in system-boot bootfs boot; do
        if [[ -d "/Volumes/$label" ]]; then
            boot_mnt="/Volumes/$label"
            break
        fi
    done
    [[ -n "$boot_mnt" ]] || die "Could not find boot partition. Try re-inserting the SD card."

    ok "  Boot partition: $boot_mnt"

    # ── Write user-data (cloud-init) ──────────────────────────────────
    echo -n "$SSH_PUB_KEY" > "$WORK_DIR/.ssh_key"

    python3 - "$TARGET_HOSTNAME" "$TARGET_USERNAME" "$WORK_DIR" "$WIFI_SSID" "$WIFI_PASS" "$WIFI_COUNTRY" <<'PYEOF'
import sys, os, secrets, subprocess, textwrap

hostname     = sys.argv[1]
username     = sys.argv[2]
work_dir     = sys.argv[3]
wifi_ssid    = sys.argv[4]
wifi_pass    = sys.argv[5]
wifi_country = sys.argv[6]

# ── Generate SHA-512 password hash ───────────────────────────────────
def generate_sha512_hash(password):
    salt = secrets.token_hex(8)
    for method_name, method_fn in [
        ("crypt", lambda: __import__("crypt").crypt(password, f"$6${salt}$")),
    ]:
        try:
            result = method_fn()
            if result and result.startswith("$6$"):
                return result
        except Exception:
            pass
    for ossl in [
        "/opt/homebrew/bin/openssl", "/usr/local/bin/openssl",
        "/opt/homebrew/opt/openssl/bin/openssl", "/usr/local/opt/openssl/bin/openssl",
    ]:
        if os.path.isfile(ossl):
            try:
                r = subprocess.run([ossl, "passwd", "-6", "-salt", salt, "-stdin"],
                                   input=password, capture_output=True, text=True, timeout=10)
                if r.returncode == 0 and r.stdout.strip().startswith("$6$"):
                    return r.stdout.strip()
            except Exception:
                pass
    try:
        r = subprocess.run(["openssl", "passwd", "-6", "-salt", salt, "-stdin"],
                           input=password, capture_output=True, text=True, timeout=10)
        if r.returncode == 0 and r.stdout.strip().startswith("$6$"):
            return r.stdout.strip()
    except Exception:
        pass
    try:
        r = subprocess.run(["perl", "-e", f'print crypt("{password}", "\\$6\\${salt}\\$")'],
                           capture_output=True, text=True, timeout=10)
        if r.returncode == 0 and r.stdout.strip().startswith("$6$"):
            return r.stdout.strip()
    except Exception:
        pass
    try:
        from passlib.hash import sha512_crypt
        return sha512_crypt.using(salt=salt, rounds=5000).hash(password)
    except ImportError:
        pass
    print("ERROR: Could not generate SHA-512 hash. brew install openssl", file=sys.stderr)
    sys.exit(1)

random_pw = secrets.token_urlsafe(32)
pw_hash   = generate_sha512_hash(random_pw)

with open(os.path.join(work_dir, ".ssh_key"), "r") as f:
    ssh_key = f.read().strip()

# ── Build cloud-init user-data ───────────────────────────────────────
config = textwrap.dedent(f"""\
    #cloud-config
    hostname: {hostname}
    manage_etc_hosts: true

    users:
      - name: {username}
        groups: sudo, adm, dialout, cdrom, audio, video, plugdev, games, users, input, render, netdev
        shell: /bin/bash
        sudo: ALL=(ALL) NOPASSWD:ALL
        lock_passwd: true
        passwd: "{pw_hash}"
        ssh_authorized_keys:
          - "{ssh_key}"

    ssh_pwauth: false

    packages:
      - openssh-server
      - avahi-daemon
      - curl
      - wget
      - net-tools
      - htop

    write_files:
      - path: /etc/ssh/sshd_config.d/99-headless.conf
        content: |
          PasswordAuthentication no
          PubkeyAuthentication yes
          PermitRootLogin no
          ChallengeResponseAuthentication no
          KbdInteractiveAuthentication no

    runcmd:
      - systemctl enable ssh
      - systemctl restart ssh
      - systemctl enable avahi-daemon
""")

# ── WiFi via netplan (if configured) ─────────────────────────────────
wifi_netplan = ""
if wifi_ssid:
    wifi_netplan = textwrap.dedent(f"""\
        network:
          version: 2
          wifis:
            wlan0:
              dhcp4: true
              optional: true
              access-points:
                "{wifi_ssid}":
                  password: "{wifi_pass}"
              regulatory-domain: {wifi_country}
    """)

# ── Write files ──────────────────────────────────────────────────────
with open(os.path.join(work_dir, "user-data"), "w") as f:
    f.write(config)

with open(os.path.join(work_dir, "network-config"), "w") as f:
    if wifi_netplan:
        f.write(wifi_netplan)
    else:
        # Default: DHCP on ethernet
        f.write(textwrap.dedent("""\
            network:
              version: 2
              ethernets:
                eth0:
                  dhcp4: true
                  optional: true
        """))

print("done")
PYEOF

    cp "$WORK_DIR/user-data" "$boot_mnt/user-data"
    cp "$WORK_DIR/network-config" "$boot_mnt/network-config"

    # Empty meta-data (required by cloud-init)
    touch "$boot_mnt/meta-data" 2>/dev/null || true

    ok "  cloud-init user-data written"
    ok "  network-config written"

    BOOT_MNT="$boot_mnt"
}

# ══════════════════════════════════════════════════════════════════════
#  Step 7b — Configure Raspberry Pi OS (firstrun.sh)
# ══════════════════════════════════════════════════════════════════════
configure_pios() {
    info "Configuring Raspberry Pi OS …"

    # Find boot partition (Pi OS Bookworm labels it "bootfs")
    local boot_mnt=""
    for label in bootfs boot system-boot; do
        if [[ -d "/Volumes/$label" ]]; then
            boot_mnt="/Volumes/$label"
            break
        fi
    done
    [[ -n "$boot_mnt" ]] || die "Could not find boot partition. Try re-inserting the SD card."

    ok "  Boot partition: $boot_mnt"

    # ── Enable SSH ────────────────────────────────────────────────────
    touch "$boot_mnt/ssh"
    ok "  SSH enabled"

    # ── Create userconf.txt ───────────────────────────────────────────
    echo -n "$SSH_PUB_KEY" > "$WORK_DIR/.ssh_key"

    local pw_hash
    pw_hash=$(python3 - <<'PYEOF'
import secrets, subprocess, os, sys
password = secrets.token_urlsafe(32)
salt = secrets.token_hex(8)
try:
    import crypt
    r = crypt.crypt(password, f"$6${salt}$")
    if r and r.startswith("$6$"):
        print(r, end="")
        sys.exit(0)
except Exception:
    pass
for ossl in ["/opt/homebrew/bin/openssl", "/usr/local/bin/openssl",
             "/opt/homebrew/opt/openssl/bin/openssl", "/usr/local/opt/openssl/bin/openssl"]:
    if os.path.isfile(ossl):
        try:
            r = subprocess.run([ossl, "passwd", "-6", "-salt", salt, "-stdin"],
                               input=password, capture_output=True, text=True, timeout=10)
            if r.returncode == 0 and r.stdout.strip().startswith("$6$"):
                print(r.stdout.strip(), end="")
                sys.exit(0)
        except Exception:
            pass
try:
    r = subprocess.run(["perl", "-e", f'print crypt("{password}", "\\$6\\${salt}\\$")'],
                       capture_output=True, text=True, timeout=10)
    if r.returncode == 0 and r.stdout.strip().startswith("$6$"):
        print(r.stdout.strip(), end="")
        sys.exit(0)
except Exception:
    pass
print("ERROR", file=sys.stderr)
sys.exit(1)
PYEOF
    )

    echo "${TARGET_USERNAME}:${pw_hash}" > "$boot_mnt/userconf.txt"
    ok "  User '${TARGET_USERNAME}' configured"

    # ── USB gadget ethernet for Pi Zero ───────────────────────────────
    if (( NEEDS_GADGET )); then
        # Add dwc2 overlay to config.txt
        if ! grep -q 'dtoverlay=dwc2' "$boot_mnt/config.txt" 2>/dev/null; then
            echo "" >> "$boot_mnt/config.txt"
            echo "# USB OTG Ethernet gadget for Pi Zero" >> "$boot_mnt/config.txt"
            echo "dtoverlay=dwc2" >> "$boot_mnt/config.txt"
        fi

        # Add modules-load to cmdline.txt (must be on the same line)
        if [[ -f "$boot_mnt/cmdline.txt" ]]; then
            # Insert modules-load right after rootwait
            sed -i '' 's/rootwait/rootwait modules-load=dwc2,g_ether/' "$boot_mnt/cmdline.txt"
        fi
        ok "  USB gadget ethernet (dwc2 + g_ether) enabled"
    fi

    # ── Create firstrun.sh for SSH key hardening ──────────────────────
    # Determine boot path inside the running Pi
    # Bookworm: /boot/firmware/   Bullseye: /boot/
    local pi_boot_path="/boot/firmware"

    cat > "$boot_mnt/firstrun.sh" << FIRSTRUNEOF
#!/bin/bash
set -e

HOSTNAME_VAL="${TARGET_HOSTNAME}"
USERNAME_VAL="${TARGET_USERNAME}"
SSH_KEY='${SSH_PUB_KEY}'

# ── Set hostname ──────────────────────────────────────────────────
raspi-config nonint do_hostname "\$HOSTNAME_VAL" 2>/dev/null || {
    echo "\$HOSTNAME_VAL" > /etc/hostname
    sed -i "s/127.0.1.1.*/127.0.1.1\t\$HOSTNAME_VAL/" /etc/hosts
}

# ── SSH key setup ─────────────────────────────────────────────────
install -d -m 700 -o "\$USERNAME_VAL" -g "\$USERNAME_VAL" "/home/\${USERNAME_VAL}/.ssh"
echo "\$SSH_KEY" > "/home/\${USERNAME_VAL}/.ssh/authorized_keys"
chmod 600 "/home/\${USERNAME_VAL}/.ssh/authorized_keys"
chown "\${USERNAME_VAL}:\${USERNAME_VAL}" "/home/\${USERNAME_VAL}/.ssh/authorized_keys"

# ── Passwordless sudo ─────────────────────────────────────────────
echo "\${USERNAME_VAL} ALL=(ALL) NOPASSWD:ALL" > "/etc/sudoers.d/010_\${USERNAME_VAL}-nopasswd"
chmod 440 "/etc/sudoers.d/010_\${USERNAME_VAL}-nopasswd"

# ── Harden SSH (key-only, no password) ────────────────────────────
mkdir -p /etc/ssh/sshd_config.d
cat > /etc/ssh/sshd_config.d/99-headless.conf <<'SSHCFG'
PasswordAuthentication no
PubkeyAuthentication yes
PermitRootLogin no
ChallengeResponseAuthentication no
KbdInteractiveAuthentication no
SSHCFG
systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || true

# ── Install avahi for .local mDNS ─────────────────────────────────
apt-get update -qq
apt-get install -y -qq avahi-daemon > /dev/null 2>&1
systemctl enable avahi-daemon
systemctl start avahi-daemon

# ── WiFi (if configured) ─────────────────────────────────────────
FIRSTRUNEOF

    # Inject WiFi setup if SSID was provided
    if [[ -n "$WIFI_SSID" ]]; then
        cat >> "$boot_mnt/firstrun.sh" << WIFIEOF
nmcli dev wifi connect '${WIFI_SSID}' password '${WIFI_PASS}' 2>/dev/null || {
    # Fallback: create wpa_supplicant config for older Pi OS
    cat > /etc/wpa_supplicant/wpa_supplicant.conf <<'WPAEOF'
ctrl_interface=DIR=/var/run/wpa_supplicant GROUP=netdev
update_config=1
country=${WIFI_COUNTRY}

network={
    ssid="${WIFI_SSID}"
    psk="${WIFI_PASS}"
    key_mgmt=WPA-PSK
}
WPAEOF
    rfkill unblock wifi 2>/dev/null || true
    wpa_cli -i wlan0 reconfigure 2>/dev/null || true
}
WIFIEOF
    fi

    # Cleanup section of firstrun.sh
    cat >> "$boot_mnt/firstrun.sh" << CLEANUPEOF

# ── Cleanup ───────────────────────────────────────────────────────
# Determine boot firmware path
if [ -d "${pi_boot_path}" ]; then
    BOOT="${pi_boot_path}"
else
    BOOT="/boot"
fi
sed -i 's| systemd.run=[^ ]*||g' "\$BOOT/cmdline.txt"
sed -i 's| systemd.run_success_action=[^ ]*||g' "\$BOOT/cmdline.txt"
sed -i 's| systemd.unit=[^ ]*||g' "\$BOOT/cmdline.txt"
rm -f "\$BOOT/firstrun.sh"

exit 0
CLEANUPEOF

    chmod +x "$boot_mnt/firstrun.sh"
    ok "  firstrun.sh written"

    # ── Patch cmdline.txt to run firstrun.sh on boot ──────────────────
    if [[ -f "$boot_mnt/cmdline.txt" ]]; then
        local cmdline
        cmdline=$(<"$boot_mnt/cmdline.txt")
        # Remove any trailing newline, append systemd.run
        cmdline=$(echo "$cmdline" | tr -d '\n')
        cmdline="$cmdline systemd.run=${pi_boot_path}/firstrun.sh systemd.run_success_action=reboot systemd.unit=kernel-command-line.target"
        echo "$cmdline" > "$boot_mnt/cmdline.txt"
        ok "  cmdline.txt patched for firstrun"
    else
        warn "  cmdline.txt not found — firstrun.sh may not execute automatically"
    fi

    BOOT_MNT="$boot_mnt"
}

# ══════════════════════════════════════════════════════════════════════
#  Step 8 — Unmount & eject
# ══════════════════════════════════════════════════════════════════════
finalize() {
    info "Unmounting and ejecting …"
    sync
    diskutil unmountDisk "$SD_DEV" 2>/dev/null || true
    diskutil eject "$SD_DEV" 2>/dev/null || true
    ok "SD card ejected — safe to remove"
}

# ══════════════════════════════════════════════════════════════════════
#  Main
# ══════════════════════════════════════════════════════════════════════
echo ""
printf '%s\n' "${BOLD}${C}┌──────────────────────────────────────────────────┐${NC}"
printf '%s\n' "${BOLD}${C}│  Raspberry Pi Headless — SD Card Creator         │${NC}"
printf '%s\n' "${BOLD}${C}│  (macOS edition)                                 │${NC}"
printf '%s\n' "${BOLD}${C}└──────────────────────────────────────────────────┘${NC}"

preflight

# 1) Pi model → determines OS, arch, features
select_model

# 2) Download / cache image
download_image

# 3) Select SD card
select_sd

# 4) SSH key
get_ssh_key

# 5) WiFi (or USB gadget for Pi Zero)
get_wifi

# 6) Flash image
flash_image

# 7) Configure for headless SSH
if [[ "$OS_TYPE" == "ubuntu" ]]; then
    configure_ubuntu
else
    configure_pios
fi

# 8) Eject
finalize

# ── Summary ───────────────────────────────────────────────────────────
hr
echo ""
printf '  %s\n' "${G}${BOLD}SD card is ready!${NC}"
echo ""
printf '  %s\n' "${BOLD}Next steps:${NC}"
printf '    %s\n' "1.  Insert the SD card into your ${PI_MODELS[$MODEL_IDX]}"

if (( NEEDS_GADGET )); then
    printf '    %s\n' "2.  Connect Pi Zero to your Mac via the ${BOLD}data${NC} USB port (not PWR)"
    printf '    %s\n' "3.  Wait ~2 minutes for first-boot setup"
    printf '    %s\n' "4.  SSH in:"
else
    printf '    %s\n' "2.  Connect Ethernet (or WiFi will connect if configured)"
    printf '    %s\n' "3.  Power on and wait ~2 minutes for first-boot setup"
    printf '    %s\n' "4.  SSH in:"
fi

echo ""
printf '        %s\n' "${G}ssh ${TARGET_USERNAME}@${TARGET_HOSTNAME}.local${NC}"
printf '        %s\n' "${G}ssh ${TARGET_USERNAME}@<ip-address>${NC}"
echo ""
printf '  %s\n' "${BOLD}Credentials:${NC}"
printf '    %s\n' "OS ............... ${C}${IMG_LABEL}${NC}"
printf '    %s\n' "User ............. ${C}${TARGET_USERNAME}${NC}"
printf '    %s\n' "Hostname ......... ${C}${TARGET_HOSTNAME}${NC}"
printf '    %s\n' "SSH key .......... ${C}${SSH_KEY_PATH}${NC}"
printf '    %s\n' "Password auth .... ${C}disabled${NC}"
printf '    %s\n' "sudo ............. ${C}passwordless${NC}"
if [[ -n "$WIFI_SSID" ]]; then
    printf '    %s\n' "WiFi ............. ${C}${WIFI_SSID}${NC}"
fi
if (( NEEDS_GADGET )); then
    printf '    %s\n' "USB Ethernet ..... ${C}enabled (dwc2 + g_ether)${NC}"
fi
echo ""
printf '  %s\n' "${BOLD}Tip:${NC}  If ${TARGET_HOSTNAME}.local doesn't resolve,"
printf '  %s\n' "check your router's DHCP leases for the Pi's IP."
if (( NEEDS_GADGET )); then
    echo ""
    printf '  %s\n' "${BOLD}Pi Zero USB note:${NC}  The Pi will appear as a USB"
    printf '  %s\n' "Ethernet adapter. On macOS, check System Settings → Network"
    printf '  %s\n' "for an RNDIS/Ethernet Gadget device."
fi
echo ""
hr