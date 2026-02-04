# BluSec 2.0 — Proximity-Derived Ephemeral Key Authentication

**BluSec 2.0** is an authentication system for Linux that cryptographically binds password verification to physical Bluetooth proximity. Rather than adding Bluetooth as a simple second factor, BluSec 2.0 derives session-unique ephemeral keys from a BLE challenge-response protocol, ensuring that password verification is only possible when a trusted device is nearby.

> **Status:** Alpha (v0.1.0) — suitable for development and testing.
> **Platform:** Linux (BlueZ) | **Python:** 3.9+
> **Author:** [seloc0des](https://github.com/seloc0des) | [selodev.com](https://selodev.com)

## How It Works

BluSec 2.0 uses two machines: a **gate** (the Linux PC you log into) and a **trusted device** (an ESP32, phone, or second Linux machine with Bluetooth).

1. The gate runs a BLE GATT server and broadcasts a signed challenge (valid for 11-second time windows).
2. The trusted device connects as a GATT client, verifies the challenge signature, and writes back an HMAC response.
3. The gate verifies the response, checks that the device is physically nearby (RSSI), and derives a session-unique ephemeral key.
4. The user enters their password, which is verified against an Argon2id hash stored encrypted on disk.
5. Authentication succeeds only if both the proximity proof and the password are valid.

In day-to-day use, this is transparent: when you run `sudo` (or any PAM-configured service), BluSec 2.0 checks for your trusted device over Bluetooth before prompting for your password. If the device is not nearby, authentication is denied before the password prompt.

## Key Features

- **Cryptographic Challenge-Response** — HMAC-SHA256 prevents MAC spoofing and replay attacks
- **Ephemeral Key Derivation** — Session-unique keys derived via HKDF; 11-second time windows provide replay protection
- **Proximity Verification** — RSSI-based distance checks prevent long-range relay attacks
- **Forward Secrecy** — Compromised session keys cannot reconstruct past or future sessions
- **Multi-Factor** — Combines possession (BLE device), knowledge (password), and proximity (RSSI)
- **PAM Integration** — Plugs into sudo, login, sshd, or any PAM-aware service

## Architecture

```
  Gate (Linux PC)                  Trusted Device (ESP32/Phone)
  ─────────────                    ────────────────────────────
  BLE GATT Server (bless)          BLE GATT Client (bleak)
  │                                │
  │  1. Advertise BluSec2 service  │
  │  2. Generate challenge         │
  │ ◄──────────────────────────────┤  3. Connect & read challenge
  │                                │  4. Verify signature (HMAC)
  │  5. Receive response     ◄─────┤  5. Write response
  │  6. Verify response (HMAC)     │
  │  7. Derive ephemeral key       │
  │  8. Check RSSI proximity       │
  │                                │
  │  9. Decrypt password hash      │
  │     (AES-256-GCM)              │
  │ 10. User enters password       │
  │ 11. Verify (Argon2id)          │
  │ 12. Grant / Deny               │
  └────────────────────────────────┘
```

## Prerequisites

### Gate (Linux PC)

A Linux machine with a Bluetooth 4.0+ (BLE) adapter. Most laptops have one built in; for desktops, a USB BLE dongle works.

```bash
# Install system dependencies
sudo apt-get update
sudo apt-get install -y bluez python3-dev python3-pip libpam0g-dev

# Ensure Bluetooth is unblocked and running
sudo rfkill unblock bluetooth
sudo systemctl enable --now bluetooth

# Verify your adapter is visible
hciconfig
```

You should see an `hci0` entry (or similar) with `UP RUNNING`. If not, check that your Bluetooth adapter is connected and recognized by the kernel.

### Trusted device

You need **one** of the following to act as the trusted device:

| Device | Status | Notes |
|--------|--------|-------|
| Second Linux machine | Ready | Run the Python reference client (`blusec2_trusted_device.py`) — best for testing |
| ESP32 | Reference code | Arduino/ESP-IDF pseudocode included; requires porting to a buildable project |
| Android / iOS | Not yet available | Planned; requires a native BLE app |

## Installation

### For development and testing

```bash
git clone https://github.com/seloc0des/BluSec2.git
cd BluSec2
python3 -m pip install .
```

### For PAM integration (system-wide)

PAM modules run as root. The `blusec2-pam` command must be installed system-wide so that root can find it:

```bash
git clone https://github.com/seloc0des/BluSec2.git
cd BluSec2
sudo python3 -m pip install .
```

Or use the automated installer, which handles both the pip install and PAM config:

```bash
sudo ./pam/install.sh
```

### Installed commands

| Command | Purpose |
|---------|---------|
| `blusec2` | Setup, enrollment, and standalone authentication |
| `blusec2-pam` | PAM exec helper (invoked automatically by pam_exec.so) |

### Verify the cryptographic module

```bash
python3 blusec2_crypto.py
```

This runs a self-test covering ECDH key exchange, challenge-response, ephemeral key derivation, AES-256-GCM encryption, and Argon2id password verification. All tests should end with `All tests completed successfully!`.

## Setup

### Step 1: Pair a trusted device

Pairing performs an ECDH key exchange between the gate and the trusted device. Both sides derive the same master key, which is stored in `/etc/blusec2/`.

```bash
sudo blusec2 --mode setup \
    --device-address AA:BB:CC:DD:EE:FF \
    --device-id MY-DEVICE-001
```

- Replace `AA:BB:CC:DD:EE:FF` with the BLE MAC address of your trusted device.
- Replace `MY-DEVICE-001` with a unique identifier for the device.

The gate displays its ECDH public key (hex). You must transfer this to the trusted device and enter the device's public key when prompted. In production, this exchange would be automated over BLE; in the current alpha, it is manual.

**What gets saved to `/etc/blusec2/`:**

| File | Contents |
|------|----------|
| `master_key.bin` | 32-byte shared master key (read-only by root) |
| `device_id.txt` | Device identifier string |
| `device_address.txt` | BLE MAC address |

### Step 2: Enroll a user

Enrollment hashes the user's password with Argon2id and encrypts the hash with AES-256-GCM using the master key.

```bash
sudo blusec2 --mode enroll --user alice
```

You will be prompted to enter and confirm the password. The encrypted hash is saved to `/etc/blusec2/password_hashes/alice.bin`.

### Step 3: Test authentication

Make sure the trusted device is running and in Bluetooth range, then:

```bash
sudo blusec2 --mode auth --user alice --verbose
```

This starts the BLE GATT server, waits for the trusted device to respond to a challenge, checks RSSI proximity, then prompts for the password. Both factors must succeed.

## Testing with Two Linux Machines

The easiest way to test BluSec 2.0 without an ESP32 is to use two Linux machines (or a Linux machine and a Linux laptop), both with Bluetooth adapters.

### On the gate (Machine A)

1. Install BluSec2 and run pairing as described in [Setup](#setup).
2. Note the master key that was generated. You can find it at `/etc/blusec2/master_key.bin`:
   ```bash
   sudo xxd /etc/blusec2/master_key.bin
   ```
3. Note the gate's BLE MAC address:
   ```bash
   hciconfig hci0 | grep "BD Address"
   ```

### On the trusted device (Machine B)

1. Install BluSec2:
   ```bash
   git clone https://github.com/seloc0des/BluSec2.git
   cd BluSec2
   python3 -m pip install .
   ```

2. Edit `blusec2_trusted_device.py` and update the `main()` function at the bottom of the file:
   - Set `master_key` to the hex value from Machine A's `master_key.bin`
   - Set `device_id` to match the `--device-id` used during pairing (e.g., `b"MY-DEVICE-001"`)
   - Set `gate_address` to Machine A's BLE MAC address
   - Uncomment `asyncio.run(main())` at the bottom of the file

3. Run the trusted device client:
   ```bash
   python3 blusec2_trusted_device.py
   ```
   It will connect to the gate's GATT server and listen for challenges.

### On the gate (Machine A) — authenticate

With Machine B running the trusted device client nearby:

```bash
sudo blusec2 --mode auth --user alice --verbose
```

You should see the challenge-response exchange in the logs on both machines.

## PAM Integration

BluSec2 integrates with any PAM-aware service (sudo, login, sshd, etc.) via `pam_exec.so`.

### Automated install

```bash
sudo ./pam/install.sh
```

This installs the package system-wide, copies the PAM config to `/etc/pam.d/blusec2-auth`, and verifies that `blusec2-pam` is on PATH.

To uninstall:

```bash
sudo ./pam/install.sh --uninstall
```

### Manual PAM configuration

Add one of the following to `/etc/pam.d/sudo` (or `login`, `sshd`, etc.):

**Option A — BluSec2 required (no fallback):**

```
auth  required  pam_exec.so  expose_authtok  /usr/local/bin/blusec2-pam
```

If the trusted device is not nearby or the password is wrong, authentication fails with no fallback.

**Option B — BluSec2 with password fallback (recommended for testing):**

```
auth  [success=1 default=ignore]  pam_exec.so  expose_authtok  /usr/local/bin/blusec2-pam
auth  required                    pam_unix.so  try_first_pass
```

If BluSec2 succeeds (device nearby + correct password), the standard password prompt is skipped. If it fails, you fall back to the normal unix password.

**Option C — MFA (password + proximity):**

```
auth  required  pam_unix.so
auth  required  pam_exec.so  /usr/local/bin/blusec2-pam
```

Standard password must succeed AND the trusted device must be nearby. Note that `expose_authtok` is omitted here because pam_unix already verified the password; BluSec2 runs in proximity-only mode.

### Environment overrides

| Variable | Default | Description |
|----------|---------|-------------|
| `BLUSEC2_CONFIG_DIR` | `/etc/blusec2` | Configuration directory |
| `BLUSEC2_TIMEOUT` | `30` | Authentication timeout in seconds |

### Verify PAM setup

```bash
sudo -k && sudo echo 'BluSec2 works!'
```

`sudo -k` clears cached credentials so the PAM stack runs fresh. If PAM Option B is configured, you can also test the fallback by moving the trusted device out of range.

### PAM audit logging

All authentication attempts are logged to syslog under the `pam_blusec2` identifier:

```bash
journalctl -t pam_blusec2 --no-pager -n 20
```

## Project Structure

| File | Description |
|------|-------------|
| `blusec2_crypto.py` | Cryptographic core: ECDH, HKDF, HMAC-SHA256, AES-256-GCM, Argon2id |
| `blusec2_gate_server.py` | BLE GATT server (gate side) using `bless` |
| `blusec2_trusted_device.py` | BLE GATT client (device side) using `bleak`, with ESP32 reference code |
| `blusec2_auth.py` | Authentication orchestrator, setup manager, and CLI |
| `pam_blusec2.py` | PAM module with syslog audit logging |
| `pam/install.sh` | Automated PAM installer/uninstaller |
| `pam/blusec2-auth` | PAM config example with annotated options |
| `BluSec_2.0_Design_Document.docx` | Full design document with protocol specs and threat model |

## ESP32 Implementation

`blusec2_trusted_device.py` contains ESP32 Arduino/ESP-IDF reference code as inline C pseudocode. The ESP32 acts as a BLE GATT **client** that connects to the gate's GATT server.

> **Note:** The ESP32 code is reference pseudocode for the challenge-response flow. It does not include the ECDH pairing step — it assumes the master key has already been provisioned to NVS flash. A complete ESP32 firmware project (with pairing, OTA updates, and secure boot) is planned for a future release.

**Required components:**

- ESP32 BLE Arduino library (or ESP-IDF BLE stack)
- mbedtls for HMAC-SHA256 and constant-time comparison (`mbedtls_ct_memcmp`)
- NTP time sync (`configTime()`) for matching 11-second timestamp windows
- Encrypted NVS flash for master key storage

**Important:** The `device_id` byte length must match exactly between the ESP32 firmware and the gate-side configuration. The HMAC input is `challenge(32) + device_id(N) + timestamp(8)` — a length mismatch will cause response verification to fail silently.

## Security Considerations

### Threat coverage

| Attack Vector | Defense | Effectiveness |
|---------------|---------|---------------|
| Remote brute force | Requires physical BLE device | Complete |
| MAC spoofing | HMAC challenge-response with shared key | Complete |
| Replay attacks | Timestamp-bound 11-second response windows | Complete |
| Long-range relay | RSSI threshold verification (-70 dBm default) | High |
| Password capture | Password unusable without BLE proximity | High |
| Cryptanalysis | NIST P-256, HKDF-SHA256, AES-256-GCM, Argon2id | High |

### Recommendations

1. Enable PIN/biometric on the trusted Bluetooth device
2. Store the master key in an HSM if available (currently stored as a file with `0600` permissions)
3. Tune the RSSI threshold for your environment (`-70 dBm` is a good starting point)
4. Monitor syslog for `pam_blusec2` audit entries
5. Keep system clocks synchronized (NTP) on both gate and device
6. Maintain a backup authentication method (PAM Option B) in case of device loss

## Troubleshooting

**"Master key not found"**
Run pairing first: `sudo blusec2 --mode setup --device-address ... --device-id ...`

**"Device not in range"**
- Verify the device is powered on and the BLE client is running
- Confirm the BLE MAC address matches: `hciconfig hci0 | grep "BD Address"`
- Check that Bluetooth is up: `sudo systemctl status bluetooth`
- Try moving the device closer (within ~2 meters for the default -70 dBm threshold)

**"Invalid challenge response"**
- Verify the master key is identical on both sides
- Ensure system clocks are NTP-synchronized — a drift beyond one 11-second window will cause failures
- Confirm the `device_id` string is the same length and value on both sides

**"Decryption failed"**
- The authentication window may have expired — re-run the flow
- If this happens consistently, verify the master key file is not corrupted: `wc -c /etc/blusec2/master_key.bin` (should be exactly 32 bytes)

**Bluetooth adapter not detected**
```bash
# Check if the adapter is recognized
lsusb | grep -i bluetooth    # USB adapters
hciconfig -a                  # All HCI devices

# If blocked by rfkill
sudo rfkill list
sudo rfkill unblock bluetooth

# Restart BlueZ
sudo systemctl restart bluetooth
```

## Contributing

Pull requests are welcome. See the [issues page](https://github.com/seloc0des/BluSec2/issues) for open tasks.

Areas of interest:

- Complete ESP32 firmware project (pairing + challenge-response)
- Android and iOS BLE client apps
- HSM integration for master key storage
- Rate limiting and account lockout
- Formal test suite (pytest + pytest-asyncio)

## License

**Free for personal use.** Commercial use requires a separate license.

See [LICENSE](LICENSE) for full terms. For commercial licensing, contact selodev3d@gmail.com.

## Security Disclosure

Found a security vulnerability? Email selodev3d@gmail.com.
Do not open public issues for security reports.

## Citation

```bibtex
@software{blusec2_2025,
  title  = {BluSec 2.0: Proximity-Derived Ephemeral Key Authentication},
  author = {seloc0des},
  year   = {2025},
  url    = {https://github.com/seloc0des/BluSec2}
}
```
