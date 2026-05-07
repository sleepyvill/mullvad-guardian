functions made by me, has been an old project rotting in my drive so i decided to improve it.
claude made the web ui version and refined the ui in the gui version + cleaned up the messy code that i made.

# 🛡️ Mullvad Guardian

**Automated device monitoring and removal for Mullvad VPN accounts**

Mullvad Guardian monitors your Mullvad account for unauthorized devices and automatically removes them. It features a beautiful glassmorphic GUI, real-time ping monitoring, persistent VPN connection, and Discord notifications.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.10+-blue.svg)
![Platform](https://img.shields.io/badge/platform-linux%20%7C%20windows%20%7C%20macos-lightgrey.svg)

---

## ✨ Features

### 🔒 Security
- **Automatic device monitoring** — Scans your Mullvad account every 3 seconds
- **Instant removal** — Unauthorized devices are removed immediately
- **Whitelist protection** — Protect specific devices by name
- **Auto-detection** — Automatically protects your current device
- **Discord notifications** — Get notified when devices are removed

### 🌐 VPN Management
- **Persistent connection** — Automatically reconnects if disconnected
- **Auto-login** — Handles device removal and re-registration
- **Kill switch support** — Blocks internet when VPN is disconnected
- **Ad blocking** — Built-in DNS-based ad blocking
- **Protocol selection** — WireGuard or OpenVPN

### 📊 Server Selection
- **Real-time ping monitoring** — Updates every 3 seconds
- **Auto-connect to fastest** — Connects to server with lowest ping
- **Expandable server list** — View all servers per country
- **Search functionality** — Quickly find countries

### 🎨 Interface
- **Web UI** — Modern dark mode interface accessible from any browser
- **Responsive design** — Works on desktop, tablet, and mobile
- **Real-time updates** — Status refreshes every 3 seconds
- **PyQt6 GUI** — Optional desktop application with glassmorphic design
- **CLI mode** — Headless operation for servers

---

## 📸 Screenshots

### GUI Mode
Beautiful glassmorphic interface with real-time monitoring:
- Dashboard with account overview and statistics
- VPN connection page with server selection and live ping
- Device management with expandable server lists
- Whitelist management with auto-protection
- Settings configuration

### CLI Mode
Interactive TUI with live updates:
```
                       🛡️  MULLVAD GUARDIAN                        
            Automated Device Monitoring & Removal             

────────────────────────────────────────────────────────────────────────────────

  Status: ACTIVE  VPN: ● Connected
         us-nyc-wg-101 • 192.0.2.1

  ⚙  Configuration
  ────────────────────────────────────────────────────────────────────────────
  Account:           5939...3847
  Check Interval:    3s
  Auto-reconnect:    Enabled
  Persistent VPN:    Enabled
  Protected Device:  My-PC

  📊 Statistics
  ────────────────────────────────────────────────────────────────────────────
  Total Scans:       142
  Devices Removed:   3
  Account Expiry:    2026-06-15

  📱 Devices (2)
  ────────────────────────────────────────────────────────────────────────────
  ✓ My-PC                                      Protected
  ✓ My-Laptop                                  Protected

  📋 Activity Log
  ────────────────────────────────────────────────────────────────────────────
  [17:08:45] Authentication successful.
  [17:08:48] Detected own device: 'My-PC' — auto-protected.
  [17:08:51] Scan completed — 2 devices found.

────────────────────────────────────────────────────────────────────────────────
  Press Ctrl+C to stop • Last update: 17:09:02
```

---

## 📦 Installation

### Prerequisites
- Python 3.10 or higher
- Mullvad VPN CLI installed (`mullvad` command available)
- PyQt6 (optional, only for GUI mode)

### Install Dependencies

**For Web UI (minimal):**
```bash
pip install requests
```

**For PyQt6 GUI (optional):**
```bash
pip install PyQt6 requests
```

### Mullvad CLI Installation

**Windows:**
1. Download Mullvad VPN from [mullvad.net/download](https://mullvad.net/download)
2. Install the application
3. The CLI is automatically included at `C:\Program Files\Mullvad VPN\resources\mullvad.exe`
4. Guardian will auto-detect the installation path

**macOS:**
```bash
brew install --cask mullvad-vpn
```

**Arch Linux:**
```bash
sudo pacman -S mullvad-vpn
```

**Ubuntu/Debian:**
```bash
wget https://mullvad.net/download/app/deb/latest -O mullvad.deb
sudo dpkg -i mullvad.deb
```

**Other distributions:**
Visit [mullvad.net/download](https://mullvad.net/download)

---

## 🖥️ Platform Support

### Windows
- ✅ Full GUI support with native fonts (Segoe UI)
- ✅ Auto-detects Mullvad CLI installation path
- ✅ Config stored in `%APPDATA%\mvad\`
- ✅ CLI mode supported

### macOS
- ✅ Full GUI support with SF Pro Display fonts
- ✅ Native look and feel
- ✅ Config stored in `~/.config/mvad/`
- ✅ CLI mode supported

### Linux
- ✅ Full GUI support
- ✅ Tested on Arch, Ubuntu, Debian
- ✅ Config stored in `~/.config/mvad/`
- ✅ CLI mode supported

---

## 🚀 Usage

### Web UI Mode (Recommended)

```bash
python3 server.py
```

Then open your browser to **http://localhost:8080**

The Web UI provides:
- **Home** — Dashboard with VPN status and statistics
- **Connect** — VPN connection controls with real-time status
- **Devices** — View all devices on your account
- **Settings** — Configure account, webhook, and intervals

**Features:**
- Modern dark mode interface
- Real-time status updates every 3 seconds
- Responsive design (works on mobile, tablet, desktop)
- No Python GUI dependencies required
- Access from any device on your network

**Custom Port:**
```bash
# Edit server.py and change the port in run_server(port=8080)
python3 server.py
```

### GUI Mode (PyQt6)

```bash
python gui.py
```

The GUI provides:
- **Home** — Dashboard with account info and statistics
- **Connect** — VPN connection with server selection and ping monitoring
- **Devices** — View all devices on your account
- **Whitelist** — Manage protected devices
- **Settings** — Configure account, webhook, and intervals

### CLI Mode

**Interactive TUI (Text User Interface):**

```bash
python cli.py
```

The interactive CLI provides a beautiful real-time dashboard with:
- **Live status updates** — Guardian status and VPN connection state
- **Configuration display** — Account, intervals, and settings at a glance
- **Real-time statistics** — Scans, removals, and account expiry
- **Device list** — All devices with protection status
- **Activity log** — Last 10 log entries with color coding
- **Auto-refresh** — Updates every second
- **Interactive controls** — Change settings on the fly with keyboard shortcuts

**Keyboard Shortcuts:**
- **[I]** — Change check interval (1-60 seconds)
- **[R]** — Toggle auto-reconnect on/off
- **[P]** — Toggle persistent VPN connection on/off
- **[W]** — Add device to whitelist
- **[S]** — Save configuration to file
- **[Q]** — Quit gracefully

All changes take effect immediately and are applied to the running guardian without restart!

**Command-line options:**

```bash
# Start with saved config
python cli.py

# Override settings
python cli.py --account 1234567890123456 --interval 5

# Add whitelisted devices
python cli.py --whitelist "My PC" --whitelist "My Laptop"

# Disable auto-reconnect
python cli.py --no-reconnect

# Disable persistent connection
python cli.py --no-persistent
```

**CLI Options:**
```
--account NUM          Mullvad account number
--whitelist NAME       Device name to whitelist (repeatable)
--webhook URL          Discord webhook URL
--interval SEC         Check interval in seconds (default: 3)
--no-reconnect         Disable auto-reconnect on device removal
--no-persistent        Disable persistent VPN connection
```

---

## ⚙️ Configuration

Configuration is stored in `~/.config/mvad/settings.json`

### Default Settings

```json
{
  "account_num": "1234567890123456",
  "whitelist": ["My Device"],
  "discord_webhook": "https://discord.com/api/webhooks/...",
  "check_interval": 3,
  "auto_start": false,
  "auto_reconnect": true,
  "persistent_connect": true,
  "max_retries": 3,
  "backoff_base": 30,
  "session_refresh": 3600,
  "vpn_protocol": "wireguard",
  "vpn_kill_switch": true,
  "vpn_block_ads": false
}
```

### Configuration Options

| Option | Type | Description |
|--------|------|-------------|
| `account_num` | string | Your Mullvad account number |
| `whitelist` | array | List of device names to protect |
| `discord_webhook` | string | Discord webhook URL for notifications |
| `check_interval` | number | Seconds between device checks (default: 3) |
| `auto_start` | boolean | Start guardian automatically on launch |
| `auto_reconnect` | boolean | Reconnect when device is removed |
| `persistent_connect` | boolean | Keep VPN connected at all times |
| `max_retries` | number | Max fetch retries before error (default: 3) |
| `backoff_base` | number | Base backoff time in seconds (default: 30) |
| `session_refresh` | number | Session refresh interval in seconds (default: 3600) |
| `vpn_protocol` | string | VPN protocol: `wireguard` or `openvpn` |
| `vpn_kill_switch` | boolean | Enable kill switch |
| `vpn_block_ads` | boolean | Enable ad blocking |

---

## 🔔 Discord Notifications

To receive notifications when devices are removed:

1. Create a Discord webhook in your server settings
2. Copy the webhook URL
3. Paste it in Settings → Discord Webhook
4. Click Save

**Notification includes:**
- Device name
- Account number (masked)
- Expiry date
- Total devices removed
- Scan count
- Timestamp

---

## 🛠️ How It Works

### Device Monitoring
1. Authenticates with Mullvad API using your account number
2. Fetches device list every 3 seconds
3. Compares devices against whitelist
4. Removes unauthorized devices automatically
5. Sends Discord notification on removal

### Auto-Reconnect
When your device is removed from the account:
1. Detects device is invalid/revoked
2. Disconnects VPN to restore internet
3. Forces logout to clear revoked device
4. Re-logs in with your account number
5. Reconnects to VPN
6. Continues monitoring

### Persistent Connection
When enabled (default):
1. Checks VPN status every loop iteration
2. If disconnected, checks if logged in
3. If not logged in, logs in automatically
4. Connects to VPN
5. Continues monitoring

---

## 🎯 Use Cases

### Personal Use
- Protect your account from unauthorized access
- Monitor family members' devices
- Get notified when someone logs in

### Shared Accounts
- Automatically remove unauthorized users
- Whitelist trusted devices
- Keep your connection stable

### Server Deployment
- Run in CLI mode on a VPS
- Headless operation with Discord notifications
- Persistent monitoring 24/7

---

## 🐛 Troubleshooting

### "mullvad: command not found"
Install Mullvad CLI from [mullvad.net/download](https://mullvad.net/download)

### "Login failed"
- Check your account number is correct
- Ensure you have an active Mullvad subscription
- Try logging in manually: `mullvad account login 1234567890123456`

### "Connection failed"
- Check your internet connection
- Verify Mullvad service is running: `systemctl status mullvad-daemon`
- Try connecting manually: `mullvad connect`

### GUI doesn't start
- Install PyQt6: `pip install PyQt6`
- Check Python version: `python --version` (requires 3.10+)

### Persistent connection not working
- Enable it in Settings → Auto-reconnect toggle
- Restart the guardian
- Check logs for connection errors

---

## 📝 License

MIT License - See LICENSE file for details

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

---

## ⚠️ Disclaimer

This tool is for personal use only. Use responsibly and in accordance with Mullvad's Terms of Service. The authors are not responsible for any misuse or account issues.

---

## 🔗 Links

- [Mullvad VPN](https://mullvad.net)
- [Mullvad API Documentation](https://mullvad.net/en/help/api)
- [Report Issues](https://github.com/sleepyvill/mullvad-guardian/issues)

---

**Made with ❤️ by sleepyvill + claude**
