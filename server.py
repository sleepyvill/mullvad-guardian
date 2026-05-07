
import json
import subprocess
import platform
import re
import shutil
import socket
import logging
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from dataclasses import dataclass
from datetime import datetime, timezone
import threading
import time
import requests

_IS_WINDOWS = platform.system() == "Windows"

if _IS_WINDOWS:
    _CFG_PATH = Path.home() / "AppData" / "Roaming" / "mvad" / "settings.json"
else:
    _CFG_PATH = Path.home() / ".config" / "mvad" / "settings.json"

_DEFAULTS = {
    "account_num": "",
    "whitelist": [],
    "discord_webhook": "",
    "check_interval": 3,
    "auto_start": False,
    "auto_reconnect": True,
    "persistent_connect": True,
    "max_retries": 3,
    "backoff_base": 30,
    "session_refresh": 3600,
    "vpn_protocol": "wireguard",
    "vpn_kill_switch": True,
    "vpn_block_ads": False,
}

@dataclass
class _Device:
    id: str
    name: str

class AuthenticationError(Exception):
    pass

def load_config():
    if _CFG_PATH.exists():
        try:
            return {**_DEFAULTS, **json.loads(_CFG_PATH.read_text())}
        except Exception:
            pass
    return dict(_DEFAULTS)

def save_config(cfg):
    _CFG_PATH.parent.mkdir(parents=True, exist_ok=True)
    _CFG_PATH.write_text(json.dumps(cfg, indent=2))

class MullvadCLI:
    @staticmethod
    def _get_mullvad_cmd():
        if _IS_WINDOWS:
            paths = [
                r"C:\Program Files\Mullvad VPN\resources\mullvad.exe",
                r"C:\Program Files (x86)\Mullvad VPN\resources\mullvad.exe",
            ]
            for path in paths:
                if Path(path).exists():
                    return path
            return "mullvad.exe"
        return "mullvad"

    @staticmethod
    def _run(*args, timeout=6):
        try:
            cmd = MullvadCLI._get_mullvad_cmd()
            r = subprocess.run(
                [cmd, *args],
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            return r.stdout, r.stderr, r.returncode
        except FileNotFoundError:
            return "", "not_found", 127
        except subprocess.TimeoutExpired:
            return "", "timeout", 1
        except Exception as exc:
            return "", str(exc), 1

    @classmethod
    def status(cls):
        out, err, rc = cls._run("status")
        res = {
            "state": "unknown",
            "ip": None,
            "server": None,
            "location": None,
            "country_code": None,
        }
        if rc == 127 or err == "not_found":
            res["state"] = "unavailable"
            return res
        text = out.strip()
        if "Connected" in text:
            res["state"] = "connected"
            m = re.search(r"(\d+\.\d+\.\d+\.\d+)", text)
            if m:
                res["ip"] = m.group(1)
            m = re.search(r"\b([a-z]{2})-[a-z]{3}-(?:wg|ovpn)-\d+", text)
            if m:
                res["country_code"] = m.group(0).split("-")[0].upper()
                res["server"] = m.group(0)
            m = re.search(r"in\s+(.+?)(?:\s+using|\s*$)", text, re.MULTILINE)
            if m:
                res["location"] = m.group(1).strip().rstrip(",")
        elif "Disconnected" in text:
            res["state"] = "disconnected"
        elif "Connecting" in text or "connecting" in text.lower():
            res["state"] = "connecting"
        elif "Blocked" in text:
            res["state"] = "blocked"
        return res

    @classmethod
    def connect(cls):
        _, _, rc = cls._run("connect")
        return rc == 0

    @classmethod
    def disconnect(cls):
        _, _, rc = cls._run("disconnect")
        return rc == 0

    @classmethod
    def is_logged_in(cls):
        out, err, rc = cls._run("account", "get")
        if rc == 0 and "not logged in" not in out.lower():
            return True
        return False

    @classmethod
    def relogin(cls, account_num):
        cls._run("account", "logout")
        time.sleep(1)
        out, err, rc = cls._run("account", "login", account_num)
        return rc == 0

    @classmethod
    def detect_my_device(cls):
        out, err, rc = cls._run("account", "get")
        if rc == 0:
            for line in out.splitlines():
                low = line.lower()
                if "device name" in low:
                    parts = line.split(":", 1)
                    if len(parts) > 1:
                        name = parts[1].strip()
                        if name:
                            return name
        return None

    @classmethod
    def available(cls):
        _, err, rc = cls._run("version")
        return rc == 0 and err != "not_found"

    @classmethod
    def is_device_valid(cls):
        out, err, rc = cls._run("account", "get")
        return rc == 0 and "device" in out.lower()

    @classmethod
    def set_relay(cls, hostname):
        _, _, rc = cls._run("relay", "set", "hostname", hostname)
        return rc == 0

    @classmethod
    def set_location(cls, country, city=""):
        args = ["relay", "set", "location", country]
        if city:
            args.append(city)
        _, _, rc = cls._run(*args)
        return rc == 0

    @classmethod
    def set_auto_location(cls):
        _, _, rc = cls._run("relay", "set", "location", "any")
        return rc == 0

    @classmethod
    def set_protocol(cls, proto):
        _, _, rc = cls._run("relay", "set", "tunnel-protocol", proto)
        return rc == 0

    @classmethod
    def set_kill_switch(cls, on):
        val = "on" if on else "off"
        out, err, rc = cls._run("always-require-vpn", "set", val)
        if rc != 0:
            out, err, rc = cls._run("lockdown-mode", "set", val)
        return rc == 0

    @classmethod
    def set_block_ads(cls, on):
        if on:
            _, _, rc = cls._run("dns", "set", "default", "--block-ads", "--block-malware")
        else:
            _, _, rc = cls._run("dns", "set", "default")
        return rc == 0

class GuardianWorker(threading.Thread):
    AUTH_URL = "https://api.mullvad.net/auth/v1/token"
    BASE_URL = "https://mullvad.net/en/account/devices"
    REVOKE_URL = "https://mullvad.net/en/account/devices?/revoke-device"

    def __init__(self, account_num, whitelist, discord_webhook="", check_interval=3,
                 max_retries=3, session_refresh=3600, auto_reconnect=True,
                 persistent_connect=True):
        super().__init__(daemon=True)
        self._account_num = account_num
        self.whitelist = {n.lower().strip() for n in whitelist if n}
        self._discord = discord_webhook
        self._interval = check_interval
        self._max_retries = max_retries
        self._session_refresh = session_refresh
        self._auto_reconnect = auto_reconnect
        self._persistent_connect = persistent_connect
        self._active = True
        self._session_active = False
        self._last_login = 0.0
        self._total_removed = 0
        self._scan_count = 0
        self._my_device = None
        self._self_detected = False
        self._auto_whitelist = set()
        self._current_devices = []
        self._expiry = "Unknown"
        self._status = "idle"
        self._logs = []

        self.net = requests.Session()
        self.net.headers.update({
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            "Accept-Language": "en-US,en;q=0.9",
        })

    def _log(self, level, msg):
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_entry = {"time": timestamp, "level": level, "message": msg}
        self._logs.append(log_entry)
        if len(self._logs) > 100:
            self._logs.pop(0)
        print(f"[{timestamp}] {level}: {msg}")

    def update_whitelist(self, names):
        self.whitelist = {n.lower().strip() for n in names if n}

    def update_interval(self, seconds):
        self._interval = max(1, seconds)

    def update_webhook(self, url):
        self._discord = url

    def get_stats(self):
        return {
            "scan_count": self._scan_count,
            "total_removed": self._total_removed,
            "expiry": self._expiry,
            "status": self._status,
            "my_device": self._my_device,
            "logs": self._logs[-20:],
        }

    def get_devices(self):
        return [
            {
                "id": d.id,
                "name": d.name,
                "whitelisted": d.name.lower().strip() in self.whitelist or d.name.lower().strip() in self._auto_whitelist
            }
            for d in self._current_devices
        ]

    def _login(self):
        self._status = "authenticating"

        if not self._self_detected:
            name = MullvadCLI.detect_my_device()
            if name:
                self._my_device = name
                self._self_detected = True
                self._auto_whitelist = {name.lower().strip()}
                self._log("INFO", f"Detected own device: '{name}' - auto-protected")

        self._log("INFO", "Authenticating with Mullvad API...")
        try:
            resp = self.net.post(
                self.AUTH_URL,
                json={"account_number": self._account_num},
                headers={"Content-Type": "application/json"},
                timeout=10,
            )
            if resp.status_code == 200:
                token = resp.json().get("access_token", "")
                if token:
                    ck = requests.cookies.create_cookie(
                        name="accessToken", value=token, domain="mullvad.net"
                    )
                    self.net.cookies.set_cookie(ck)
                    self.net.headers["Authorization"] = f"Bearer {token}"
                    self._session_active = True
                    self._last_login = time.monotonic()
                    self._log("INFO", "Authentication successful")
                    return True
            if resp.status_code in (400, 401):
                raise AuthenticationError("Invalid account number")
            self._log("ERROR", f"Login failed - HTTP {resp.status_code}")
            return False
        except AuthenticationError:
            raise
        except requests.RequestException as exc:
            self._log("ERROR", f"Login error: {exc}")
            return False

    def _ensure_session(self):
        if not self._session_active or time.monotonic() - self._last_login >= self._session_refresh:
            if self._session_active:
                self._log("INFO", "Session refresh - re-authenticating...")
            return self._login()
        return True

    def _ensure_connected(self):
        if not self._persistent_connect or not MullvadCLI.available():
            return

        status = MullvadCLI.status()
        state = status.get("state", "disconnected")

        if state == "connected":
            return

        self._log("INFO", f"VPN is {state} - connecting...")

        if not MullvadCLI.is_device_valid():
            self._log("INFO", "Not logged in - logging in...")
            MullvadCLI._run("account", "logout")
            time.sleep(1)
            if not MullvadCLI.relogin(self._account_num):
                self._log("ERROR", "Login failed")
                return
            self._session_active = False

        if MullvadCLI.connect():
            self._log("INFO", "Connected successfully")
        else:
            self._log("ERROR", "Connection failed")

    def _session_expired(self, text):
        return "account_number" in text and "login" in text

    def _fetch(self):
        for attempt in range(1, self._max_retries + 1):
            try:
                resp = self.net.get(self.BASE_URL, timeout=10)
                resp.raise_for_status()
                if self._session_expired(resp.text):
                    self._log("WARNING", "Session expired - re-authenticating...")
                    self._session_active = False
                    if not self._login():
                        return [], "Error"
                    continue
                return self._parse(resp.text)
            except requests.RequestException as exc:
                self._log("WARNING", f"Fetch {attempt}/{self._max_retries}: {exc}")
                if attempt < self._max_retries:
                    time.sleep(2)
                    continue

        return [], "Error"

    def _parse(self, text):
        devices = [
            _Device(id=m[0], name=m[1])
            for m in re.findall(r'id:"([^"]+)",name:"([^"]+)"', text)
        ]
        m = re.search(r'expiry:"([^"]+)"', text)
        return devices, (m.group(1) if m else "Unknown")

    def _revoke(self, device):
        try:
            res = self.net.post(
                self.REVOKE_URL,
                data={"id": device.id},
                headers={
                    "Referer": self.BASE_URL,
                    "Origin": "https://mullvad.net",
                    "x-sveltekit-action": "true",
                },
                timeout=10,
            )
            return '"type":"success"' in res.text
        except requests.RequestException as exc:
            self._log("ERROR", f"Revoke error for '{device.name}': {exc}")
            return False

    def _notify(self, device_name, expiry):
        if not self._discord:
            return
        embed = {
            "title": "🛡️ Device Removed",
            "description": f"Unauthorized device **{device_name}** has been removed from your Mullvad account.",
            "color": 0xFF4444,
            "fields": [
                {"name": "📱 Device Name", "value": f"`{device_name}`", "inline": True},
                {"name": "🔢 Account", "value": f"`{self._account_num[:4]}...{self._account_num[-4:]}`", "inline": True},
                {"name": "📅 Expiry", "value": f"`{expiry}`", "inline": True},
                {"name": "🗑️ Total Removed", "value": f"`{self._total_removed}`", "inline": True},
                {"name": "🔍 Scans", "value": f"`{self._scan_count}`", "inline": True},
                {"name": "⏰ Time", "value": f"<t:{int(datetime.now(timezone.utc).timestamp())}:R>", "inline": True},
            ],
            "thumbnail": {"url": "https://mullvad.net/media/logo/logo-round.png"},
            "footer": {
                "text": "Mullvad Guardian",
                "icon_url": "https://mullvad.net/favicon.ico"
            },
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        try:
            requests.post(self._discord, json={"embeds": [embed]}, timeout=5)
        except Exception:
            pass

    def _try_detect_self(self, devices):
        if self._self_detected:
            return
        name = MullvadCLI.detect_my_device()
        if not name:
            hostname = socket.gethostname().lower()
            for d in devices:
                if d.name.lower() == hostname or hostname in d.name.lower():
                    name = d.name
                    break
        if name:
            self._my_device = name
            self._self_detected = True
            self._auto_whitelist = {name.lower().strip()}
            self._log("INFO", f"Detected own device: '{name}' - auto-protected")

    def stop(self):
        self._active = False
        self._status = "stopped"

    def run(self):
        try:
            if not self._login():
                self._status = "error"
                return
        except AuthenticationError as exc:
            self._log("ERROR", str(exc))
            self._status = "error"
            return

        self._status = "running"
        self._log("INFO", "Guardian active - monitoring devices...")

        while self._active:
            self._ensure_connected()

            if not self._ensure_session():
                self._log("WARNING", "Session refresh failed - will retry next cycle")
                time.sleep(self._interval)
                continue

            devices, expiry = self._fetch()

            if expiry == "Error":
                self._log("WARNING", "Fetch failed - will retry next cycle")
                time.sleep(self._interval)
                continue

            self._status = "running"
            self._expiry = expiry
            self._current_devices = devices

            self._try_detect_self(devices)

            if self._my_device:
                names_lower = {d.name.lower().strip() for d in devices}
                if self._my_device.lower().strip() not in names_lower:
                    self._log("WARNING", f"Own device '{self._my_device}' was removed from account - re-registering...")
                    if self._auto_reconnect and MullvadCLI.available():
                        self._log("INFO", "Disconnecting VPN to allow login...")
                        MullvadCLI.disconnect()
                        time.sleep(2)

                        self._log("INFO", "Device removed - forcing logout to clear revoked device...")
                        MullvadCLI._run("account", "logout")
                        time.sleep(1)

                        self._log("INFO", "Logging in to create new device...")
                        if MullvadCLI.relogin(self._account_num):
                            self._log("INFO", "Re-login successful - attempting connection...")
                            if MullvadCLI.connect():
                                self._log("INFO", "Connection successful")
                            else:
                                self._log("WARNING", "Connection failed - will retry next cycle")
                        else:
                            self._log("ERROR", "Re-login failed - will retry next cycle")

                        self._self_detected = False
                        self._my_device = None
                        self._auto_whitelist = set()

            for d in devices:
                norm = d.name.lower().strip()
                if norm in self.whitelist or norm in self._auto_whitelist:
                    continue
                self._log("WARNING", f"Unauthorized device detected: '{d.name}'")
                if self._revoke(d):
                    self._total_removed += 1
                    self._log("INFO", f"Removed '{d.name}' (total: {self._total_removed})")
                    self._notify(d.name, expiry)
                else:
                    self._log("ERROR", f"Failed to remove '{d.name}'")

            self._scan_count += 1

            for _ in range(self._interval * 10):
                if not self._active:
                    break
                time.sleep(0.1)

        self._log("INFO", "Guardian stopped")

_guardian_worker = None

class RequestHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def _send_json(self, data, status=200):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def _send_html(self, content):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(content.encode())

    def do_GET(self):
        global _guardian_worker
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/":
            html_path = Path(__file__).parent / "index.html"
            if html_path.exists():
                self._send_html(html_path.read_text())
            else:
                self._send_html("<h1>index.html not found</h1>")

        elif path == "/api/status":
            status = MullvadCLI.status()
            logged_in = MullvadCLI.is_logged_in()
            status["logged_in"] = logged_in
            self._send_json(status)

        elif path == "/api/config":
            config = load_config()
            if config.get("account_num"):
                acc = config["account_num"]
                config["account_num_masked"] = acc[:4] + "..." + acc[-4:] if len(acc) > 8 else acc
            self._send_json(config)

        elif path == "/api/devices":
            if _guardian_worker and _guardian_worker.is_alive():
                devices = _guardian_worker.get_devices()
                self._send_json({"devices": devices})
            else:
                self._send_json({"devices": [], "message": "Guardian not running"})

        elif path == "/api/stats":
            if _guardian_worker and _guardian_worker.is_alive():
                stats = _guardian_worker.get_stats()
                self._send_json(stats)
            else:
                self._send_json({
                    "scan_count": 0,
                    "total_removed": 0,
                    "expiry": "Unknown",
                    "status": "stopped",
                    "my_device": None,
                    "logs": []
                })

        elif path == "/api/logs":
            if _guardian_worker and _guardian_worker.is_alive():
                stats = _guardian_worker.get_stats()
                self._send_json({"logs": stats.get("logs", [])})
            else:
                self._send_json({"logs": []})

        elif path == "/api/relays":
            try:
                resp = requests.get("https://api.mullvad.net/www/relays/all/", timeout=12)
                data = resp.json()
                countries = {}

                for relay in data:
                    if relay.get("type") != "wireguard":
                        continue
                    cc = relay.get("country_code", "").upper()
                    cn = relay.get("country_name", "")
                    city = relay.get("city_name", "")
                    hostname = relay.get("hostname", "")
                    ipv4 = relay.get("ipv4_addr_in", "")
                    active = relay.get("active", False)
                    owned = relay.get("owned", False)

                    if not cc or not cn:
                        continue

                    if cc not in countries:
                        countries[cc] = {
                            "name": cn,
                            "code": cc,
                            "cities": set(),
                            "servers": []
                        }

                    countries[cc]["cities"].add(city)
                    countries[cc]["servers"].append({
                        "hostname": hostname,
                        "ipv4": ipv4,
                        "city": city,
                        "active": active,
                        "owned": owned
                    })

                result = [
                    {
                        "name": v["name"],
                        "code": k,
                        "city_count": len(v["cities"]),
                        "servers": v["servers"]
                    }
                    for k, v in sorted(countries.items(), key=lambda x: x[1]["name"])
                ]
                self._send_json({"countries": result})
            except Exception as e:
                self._send_json({"countries": [], "error": str(e)})

        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        global _guardian_worker
        parsed = urlparse(self.path)
        path = parsed.path

        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode() if content_length > 0 else "{}"

        try:
            data = json.loads(body)
        except:
            data = {}

        if path == "/api/connect":
            success = MullvadCLI.connect()
            self._send_json({"success": success})

        elif path == "/api/disconnect":
            success = MullvadCLI.disconnect()
            self._send_json({"success": success})

        elif path == "/api/config":
            config = load_config()
            config.update(data)
            save_config(config)

            if _guardian_worker and _guardian_worker.is_alive():
                _guardian_worker.update_whitelist(config.get("whitelist", []))
                _guardian_worker.update_interval(config.get("check_interval", 3))
                _guardian_worker.update_webhook(config.get("discord_webhook", ""))

            self._send_json({"success": True})

        elif path == "/api/guardian/start":
            if _guardian_worker and _guardian_worker.is_alive():
                self._send_json({"success": False, "message": "Guardian already running"})
            else:
                config = load_config()
                _guardian_worker = GuardianWorker(
                    account_num=config.get("account_num", ""),
                    whitelist=config.get("whitelist", []),
                    discord_webhook=config.get("discord_webhook", ""),
                    check_interval=config.get("check_interval", 3),
                    max_retries=config.get("max_retries", 3),
                    session_refresh=config.get("session_refresh", 3600),
                    auto_reconnect=config.get("auto_reconnect", True),
                    persistent_connect=config.get("persistent_connect", True),
                )
                _guardian_worker.start()
                self._send_json({"success": True, "message": "Guardian started"})

        elif path == "/api/guardian/stop":
            if _guardian_worker and _guardian_worker.is_alive():
                _guardian_worker.stop()
                _guardian_worker = None
                self._send_json({"success": True, "message": "Guardian stopped"})
            else:
                self._send_json({"success": False, "message": "Guardian not running"})

        elif path == "/api/whitelist/add":
            device_name = data.get("device_name", "")
            if device_name:
                config = load_config()
                whitelist = config.get("whitelist", [])
                if device_name not in whitelist:
                    whitelist.append(device_name)
                    config["whitelist"] = whitelist
                    save_config(config)

                    if _guardian_worker and _guardian_worker.is_alive():
                        _guardian_worker.update_whitelist(whitelist)

                    self._send_json({"success": True})
                else:
                    self._send_json({"success": False, "message": "Device already whitelisted"})
            else:
                self._send_json({"success": False, "message": "No device name provided"})

        elif path == "/api/whitelist/remove":
            device_name = data.get("device_name", "")
            if device_name:
                config = load_config()
                whitelist = config.get("whitelist", [])
                if device_name in whitelist:
                    whitelist.remove(device_name)
                    config["whitelist"] = whitelist
                    save_config(config)

                    if _guardian_worker and _guardian_worker.is_alive():
                        _guardian_worker.update_whitelist(whitelist)

                    self._send_json({"success": True})
                else:
                    self._send_json({"success": False, "message": "Device not in whitelist"})
            else:
                self._send_json({"success": False, "message": "No device name provided"})

        elif path == "/api/relay/set":
            relay_type = data.get("type", "")
            value = data.get("value", "")

            if relay_type == "hostname":
                success = MullvadCLI.set_relay(value)
                self._send_json({"success": success})
            elif relay_type == "country":
                city = data.get("city", "")
                success = MullvadCLI.set_location(value, city)
                self._send_json({"success": success})
            elif relay_type == "auto":
                success = MullvadCLI.set_auto_location()
                self._send_json({"success": success})
            else:
                self._send_json({"success": False, "message": "Invalid relay type"})

        elif path == "/api/vpn/protocol":
            protocol = data.get("protocol", "")
            if protocol in ["wireguard", "openvpn"]:
                success = MullvadCLI.set_protocol(protocol)
                if success:
                    config = load_config()
                    config["vpn_protocol"] = protocol
                    save_config(config)
                self._send_json({"success": success})
            else:
                self._send_json({"success": False, "message": "Invalid protocol"})

        elif path == "/api/vpn/killswitch":
            enabled = data.get("enabled", False)
            success = MullvadCLI.set_kill_switch(enabled)
            if success:
                config = load_config()
                config["vpn_kill_switch"] = enabled
                save_config(config)
            self._send_json({"success": success})

        elif path == "/api/vpn/blockads":
            enabled = data.get("enabled", False)
            success = MullvadCLI.set_block_ads(enabled)
            if success:
                config = load_config()
                config["vpn_block_ads"] = enabled
                save_config(config)
            self._send_json({"success": success})

        else:
            self.send_response(404)
            self.end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

def run_server(port=1367):
    global _guardian_worker
    config = load_config()
    if config.get("auto_start", False):
        _guardian_worker = GuardianWorker(
            account_num=config.get("account_num", ""),
            whitelist=config.get("whitelist", []),
            discord_webhook=config.get("discord_webhook", ""),
            check_interval=config.get("check_interval", 3),
            max_retries=config.get("max_retries", 3),
            session_refresh=config.get("session_refresh", 3600),
            auto_reconnect=config.get("auto_reconnect", True),
            persistent_connect=config.get("persistent_connect", True),
        )
        _guardian_worker.start()
        print("🛡️  Guardian auto-started")

    server = HTTPServer(("0.0.0.0", port), RequestHandler)
    print(f"🛡️  Mullvad Guardian Web UI")
    print(f"📡 Server running on http://localhost:{port}")
    print(f"Press Ctrl+C to stop")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n\n✓ Server stopped")
        if _guardian_worker and _guardian_worker.is_alive():
            _guardian_worker.stop()
        server.shutdown()

if __name__ == "__main__":
    run_server()
