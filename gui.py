
import math, re, sys, time, logging, json, subprocess, shutil, socket, asyncio, platform
from datetime import datetime, timezone
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import requests
from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QScrollArea, QTextEdit, QSizePolicy, QLineEdit, QStackedWidget,
    QGraphicsOpacityEffect,
)
from PyQt6.QtCore import (
    Qt, QThread, pyqtSignal, QTimer, QRectF, QPointF, QPoint,
    QPropertyAnimation, QEasingCurve, pyqtProperty,
)
from PyQt6.QtGui import (
    QColor, QPainter, QPainterPath, QLinearGradient, QRadialGradient,
    QPen, QBrush, QFont, QCursor, QPalette,
)


_IS_WINDOWS = platform.system() == "Windows"
_IS_MACOS = platform.system() == "Darwin"
_IS_LINUX = platform.system() == "Linux"

def _get_font(size: int, weight=None, monospace: bool = False) -> QFont:
    if monospace:
        if _IS_WINDOWS:
            family = "Consolas"
        elif _IS_MACOS:
            family = "SF Mono"
        else:
            family = "Monospace"
    else:
        if _IS_WINDOWS:
            family = "Segoe UI"
        elif _IS_MACOS:
            family = "SF Pro Display"
        else:
            family = "Sans Serif"

    font = QFont(family, size, weight or QFont.Weight.Normal)
    if not monospace:
        font.setStyleHint(QFont.StyleHint.SansSerif)
    else:
        font.setStyleHint(QFont.StyleHint.Monospace)
    return font


if _IS_WINDOWS:
    _CFG_PATH = Path.home() / "AppData" / "Roaming" / "mvad" / "settings.json"
else:
    _CFG_PATH = Path.home() / ".config" / "mvad" / "settings.json"

_DEFAULTS: dict = {
    "account_num":        "",
    "whitelist":          [""],
    "discord_webhook":    (
        "https://discord.com/api/webhooks/0000000000000000000000000000000000/"
        "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
    ),
    "check_interval":     3,
    "auto_start":         False,
    "auto_reconnect":     True,
    "persistent_connect": True,
    "max_retries":        3,
    "backoff_base":       30,
    "session_refresh":    3600,
    "vpn_protocol":       "wireguard",
    "vpn_kill_switch":    True,
    "vpn_block_ads":      False,
}


def _load_cfg() -> dict:
    if _CFG_PATH.exists():
        try:
            return {**_DEFAULTS, **json.loads(_CFG_PATH.read_text())}
        except Exception:
            pass
    return dict(_DEFAULTS)


def _save_cfg(cfg: dict) -> None:
    _CFG_PATH.parent.mkdir(parents=True, exist_ok=True)
    _CFG_PATH.write_text(json.dumps(cfg, indent=2))


CFG = _load_cfg()

_BLUE   = QColor( 10, 132, 255)
_GREEN  = QColor( 48, 209,  88)
_RED    = QColor(255,  69,  58)
_ORANGE = QColor(255, 159,  10)
_WHITE  = QColor(255, 255, 255)
_PURPLE = QColor(175,  82, 222)
_TEAL   = QColor( 90, 200, 250)



class MullvadCLI:
    log_callback = None

    @staticmethod
    def _get_mullvad_cmd() -> str:
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
    def _run(*args, timeout: int = 6) -> tuple[str, str, int]:
        try:
            cmd = MullvadCLI._get_mullvad_cmd()
            r = subprocess.run(
                [cmd, *args],
                capture_output=True, text=True, timeout=timeout,
            )
            out, err, rc = r.stdout, r.stderr, r.returncode
        except FileNotFoundError:
            return "", "not_found", 127
        except subprocess.TimeoutExpired:
            return "", "timeout", 1
        except Exception as exc:
            return "", str(exc), 1
        if rc != 0 and MullvadCLI.log_callback and args[:1] != ("status",):
            cmd_str = " ".join(args)
            msg = (err.strip() or out.strip() or f"exit {rc}").splitlines()[0]
            MullvadCLI.log_callback("ERROR", f"mullvad {cmd_str}: {msg}")
        return out, err, rc

    @staticmethod
    def available() -> bool:
        if _IS_WINDOWS:
            cmd = MullvadCLI._get_mullvad_cmd()
            return Path(cmd).exists() if cmd.endswith('.exe') and '\\' in cmd else shutil.which(cmd) is not None
        return shutil.which("mullvad") is not None

    @classmethod
    def status(cls) -> dict:
        out, err, rc = cls._run("status")
        res = {"state": "unknown", "ip": None, "server": None,
               "location": None, "country_code": None}
        if rc == 127 or err == "not_found":
            res["state"] = "unavailable"
            return res
        text = out.strip()
        low = text.lower()
        if "inactive" in low:
            res["state"] = "inactive"
        elif "Connected" in text:
            res["state"] = "connected"
            m = re.search(r'(\d+\.\d+\.\d+\.\d+)', text)
            if m: res["ip"] = m.group(1)
            m = re.search(r'\b([a-z]{2})-[a-z]{3}-(?:wg|ovpn)-\d+', text)
            if m:
                res["country_code"] = m.group(0).split("-")[0].upper()
                res["server"] = m.group(0)
            else:
                m = re.search(r'(?:via|to)\s+(\S+)', text)
                if m:
                    server = m.group(1).rstrip(".,")
                    res["server"] = server
                    cc = re.match(r'([a-z]{2})-', server)
                    if cc:
                        res["country_code"] = cc.group(1).upper()
            m = re.search(r'in\s+(.+?)(?:\s+using|\s*$)', text, re.MULTILINE)
            if m: res["location"] = m.group(1).strip().rstrip(",")
        elif "Disconnected" in text:
            res["state"] = "disconnected"
        elif "Connecting" in text or "connecting" in text.lower():
            res["state"] = "connecting"
        elif "Blocked" in text:
            res["state"] = "blocked"
        return res

    @classmethod
    def connect(cls) -> bool:
        _, _, rc = cls._run("connect")
        return rc == 0

    @classmethod
    def disconnect(cls) -> bool:
        _, _, rc = cls._run("disconnect")
        return rc == 0

    @classmethod
    def reconnect(cls) -> bool:
        _, _, rc = cls._run("reconnect")
        return rc == 0

    @classmethod
    def set_location(cls, country: str, city: str = "") -> bool:
        args = ["relay", "set", "location", country]
        if city:
            args.append(city)
        _, _, rc = cls._run(*args)
        return rc == 0

    @classmethod
    def set_auto_location(cls) -> bool:
        _, _, rc = cls._run("relay", "set", "location", "any")
        return rc == 0

    @classmethod
    def set_protocol(cls, proto: str) -> bool:
        _, _, rc = cls._run("relay", "set", "tunnel-protocol", proto)
        return rc == 0

    @classmethod
    def set_kill_switch(cls, on: bool) -> bool:
        val = "on" if on else "off"
        out, err, rc = cls._run("always-require-vpn", "set", val)
        if rc != 0:
            out, err, rc = cls._run("lockdown-mode", "set", val)
        return rc == 0

    @classmethod
    def set_block_ads(cls, on: bool) -> bool:
        if on:
            _, _, rc = cls._run("dns", "set", "default", "--block-ads", "--block-malware")
        else:
            _, _, rc = cls._run("dns", "set", "default")
        return rc == 0

    @classmethod
    def is_device_valid(cls) -> bool:
        out, _, rc = cls._run("account", "get")
        text = out.lower()
        if rc != 0:
            return False
        if any(s in text for s in ("not logged in", "revoked", "inactive")):
            return False
        return "mullvad account:" in text

    @classmethod
    def is_logged_in(cls) -> bool:
        out, err, rc = cls._run("account", "get")
        text = out.lower()

        if rc == 0 and not any(s in text for s in ("not logged in", "revoked", "inactive")):
            return True

        return False

    @classmethod
    def ensure_logged_in(cls, account_num: str) -> bool:
        if cls.is_device_valid():
            return True
        return cls.relogin(account_num)

    @classmethod
    def detect_my_device(cls) -> str | None:
        out, _, rc = cls._run("account", "get")
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
    def rotate_key(cls) -> bool:
        _, _, rc = cls._run("tunnel", "wireguard", "rotate-key", timeout=15)
        return rc == 0

    @classmethod
    def relogin(cls, account_num: str) -> bool:
        state = cls.status().get("state", "unknown")
        out, _, _ = cls._run("account", "get")
        account_state = out.lower()
        if state in ("connected", "connecting", "blocked", "inactive", "unknown") or any(s in account_state for s in ("revoked", "inactive")):
            cls.disconnect()
            time.sleep(2)
        cls._run("account", "logout")
        time.sleep(1)
        _, _, rc = cls._run("account", "login", account_num, timeout=15)
        return rc == 0



class VPNStatusWorker(QThread):
    status_changed = pyqtSignal(dict)
    logged_out = pyqtSignal()

    def __init__(self, account_num: str = "") -> None:
        super().__init__()
        self._active = True
        self._account_num = account_num
        self._check_count = 0

    def stop(self) -> None:
        self._active = False

    def run(self) -> None:
        while self._active:
            self._check_count += 1
            if self._check_count >= 10:
                self._check_count = 0
                if not MullvadCLI.is_logged_in():
                    self.logged_out.emit()

            self.status_changed.emit(MullvadCLI.status())
            for _ in range(25):
                if not self._active:
                    break
                time.sleep(0.1)



@dataclass
class RelayServer:
    hostname:    str
    ipv4:        str
    country:     str
    city:        str
    active:      bool
    owned:       bool
    ping:        Optional[float] = None

@dataclass
class RelayCountry:
    name:       str
    code:       str
    flag:       str
    city_count: int
    servers:    list = None

    def __post_init__(self):
        if self.servers is None:
            self.servers = []


def _flag(code: str) -> str:
    if len(code) != 2:
        return "🌐"
    return (
        chr(0x1F1E6 + ord(code[0].upper()) - ord('A')) +
        chr(0x1F1E6 + ord(code[1].upper()) - ord('A'))
    )


class RelayFetcher(QThread):
    done = pyqtSignal(list)

    def run(self) -> None:
        try:
            resp = requests.get(
                "https://api.mullvad.net/www/relays/all/",
                timeout=12,
            )
            data = resp.json()
            countries: dict[str, dict] = {}

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
                    countries[cc] = {"name": cn, "cities": set(), "servers": []}

                countries[cc]["cities"].add(city)
                countries[cc]["servers"].append(
                    RelayServer(
                        hostname=hostname,
                        ipv4=ipv4,
                        country=cn,
                        city=city,
                        active=active,
                        owned=owned,
                    )
                )

            result = [
                RelayCountry(
                    name=v["name"],
                    code=k,
                    flag=_flag(k),
                    city_count=len(v["cities"]),
                    servers=v["servers"],
                )
                for k, v in sorted(countries.items(), key=lambda x: x[1]["name"])
            ]
            self.done.emit(result)
        except Exception as e:
            self.done.emit([])



class PingWorker(QThread):
    ping_result = pyqtSignal(str, float)
    cycle_finished = pyqtSignal()

    def __init__(self, servers: list, auto_refresh: bool = False, refresh_interval: int = 3) -> None:
        super().__init__()
        self._servers = servers
        self._active = True
        self._auto_refresh = auto_refresh
        self._refresh_interval = refresh_interval

    def stop(self) -> None:
        self._active = False

    async def _ping_server(self, server: RelayServer) -> tuple:
        if not self._active:
            return server.hostname, math.inf

        ip = server.ipv4
        timeout = 2

        if sys.platform.startswith("linux"):
            cmd = ["ping", "-c", "1", "-W", str(int(timeout * 1000)), ip]
        elif sys.platform == "darwin":
            cmd = ["ping", "-c", "1", "-t", str(int(timeout)), ip]
        else:
            cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), ip]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL
            )
            try:
                out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout + 1)
            except asyncio.TimeoutError:
                try:
                    proc.kill()
                    await proc.wait()
                except:
                    pass
                return server.hostname, math.inf

            m = re.search(r"time[=<]([\d.]+)\s*ms", out.decode("utf-8", "ignore"))
            delay = float(m.group(1)) if m and proc.returncode == 0 else math.inf
        except (OSError, asyncio.TimeoutError):
            delay = math.inf
        except Exception:
            delay = math.inf

        return server.hostname, delay

    async def _ping_all(self) -> None:
        sem = asyncio.Semaphore(20)

        async def run(server):
            if not self._active:
                return
            async with sem:
                hostname, delay = await self._ping_server(server)
                if self._active:
                    self.ping_result.emit(hostname, delay)

        await asyncio.gather(*(run(s) for s in self._servers if self._active), return_exceptions=True)

    def run(self) -> None:
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

            while self._active:
                try:
                    loop.run_until_complete(self._ping_all())
                    self.cycle_finished.emit()
                except Exception:
                    pass

                if not self._auto_refresh or not self._active:
                    break

                for _ in range(self._refresh_interval * 10):
                    if not self._active:
                        break
                    time.sleep(0.1)

            try:
                pending = asyncio.all_tasks(loop)
                for task in pending:
                    task.cancel()
                if pending:
                    loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
            except Exception:
                pass
            finally:
                loop.close()
        except Exception:
            pass



@dataclass
class _Device:
    id:   str
    name: str


class AuthenticationError(Exception):
    pass


class GuardianWorker(QThread):
    log_emitted     = pyqtSignal(str, str)
    status_changed  = pyqtSignal(str)
    devices_updated = pyqtSignal(list)
    expiry_updated  = pyqtSignal(str)
    stats_updated   = pyqtSignal(int, int)
    self_detected   = pyqtSignal(str)
    self_removed    = pyqtSignal()

    AUTH_URL   = "https://api.mullvad.net/auth/v1/token"
    BASE_URL   = "https://mullvad.net/en/account/devices"
    REVOKE_URL = "https://mullvad.net/en/account/devices?/revoke-device"

    def __init__(self, account_num: str, whitelist: list,
                 discord_webhook: str = "", check_interval: int = 3,
                 max_retries: int = 3, backoff_base: int = 30,
                 session_refresh: int = 3600,
                 auto_reconnect: bool = True,
                 persistent_connect: bool = True) -> None:
        super().__init__()
        self._account_num        = account_num
        self.whitelist           = {n.lower().strip() for n in whitelist}
        self._discord            = discord_webhook
        self._interval           = check_interval
        self._max_retries        = max_retries
        self._backoff_base       = backoff_base
        self._session_refresh    = session_refresh
        self._auto_reconnect     = auto_reconnect
        self._persistent_connect = persistent_connect
        self._active             = True
        self._session_active     = False
        self._last_login         = 0.0
        self._failures           = 0
        self._total_removed      = 0
        self._scan_count         = 0
        self._my_device: str | None = None
        self._self_detected      = False
        self._auto_whitelist: set[str] = set()

        self.net = requests.Session()
        self.net.headers.update({
            "User-Agent":      "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            "Accept-Language": "en-US,en;q=0.9",
        })

        self._log = logging.getLogger("MullvadGuardian")
        self._log.setLevel(logging.DEBUG)
        self._log.propagate = False
        worker = self

        class _SH(logging.Handler):
            def emit(self_, rec: logging.LogRecord) -> None:
                worker.log_emitted.emit(rec.levelname, self_.format(rec))

        h = _SH()
        h.setFormatter(logging.Formatter("%(asctime)s  %(message)s", "%H:%M:%S"))
        self._log.addHandler(h)
        self._handler = h

    def update_whitelist(self, names: list) -> None:
        self.whitelist = {n.lower().strip() for n in names}

    def update_interval(self, seconds: int) -> None:
        self._interval = max(1, seconds)

    def update_webhook(self, url: str) -> None:
        self._discord = url

    def set_my_device(self, name: str) -> None:
        self._my_device = name
        self._self_detected = True


    def _login(self) -> bool:
        self.status_changed.emit("authenticating")
        self._log.info("Authenticating with Mullvad API…")
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
                    self._last_login     = time.monotonic()
                    self._log.info("Authentication successful.")
                    return True
            if resp.status_code in (400, 401):
                raise AuthenticationError("Invalid account number.")
            self._log.error("Login failed — HTTP %s", resp.status_code)
            return False
        except AuthenticationError:
            raise
        except requests.RequestException as exc:
            self._log.error("Login error: %s", exc)
            return False

    def _ensure_session(self) -> bool:
        if not self._session_active or time.monotonic() - self._last_login >= self._session_refresh:
            if self._session_active:
                self._log.info("Session refresh — re-authenticating…")
            return self._login()
        return True

    def _check_login_status(self) -> None:
        if not MullvadCLI.available():
            return
        if MullvadCLI.is_device_valid():
            return
        state = MullvadCLI.status().get("state", "unknown")
        if state in ("connected", "connecting", "blocked", "inactive", "unknown"):
            self._log.info("Disconnecting inactive VPN session…")
            MullvadCLI.disconnect()
            time.sleep(2)

        if not (self._auto_reconnect or self._persistent_connect):
            return

        self._log.warning("Mullvad device is not valid — re-logging in…")
        if MullvadCLI.relogin(self._account_num):
            self._log.info("Re-login successful.")
            self._self_detected = False
            self._my_device = None
            self._auto_whitelist = set()
            self._session_active = False
            if self._auto_reconnect or self._persistent_connect:
                if MullvadCLI.connect():
                    self._log.info("Reconnected after re-login.")
                else:
                    self._log.warning("Reconnect after re-login failed — will retry.")
        else:
            self._log.error("Re-login failed.")

    def _ensure_connected(self) -> None:
        if not self._persistent_connect or not MullvadCLI.available():
            return

        status = MullvadCLI.status()
        state = status.get("state", "disconnected")

        if state == "connected":
            return

        self._log.info("VPN is %s — connecting…", state)

        if not MullvadCLI.is_device_valid():
            self._log.info("Not logged in — logging in…")
            if not MullvadCLI.relogin(self._account_num):
                self._log.error("Login failed.")
                return
            self._session_active = False

        if MullvadCLI.connect():
            self._log.info("Connected successfully.")
        else:
            self._log.error("Connection failed.")

    def _session_expired(self, text: str) -> bool:
        return "account_number" in text and "login" in text


    def _fetch(self) -> tuple:
        for attempt in range(1, self._max_retries + 1):
            try:
                resp = self.net.get(self.BASE_URL, timeout=10)
                resp.raise_for_status()
                if self._session_expired(resp.text):
                    self._log.warning("Session expired — re-authenticating…")
                    self._session_active = False
                    if not self._login():
                        return [], "Error"
                    continue
                self._failures = 0
                return self._parse(resp.text)
            except requests.RequestException as exc:
                self._log.warning("Fetch %d/%d: %s", attempt, self._max_retries, exc)
                if attempt < self._max_retries:
                    time.sleep(2)
                    continue

        return [], "Error"

    def _parse(self, text: str) -> tuple:
        devices = [
            _Device(id=m[0], name=m[1])
            for m in re.findall(r'id:"([^"]+)",name:"([^"]+)"', text)
        ]
        m = re.search(r'expiry:"([^"]+)"', text)
        return devices, (m.group(1) if m else "Unknown")


    def _revoke(self, device: _Device) -> bool:
        try:
            res = self.net.post(
                self.REVOKE_URL,
                data={"id": device.id},
                headers={
                    "Referer":            self.BASE_URL,
                    "Origin":             "https://mullvad.net",
                    "x-sveltekit-action": "true",
                },
                timeout=10,
            )
            return '"type":"success"' in res.text
        except requests.RequestException as exc:
            self._log.error("Revoke error for '%s': %s", device.name, exc)
            return False


    def _notify(self, device_name: str, expiry: str) -> None:
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


    def _try_detect_self(self, devices: list[_Device]) -> None:
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
            self._my_device      = name
            self._self_detected  = True
            self._auto_whitelist = {name.lower().strip()}
            self._log.info("Detected own device: '%s' — auto-protected.", name)
            self.self_detected.emit(name)


    def stop(self) -> None:
        self._active = False
        self._log.removeHandler(self._handler)

    def run(self) -> None:
        try:
            if not self._login():
                self.status_changed.emit("error")
                return
        except AuthenticationError as exc:
            self._log.error(str(exc))
            self.status_changed.emit("error")
            return

        self.status_changed.emit("running")
        self._log.info("Guardian active — monitoring devices…")

        while self._active:
            self._check_login_status()
            self._ensure_connected()

            if not self._ensure_session():
                self._log.warning("Session refresh failed — will retry next cycle.")
                time.sleep(self._interval)
                continue

            devices, expiry = self._fetch()

            if expiry == "Error":
                self._log.warning("Fetch failed — will retry next cycle.")
                time.sleep(self._interval)
                continue

            self.status_changed.emit("running")
            self.expiry_updated.emit(expiry)

            self._try_detect_self(devices)

            if self._my_device:
                names_lower = {d.name.lower().strip() for d in devices}
                if self._my_device.lower().strip() not in names_lower:
                    self._log.warning(
                        "Own device '%s' was removed from account — checking current state…",
                        self._my_device,
                    )
                    self.self_removed.emit()

                    # Before forcing a re-login, check if user already logged in manually
                    # under a different device name — if so, adopt it and protect it.
                    current_device = MullvadCLI.detect_my_device()
                    if current_device and current_device.lower().strip() in names_lower:
                        self._log.info(
                            "Already logged in as '%s' — adopting as protected device.",
                            current_device,
                        )
                        self._my_device      = current_device
                        self._self_detected  = True
                        self._auto_whitelist = {current_device.lower().strip()}
                        self.self_detected.emit(current_device)
                        if self._auto_reconnect and MullvadCLI.available():
                            state = MullvadCLI.status().get("state", "disconnected")
                            if state not in ("connected", "connecting"):
                                self._log.info("Connecting VPN for adopted device…")
                                if MullvadCLI.connect():
                                    self._log.info("Connected successfully.")
                                else:
                                    self._log.warning("Connection failed — will retry next cycle.")
                    elif self._auto_reconnect and MullvadCLI.available():
                        reconnected = False
                        state = MullvadCLI.status().get("state", "unknown")
                        if state in ("connected", "connecting", "blocked", "inactive", "unknown"):
                            self._log.info("Disconnecting VPN to allow login…")
                            MullvadCLI.disconnect()
                            time.sleep(2)

                        self._log.info("Logging in to create new device…")
                        if MullvadCLI.relogin(self._account_num):
                            self._log.info("Re-login successful — attempting connection…")

                            reconnected = MullvadCLI.connect()

                            if reconnected:
                                self._log.info("Connection successful.")
                            else:
                                self._log.warning("Connection failed — will retry next cycle.")
                        else:
                            self._log.error("Re-login failed — will retry next cycle.")

                        if reconnected:
                            self._log.info("Reconnected successfully.")
                        else:
                            self._log.error("Reconnect failed — will retry next cycle.")
                        self._self_detected  = False
                        self._my_device      = None
                        self._auto_whitelist = set()
                    else:
                        if MullvadCLI.available():
                            state = MullvadCLI.status().get("state", "unknown")
                            if state in ("connected", "connecting", "blocked", "inactive", "unknown"):
                                self._log.info("Disconnecting inactive VPN session.")
                                MullvadCLI.disconnect()
                                time.sleep(2)
                        self._self_detected  = False
                        self._my_device      = None
                        self._auto_whitelist = set()

            self.devices_updated.emit([
                (d.id, d.name,
                 d.name.lower().strip() in self.whitelist
                 or d.name.lower().strip() in self._auto_whitelist)
                for d in devices
            ])

            for d in devices:
                norm = d.name.lower().strip()
                if norm in self.whitelist or norm in self._auto_whitelist:
                    continue
                self._log.warning("Unauthorized device detected: '%s'", d.name)
                if self._revoke(d):
                    self._total_removed += 1
                    self._log.info("Removed '%s' (total: %d)", d.name, self._total_removed)
                    self._notify(d.name, expiry)
                else:
                    self._log.error("Failed to remove '%s'", d.name)

            self._scan_count += 1
            self.stats_updated.emit(self._scan_count, self._total_removed)

            for _ in range(self._interval * 10):
                if not self._active:
                    break
                time.sleep(0.1)

        self.status_changed.emit("idle")
        self._log.info("Guardian stopped.")



def _glass_path(rect: QRectF, radius: float) -> QPainterPath:
    p = QPainterPath()
    p.addRoundedRect(rect, radius, radius)
    return p


class GlassPanel(QWidget):
    def __init__(self, parent=None, *, radius: int = 16,
                 tint: QColor = None, dark: bool = False, hoverable: bool = False) -> None:
        super().__init__(parent)
        self._radius = radius
        self._tint   = tint
        self._dark   = dark
        self._hoverable = hoverable
        self._hover = False
        self._hover_progress = 0.0
        self._lift_offset = 0.0
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)

        if hoverable:
            self.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
            self._hover_anim = QPropertyAnimation(self, b"hover_progress")
            self._hover_anim.setDuration(300)
            self._hover_anim.setEasingCurve(QEasingCurve.Type.OutCubic)

            self._lift_anim = QPropertyAnimation(self, b"lift_offset")
            self._lift_anim.setDuration(300)
            self._lift_anim.setEasingCurve(QEasingCurve.Type.OutCubic)

    @pyqtProperty(float)
    def hover_progress(self):
        return self._hover_progress

    @hover_progress.setter
    def hover_progress(self, value):
        self._hover_progress = value
        self.update()

    @pyqtProperty(float)
    def lift_offset(self):
        return self._lift_offset

    @lift_offset.setter
    def lift_offset(self, value):
        self._lift_offset = value
        self.update()

    def enterEvent(self, _):
        if not self._hoverable:
            return
        self._hover = True
        self._hover_anim.setStartValue(self._hover_progress)
        self._hover_anim.setEndValue(1.0)
        self._hover_anim.start()

        self._lift_anim.setStartValue(self._lift_offset)
        self._lift_anim.setEndValue(-4.0)
        self._lift_anim.start()

    def leaveEvent(self, _):
        if not self._hoverable:
            return
        self._hover = False
        self._hover_anim.setStartValue(self._hover_progress)
        self._hover_anim.setEndValue(0.0)
        self._hover_anim.start()

        self._lift_anim.setStartValue(self._lift_offset)
        self._lift_anim.setEndValue(0.0)
        self._lift_anim.start()

    def paintEvent(self, _) -> None:
        p    = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)

        lift = self._lift_offset if self._hoverable else 0.0
        r    = QRectF(self.rect()).adjusted(0.5, 0.5 + lift, -0.5, -0.5 + lift)
        path = _glass_path(r, self._radius)

        if self._hoverable and self._hover_progress > 0:
            shadow_layers = 3
            for i in range(shadow_layers):
                shadow_offset = 10 + (self._hover_progress * 8) + (i * 2)
                shadow_blur = 20 + (self._hover_progress * 15) + (i * 5)
                shadow_alpha = int((30 - i * 8) * self._hover_progress)

                shadow_rect = r.adjusted(-shadow_blur/2, -shadow_blur/2 + shadow_offset,
                                        shadow_blur/2, shadow_blur/2 + shadow_offset)
                shadow_path = _glass_path(shadow_rect, self._radius + shadow_blur/2)

                for j in range(int(shadow_blur)):
                    alpha = int((shadow_blur - j) / shadow_blur * shadow_alpha)
                    blur_rect = shadow_rect.adjusted(-j, -j, j, j)
                    blur_path = _glass_path(blur_rect, self._radius + shadow_blur/2 + j)
                    p.fillPath(blur_path, QBrush(QColor(0, 0, 0, alpha)))

        base_alpha = 130 if self._dark else 75
        if self._hoverable:
            base_alpha += int(self._hover_progress * 35)
        base = self._tint if self._tint else QColor(14, 16, 28, base_alpha)
        p.fillPath(path, QBrush(base))

        vg = QLinearGradient(QPointF(r.left(), r.top()), QPointF(r.left(), r.bottom()))
        vg_top = 42 + int(self._hover_progress * 28) if self._hoverable else 42
        vg.setColorAt(0.00, QColor(255, 255, 255, vg_top))
        vg.setColorAt(0.40, QColor(255, 255, 255, 10))
        vg.setColorAt(1.00, QColor(255, 255, 255, 0))
        p.fillPath(path, QBrush(vg))

        dg = QLinearGradient(QPointF(r.left(), r.top()), QPointF(r.right(), r.bottom()))
        dg_alpha = 18 + int(self._hover_progress * 12) if self._hoverable else 18
        dg.setColorAt(0.00, QColor(255, 255, 255, dg_alpha))
        dg.setColorAt(0.45, QColor(255, 255, 255, 3))
        dg.setColorAt(1.00, QColor(255, 255, 255, 0))
        p.fillPath(path, QBrush(dg))

        sw = r.width() * 0.55
        sx = r.left() + (r.width() - sw) / 2
        sr = QRectF(sx, r.top() + 1.8, sw, 1.8)
        sg = QLinearGradient(sr.topLeft(), sr.topRight())
        spec_alpha = 175 + int(self._hover_progress * 80) if self._hoverable else 175
        sg.setColorAt(0.00, QColor(255, 255, 255, 0))
        sg.setColorAt(0.30, QColor(255, 255, 255, spec_alpha))
        sg.setColorAt(0.70, QColor(255, 255, 255, spec_alpha))
        sg.setColorAt(1.00, QColor(255, 255, 255, 0))
        sp = QPainterPath()
        sp.addRoundedRect(sr, 0.9, 0.9)
        p.fillPath(sp, QBrush(sg))

        border_alpha = 55 + int(self._hover_progress * 45) if self._hoverable else 55
        p.setPen(QPen(QColor(255, 255, 255, border_alpha), 1.0))
        p.setBrush(Qt.BrushStyle.NoBrush)
        p.drawPath(path)

        br = QRectF(r.left() + 8, r.bottom() - 1.5, r.width() - 16, 1.5)
        bg = QLinearGradient(br.topLeft(), br.topRight())
        bg.setColorAt(0.0, QColor(0, 0, 0, 0))
        bg.setColorAt(0.5, QColor(0, 0, 0, 28))
        bg.setColorAt(1.0, QColor(0, 0, 0, 0))
        bp = QPainterPath()
        bp.addRect(br)
        p.fillPath(bp, QBrush(bg))


class StatusDot(QWidget):
    _COLORS = {
        "running":        _GREEN,
        "connected":      _GREEN,
        "error":          _RED,
        "disconnected":   _RED,
        "authenticating": _ORANGE,
        "connecting":     _ORANGE,
        "blocked":        _ORANGE,
        "idle":           QColor(110, 110, 125),
        "unavailable":    QColor(110, 110, 125),
    }

    def __init__(self, size: int = 9, parent=None) -> None:
        super().__init__(parent)
        self._r     = size / 2
        self._color = QColor(110, 110, 125)
        self._phase = 0.0
        self._hover = False
        self._hover_progress = 0.0
        self._scale = 1.0
        self.setFixedSize(size + 14, size + 14)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))

        t = QTimer(self)
        t.timeout.connect(self._tick)
        t.start(16)

        self._hover_anim = QPropertyAnimation(self, b"hover_progress")
        self._hover_anim.setDuration(250)
        self._hover_anim.setEasingCurve(QEasingCurve.Type.OutCubic)

        self._scale_anim = QPropertyAnimation(self, b"scale")
        self._scale_anim.setDuration(250)
        self._scale_anim.setEasingCurve(QEasingCurve.Type.OutCubic)

    @pyqtProperty(float)
    def hover_progress(self):
        return self._hover_progress

    @hover_progress.setter
    def hover_progress(self, value):
        self._hover_progress = value
        self.update()

    @pyqtProperty(float)
    def scale(self):
        return self._scale

    @scale.setter
    def scale(self, value):
        self._scale = value
        self.update()

    def set_status(self, s: str) -> None:
        self._color = self._COLORS.get(s, self._COLORS["idle"])
        self.update()

    def _tick(self) -> None:
        self._phase = (self._phase + 0.045) % (2 * math.pi)
        self.update()

    def enterEvent(self, _):
        self._hover = True
        self._hover_anim.setStartValue(self._hover_progress)
        self._hover_anim.setEndValue(1.0)
        self._hover_anim.start()

        self._scale_anim.setStartValue(self._scale)
        self._scale_anim.setEndValue(1.15)
        self._scale_anim.start()

    def leaveEvent(self, _):
        self._hover = False
        self._hover_anim.setStartValue(self._hover_progress)
        self._hover_anim.setEndValue(0.0)
        self._hover_anim.start()

        self._scale_anim.setStartValue(self._scale)
        self._scale_anim.setEndValue(1.0)
        self._scale_anim.start()

    def paintEvent(self, _) -> None:
        p  = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        cx = self.width()  / 2
        cy = self.height() / 2
        pulse = (math.sin(self._phase) + 1) / 2
        r  = self._r * self._scale

        glow_base = 80 + (pulse * 40)
        glow_intensity = glow_base + (self._hover_progress * 100)
        gr   = r + 6 + (pulse * 4) + (self._hover_progress * 5)
        glow = QRadialGradient(QPointF(cx, cy), gr)
        gc   = QColor(self._color); gc.setAlpha(int(glow_intensity))
        glow.setColorAt(0.0, gc)
        glow.setColorAt(0.6, QColor(self._color.red(), self._color.green(), self._color.blue(), int(glow_intensity * 0.3)))
        glow.setColorAt(1.0, QColor(0, 0, 0, 0))
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QBrush(glow))
        p.drawEllipse(QPointF(cx, cy), gr, gr)

        dot_color = QColor(self._color)
        if self._hover_progress > 0:
            h, s, v, a = dot_color.getHsv()
            v = min(255, int(v + self._hover_progress * 40))
            s = max(0, int(s - self._hover_progress * 20))
            dot_color.setHsv(h, s, v, a)

        p.setBrush(QBrush(dot_color))
        p.setPen(QPen(QColor(255, 255, 255, int(30 + self._hover_progress * 50)), 0.5))
        p.drawEllipse(QPointF(cx, cy), r, r)

        hi = QRadialGradient(QPointF(cx - r * 0.3, cy - r * 0.3), r * 0.7)
        hi.setColorAt(0.0, QColor(255, 255, 255, int(140 + self._hover_progress * 80)))
        hi.setColorAt(0.7, QColor(255, 255, 255, int(20 + self._hover_progress * 30)))
        hi.setColorAt(1.0, QColor(255, 255, 255, 0))
        p.setBrush(QBrush(hi))
        p.setPen(Qt.PenStyle.NoPen)
        p.drawEllipse(QPointF(cx, cy), r, r)


class _TrafficBtn(QWidget):
    clicked = pyqtSignal()

    def __init__(self, hex_color: str, parent=None) -> None:
        super().__init__(parent)
        self._color = QColor(hex_color)
        self._hover = False
        self.setFixedSize(13, 13)
        self.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)

    def enterEvent(self, _): self._hover = True;  self.update()
    def leaveEvent(self, _): self._hover = False; self.update()

    def mouseReleaseEvent(self, e) -> None:
        if e.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit()

    def paintEvent(self, _) -> None:
        p  = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        cx, cy, r = self.width() / 2, self.height() / 2, 5.5
        c = self._color if self._hover else self._color.darker(118)
        p.setBrush(QBrush(c))
        p.setPen(QPen(QColor(0, 0, 0, 35), 0.6))
        p.drawEllipse(QPointF(cx, cy), r, r)
        hi = QRadialGradient(QPointF(cx - 1.5, cy - 1.5), r * 0.6)
        hi.setColorAt(0.0, QColor(255, 255, 255, 90))
        hi.setColorAt(1.0, QColor(255, 255, 255,  0))
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QBrush(hi))
        p.drawEllipse(QPointF(cx, cy), r, r)


class GlassButton(QWidget):
    clicked = pyqtSignal()

    def __init__(self, text: str, color: QColor = None,
                 parent=None, height: int = 38) -> None:
        super().__init__(parent)
        self._text    = text
        self._color   = color or _BLUE
        self._hover   = False
        self._pressed = False
        self._opacity = 1.0
        self._scale = 1.0
        self.setFixedHeight(height)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)

        self._hover_progress = 0.0
        self._hover_anim = QPropertyAnimation(self, b"hover_progress")
        self._hover_anim.setDuration(250)
        self._hover_anim.setEasingCurve(QEasingCurve.Type.OutCubic)

        self._scale_anim = QPropertyAnimation(self, b"scale")
        self._scale_anim.setDuration(250)
        self._scale_anim.setEasingCurve(QEasingCurve.Type.OutCubic)

    @pyqtProperty(float)
    def hover_progress(self):
        return self._hover_progress

    @hover_progress.setter
    def hover_progress(self, value):
        self._hover_progress = value
        self.update()

    @pyqtProperty(float)
    def scale(self):
        return self._scale

    @scale.setter
    def scale(self, value):
        self._scale = value
        self.update()

    @property
    def text(self) -> str:      return self._text
    @text.setter
    def text(self, v: str):     self._text = v;   self.update()

    @property
    def color(self) -> QColor:  return self._color
    @color.setter
    def color(self, v: QColor): self._color = v;  self.update()

    def enterEvent(self, _):
        self._hover = True
        self._hover_anim.setStartValue(self._hover_progress)
        self._hover_anim.setEndValue(1.0)
        self._hover_anim.start()

        self._scale_anim.setStartValue(self._scale)
        self._scale_anim.setEndValue(1.02)
        self._scale_anim.start()

    def leaveEvent(self, _):
        self._hover = False
        self._hover_anim.setStartValue(self._hover_progress)
        self._hover_anim.setEndValue(0.0)
        self._hover_anim.start()

        self._scale_anim.setStartValue(self._scale)
        self._scale_anim.setEndValue(1.0)
        self._scale_anim.start()

    def mousePressEvent(self, e) -> None:
        if e.button() == Qt.MouseButton.LeftButton:
            self._pressed = True
            self._scale_anim.stop()
            self._scale = 0.97
            self.update()

    def mouseReleaseEvent(self, e) -> None:
        if e.button() == Qt.MouseButton.LeftButton and self._pressed:
            self._pressed = False
            self._scale_anim.setStartValue(self._scale)
            self._scale_anim.setEndValue(1.02 if self._hover else 1.0)
            self._scale_anim.start()
            self.update()
            if self.rect().contains(e.pos()):
                self.clicked.emit()

    def paintEvent(self, _) -> None:
        p      = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)

        center = QPointF(self.rect().center())
        p.translate(center)
        p.scale(self._scale, self._scale)
        p.translate(-center)

        r      = QRectF(self.rect()).adjusted(1.0, 1.0, -1.0, -1.0)
        radius = r.height() / 2
        path   = _glass_path(r, radius)

        if self._hover_progress > 0:
            glow_r = r.adjusted(-2, -2, 2, 2)
            glow_path = _glass_path(glow_r, radius + 2)
            glow_alpha = int(self._hover_progress * 35)
            glow_color = QColor(self._color)
            glow_color.setAlpha(glow_alpha)
            p.fillPath(glow_path, QBrush(glow_color))

        base_alpha = 32 + int(self._hover_progress * 28)
        if self._pressed:
            base_alpha = 70

        fc = QColor(self._color); fc.setAlpha(base_alpha)
        p.fillPath(path, QBrush(fc))

        sg = QLinearGradient(QPointF(0, r.top()), QPointF(0, r.bottom()))
        shine_top = 35 + int(self._hover_progress * 25)
        sg.setColorAt(0.0, QColor(255, 255, 255, shine_top if not self._pressed else 10))
        sg.setColorAt(0.5, QColor(255, 255, 255, 8 if not self._pressed else 3))
        sg.setColorAt(1.0, QColor(255, 255, 255, 0))
        p.fillPath(path, QBrush(sg))

        spec_w = r.width() - radius * 2 - 4
        if spec_w > 0 and not self._pressed:
            spec_r = QRectF(r.left() + radius + 2, r.top() + 2.5, spec_w, 1.6)
            specg  = QLinearGradient(spec_r.topLeft(), spec_r.topRight())
            spec_alpha = int(100 + self._hover_progress * 55)
            specg.setColorAt(0.0, QColor(255, 255, 255, 0))
            specg.setColorAt(0.5, QColor(255, 255, 255, spec_alpha))
            specg.setColorAt(1.0, QColor(255, 255, 255, 0))
            spp = QPainterPath()
            spp.addRoundedRect(spec_r, 0.8, 0.8)
            p.fillPath(spp, QBrush(specg))

        border_alpha = 100 + int(self._hover_progress * 55)
        bc = QColor(self._color); bc.setAlpha(border_alpha)
        p.setPen(QPen(bc, 1.0))
        p.setBrush(Qt.BrushStyle.NoBrush)
        p.drawPath(path)

        text_len = len(self._text)
        if text_len <= 8:
            font_size = 12
        elif text_len <= 12:
            font_size = 11
        else:
            font_size = 10

        font = _get_font(font_size, QFont.Weight.Medium)
        p.setFont(font)

        fm = p.fontMetrics()
        available_width = int(r.width() - 16)
        elided_text = fm.elidedText(self._text, Qt.TextElideMode.ElideRight, available_width)

        text_alpha = 230 + int(self._hover_progress * 25)
        if self._pressed:
            text_alpha = 160
        tc = QColor(255, 255, 255, text_alpha)
        p.setPen(tc)
        p.drawText(r.toRect(), Qt.AlignmentFlag.AlignCenter, elided_text)


class ToggleSwitch(QWidget):
    toggled = pyqtSignal(bool)

    def __init__(self, checked: bool = False, parent=None) -> None:
        super().__init__(parent)
        self._checked  = checked
        self._anim_pos = 1.0 if checked else 0.0
        self._hover = False
        self._hover_progress = 0.0
        self._glow_intensity = 0.0
        self.setFixedSize(46, 27)
        self.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)

        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick)

        self._hover_anim = QPropertyAnimation(self, b"hover_progress")
        self._hover_anim.setDuration(250)
        self._hover_anim.setEasingCurve(QEasingCurve.Type.OutCubic)

        self._glow_anim = QPropertyAnimation(self, b"glow_intensity")
        self._glow_anim.setDuration(250)
        self._glow_anim.setEasingCurve(QEasingCurve.Type.OutCubic)

    @pyqtProperty(float)
    def hover_progress(self):
        return self._hover_progress

    @hover_progress.setter
    def hover_progress(self, value):
        self._hover_progress = value
        self.update()

    @pyqtProperty(float)
    def glow_intensity(self):
        return self._glow_intensity

    @glow_intensity.setter
    def glow_intensity(self, value):
        self._glow_intensity = value
        self.update()

    def enterEvent(self, _):
        self._hover = True
        self._hover_anim.setStartValue(self._hover_progress)
        self._hover_anim.setEndValue(1.0)
        self._hover_anim.start()

        self._glow_anim.setStartValue(self._glow_intensity)
        self._glow_anim.setEndValue(1.0)
        self._glow_anim.start()

    def leaveEvent(self, _):
        self._hover = False
        self._hover_anim.setStartValue(self._hover_progress)
        self._hover_anim.setEndValue(0.0)
        self._hover_anim.start()

        self._glow_anim.setStartValue(self._glow_intensity)
        self._glow_anim.setEndValue(0.0)
        self._glow_anim.start()

    def mousePressEvent(self, _) -> None:
        self._checked = not self._checked
        self._timer.start(16)
        self.toggled.emit(self._checked)

    def _tick(self) -> None:
        target = 1.0 if self._checked else 0.0
        diff   = target - self._anim_pos
        if abs(diff) < 0.01:
            self._anim_pos = target
            self._timer.stop()
        else:
            self._anim_pos += diff * 0.18
        self.update()

    def paintEvent(self, _) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        w, h = self.width(), self.height()

        if self._glow_intensity > 0:
            glow_rect = QRectF(-3, -3, w + 6, h + 6)
            glow_path = QPainterPath()
            glow_path.addRoundedRect(glow_rect, h / 2 + 3, h / 2 + 3)
            glow_color = _GREEN if self._checked else QColor(255, 255, 255, 30)
            glow_alpha = int(self._glow_intensity * (50 if self._checked else 25))
            glow_color.setAlpha(glow_alpha)
            p.fillPath(glow_path, QBrush(glow_color))

        track = QRectF(0, 0, w, h)
        track_path = QPainterPath()
        track_path.addRoundedRect(track, h / 2, h / 2)

        if self._checked:
            track_color = QColor(_GREEN)
            brightness_boost = int(self._hover_progress * 25)
            h_val, s_val, v_val, a_val = track_color.getHsv()
            v_val = min(255, v_val + brightness_boost)
            track_color.setHsv(h_val, s_val, v_val, a_val)
            track_color.setAlpha(200 + int(self._hover_progress * 55))
        else:
            base_alpha = 45 + int(self._hover_progress * 25)
            track_color = QColor(255, 255, 255, base_alpha)

        p.fillPath(track_path, QBrush(track_color))

        track_shine = QLinearGradient(QPointF(0, 0), QPointF(0, h))
        shine_alpha = int(25 + self._hover_progress * 15)
        track_shine.setColorAt(0.0, QColor(255, 255, 255, shine_alpha))
        track_shine.setColorAt(0.5, QColor(255, 255, 255, 5))
        track_shine.setColorAt(1.0, QColor(255, 255, 255, 0))
        p.fillPath(track_path, QBrush(track_shine))

        border_alpha = int(60 + self._hover_progress * 40)
        if self._checked:
            border_color = QColor(_GREEN)
            border_color.setAlpha(border_alpha + 80)
        else:
            border_color = QColor(255, 255, 255, border_alpha)
        p.setPen(QPen(border_color, 1.0))
        p.setBrush(Qt.BrushStyle.NoBrush)
        p.drawPath(track_path)

        thumb_x = 3 + self._anim_pos * (w - h)
        thumb_r = (h / 2 - 3) * (1.0 + self._hover_progress * 0.12)
        thumb_center = QPointF(thumb_x + h / 2 - 3, h / 2)

        if self._hover_progress > 0:
            glow_r = thumb_r + 4 + (self._hover_progress * 3)
            thumb_glow = QRadialGradient(thumb_center, glow_r)
            glow_alpha = int(self._hover_progress * 60)
            thumb_glow.setColorAt(0.0, QColor(255, 255, 255, glow_alpha))
            thumb_glow.setColorAt(0.6, QColor(255, 255, 255, int(glow_alpha * 0.3)))
            thumb_glow.setColorAt(1.0, QColor(255, 255, 255, 0))
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(QBrush(thumb_glow))
            p.drawEllipse(thumb_center, glow_r, glow_r)

        p.setBrush(QBrush(QColor(255, 255, 255, 245)))
        p.setPen(QPen(QColor(0, 0, 0, 15), 0.5))
        p.drawEllipse(thumb_center, thumb_r, thumb_r)

        hi = QRadialGradient(QPointF(thumb_center.x() - thumb_r * 0.3,
                                      thumb_center.y() - thumb_r * 0.3),
                             thumb_r * 0.7)
        hi_alpha = int(180 + self._hover_progress * 75)
        hi.setColorAt(0.0, QColor(255, 255, 255, hi_alpha))
        hi.setColorAt(0.7, QColor(255, 255, 255, int(hi_alpha * 0.2)))
        hi.setColorAt(1.0, QColor(255, 255, 255, 0))
        p.setBrush(QBrush(hi))
        p.setPen(Qt.PenStyle.NoPen)
        p.drawEllipse(thumb_center, thumb_r, thumb_r)
        self._hover_anim.setEasingCurve(QEasingCurve.Type.OutCubic)

    @pyqtProperty(float)
    def hover_progress(self):
        return self._hover_progress

    @hover_progress.setter
    def hover_progress(self, value):
        self._hover_progress = value
        self.update()

    def _tick(self) -> None:
        target = 1.0 if self._checked else 0.0
        diff   = target - self._anim_pos
        if abs(diff) < 0.04:
            self._anim_pos = target; self._timer.stop()
        else:
            self._anim_pos += diff * 0.25
        self.update()

    @property
    def checked(self) -> bool: return self._checked

    @checked.setter
    def checked(self, v: bool) -> None:
        self._checked  = v
        self._anim_pos = 1.0 if v else 0.0
        self.update()

    def enterEvent(self, _):
        self._hover = True
        self._hover_anim.setStartValue(self._hover_progress)
        self._hover_anim.setEndValue(1.0)
        self._hover_anim.start()

    def leaveEvent(self, _):
        self._hover = False
        self._hover_anim.setStartValue(self._hover_progress)
        self._hover_anim.setEndValue(0.0)
        self._hover_anim.start()

    def mouseReleaseEvent(self, e) -> None:
        if e.button() == Qt.MouseButton.LeftButton:
            self._checked = not self._checked
            self._timer.start(16)
            self.toggled.emit(self._checked)

    def paintEvent(self, _) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        w, h = self.width(), self.height()
        r    = h / 2

        if self._hover_progress > 0:
            glow_rect = QRectF(-2, -2, w + 4, h + 4)
            glow_alpha = int(self._hover_progress * 30)
            if self._checked:
                glow_color = QColor(48, 209, 88, glow_alpha)
            else:
                glow_color = QColor(100, 210, 255, glow_alpha)
            p.setBrush(QBrush(glow_color))
            p.setPen(Qt.PenStyle.NoPen)
            p.drawRoundedRect(glow_rect, r + 2, r + 2)

        track = QColor(48, 209, 88) if self._checked else QColor(65, 65, 80)
        if self._hover_progress > 0:
            if self._checked:
                track = QColor(48, 209, 88).lighter(100 + int(self._hover_progress * 15))
            else:
                track = QColor(65, 65, 80).lighter(100 + int(self._hover_progress * 20))

        p.setBrush(QBrush(track))
        p.setPen(Qt.PenStyle.NoPen)
        p.drawRoundedRect(0, 0, w, h, r, r)

        thumb_r = h / 2 - 3 + (self._hover_progress * 1.5)
        thumb_x = 3 + self._anim_pos * (w - h)
        thumb_y = h / 2

        if self._hover_progress > 0:
            shadow_r = thumb_r + 2
            shadow_alpha = int(self._hover_progress * 40)
            p.setBrush(QBrush(QColor(0, 0, 0, shadow_alpha)))
            p.drawEllipse(QPointF(thumb_x + thumb_r, thumb_y + 1), shadow_r, shadow_r)

        thumb_brightness = 240 + int(self._hover_progress * 15)
        p.setBrush(QBrush(QColor(255, 255, 255, thumb_brightness)))
        p.drawEllipse(QPointF(thumb_x + thumb_r, thumb_y), thumb_r, thumb_r)



class ShieldWidget(QWidget):
    _STATUS_COLORS = {
        "running":        _GREEN,
        "connected":      _GREEN,
        "error":          _RED,
        "disconnected":   _RED,
        "authenticating": _ORANGE,
        "connecting":     _ORANGE,
        "blocked":        _ORANGE,
        "idle":           QColor(90, 92, 110),
        "unavailable":    QColor(90, 92, 110),
        "unknown":        QColor(90, 92, 110),
    }

    def __init__(self, size: int = 100, parent=None) -> None:
        super().__init__(parent)
        self._size   = size
        self._status = "idle"
        self._phase  = 0.0
        self._hover = False
        self._hover_progress = 0.0
        self._scale = 1.0
        pad = size // 2
        self.setFixedSize(size + pad, int(size * 1.18) + pad)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))

        t = QTimer(self)
        t.timeout.connect(self._tick)
        t.start(16)

        self._hover_anim = QPropertyAnimation(self, b"hover_progress")
        self._hover_anim.setDuration(300)
        self._hover_anim.setEasingCurve(QEasingCurve.Type.OutCubic)

        self._scale_anim = QPropertyAnimation(self, b"scale")
        self._scale_anim.setDuration(300)
        self._scale_anim.setEasingCurve(QEasingCurve.Type.OutCubic)

    @pyqtProperty(float)
    def hover_progress(self):
        return self._hover_progress

    @hover_progress.setter
    def hover_progress(self, value):
        self._hover_progress = value
        self.update()

    @pyqtProperty(float)
    def scale(self):
        return self._scale

    @scale.setter
    def scale(self, value):
        self._scale = value
        self.update()

    def set_status(self, s: str) -> None:
        self._status = s
        self.update()

    def _tick(self) -> None:
        self._phase = (self._phase + 0.038) % (2 * math.pi)
        self.update()

    def enterEvent(self, _):
        self._hover = True
        self._hover_anim.setStartValue(self._hover_progress)
        self._hover_anim.setEndValue(1.0)
        self._hover_anim.start()

        self._scale_anim.setStartValue(self._scale)
        self._scale_anim.setEndValue(1.08)
        self._scale_anim.start()

    def leaveEvent(self, _):
        self._hover = False
        self._hover_anim.setStartValue(self._hover_progress)
        self._hover_anim.setEndValue(0.0)
        self._hover_anim.start()

        self._scale_anim.setStartValue(self._scale)
        self._scale_anim.setEndValue(1.0)
        self._scale_anim.start()

    @staticmethod
    def _shield_path(cx: float, cy: float, w: float, h: float) -> QPainterPath:
        p = QPainterPath()
        r = w * 0.18
        p.moveTo(cx - w / 2 + r, cy - h / 2)
        p.lineTo(cx + w / 2 - r, cy - h / 2)
        p.quadTo(cx + w / 2, cy - h / 2, cx + w / 2, cy - h / 2 + r)
        p.lineTo(cx + w / 2, cy + h * 0.16)
        p.cubicTo(cx + w / 2, cy + h * 0.60, cx + w * 0.14, cy + h / 2, cx, cy + h / 2)
        p.cubicTo(cx - w * 0.14, cy + h / 2, cx - w / 2, cy + h * 0.60, cx - w / 2, cy + h * 0.16)
        p.lineTo(cx - w / 2, cy - h / 2 + r)
        p.quadTo(cx - w / 2, cy - h / 2, cx - w / 2 + r, cy - h / 2)
        p.closeSubpath()
        return p

    def paintEvent(self, _) -> None:
        p  = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        cx = self.width()  / 2
        cy = self.height() / 2
        sw = self._size * 0.82 * self._scale
        sh = self._size * self._scale

        color = self._STATUS_COLORS.get(self._status, self._STATUS_COLORS["idle"])
        pulse = (math.sin(self._phase) + 1) / 2

        if self._status in ("running", "connected", "authenticating", "connecting"):
            base_glow = sw * 0.75 + pulse * 20
            gr = base_glow + (self._hover_progress * 18)
            glow = QRadialGradient(QPointF(cx, cy), gr)
            glow_alpha = int((60 + self._hover_progress * 50) * pulse)
            gc = QColor(color); gc.setAlpha(glow_alpha)
            glow.setColorAt(0.0, gc)
            glow.setColorAt(0.5, QColor(color.red(), color.green(), color.blue(), int(glow_alpha * 0.4)))
            glow.setColorAt(1.0, QColor(0, 0, 0, 0))
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(QBrush(glow))
            p.drawEllipse(QPointF(cx, cy), gr, gr)
        elif self._hover_progress > 0:
            gr = sw * 0.75 + (self._hover_progress * 22)
            glow = QRadialGradient(QPointF(cx, cy), gr)
            glow_alpha = int(self._hover_progress * 60)
            gc = QColor(color); gc.setAlpha(glow_alpha)
            glow.setColorAt(0.0, gc)
            glow.setColorAt(0.6, QColor(color.red(), color.green(), color.blue(), int(glow_alpha * 0.3)))
            glow.setColorAt(1.0, QColor(0, 0, 0, 0))
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(QBrush(glow))
            p.drawEllipse(QPointF(cx, cy), gr, gr)

        shield = self._shield_path(cx, cy - sh * 0.04, sw, sh)

        grad = QLinearGradient(QPointF(cx, cy - sh / 2), QPointF(cx, cy + sh / 2))
        top  = QColor(color); top.setAlpha(210 + int(self._hover_progress * 45))
        bot  = QColor(color).darker(200); bot.setAlpha(230 + int(self._hover_progress * 25))
        grad.setColorAt(0.0, top)
        grad.setColorAt(1.0, bot)
        p.fillPath(shield, QBrush(grad))

        shim = QLinearGradient(QPointF(cx - sw / 2, cy), QPointF(cx + sw / 2, cy))
        shim.setColorAt(0.00, QColor(255, 255, 255, 0))
        shim.setColorAt(0.25, QColor(255, 255, 255, 55 + int(self._hover_progress * 45)))
        shim.setColorAt(0.55, QColor(255, 255, 255, 10 + int(self._hover_progress * 25)))
        shim.setColorAt(1.00, QColor(255, 255, 255, 0))
        p.fillPath(shield, QBrush(shim))

        hi_r = QRectF(cx - sw * 0.28, cy - sh / 2 + 3, sw * 0.56, sh * 0.22)
        hi_g = QLinearGradient(hi_r.topLeft(), hi_r.bottomLeft())
        hi_g.setColorAt(0.0, QColor(255, 255, 255, 60 + int(self._hover_progress * 60)))
        hi_g.setColorAt(1.0, QColor(255, 255, 255, 0))
        hi_p = QPainterPath()
        hi_p.addRoundedRect(hi_r, 6, 6)
        hi_p = hi_p.intersected(shield)
        p.fillPath(hi_p, QBrush(hi_g))

        border_width = 1.8 + (self._hover_progress * 0.6)
        border_alpha = 70 + int(self._hover_progress * 80)
        p.setPen(QPen(QColor(255, 255, 255, border_alpha), border_width))
        p.setBrush(Qt.BrushStyle.NoBrush)
        p.drawPath(shield)

        pen_w    = sw * 0.075
        icon_pen = QPen(QColor(255, 255, 255, 200 + int(self._hover_progress * 55)), pen_w,
                        Qt.PenStyle.SolidLine,
                        Qt.PenCapStyle.RoundCap,
                        Qt.PenJoinStyle.RoundJoin)
        p.setPen(icon_pen)
        p.setBrush(Qt.BrushStyle.NoBrush)

        if self._status in ("running", "connected"):
            check = QPainterPath()
            check.moveTo(cx - sw * 0.22, cy + sh * 0.02)
            check.lineTo(cx - sw * 0.04, cy + sh * 0.20)
            check.lineTo(cx + sw * 0.26, cy - sh * 0.14)
            p.drawPath(check)
        elif self._status in ("error", "disconnected"):
            p.drawLine(QPointF(cx - sw * 0.20, cy - sh * 0.16),
                       QPointF(cx + sw * 0.20, cy + sh * 0.16))
            p.drawLine(QPointF(cx + sw * 0.20, cy - sh * 0.16),
                       QPointF(cx - sw * 0.20, cy + sh * 0.16))
        elif self._status in ("authenticating", "connecting"):
            arc_r    = sw * 0.22
            arc_rect = QRectF(cx - arc_r, cy - arc_r, arc_r * 2, arc_r * 2)
            start_a  = int(self._phase / (2 * math.pi) * 360 * 16)
            p.drawArc(arc_rect, -start_a, 240 * 16)
        else:
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(QBrush(QColor(255, 255, 255, 70 + int(self._hover_progress * 50))))
            bw = sw * 0.10
            bh = sh * 0.28
            p.drawRoundedRect(QRectF(cx - sw * 0.16 - bw / 2, cy - bh / 2, bw, bh), bw / 2, bw / 2)
            p.drawRoundedRect(QRectF(cx + sw * 0.06 - bw / 2, cy - bh / 2, bw, bh), bw / 2, bw / 2)
        p.setPen(icon_pen)
        p.setBrush(Qt.BrushStyle.NoBrush)

        if self._status in ("running", "connected"):
            check = QPainterPath()
            check.moveTo(cx - sw * 0.22, cy + sh * 0.02)
            check.lineTo(cx - sw * 0.04, cy + sh * 0.20)
            check.lineTo(cx + sw * 0.26, cy - sh * 0.14)
            p.drawPath(check)
        elif self._status in ("error", "disconnected"):
            p.drawLine(QPointF(cx - sw * 0.20, cy - sh * 0.16),
                       QPointF(cx + sw * 0.20, cy + sh * 0.16))
            p.drawLine(QPointF(cx + sw * 0.20, cy - sh * 0.16),
                       QPointF(cx - sw * 0.20, cy + sh * 0.16))
        elif self._status in ("authenticating", "connecting"):
            arc_r    = sw * 0.22
            arc_rect = QRectF(cx - arc_r, cy - arc_r, arc_r * 2, arc_r * 2)
            start_a  = int(self._phase / (2 * math.pi) * 360 * 16)
            p.drawArc(arc_rect, -start_a, 240 * 16)
        else:
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(QBrush(QColor(255, 255, 255, 70 + int(self._hover_progress * 30))))
            bw = sw * 0.10
            bh = sh * 0.28
            p.drawRoundedRect(QRectF(cx - sw * 0.16 - bw / 2, cy - bh / 2, bw, bh), bw / 2, bw / 2)
            p.drawRoundedRect(QRectF(cx + sw * 0.06 - bw / 2, cy - bh / 2, bw, bh), bw / 2, bw / 2)
        hi_p = QPainterPath()
        hi_p.addRoundedRect(hi_r, 6, 6)
        hi_p = hi_p.intersected(shield)
        p.fillPath(hi_p, QBrush(hi_g))

        p.setPen(QPen(QColor(255, 255, 255, 70), 1.8))
        p.setBrush(Qt.BrushStyle.NoBrush)
        p.drawPath(shield)

        pen_w    = sw * 0.075
        icon_pen = QPen(QColor(255, 255, 255, 200), pen_w,
                        Qt.PenStyle.SolidLine,
                        Qt.PenCapStyle.RoundCap,
                        Qt.PenJoinStyle.RoundJoin)
        p.setPen(icon_pen)
        p.setBrush(Qt.BrushStyle.NoBrush)

        if self._status in ("running", "connected"):
            check = QPainterPath()
            check.moveTo(cx - sw * 0.22, cy + sh * 0.02)
            check.lineTo(cx - sw * 0.04, cy + sh * 0.20)
            check.lineTo(cx + sw * 0.26, cy - sh * 0.14)
            p.drawPath(check)
        elif self._status in ("error", "disconnected"):
            p.drawLine(QPointF(cx - sw * 0.20, cy - sh * 0.16),
                       QPointF(cx + sw * 0.20, cy + sh * 0.16))
            p.drawLine(QPointF(cx + sw * 0.20, cy - sh * 0.16),
                       QPointF(cx - sw * 0.20, cy + sh * 0.16))
        elif self._status in ("authenticating", "connecting"):
            arc_r    = sw * 0.22
            arc_rect = QRectF(cx - arc_r, cy - arc_r, arc_r * 2, arc_r * 2)
            start_a  = int(self._phase / (2 * math.pi) * 360 * 16)
            p.drawArc(arc_rect, -start_a, 240 * 16)
        else:
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(QBrush(QColor(255, 255, 255, 70)))
            bw = sw * 0.10
            bh = sh * 0.28
            p.drawRoundedRect(QRectF(cx - sw * 0.16 - bw / 2, cy - bh / 2, bw, bh), bw / 2, bw / 2)
            p.drawRoundedRect(QRectF(cx + sw * 0.06 - bw / 2, cy - bh / 2, bw, bh), bw / 2, bw / 2)



class NavBtn(QWidget):
    clicked = pyqtSignal()

    def __init__(self, icon: str, label: str, parent=None) -> None:
        super().__init__(parent)
        self._icon   = icon
        self._label  = label
        self._active = False
        self._hover  = False
        self._hover_progress = 0.0
        self._scale = 1.0
        self.setFixedHeight(58)
        self.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)

        self._hover_anim = QPropertyAnimation(self, b"hover_progress")
        self._hover_anim.setDuration(250)
        self._hover_anim.setEasingCurve(QEasingCurve.Type.OutCubic)

        self._scale_anim = QPropertyAnimation(self, b"scale")
        self._scale_anim.setDuration(250)
        self._scale_anim.setEasingCurve(QEasingCurve.Type.OutCubic)

    @pyqtProperty(float)
    def hover_progress(self):
        return self._hover_progress

    @hover_progress.setter
    def hover_progress(self, value):
        self._hover_progress = value
        self.update()

    @pyqtProperty(float)
    def scale(self):
        return self._scale

    @scale.setter
    def scale(self, value):
        self._scale = value
        self.update()

    def set_active(self, v: bool) -> None:
        self._active = v
        self.update()

    def enterEvent(self, _):
        self._hover = True
        self._hover_anim.setStartValue(self._hover_progress)
        self._hover_anim.setEndValue(1.0)
        self._hover_anim.start()

        self._scale_anim.setStartValue(self._scale)
        self._scale_anim.setEndValue(1.05)
        self._scale_anim.start()

    def leaveEvent(self, _):
        self._hover = False
        self._hover_anim.setStartValue(self._hover_progress)
        self._hover_anim.setEndValue(0.0)
        self._hover_anim.start()

        self._scale_anim.setStartValue(self._scale)
        self._scale_anim.setEndValue(1.0)
        self._scale_anim.start()

    def mouseReleaseEvent(self, e) -> None:
        if e.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit()

    def paintEvent(self, _) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)

        center = QPointF(self.rect().center())
        p.translate(center)
        p.scale(self._scale, self._scale)
        p.translate(-center)

        r = QRectF(5, 5, self.width() - 10, self.height() - 10)

        if self._active:
            bg = QPainterPath()
            bg.addRoundedRect(r, 10, 10)
            active_alpha = 18 + int(self._hover_progress * 12)
            p.fillPath(bg, QBrush(QColor(255, 255, 255, active_alpha)))

            bar = QRectF(0, r.top() + 10, 3, r.height() - 20)
            bp  = QPainterPath()
            bp.addRoundedRect(bar, 1.5, 1.5)
            bar_color = QColor(_BLUE)
            if self._hover_progress > 0:
                h, s, v, a = bar_color.getHsv()
                v = min(255, int(v + self._hover_progress * 30))
                bar_color.setHsv(h, s, v, a)
            p.fillPath(bp, QBrush(bar_color))

            if self._hover_progress > 0:
                glow_r = r.adjusted(-2, -2, 2, 2)
                glow_path = QPainterPath()
                glow_path.addRoundedRect(glow_r, 12, 12)
                glow_alpha = int(self._hover_progress * 20)
                p.fillPath(glow_path, QBrush(QColor(_BLUE.red(), _BLUE.green(), _BLUE.blue(), glow_alpha)))
        elif self._hover_progress > 0:
            bg = QPainterPath()
            bg.addRoundedRect(r, 10, 10)
            alpha = int(10 * self._hover_progress)
            p.fillPath(bg, QBrush(QColor(255, 255, 255, alpha)))

            glow_r = r.adjusted(-1, -1, 1, 1)
            glow_path = QPainterPath()
            glow_path.addRoundedRect(glow_r, 11, 11)
            glow_alpha = int(self._hover_progress * 12)
            p.fillPath(glow_path, QBrush(QColor(100, 210, 255, glow_alpha)))

        icon_f = _get_font(17)
        p.setFont(icon_f)
        icon_alpha = 230 if self._active else int(100 + 60 * self._hover_progress)
        p.setPen(QColor(255, 255, 255, icon_alpha))
        p.drawText(QRectF(0, 0, self.width(), self.height() - 16),
                   Qt.AlignmentFlag.AlignCenter, self._icon)

        lbl_f = _get_font(8, QFont.Weight.Medium)
        p.setFont(lbl_f)
        lbl_alpha = 200 if self._active else int(60 + 50 * self._hover_progress)
        p.setPen(QColor(255, 255, 255, lbl_alpha))
        p.drawText(QRectF(0, self.height() - 20, self.width(), 18),
                   Qt.AlignmentFlag.AlignCenter, self._label)



def _sh(text: str) -> QLabel:
    lbl = QLabel(text)
    f   = _get_font(9, QFont.Weight.Bold)
    lbl.setFont(f)
    lbl.setStyleSheet("color: rgba(255,255,255,0.28); letter-spacing:1.3px;")
    return lbl


def _label(text: str) -> QLabel:
    lbl = QLabel(text)
    f = _get_font(11, QFont.Weight.Medium)
    lbl.setFont(f)
    lbl.setStyleSheet("color: rgba(255,255,255,0.55);")
    return lbl


def _field(value: str = "", placeholder: str = "") -> QLineEdit:
    class AnimatedLineEdit(QLineEdit):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self._focus_progress = 0.0
            self._focus_anim = QPropertyAnimation(self, b"focus_progress")
            self._focus_anim.setDuration(250)
            self._focus_anim.setEasingCurve(QEasingCurve.Type.OutCubic)

        @pyqtProperty(float)
        def focus_progress(self):
            return self._focus_progress

        @focus_progress.setter
        def focus_progress(self, value):
            self._focus_progress = value
            self._update_style()

        def focusInEvent(self, event):
            super().focusInEvent(event)
            self._focus_anim.setStartValue(self._focus_progress)
            self._focus_anim.setEndValue(1.0)
            self._focus_anim.start()

        def focusOutEvent(self, event):
            super().focusOutEvent(event)
            self._focus_anim.setStartValue(self._focus_progress)
            self._focus_anim.setEndValue(0.0)
            self._focus_anim.start()

        def _update_style(self):
            border_alpha = int(17 + self._focus_progress * 70)
            bg_alpha = int(7 + self._focus_progress * 11)
            glow_size = int(self._focus_progress * 3)

            self.setStyleSheet(f"""
                QLineEdit {{
                    background: rgba(255,255,255,{bg_alpha});
                    color: rgba(255,255,255,0.88);
                    border: 1px solid rgba(10,132,255,{border_alpha});
                    border-radius: 9px;
                    padding: 9px 13px;
                    font-size: 13px;
                }}
            """)

    w = AnimatedLineEdit(value)
    w.setPlaceholderText(placeholder)
    w.setStyleSheet("""
        QLineEdit {
            background: rgba(255,255,255,0.07);
            color: rgba(255,255,255,0.88);
            border: 1px solid rgba(255,255,255,0.11);
            border-radius: 9px;
            padding: 9px 13px;
            font-size: 13px;
        }
        QLineEdit:focus {
            border: 1px solid rgba(10,132,255,0.55);
            background: rgba(10,132,255,0.07);
        }
    """)
    return w


def _scrollarea() -> QScrollArea:
    scroll = QScrollArea()
    scroll.setWidgetResizable(True)
    scroll.setStyleSheet("""
        QScrollArea { background: transparent; border: none; }
        QScrollBar:vertical {
            background: rgba(255,255,255,0.04); width: 4px; border-radius: 2px;
        }
        QScrollBar::handle:vertical {
            background: rgba(255,255,255,0.18); border-radius: 2px; min-height: 20px;
        }
        QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
    """)
    return scroll


class NavBtn(QWidget):
    clicked = pyqtSignal()

    def __init__(self, icon: str, label: str, parent=None) -> None:
        super().__init__(parent)
        self._icon   = icon
        self._label  = label
        self._active = False
        self._hover  = False
        self._hover_progress = 0.0
        self.setFixedHeight(58)
        self.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)

        self._hover_anim = QPropertyAnimation(self, b"hover_progress")
        self._hover_anim.setDuration(200)
        self._hover_anim.setEasingCurve(QEasingCurve.Type.OutCubic)

    @pyqtProperty(float)
    def hover_progress(self):
        return self._hover_progress

    @hover_progress.setter
    def hover_progress(self, value):
        self._hover_progress = value
        self.update()

    def set_active(self, v: bool) -> None:
        self._active = v
        self.update()

    def enterEvent(self, _):
        self._hover = True
        self._hover_anim.setStartValue(self._hover_progress)
        self._hover_anim.setEndValue(1.0)
        self._hover_anim.start()

    def leaveEvent(self, _):
        self._hover = False
        self._hover_anim.setStartValue(self._hover_progress)
        self._hover_anim.setEndValue(0.0)
        self._hover_anim.start()

    def mousePressEvent(self, e) -> None:
        if e.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit()

    def paintEvent(self, _) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)

        r = QRectF(self.rect()).adjusted(4, 4, -4, -4)
        path = QPainterPath()
        path.addRoundedRect(r, 10, 10)

        if self._active:
            p.fillPath(path, QBrush(QColor(10, 132, 255, 35)))
        elif self._hover_progress > 0:
            alpha = int(12 * self._hover_progress)
            p.fillPath(path, QBrush(QColor(255, 255, 255, alpha)))

        if self._active:
            bar_r = QRectF(4, r.top(), 3, r.height())
            bar_path = QPainterPath()
            bar_path.addRoundedRect(bar_r, 1.5, 1.5)
            p.fillPath(bar_path, QBrush(_BLUE))

        icon_f = _get_font(20)
        p.setFont(icon_f)
        p.setPen(QPen(QColor(255, 255, 255, 220 if self._active else 140)))
        p.drawText(r.adjusted(0, -8, 0, 0), Qt.AlignmentFlag.AlignCenter, self._icon)

        lbl_f = _get_font(9, QFont.Weight.Medium)
        p.setFont(lbl_f)
        p.setPen(QPen(QColor(255, 255, 255, 180 if self._active else 100)))
        p.drawText(r.adjusted(0, 18, 0, 0), Qt.AlignmentFlag.AlignCenter, self._label)


class ServerRow(QWidget):
    connect_clicked = pyqtSignal(str)

    def __init__(self, server: RelayServer, parent=None) -> None:
        super().__init__(parent)
        self._server = server
        self._ping = server.ping
        self._hover = False
        self._hover_progress = 0.0
        self._scale = 1.0
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self.setFixedHeight(48)
        self.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))

        self._opacity_effect = QGraphicsOpacityEffect(self)
        self.setGraphicsEffect(self._opacity_effect)
        self._fade_anim = QPropertyAnimation(self._opacity_effect, b"opacity")
        self._fade_anim.setDuration(200)
        self._fade_anim.setStartValue(0.0)
        self._fade_anim.setEndValue(1.0)
        self._fade_anim.setEasingCurve(QEasingCurve.Type.OutCubic)

        self._hover_anim = QPropertyAnimation(self, b"hover_progress")
        self._hover_anim.setDuration(250)
        self._hover_anim.setEasingCurve(QEasingCurve.Type.OutCubic)

        self._scale_anim = QPropertyAnimation(self, b"scale")
        self._scale_anim.setDuration(250)
        self._scale_anim.setEasingCurve(QEasingCurve.Type.OutCubic)

        row = QHBoxLayout(self)
        row.setContentsMargins(48, 0, 16, 0)
        row.setSpacing(12)

        name = QLabel(server.hostname)
        nf = _get_font(11, QFont.Weight.Medium, monospace=True)
        name.setFont(nf)
        name.setStyleSheet("color: rgba(255,255,255,0.80);")
        name.setFixedWidth(200)
        row.addWidget(name)

        city = QLabel(server.city)
        cf = _get_font(11)
        city.setFont(cf)
        city.setStyleSheet("color: rgba(255,255,255,0.50);")
        city.setFixedWidth(140)
        row.addWidget(city)

        row.addStretch()

        self._ping_lbl = QLabel("—")
        pf = _get_font(11, QFont.Weight.DemiBold, monospace=True)
        self._ping_lbl.setFont(pf)
        self._ping_lbl.setFixedWidth(90)
        self._ping_lbl.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        self._update_ping_display()
        row.addWidget(self._ping_lbl)

        conn_btn = GlassButton("Connect", _TEAL, height=30)
        conn_btn.setFixedWidth(100)
        conn_btn.clicked.connect(lambda: self.connect_clicked.emit(server.hostname))
        row.addWidget(conn_btn)

    @pyqtProperty(float)
    def hover_progress(self):
        return self._hover_progress

    @hover_progress.setter
    def hover_progress(self, value):
        self._hover_progress = value
        self.update()

    @pyqtProperty(float)
    def scale(self):
        return self._scale

    @scale.setter
    def scale(self, value):
        self._scale = value
        self.update()

    def showEvent(self, event) -> None:
        super().showEvent(event)
        self._fade_anim.start()

    def set_ping(self, ping_ms: float) -> None:
        self._ping = ping_ms
        self._server.ping = ping_ms
        self._update_ping_display()

    def _update_ping_display(self) -> None:
        if self._ping is None:
            self._ping_lbl.setText("—")
            self._ping_lbl.setStyleSheet("color: rgba(255,255,255,0.25);")
        elif self._ping == math.inf:
            self._ping_lbl.setText("timeout")
            self._ping_lbl.setStyleSheet("color: rgba(255,69,58,0.65);")
        else:
            self._ping_lbl.setText(f"{self._ping:.0f} ms")
            if self._ping < 50:
                color = "rgba(48,209,88,0.90)"
            elif self._ping < 100:
                color = "rgba(100,210,255,0.90)"
            elif self._ping < 200:
                color = "rgba(255,159,10,0.90)"
            else:
                color = "rgba(255,69,58,0.90)"
            self._ping_lbl.setStyleSheet(f"color: {color};")

    def get_hostname(self) -> str:
        return self._server.hostname

    def enterEvent(self, event) -> None:
        self._hover = True
        self._hover_anim.setStartValue(self._hover_progress)
        self._hover_anim.setEndValue(1.0)
        self._hover_anim.start()

        self._scale_anim.setStartValue(self._scale)
        self._scale_anim.setEndValue(1.008)
        self._scale_anim.start()

    def leaveEvent(self, event) -> None:
        self._hover = False
        self._hover_anim.setStartValue(self._hover_progress)
        self._hover_anim.setEndValue(0.0)
        self._hover_anim.start()

        self._scale_anim.setStartValue(self._scale)
        self._scale_anim.setEndValue(1.0)
        self._scale_anim.start()

    def paintEvent(self, _) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)

        center = QPointF(self.rect().center())
        p.translate(center)
        p.scale(self._scale, self._scale)
        p.translate(-center)

        if self._hover_progress > 0:
            r = QRectF(self.rect()).adjusted(8, 2, -8, -2)
            path = QPainterPath()
            path.addRoundedRect(r, 8, 8)
            alpha = int(8 + self._hover_progress * 10)
            p.fillPath(path, QBrush(QColor(255, 255, 255, alpha)))

            if self._hover_progress > 0.3:
                glow_r = r.adjusted(-1, -1, 1, 1)
                glow_path = QPainterPath()
                glow_path.addRoundedRect(glow_r, 9, 9)
                glow_alpha = int((self._hover_progress - 0.3) / 0.7 * 20)
                p.fillPath(glow_path, QBrush(QColor(100, 210, 255, glow_alpha)))

            shine = QLinearGradient(QPointF(r.left(), r.top()), QPointF(r.left(), r.bottom()))
            shine_alpha = int(self._hover_progress * 15)
            shine.setColorAt(0.0, QColor(255, 255, 255, shine_alpha))
            shine.setColorAt(0.6, QColor(255, 255, 255, 0))
            p.fillPath(path, QBrush(shine))

        p.setPen(QPen(QColor(255, 255, 255, 6), 1))
        p.drawLine(48, self.height() - 1, self.width() - 16, self.height() - 1)
        self._hover_anim.start()

    def leaveEvent(self, event) -> None:
        self._hover = False
        self._hover_anim.setStartValue(self._hover_progress)
        self._hover_anim.setEndValue(0.0)
        self._hover_anim.start()

    def paintEvent(self, _) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)

        if self._hover_progress > 0:
            r = QRectF(self.rect()).adjusted(8, 2, -8, -2)
            path = QPainterPath()
            path.addRoundedRect(r, 8, 8)
            alpha = int(6 + self._hover_progress * 8)
            p.fillPath(path, QBrush(QColor(255, 255, 255, alpha)))

            if self._hover_progress > 0.5:
                glow_r = r.adjusted(-1, -1, 1, 1)
                glow_path = QPainterPath()
                glow_path.addRoundedRect(glow_r, 9, 9)
                glow_alpha = int((self._hover_progress - 0.5) * 2 * 20)
                p.fillPath(glow_path, QBrush(QColor(100, 210, 255, glow_alpha)))

        p.setPen(QPen(QColor(255, 255, 255, 6), 1))
        p.drawLine(48, self.height() - 1, self.width() - 16, self.height() - 1)


class LogPanel(GlassPanel):
    _COLS = {
        "DEBUG":    "rgba(155,155,175,0.55)",
        "INFO":     "rgba(210,212,228,0.85)",
        "WARNING":  "#FF9F0A",
        "ERROR":    "#FF453A",
        "CRITICAL": "#FF453A",
    }

    def __init__(self, parent=None) -> None:
        super().__init__(parent, radius=0, dark=True)
        col = QVBoxLayout(self)
        col.setContentsMargins(0, 8, 0, 0)
        col.setSpacing(0)
        hdr = QLabel("  LOG OUTPUT")
        hf  = _get_font(8, QFont.Weight.Bold)
        hdr.setFont(hf)
        hdr.setStyleSheet("color: rgba(255,255,255,0.22); letter-spacing:1.6px; padding-left:14px;")
        col.addWidget(hdr)
        self._view = QTextEdit(readOnly=True)
        mf = QFont("JetBrains Mono", 10)
        self._view.setFont(mf)
        self._view.setStyleSheet("""
            QTextEdit { background: transparent; color: rgba(210,212,228,0.85);
                        border: none; padding: 4px 14px 8px; }
            QScrollBar:vertical { background: rgba(255,255,255,0.03); width: 4px; border-radius: 2px; margin: 0; }
            QScrollBar::handle:vertical { background: rgba(255,255,255,0.18); border-radius: 2px; min-height: 20px; }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
        """)
        col.addWidget(self._view)

    def append(self, level: str, msg: str) -> None:
        ts = datetime.now().strftime("%H:%M:%S")
        col = self._COLS.get(level, self._COLS["INFO"])
        html = f'<span style="color: rgba(255,255,255,0.35);">[{ts}]</span> <span style="color: {col};">{msg}</span>'
        self._view.append(html)
        self._view.verticalScrollBar().setValue(self._view.verticalScrollBar().maximum())


class ConnectPage(QWidget):
    def __init__(self, cfg: dict, main_window=None, parent=None) -> None:
        super().__init__(parent)
        self._cfg = cfg
        self._main_window = main_window
        self._vpn_worker = None
        self._ping_worker = None
        self._countries = []
        self._server_rows = {}
        self._all_servers = []
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)

        col = QVBoxLayout(self)
        col.setContentsMargins(24, 24, 24, 24)
        col.setSpacing(12)

        hdr_row = QHBoxLayout()
        hdr = QLabel("VPN Connection")
        hf = _get_font(18, QFont.Weight.DemiBold)
        hdr.setFont(hf)
        hdr.setStyleSheet("color: rgba(255,255,255,0.88);")
        hdr_row.addWidget(hdr)
        hdr_row.addStretch()
        col.addLayout(hdr_row)

        status_panel = GlassPanel(radius=14, dark=True)
        sp_layout = QVBoxLayout(status_panel)
        sp_layout.setContentsMargins(20, 16, 20, 16)
        sp_layout.setSpacing(10)

        status_row = QHBoxLayout()
        self._vpn_dot = StatusDot()
        status_row.addWidget(self._vpn_dot)
        self._vpn_state_lbl = QLabel("Disconnected")
        vf = _get_font(14, QFont.Weight.DemiBold)
        self._vpn_state_lbl.setFont(vf)
        self._vpn_state_lbl.setStyleSheet("color: rgba(255,255,255,0.88);")
        status_row.addWidget(self._vpn_state_lbl)
        status_row.addStretch()
        sp_layout.addLayout(status_row)

        self._vpn_detail_lbl = QLabel("—")
        df = _get_font(11)
        self._vpn_detail_lbl.setFont(df)
        self._vpn_detail_lbl.setStyleSheet("color: rgba(255,255,255,0.50);")
        sp_layout.addWidget(self._vpn_detail_lbl)

        self._vpn_ip_lbl = QLabel("")
        ipf = _get_font(10, monospace=True)
        self._vpn_ip_lbl.setFont(ipf)
        self._vpn_ip_lbl.setStyleSheet("color: rgba(255,255,255,0.38);")
        sp_layout.addWidget(self._vpn_ip_lbl)

        btn_row = QHBoxLayout()
        self._vpn_btn = GlassButton("Connect", _GREEN, height=38)
        self._vpn_btn.clicked.connect(self._toggle_vpn)
        btn_row.addWidget(self._vpn_btn)

        self._ping_btn = GlassButton("📡 Ping All Servers", QColor(255, 255, 255, 30), height=38)
        self._ping_btn.clicked.connect(self._start_ping_all)
        btn_row.addWidget(self._ping_btn)

        sp_layout.addLayout(btn_row)
        col.addWidget(status_panel)

        search_row = QHBoxLayout()
        search_field = _field("", "Search countries...")
        search_field.textChanged.connect(self._filter)
        search_row.addWidget(search_field)
        col.addLayout(search_row)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea { background: transparent; border: none; }")

        scroll_content = QWidget()
        self._c_layout = QVBoxLayout(scroll_content)
        self._c_layout.setContentsMargins(0, 0, 0, 0)
        self._c_layout.setSpacing(4)

        self._loading_lbl = QLabel("Loading servers...")
        lf = _get_font(12)
        self._loading_lbl.setFont(lf)
        self._loading_lbl.setStyleSheet("color: rgba(255,255,255,0.45);")
        self._loading_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._c_layout.addWidget(self._loading_lbl)

        self._c_layout.addStretch()

        scroll.setWidget(scroll_content)
        col.addWidget(scroll, 1)

        self._fetch_relays()
        self._start_vpn_worker()

    def _toggle_vpn(self) -> None:
        if not MullvadCLI.available():
            return

        status = MullvadCLI.status()
        state = status.get("state", "unknown")

        if state == "connected":
            MullvadCLI.disconnect()
        else:
            if not MullvadCLI.ensure_logged_in(self._cfg.get("account_num", "")):
                return
            MullvadCLI.connect()

    def _connect_server(self, hostname: str) -> None:
        if not MullvadCLI.ensure_logged_in(self._cfg.get("account_num", "")):
            return
        MullvadCLI.set_relay(hostname)
        MullvadCLI.connect()

    def _connect_country(self, hostname: str) -> None:
        if not MullvadCLI.ensure_logged_in(self._cfg.get("account_num", "")):
            return
        parts = hostname.split("-")
        if len(parts) >= 2:
            country = parts[0]
            city = parts[1]
            MullvadCLI.set_location(country, city)
            MullvadCLI.connect()

    def _set_proto(self, proto: str) -> None:
        MullvadCLI.set_protocol(proto)
        self._cfg["vpn_protocol"] = proto
        _save_cfg(self._cfg)

    def _set_kill_switch(self, on: bool) -> None:
        MullvadCLI.set_kill_switch(on)
        self._cfg["vpn_kill_switch"] = on
        _save_cfg(self._cfg)

    def _set_block_ads(self, on: bool) -> None:
        MullvadCLI.set_block_ads(on)
        self._cfg["vpn_block_ads"] = on
        _save_cfg(self._cfg)

    def _set_auto_reconnect(self, on: bool) -> None:
        self._cfg["auto_reconnect"] = on
        _save_cfg(self._cfg)
        if self._main_window and hasattr(self._main_window, '_worker') and self._main_window._worker:
            self._main_window._worker._auto_reconnect = on

    def _set_persistent_connect(self, on: bool) -> None:
        self._cfg["persistent_connect"] = on
        _save_cfg(self._cfg)
        if self._main_window and hasattr(self._main_window, '_worker') and self._main_window._worker:
            self._main_window._worker._persistent_connect = on

    def _start_auto_ping(self) -> None:
        if self._ping_worker and self._ping_worker.isRunning():
            self._ping_worker.stop()
            self._ping_worker.wait(2000)

        if not self._all_servers:
            return

        self._ping_worker = PingWorker(self._all_servers, auto_refresh=True, refresh_interval=3)
        self._ping_worker.ping_result.connect(self._on_ping_result)
        self._ping_worker.cycle_finished.connect(self._on_ping_cycle_finished)
        self._ping_worker.start()

    def _start_ping_all(self) -> None:
        if self._ping_worker and self._ping_worker.isRunning():
            return

        if not self._all_servers:
            return

        self._ping_btn.text = "Pinging..."
        self._ping_btn.setEnabled(False)

        self._ping_worker = PingWorker(self._all_servers, auto_refresh=False)
        self._ping_worker.ping_result.connect(self._on_ping_result)
        self._ping_worker.cycle_finished.connect(self._on_ping_finished)
        self._ping_worker.start()

    def _on_ping_result(self, hostname: str, ping_ms: float) -> None:
        for country_code, server_rows in self._server_rows.items():
            for server_row in server_rows:
                if server_row.get_hostname() == hostname:
                    server_row.set_ping(ping_ms)
                    break

        for country_row in self._countries:
            country_row.update_best_ping()

    def _on_ping_cycle_finished(self) -> None:
        pass

    def _on_ping_finished(self) -> None:
        self._ping_btn.text = "📡 Ping All Servers"
        self._ping_btn.setEnabled(True)


    def _start_vpn_worker(self) -> None:
        if not MullvadCLI.available():
            return
        self._vpn_worker = VPNStatusWorker(self._cfg.get("account_num", ""))
        self._vpn_worker.status_changed.connect(self._on_vpn_status)
        self._vpn_worker.logged_out.connect(self._on_logged_out)
        self._vpn_worker.start()

    def _on_logged_out(self) -> None:
        pass

    def _on_vpn_status(self, status: dict) -> None:
        state    = status.get("state", "unknown")
        location = status.get("location") or ""
        server   = status.get("server") or ""
        ip       = status.get("ip") or ""

        labels = {
            "connected":    "Connected",
            "disconnected": "Disconnected",
            "connecting":   "Connecting…",
            "blocked":      "Kill Switch Active",
            "inactive":     "Device inactive",
            "unavailable":  "mullvad CLI not found",
            "unknown":      "Unknown",
        }
        self._vpn_state_lbl.setText(labels.get(state, state.capitalize()))
        self._vpn_dot.set_status(state)
        self._vpn_ip_lbl.setText(ip)

        if state == "connected":
            detail = location or server
            self._vpn_detail_lbl.setText(detail)
            self._vpn_btn.text  = "Disconnect"
            self._vpn_btn.color = _RED
            cc        = (status.get("country_code") or "").upper()
            loc_lower = location.lower()
            for row in self._countries:
                match_cc   = bool(cc)        and row._code == cc
                match_name = bool(loc_lower) and row._name.lower() in loc_lower
                row.set_active(match_cc or match_name)
        elif state == "blocked":
            self._vpn_detail_lbl.setText("Traffic blocked until connected")
            self._vpn_btn.text  = "Connect"
            self._vpn_btn.color = _ORANGE
            for row in self._countries:
                row.set_active(False)
        else:
            self._vpn_detail_lbl.setText("—")
            self._vpn_btn.text  = "Connect"
            self._vpn_btn.color = _GREEN
            for row in self._countries:
                row.set_active(False)


    def _fetch_relays(self) -> None:
        fetcher = RelayFetcher(self)
        fetcher.done.connect(self._on_relays)
        fetcher.start()

    def _on_relays(self, countries: list[RelayCountry]) -> None:
        self._loading_lbl.hide()
        while self._c_layout.count() > 1:
            item = self._c_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        self._countries = []
        self._server_rows = {}
        self._all_servers = []

        for country in countries:
            self._all_servers.extend(country.servers)

            row = CountryRow(country)
            row.connect_clicked.connect(self._connect_country)
            row.expand_clicked.connect(lambda r=row: self._toggle_country_expansion(r))
            self._c_layout.insertWidget(self._c_layout.count() - 1, row)
            self._countries.append(row)

            server_rows = []
            for server in country.servers:
                server_row = ServerRow(server)
                server_row.connect_clicked.connect(self._connect_server)
                server_row.hide()
                self._c_layout.insertWidget(self._c_layout.count() - 1, server_row)
                server_rows.append(server_row)

            self._server_rows[country.code] = server_rows

        self._start_auto_ping()

    def _toggle_country_expansion(self, country_row: CountryRow) -> None:
        country_code = country_row._code
        server_rows = self._server_rows.get(country_code, [])

        is_expanded = country_row.is_expanded()

        for i, server_row in enumerate(server_rows):
            if is_expanded:
                QTimer.singleShot(i * 15, lambda sr=server_row: sr.show())
            else:
                server_row.hide()

    def _filter(self, query: str) -> None:
        for row in self._countries:
            visible = row.matches(query) if query else True
            row.setVisible(visible)

            if not visible:
                country_code = row._code
                for server_row in self._server_rows.get(country_code, []):
                    server_row.hide()

    def stop_worker(self) -> None:
        if self._vpn_worker:
            self._vpn_worker.stop()
            self._vpn_worker.wait(2000)
        if self._ping_worker:
            self._ping_worker.stop()
            self._ping_worker.wait(2000)


class DevicesPage(QWidget):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._my_device = ""
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        col = QVBoxLayout(self)
        col.setContentsMargins(24, 24, 24, 24)
        col.setSpacing(12)

        hr = QHBoxLayout()
        hdr = QLabel("Connected Devices")
        hf = _get_font(18, QFont.Weight.DemiBold)
        hdr.setFont(hf)
        hdr.setStyleSheet("color: rgba(255,255,255,0.88);")
        hr.addWidget(hdr)
        hr.addStretch()
        self._count = QLabel("—")
        cf = _get_font(12)
        self._count.setFont(cf)
        self._count.setStyleSheet("color: rgba(255,255,255,0.26);")
        hr.addWidget(self._count)
        col.addLayout(hr)

        panel = GlassPanel(radius=14, dark=True)
        pl    = QVBoxLayout(panel)
        pl.setContentsMargins(0, 0, 0, 0)
        scroll = _scrollarea()
        self._container = QWidget()
        self._container.setStyleSheet("background: transparent;")
        self._layout = QVBoxLayout(self._container)
        self._layout.setContentsMargins(12, 12, 12, 12)
        self._layout.setSpacing(6)
        self._empty = QLabel("No devices — start the guardian to monitor")
        self._empty.setAlignment(Qt.AlignmentFlag.AlignCenter)
        ef = _get_font(13)
        self._empty.setFont(ef)
        self._empty.setStyleSheet("color: rgba(255,255,255,0.16);")
        row.addWidget(conn_btn)

    def showEvent(self, event) -> None:
        super().showEvent(event)
        self._fade_anim.start()

    def set_ping(self, ping_ms: float) -> None:
        self._ping = ping_ms
        self._server.ping = ping_ms
        self._update_ping_display()

    def _update_ping_display(self) -> None:
        if self._ping is None:
            self._ping_lbl.setText("—")
            self._ping_lbl.setStyleSheet("color: rgba(255,255,255,0.25);")
        elif self._ping == math.inf:
            self._ping_lbl.setText("timeout")
            self._ping_lbl.setStyleSheet("color: rgba(255,69,58,0.65);")
        else:
            self._ping_lbl.setText(f"{self._ping:.0f} ms")
            if self._ping < 50:
                color = "rgba(48,209,88,0.90)"
            elif self._ping < 100:
                color = "rgba(100,210,255,0.90)"
            elif self._ping < 200:
                color = "rgba(255,159,10,0.90)"
            else:
                color = "rgba(255,69,58,0.90)"
            self._ping_lbl.setStyleSheet(f"color: {color};")

    def get_hostname(self) -> str:
        return self._server.hostname

    def enterEvent(self, event) -> None:
        self._hover = True
        self.update()

    def leaveEvent(self, event) -> None:
        self._hover = False
        self.update()

    def paintEvent(self, _) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)

        if self._hover:
            r = QRectF(self.rect()).adjusted(8, 2, -8, -2)
            path = QPainterPath()
            path.addRoundedRect(r, 8, 8)
            p.fillPath(path, QBrush(QColor(255, 255, 255, 6)))

        p.setPen(QPen(QColor(255, 255, 255, 6), 1))
        p.drawLine(48, self.height() - 1, self.width() - 16, self.height() - 1)


class TitleBar(QWidget):
    close_clicked = pyqtSignal()
    minimize_clicked = pyqtSignal()

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._status = "idle"
        self._drag_pos = None
        self.setFixedHeight(52)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)

        row = QHBoxLayout(self)
        row.setContentsMargins(18, 0, 12, 0)
        row.setSpacing(12)

        self._shield = ShieldWidget(18)
        row.addWidget(self._shield)

        title = QLabel("Mullvad Guardian")
        tf = _get_font(14, QFont.Weight.DemiBold)
        title.setFont(tf)
        title.setStyleSheet("color: rgba(255,255,255,0.92);")
        row.addWidget(title)

        self._status_lbl = QLabel("Idle")
        sf = _get_font(11)
        self._status_lbl.setFont(sf)
        self._status_lbl.setStyleSheet("color: rgba(255,255,255,0.38);")
        row.addWidget(self._status_lbl)

        row.addStretch()

        self._min_btn = self._create_control_btn("−")
        self._min_btn.clicked.connect(self.minimize_clicked.emit)
        row.addWidget(self._min_btn)

        self._close_btn = self._create_control_btn("×")
        self._close_btn.clicked.connect(self.close_clicked.emit)
        row.addWidget(self._close_btn)

    def _create_control_btn(self, text: str) -> GlassButton:
        btn = GlassButton(text, QColor(255, 255, 255, 30), height=28)
        btn.setFixedWidth(44)
        return btn

    def set_status(self, status: str) -> None:
        self._status = status
        self._shield.set_status(status)
        labels = {
            "idle": "Idle",
            "authenticating": "Authenticating…",
            "running": "Active",
            "error": "Error",
        }
        self._status_lbl.setText(labels.get(status, status.capitalize()))

    def mousePressEvent(self, event) -> None:
        if event.button() == Qt.MouseButton.LeftButton:
            self._drag_pos = event.globalPosition().toPoint()

    def mouseMoveEvent(self, event) -> None:
        if self._drag_pos is not None:
            window = self.window()
            delta = event.globalPosition().toPoint() - self._drag_pos
            window.move(window.pos() + delta)
            self._drag_pos = event.globalPosition().toPoint()

    def mouseReleaseEvent(self, event) -> None:
        self._drag_pos = None


class CountryRow(QWidget):
    connect_clicked = pyqtSignal(str)
    expand_clicked = pyqtSignal()

    def __init__(self, country: RelayCountry, parent=None) -> None:
        super().__init__(parent)
        self._code = country.code
        self._name = country.name
        self._servers = country.servers
        self._best_ping = None
        self._best_server = None
        self._expanded = False
        self._hover = False
        self._active = False
        self._hover_progress = 0.0
        self._scale = 1.0
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self.setFixedHeight(64)

        self._expand_rotation = 0.0
        self._rotation_anim = QPropertyAnimation(self, b"expand_rotation")
        self._rotation_anim.setDuration(250)
        self._rotation_anim.setEasingCurve(QEasingCurve.Type.OutCubic)

        self._hover_anim = QPropertyAnimation(self, b"hover_progress")
        self._hover_anim.setDuration(250)
        self._hover_anim.setEasingCurve(QEasingCurve.Type.OutCubic)

        self._scale_anim = QPropertyAnimation(self, b"scale")
        self._scale_anim.setDuration(250)
        self._scale_anim.setEasingCurve(QEasingCurve.Type.OutCubic)

        row = QHBoxLayout(self)
        row.setContentsMargins(16, 0, 16, 0)
        row.setSpacing(12)

        flag = QLabel(country.flag)
        ff = _get_font(24)
        flag.setFont(ff)
        flag.setFixedWidth(40)
        row.addWidget(flag)

        col = QVBoxLayout()
        col.setSpacing(2)

        name_lbl = QLabel(country.name)
        nf = _get_font(13, QFont.Weight.DemiBold)
        name_lbl.setFont(nf)
        name_lbl.setStyleSheet("color: rgba(255,255,255,0.92);")
        col.addWidget(name_lbl)

        self._sub_lbl = QLabel(f"{len(country.servers)} servers")
        sf = _get_font(10)
        self._sub_lbl.setFont(sf)
        self._sub_lbl.setStyleSheet("color: rgba(255,255,255,0.42);")
        col.addWidget(self._sub_lbl)

        row.addLayout(col)
        row.addStretch()

        self._ping_lbl = QLabel("—")
        pf = _get_font(13, QFont.Weight.Bold, monospace=True)
        self._ping_lbl.setFont(pf)
        self._ping_lbl.setStyleSheet("color: rgba(255,255,255,0.25);")
        self._ping_lbl.setFixedWidth(90)
        self._ping_lbl.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        row.addWidget(self._ping_lbl)

        self._conn_btn = GlassButton("Connect", _BLUE, height=34)
        self._conn_btn.setFixedWidth(110)
        self._conn_btn.clicked.connect(lambda: self._on_connect())
        row.addWidget(self._conn_btn)

        self._expand_btn = GlassButton("⌄", QColor(255, 255, 255, 20), height=34)
        self._expand_btn.setFixedWidth(40)
        self._expand_btn.clicked.connect(self._toggle_expand)
        row.addWidget(self._expand_btn)

    @pyqtProperty(float)
    def hover_progress(self):
        return self._hover_progress

    @hover_progress.setter
    def hover_progress(self, value):
        self._hover_progress = value
        self.update()

    def _on_connect(self) -> None:
        if self._best_server:
            self.connect_clicked.emit(self._best_server.hostname)
        elif self._servers:
            self.connect_clicked.emit(self._servers[0].hostname)

    def update_best_ping(self) -> None:
        best_ping = math.inf
        best_server = None

        for server in self._servers:
            if server.ping is not None and server.ping < best_ping:
                best_ping = server.ping
                best_server = server

        self._best_ping = best_ping if best_ping != math.inf else None
        self._best_server = best_server

        if self._best_ping is None:
            self._ping_lbl.setText("—")
            self._ping_lbl.setStyleSheet("color: rgba(255,255,255,0.25);")
            server_count = len(self._servers)
            self._sub_lbl.setText(f"{server_count} servers")
        elif self._best_ping == math.inf:
            self._ping_lbl.setText("timeout")
            self._ping_lbl.setStyleSheet("color: rgba(255,69,58,0.65);")
            server_count = len(self._servers)
            self._sub_lbl.setText(f"{server_count} servers  ·  All timeout")
        else:
            self._ping_lbl.setText(f"{self._best_ping:.0f} ms")
            if self._best_ping < 50:
                color = "rgba(48,209,88,0.90)"
            elif self._best_ping < 100:
                color = "rgba(100,210,255,0.90)"
            elif self._best_ping < 200:
                color = "rgba(255,159,10,0.90)"
            else:
                color = "rgba(255,69,58,0.90)"
            self._ping_lbl.setStyleSheet(f"color: {color};")

            if self._best_server:
                server_count = len(self._servers)
                self._sub_lbl.setText(f"{server_count} servers  ·  Best: {self._best_server.hostname}")

    @pyqtProperty(float)
    def expand_rotation(self):
        return self._expand_rotation

    @expand_rotation.setter
    def expand_rotation(self, value):
        self._expand_rotation = value
        self.update()

    def _toggle_expand(self):
        self._expanded = not self._expanded

        self._rotation_anim.setStartValue(self._expand_rotation)
        self._rotation_anim.setEndValue(180.0 if self._expanded else 0.0)
        self._rotation_anim.start()

        self.expand_clicked.emit()

    def is_expanded(self) -> bool:
        return self._expanded

    def get_servers(self) -> list:
        return self._servers

    def set_active(self, v: bool) -> None:
        self._active = v
        self._conn_btn.text = "Connected" if v else "Connect"
        self._conn_btn.color = _GREEN if v else _BLUE
        self.update()

    def matches(self, query: str) -> bool:
        q = query.lower()
        return q in self._name.lower() or q in self._code.lower()

    @pyqtProperty(float)
    def scale(self):
        return self._scale

    @scale.setter
    def scale(self, value):
        self._scale = value
        self.update()

    def enterEvent(self, event) -> None:
        self._hover = True
        self._hover_anim.setStartValue(self._hover_progress)
        self._hover_anim.setEndValue(1.0)
        self._hover_anim.start()

        self._scale_anim.setStartValue(self._scale)
        self._scale_anim.setEndValue(1.01)
        self._scale_anim.start()

    def leaveEvent(self, event) -> None:
        self._hover = False
        self._hover_anim.setStartValue(self._hover_progress)
        self._hover_anim.setEndValue(0.0)
        self._hover_anim.start()

        self._scale_anim.setStartValue(self._scale)
        self._scale_anim.setEndValue(1.0)
        self._scale_anim.start()

    def paintEvent(self, _) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)

        center = QPointF(self.rect().center())
        p.translate(center)
        p.scale(self._scale, self._scale)
        p.translate(-center)

        r = QRectF(self.rect()).adjusted(4, 2, -4, -2)
        path = QPainterPath()
        path.addRoundedRect(r, 12, 12)

        if self._active:
            active_alpha = 22 + int(self._hover_progress * 18)
            active_color = QColor(_GREEN if self._active else _BLUE)
            active_color.setAlpha(active_alpha)
            p.fillPath(path, QBrush(active_color))

            glow_r = r.adjusted(-2, -2, 2, 2)
            glow_path = QPainterPath()
            glow_path.addRoundedRect(glow_r, 14, 14)
            glow_alpha = int(self._hover_progress * 25)
            glow_color = QColor(_GREEN)
            glow_color.setAlpha(glow_alpha)
            p.fillPath(glow_path, QBrush(glow_color))
        elif self._hover_progress > 0:
            hover_alpha = int(10 + self._hover_progress * 12)
            p.fillPath(path, QBrush(QColor(255, 255, 255, hover_alpha)))

            glow_r = r.adjusted(-1, -1, 1, 1)
            glow_path = QPainterPath()
            glow_path.addRoundedRect(glow_r, 13, 13)
            glow_alpha = int(self._hover_progress * 15)
            p.fillPath(glow_path, QBrush(QColor(100, 210, 255, glow_alpha)))

        shine = QLinearGradient(QPointF(r.left(), r.top()), QPointF(r.left(), r.bottom()))
        shine_alpha = int(15 + self._hover_progress * 20)
        shine.setColorAt(0.0, QColor(255, 255, 255, shine_alpha))
        shine.setColorAt(0.5, QColor(255, 255, 255, 3))
        shine.setColorAt(1.0, QColor(255, 255, 255, 0))
        p.fillPath(path, QBrush(shine))

        border_alpha = int(25 + self._hover_progress * 35)
        if self._active:
            border_color = QColor(_GREEN)
            border_color.setAlpha(border_alpha + 60)
        else:
            border_color = QColor(255, 255, 255, border_alpha)
        p.setPen(QPen(border_color, 1.0))
        p.setBrush(Qt.BrushStyle.NoBrush)
        p.drawPath(path)

        p.setPen(QPen(QColor(255, 255, 255, 8), 1))
        p.drawLine(int(r.left() + 16), int(r.bottom()), int(r.right() - 16), int(r.bottom()))
        self._hover_anim.setStartValue(self._hover_progress)
        self._hover_anim.setEndValue(0.0)
        self._hover_anim.start()

    def paintEvent(self, _) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)

        r = QRectF(self.rect()).adjusted(0.5, 0.5, -0.5, -0.5)
        path = QPainterPath()
        path.addRoundedRect(r, 12, 12)

        if self._active:
            active_alpha = 18 + int(self._hover_progress * 10)
            p.fillPath(path, QBrush(QColor(48, 209, 88, active_alpha)))

            if self._hover_progress > 0:
                glow_rect = r.adjusted(-2, -2, 2, 2)
                glow_path = QPainterPath()
                glow_path.addRoundedRect(glow_rect, 14, 14)
                glow_alpha = int(self._hover_progress * 40)
                p.fillPath(glow_path, QBrush(QColor(48, 209, 88, glow_alpha)))
        elif self._hover_progress > 0:
            hover_alpha = int(8 + self._hover_progress * 8)
            p.fillPath(path, QBrush(QColor(255, 255, 255, hover_alpha)))

        if self._expand_rotation > 0:
            p.save()
            btn_rect = self._expand_btn.geometry()
            center = QPointF(btn_rect.center())
            p.translate(center)
            p.rotate(self._expand_rotation)
            p.translate(-center)
            p.restore()


class DashboardPage(QWidget):
    start_stop = pyqtSignal()

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._status = "idle"
        self._running = False
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)

        col = QVBoxLayout(self)
        col.setContentsMargins(24, 24, 24, 24)
        col.setSpacing(16)

        hdr = QLabel("Dashboard")
        hf = _get_font(20, QFont.Weight.Bold)
        hdr.setFont(hf)
        hdr.setStyleSheet("color: rgba(255,255,255,0.92);")
        col.addWidget(hdr)

        stats_row = QHBoxLayout()
        stats_row.setSpacing(12)

        self._status_card = self._create_stat_card("Status", "Idle", _BLUE)
        stats_row.addWidget(self._status_card)

        self._device_card = self._create_stat_card("Devices", "—", _TEAL)
        stats_row.addWidget(self._device_card)

        self._scan_card = self._create_stat_card("Scans", "0", _PURPLE)
        stats_row.addWidget(self._scan_card)

        self._removed_card = self._create_stat_card("Removed", "0", _RED)
        stats_row.addWidget(self._removed_card)

        col.addLayout(stats_row)

        info_panel = GlassPanel(radius=14, dark=True)
        info_layout = QVBoxLayout(info_panel)
        info_layout.setContentsMargins(20, 20, 20, 20)
        info_layout.setSpacing(12)

        expiry_row = QHBoxLayout()
        expiry_lbl = QLabel("Account Expiry:")
        ef = _get_font(12, QFont.Weight.Medium)
        expiry_lbl.setFont(ef)
        expiry_lbl.setStyleSheet("color: rgba(255,255,255,0.65);")
        expiry_row.addWidget(expiry_lbl)

        self._expiry_val = QLabel("—")
        evf = _get_font(12, QFont.Weight.Bold)
        self._expiry_val.setFont(evf)
        self._expiry_val.setStyleSheet("color: rgba(255,159,10,0.90);")
        expiry_row.addWidget(self._expiry_val)
        expiry_row.addStretch()

        info_layout.addLayout(expiry_row)
        col.addWidget(info_panel)

        col.addStretch()

        self._toggle_btn = GlassButton("Start Guardian", _GREEN, height=48)
        self._toggle_btn.clicked.connect(self.start_stop.emit)
        col.addWidget(self._toggle_btn)

    def _create_stat_card(self, label: str, value: str, color: QColor) -> QWidget:
        card = GlassPanel(radius=12, dark=True, hoverable=True)
        card.setFixedHeight(100)

        layout = QVBoxLayout(card)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(8)

        lbl = QLabel(label)
        lf = _get_font(10, QFont.Weight.Medium)
        lbl.setFont(lf)
        lbl.setStyleSheet("color: rgba(255,255,255,0.50);")
        layout.addWidget(lbl)

        val = QLabel(value)
        vf = _get_font(24, QFont.Weight.Bold)
        val.setFont(vf)
        val.setStyleSheet(f"color: {color.name()};")
        val.setObjectName("value")
        layout.addWidget(val)

        layout.addStretch()

        return card
        layout.addWidget(val)

        layout.addStretch()

        return card

    def set_status(self, status: str, running: bool) -> None:
        self._status = status
        self._running = running

        labels = {
            "idle": "Idle",
            "authenticating": "Authenticating…",
            "running": "Active",
            "error": "Error",
        }
        status_text = labels.get(status, status.capitalize())

        val_lbl = self._status_card.findChild(QLabel, "value")
        if val_lbl:
            val_lbl.setText(status_text)

        self._toggle_btn.text = "Stop Guardian" if running else "Start Guardian"
        self._toggle_btn.color = _RED if running else _GREEN

    def set_device_count(self, count: int) -> None:
        val_lbl = self._device_card.findChild(QLabel, "value")
        if val_lbl:
            val_lbl.setText(str(count))

    def set_stats(self, scans: int, removed: int) -> None:
        scan_lbl = self._scan_card.findChild(QLabel, "value")
        if scan_lbl:
            scan_lbl.setText(str(scans))

        removed_lbl = self._removed_card.findChild(QLabel, "value")
        if removed_lbl:
            removed_lbl.setText(str(removed))

    def set_expiry(self, expiry: str) -> None:
        self._expiry_val.setText(expiry)


class SettingsPage(QWidget):
    settings_saved = pyqtSignal(dict)

    def __init__(self, cfg: dict, parent=None) -> None:
        super().__init__(parent)
        self._cfg = cfg
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea { background: transparent; border: none; }")

        content = QWidget()
        col = QVBoxLayout(content)
        col.setContentsMargins(24, 24, 24, 24)
        col.setSpacing(16)

        hdr = QLabel("Settings")
        hf = _get_font(20, QFont.Weight.Bold)
        hdr.setFont(hf)
        hdr.setStyleSheet("color: rgba(255,255,255,0.92);")
        col.addWidget(hdr)

        panel = GlassPanel(radius=14, dark=True)
        pl = QVBoxLayout(panel)
        pl.setContentsMargins(20, 20, 20, 20)
        pl.setSpacing(16)

        pl.addWidget(_label("Account Number"))
        self._account_field = _field(cfg.get("account_num", ""), "Enter Mullvad account number")
        pl.addWidget(self._account_field)

        pl.addWidget(_label("Discord Webhook URL"))
        self._webhook_field = _field(cfg.get("discord_webhook", ""), "https://discord.com/api/webhooks/...")
        pl.addWidget(self._webhook_field)

        pl.addWidget(_label("Check Interval (seconds)"))
        self._interval_field = _field(str(cfg.get("check_interval", 3)), "3")
        pl.addWidget(self._interval_field)

        col.addWidget(panel)
        col.addStretch()

        save_btn = GlassButton("Save Settings", _BLUE, height=44)
        save_btn.clicked.connect(self._save)
        col.addWidget(save_btn)

        scroll.setWidget(content)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(scroll)

    def _save(self) -> None:
        self._cfg["account_num"] = self._account_field.text().strip()
        self._cfg["discord_webhook"] = self._webhook_field.text().strip()
        try:
            interval = int(self._interval_field.text().strip())
            if 1 <= interval <= 60:
                self._cfg["check_interval"] = interval
        except ValueError:
            pass

        _save_cfg(self._cfg)
        self.settings_saved.emit(self._cfg)


class LogPanel(GlassPanel):
    _COLS = {
        "DEBUG":    "rgba(155,155,175,0.55)",
        "INFO":     "rgba(210,212,228,0.85)",
        "WARNING":  "#FF9F0A",
        "ERROR":    "#FF453A",
        "CRITICAL": "#FF453A",
    }

    def __init__(self, parent=None) -> None:
        super().__init__(parent, radius=0, dark=True)
        col = QVBoxLayout(self)
        col.setContentsMargins(0, 8, 0, 0)
        col.setSpacing(0)
        hdr = QLabel("  LOG OUTPUT")
        hf  = _get_font(8, QFont.Weight.Bold)
        hdr.setFont(hf)
        hdr.setStyleSheet("color: rgba(255,255,255,0.22); letter-spacing:1.6px; padding-left:14px;")
        col.addWidget(hdr)
        self._view = QTextEdit(readOnly=True)
        mf = QFont("JetBrains Mono", 10)
        self._view.setFont(mf)
        self._view.setStyleSheet("""
            QTextEdit { background: transparent; color: rgba(210,212,228,0.85);
                        border: none; padding: 4px 14px 8px; }
            QScrollBar:vertical { background: rgba(255,255,255,0.03); width: 4px; border-radius: 2px; margin: 0; }
            QScrollBar::handle:vertical { background: rgba(255,255,255,0.18); border-radius: 2px; min-height: 20px; }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
        """)
        col.addWidget(self._view)

    def append(self, level: str, msg: str) -> None:
        ts = datetime.now().strftime("%H:%M:%S")
        col = self._COLS.get(level, self._COLS["INFO"])
        html = f'<span style="color: rgba(255,255,255,0.35);">[{ts}]</span> <span style="color: {col};">{msg}</span>'
        self._view.append(html)
        self._view.verticalScrollBar().setValue(self._view.verticalScrollBar().maximum())


class ConnectPage(QWidget):
    def __init__(self, cfg: dict, main_window=None, parent=None) -> None:
        super().__init__(parent)
        self._cfg = cfg
        self._main_window = main_window
        self._vpn_worker = None
        self._ping_worker = None
        self._countries = []
        self._server_rows = {}
        self._all_servers = []
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)

        col = QVBoxLayout(self)
        col.setContentsMargins(24, 24, 24, 24)
        col.setSpacing(12)

        hdr_row = QHBoxLayout()
        hdr = QLabel("VPN Connection")
        hf = _get_font(18, QFont.Weight.DemiBold)
        hdr.setFont(hf)
        hdr.setStyleSheet("color: rgba(255,255,255,0.88);")
        hdr_row.addWidget(hdr)
        hdr_row.addStretch()
        col.addLayout(hdr_row)

        status_panel = GlassPanel(radius=14, dark=True)
        sp_layout = QVBoxLayout(status_panel)
        sp_layout.setContentsMargins(20, 16, 20, 16)
        sp_layout.setSpacing(10)

        status_row = QHBoxLayout()
        self._vpn_dot = StatusDot()
        status_row.addWidget(self._vpn_dot)
        self._vpn_state_lbl = QLabel("Disconnected")
        vf = _get_font(14, QFont.Weight.DemiBold)
        self._vpn_state_lbl.setFont(vf)
        self._vpn_state_lbl.setStyleSheet("color: rgba(255,255,255,0.88);")
        status_row.addWidget(self._vpn_state_lbl)
        status_row.addStretch()
        sp_layout.addLayout(status_row)

        self._vpn_detail_lbl = QLabel("—")
        df = _get_font(11)
        self._vpn_detail_lbl.setFont(df)
        self._vpn_detail_lbl.setStyleSheet("color: rgba(255,255,255,0.50);")
        sp_layout.addWidget(self._vpn_detail_lbl)

        self._vpn_ip_lbl = QLabel("")
        ipf = _get_font(10, monospace=True)
        self._vpn_ip_lbl.setFont(ipf)
        self._vpn_ip_lbl.setStyleSheet("color: rgba(255,255,255,0.38);")
        sp_layout.addWidget(self._vpn_ip_lbl)

        btn_row = QHBoxLayout()
        self._vpn_btn = GlassButton("Connect", _GREEN, height=38)
        self._vpn_btn.clicked.connect(self._toggle_vpn)
        btn_row.addWidget(self._vpn_btn)

        self._ping_btn = GlassButton("📡 Ping All Servers", QColor(255, 255, 255, 30), height=38)
        self._ping_btn.clicked.connect(self._start_ping_all)
        btn_row.addWidget(self._ping_btn)

        sp_layout.addLayout(btn_row)
        col.addWidget(status_panel)

        search_row = QHBoxLayout()
        search_field = _field("", "Search countries...")
        search_field.textChanged.connect(self._filter)
        search_row.addWidget(search_field)
        col.addLayout(search_row)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea { background: transparent; border: none; }")

        scroll_content = QWidget()
        self._c_layout = QVBoxLayout(scroll_content)
        self._c_layout.setContentsMargins(0, 0, 0, 0)
        self._c_layout.setSpacing(4)

        self._loading_lbl = QLabel("Loading servers...")
        lf = _get_font(12)
        self._loading_lbl.setFont(lf)
        self._loading_lbl.setStyleSheet("color: rgba(255,255,255,0.45);")
        self._loading_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._c_layout.addWidget(self._loading_lbl)

        self._c_layout.addStretch()

        scroll.setWidget(scroll_content)
        col.addWidget(scroll, 1)

        self._fetch_relays()
        self._start_vpn_worker()

    def _toggle_vpn(self) -> None:
        if not MullvadCLI.available():
            return

        status = MullvadCLI.status()
        state = status.get("state", "unknown")

        if state == "connected":
            MullvadCLI.disconnect()
        else:
            if not MullvadCLI.ensure_logged_in(self._cfg.get("account_num", "")):
                return
            MullvadCLI.connect()

    def _connect_server(self, hostname: str) -> None:
        if not MullvadCLI.ensure_logged_in(self._cfg.get("account_num", "")):
            return
        MullvadCLI.set_relay(hostname)
        MullvadCLI.connect()

    def _connect_country(self, hostname: str) -> None:
        if not MullvadCLI.ensure_logged_in(self._cfg.get("account_num", "")):
            return
        parts = hostname.split("-")
        if len(parts) >= 2:
            country = parts[0]
            city = parts[1]
            MullvadCLI.set_location(country, city)
            MullvadCLI.connect()

    def _set_proto(self, proto: str) -> None:
        MullvadCLI.set_protocol(proto)
        self._cfg["vpn_protocol"] = proto
        _save_cfg(self._cfg)

    def _set_kill_switch(self, on: bool) -> None:
        MullvadCLI.set_kill_switch(on)
        self._cfg["vpn_kill_switch"] = on
        _save_cfg(self._cfg)

    def _set_block_ads(self, on: bool) -> None:
        MullvadCLI.set_block_ads(on)
        self._cfg["vpn_block_ads"] = on
        _save_cfg(self._cfg)

    def _set_auto_reconnect(self, on: bool) -> None:
        self._cfg["auto_reconnect"] = on
        _save_cfg(self._cfg)
        if self._main_window and hasattr(self._main_window, '_worker') and self._main_window._worker:
            self._main_window._worker._auto_reconnect = on

    def _set_persistent_connect(self, on: bool) -> None:
        self._cfg["persistent_connect"] = on
        _save_cfg(self._cfg)
        if self._main_window and hasattr(self._main_window, '_worker') and self._main_window._worker:
            self._main_window._worker._persistent_connect = on

    def _start_auto_ping(self) -> None:
        if self._ping_worker and self._ping_worker.isRunning():
            self._ping_worker.stop()
            self._ping_worker.wait(2000)

        if not self._all_servers:
            return

        self._ping_worker = PingWorker(self._all_servers, auto_refresh=True, refresh_interval=3)
        self._ping_worker.ping_result.connect(self._on_ping_result)
        self._ping_worker.cycle_finished.connect(self._on_ping_cycle_finished)
        self._ping_worker.start()

    def _start_ping_all(self) -> None:
        if self._ping_worker and self._ping_worker.isRunning():
            return

        if not self._all_servers:
            return

        self._ping_btn.text = "Pinging..."
        self._ping_btn.setEnabled(False)

        self._ping_worker = PingWorker(self._all_servers, auto_refresh=False)
        self._ping_worker.ping_result.connect(self._on_ping_result)
        self._ping_worker.cycle_finished.connect(self._on_ping_finished)
        self._ping_worker.start()

    def _on_ping_result(self, hostname: str, ping_ms: float) -> None:
        for country_code, server_rows in self._server_rows.items():
            for server_row in server_rows:
                if server_row.get_hostname() == hostname:
                    server_row.set_ping(ping_ms)
                    break

        for country_row in self._countries:
            country_row.update_best_ping()

    def _on_ping_cycle_finished(self) -> None:
        pass

    def _on_ping_finished(self) -> None:
        self._ping_btn.text = "📡 Ping All Servers"
        self._ping_btn.setEnabled(True)


    def _start_vpn_worker(self) -> None:
        if not MullvadCLI.available():
            return
        self._vpn_worker = VPNStatusWorker(self._cfg.get("account_num", ""))
        self._vpn_worker.status_changed.connect(self._on_vpn_status)
        self._vpn_worker.logged_out.connect(self._on_logged_out)
        self._vpn_worker.start()

    def _on_logged_out(self) -> None:
        pass

    def _on_vpn_status(self, status: dict) -> None:
        state    = status.get("state", "unknown")
        location = status.get("location") or ""
        server   = status.get("server") or ""
        ip       = status.get("ip") or ""

        labels = {
            "connected":    "Connected",
            "disconnected": "Disconnected",
            "connecting":   "Connecting…",
            "blocked":      "Kill Switch Active",
            "inactive":     "Device inactive",
            "unavailable":  "mullvad CLI not found",
            "unknown":      "Unknown",
        }
        self._vpn_state_lbl.setText(labels.get(state, state.capitalize()))
        self._vpn_dot.set_status(state)
        self._vpn_ip_lbl.setText(ip)

        if state == "connected":
            detail = location or server
            self._vpn_detail_lbl.setText(detail)
            self._vpn_btn.text  = "Disconnect"
            self._vpn_btn.color = _RED
            cc        = (status.get("country_code") or "").upper()
            loc_lower = location.lower()
            for row in self._countries:
                match_cc   = bool(cc)        and row._code == cc
                match_name = bool(loc_lower) and row._name.lower() in loc_lower
                row.set_active(match_cc or match_name)
        elif state == "blocked":
            self._vpn_detail_lbl.setText("Traffic blocked until connected")
            self._vpn_btn.text  = "Connect"
            self._vpn_btn.color = _ORANGE
            for row in self._countries:
                row.set_active(False)
        else:
            self._vpn_detail_lbl.setText("—")
            self._vpn_btn.text  = "Connect"
            self._vpn_btn.color = _GREEN
            for row in self._countries:
                row.set_active(False)


    def _fetch_relays(self) -> None:
        fetcher = RelayFetcher(self)
        fetcher.done.connect(self._on_relays)
        fetcher.start()

    def _on_relays(self, countries: list[RelayCountry]) -> None:
        self._loading_lbl.hide()
        while self._c_layout.count() > 1:
            item = self._c_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        self._countries = []
        self._server_rows = {}
        self._all_servers = []

        for country in countries:
            self._all_servers.extend(country.servers)

            row = CountryRow(country)
            row.connect_clicked.connect(self._connect_country)
            row.expand_clicked.connect(lambda r=row: self._toggle_country_expansion(r))
            self._c_layout.insertWidget(self._c_layout.count() - 1, row)
            self._countries.append(row)

            server_rows = []
            for server in country.servers:
                server_row = ServerRow(server)
                server_row.connect_clicked.connect(self._connect_server)
                server_row.hide()
                self._c_layout.insertWidget(self._c_layout.count() - 1, server_row)
                server_rows.append(server_row)

            self._server_rows[country.code] = server_rows

        self._start_auto_ping()

    def _toggle_country_expansion(self, country_row: CountryRow) -> None:
        country_code = country_row._code
        server_rows = self._server_rows.get(country_code, [])

        is_expanded = country_row.is_expanded()

        for i, server_row in enumerate(server_rows):
            if is_expanded:
                QTimer.singleShot(i * 15, lambda sr=server_row: sr.show())
            else:
                server_row.hide()

    def _filter(self, query: str) -> None:
        for row in self._countries:
            visible = row.matches(query) if query else True
            row.setVisible(visible)

            if not visible:
                country_code = row._code
                for server_row in self._server_rows.get(country_code, []):
                    server_row.hide()

    def stop_worker(self) -> None:
        if self._vpn_worker:
            self._vpn_worker.stop()
            self._vpn_worker.wait(2000)
        if self._ping_worker:
            self._ping_worker.stop()
            self._ping_worker.wait(2000)


class DevicesPage(QWidget):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._my_device = ""
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        col = QVBoxLayout(self)
        col.setContentsMargins(24, 24, 24, 24)
        col.setSpacing(12)

        hr = QHBoxLayout()
        hdr = QLabel("Connected Devices")
        hf = _get_font(18, QFont.Weight.DemiBold)
        hdr.setFont(hf)
        hdr.setStyleSheet("color: rgba(255,255,255,0.88);")
        hr.addWidget(hdr)
        hr.addStretch()
        self._count = QLabel("—")
        cf = _get_font(12)
        self._count.setFont(cf)
        self._count.setStyleSheet("color: rgba(255,255,255,0.26);")
        hr.addWidget(self._count)
        col.addLayout(hr)

        panel = GlassPanel(radius=14, dark=True)
        pl    = QVBoxLayout(panel)
        pl.setContentsMargins(0, 0, 0, 0)
        scroll = _scrollarea()
        self._container = QWidget()
        self._container.setStyleSheet("background: transparent;")
        self._layout = QVBoxLayout(self._container)
        self._layout.setContentsMargins(12, 12, 12, 12)
        self._layout.setSpacing(6)
        self._empty = QLabel("No devices — start the guardian to monitor")
        self._empty.setAlignment(Qt.AlignmentFlag.AlignCenter)
        ef = _get_font(13)
        self._empty.setFont(ef)
        self._empty.setStyleSheet("color: rgba(255,255,255,0.16);")
        self._layout.addWidget(self._empty)
        self._layout.addStretch()
        scroll.setWidget(self._container)
        pl.addWidget(scroll)
        col.addWidget(panel, 1)

    def set_my_device(self, name: str) -> None:
        self._my_device = name

    def update_devices(self, data: list) -> None:
        while self._layout.count():
            item = self._layout.takeAt(0)
            w = item.widget()
            if w and w is not self._empty:
                w.deleteLater()
        n = len(data)
        self._count.setText(f"{n} device{'s' if n != 1 else ''}")
        if n == 0:
            self._layout.addWidget(self._empty); self._empty.show()
            self._layout.addStretch()
        else:
            self._empty.hide()
            for _, name, authorized in data:
                is_me = name.lower().strip() == self._my_device.lower().strip()
                self._layout.addWidget(DeviceCard(name, authorized, is_me))
            self._layout.addStretch()


class WhitelistPage(QWidget):
    whitelist_changed = pyqtSignal(list)

    def __init__(self, names: list, parent=None) -> None:
        super().__init__(parent)
        self._names: list[str] = list(names)
        self._auto_name: str | None = None
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        col = QVBoxLayout(self)
        col.setContentsMargins(24, 24, 24, 24)
        col.setSpacing(12)

        hdr = QLabel("Whitelist")
        hf = _get_font(18, QFont.Weight.DemiBold)
        hdr.setFont(hf)
        hdr.setStyleSheet("color: rgba(255,255,255,0.88);")
        col.addWidget(hdr)

        sub = QLabel("Devices with these exact names are kept. Changes apply instantly, even while running.")
        subf = _get_font(11)
        sub.setFont(subf); sub.setWordWrap(True)
        sub.setStyleSheet("color: rgba(255,255,255,0.36);")
        col.addWidget(sub)

        panel = GlassPanel(radius=14, dark=True)
        pl    = QVBoxLayout(panel); pl.setContentsMargins(0, 0, 0, 0)
        scroll = _scrollarea()
        self._entries_w = QWidget()
        self._entries_w.setStyleSheet("background: transparent;")
        self._entries_l = QVBoxLayout(self._entries_w)
        self._entries_l.setContentsMargins(12, 8, 12, 8)
        self._entries_l.setSpacing(4)
        self._entries_l.addStretch()
        scroll.setWidget(self._entries_w)
        pl.addWidget(scroll)
        col.addWidget(panel, 1)

        add_row = QHBoxLayout(); add_row.setSpacing(8)
        self._add_field = _field(placeholder="Device name to allow…")
        self._add_field.returnPressed.connect(self._add)
        add_row.addWidget(self._add_field, 1)
        add_btn = GlassButton("Add", _BLUE, height=40)
        add_btn.setFixedWidth(72)
        add_btn.clicked.connect(self._add)
        add_row.addWidget(add_btn)
        col.addLayout(add_row)

        self._rebuild()

    def _rebuild(self) -> None:
        while self._entries_l.count() > 1:
            item = self._entries_l.takeAt(0)
            if item.widget(): item.widget().deleteLater()

        idx = 0
        self._entries_l.insertWidget(idx, self._section_header("MANUALLY ADDED")); idx += 1
        if self._names:
            for name in self._names:
                self._entries_l.insertWidget(idx, self._make_row(name, auto=False)); idx += 1
        else:
            self._entries_l.insertWidget(idx, self._empty_label("No manual entries")); idx += 1

        self._entries_l.insertWidget(idx, self._section_header("AUTOMATICALLY ADDED")); idx += 1
        if self._auto_name:
            self._entries_l.insertWidget(idx, self._make_row(self._auto_name, auto=True)); idx += 1
        else:
            self._entries_l.insertWidget(idx, self._empty_label("Detecting current device…")); idx += 1

    def _section_header(self, text: str) -> QLabel:
        lbl = QLabel(text)
        f = _get_font(9, QFont.Weight.Bold)
        lbl.setFont(f)
        lbl.setStyleSheet(
            "color: rgba(255,255,255,0.30); letter-spacing: 1.4px; padding: 12px 6px 6px 6px;"
        )
        return lbl

    def _empty_label(self, text: str) -> QLabel:
        lbl = QLabel(f"  {text}")
        f = _get_font(11)
        lbl.setFont(f)
        lbl.setStyleSheet("color: rgba(255,255,255,0.18); padding: 4px 6px;")
        return lbl

    def _make_row(self, name: str, auto: bool) -> QWidget:
        wrapper = QWidget(); wrapper.setStyleSheet("background: transparent;")
        wl = QVBoxLayout(wrapper); wl.setContentsMargins(0, 0, 0, 0); wl.setSpacing(0)
        row = QWidget(); row.setStyleSheet("background: transparent;")
        rl = QHBoxLayout(row); rl.setContentsMargins(6, 6, 6, 6); rl.setSpacing(10)

        dot_color = "#64D2FF" if auto else "#30D158"
        dot = QLabel(); dot.setFixedSize(8, 8)
        dot.setStyleSheet(f"background: {dot_color}; border-radius: 4px;")
        rl.addWidget(dot)

        nm = QLabel(name)
        nf = _get_font(13); nf.setStyleHint(QFont.StyleHint.SansSerif)
        nm.setFont(nf); nm.setStyleSheet("color: rgba(255,255,255,0.82);")
        rl.addWidget(nm, 1)

        if auto:
            badge = QLabel("auto")
            bf = _get_font(10, QFont.Weight.DemiBold)
            badge.setFont(bf)
            badge.setStyleSheet("""
                QLabel { color: rgba(100,210,255,0.90); background: rgba(100,210,255,0.12);
                         border: 1px solid rgba(100,210,255,0.45);
                         border-radius: 8px; padding: 2px 9px; }
            """)
            rl.addWidget(badge)
        else:
            rm_btn = GlassButton("Remove", _RED, height=28)
            rm_btn.setFixedWidth(80)
            rm_btn.clicked.connect(lambda: self._remove(name))
            rl.addWidget(rm_btn)

        wl.addWidget(row)
        sep = QWidget(); sep.setFixedHeight(1)
        sep.setStyleSheet("background: rgba(255,255,255,0.04);")
        wl.addWidget(sep)
        return wrapper

    def _add(self) -> None:
        name = self._add_field.text().strip()
        if not name or name in self._names:
            return
        self._names.append(name)
        self._add_field.clear()
        self._rebuild()
        self.whitelist_changed.emit(self._names)

    def _remove(self, name: str) -> None:
        if name in self._names:
            self._names.remove(name)
            self._rebuild()
            self.whitelist_changed.emit(self._names)

    def set_auto_protected(self, name: str) -> None:
        self._auto_name = name
        self._rebuild()

    def get_names(self) -> list[str]:
        return self._names


class MainWindow(QWidget):
    def __init__(self) -> None:
        super().__init__()
        self._cfg = _load_cfg()
        self._worker = None
        self._setup_window()
        self._build_ui()
        self._ensure_login()

    def _ensure_login(self) -> None:
        account_num = self._cfg.get("account_num", "")
        if not account_num:
            return

        def login_worker():
            max_attempts = 10
            attempt = 0

            while attempt < max_attempts:
                attempt += 1

                if MullvadCLI.is_logged_in():
                    return

                if MullvadCLI.relogin(account_num):
                    return

                time.sleep(3)

        import threading
        thread = threading.Thread(target=login_worker, daemon=True)
        thread.start()

    def _setup_window(self) -> None:
        self.setWindowTitle("Mullvad Guardian")
        self.resize(1020, 700)
        self.setMinimumSize(880, 600)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint | Qt.WindowType.Window)

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(12, 12, 12, 12)
        root.setSpacing(0)

        shell = GlassPanel(self, radius=22, dark=True)
        sl    = QVBoxLayout(shell)
        sl.setContentsMargins(0, 0, 0, 0)
        sl.setSpacing(0)

        self._title = TitleBar(shell)
        self._title.close_clicked.connect(self.close)
        self._title.minimize_clicked.connect(self.showMinimized)
        sl.addWidget(self._title)

        sep1 = QWidget(); sep1.setFixedHeight(1)
        sep1.setStyleSheet("background: rgba(255,255,255,0.07);")
        sl.addWidget(sep1)

        body = QHBoxLayout()
        body.setContentsMargins(0, 0, 0, 0); body.setSpacing(0)
        body.addWidget(self._build_nav())
        sep2 = QWidget(); sep2.setFixedWidth(1)
        sep2.setStyleSheet("background: rgba(255,255,255,0.06);")
        body.addWidget(sep2)

        self._stack = QStackedWidget()
        self._stack.setStyleSheet("background: transparent;")

        self._dash_page = DashboardPage()
        self._dash_page.start_stop.connect(self._toggle)
        self._stack.addWidget(self._dash_page)

        self._connect_page = ConnectPage(self._cfg, main_window=self)
        self._stack.addWidget(self._connect_page)

        self._dev_page = DevicesPage()
        self._stack.addWidget(self._dev_page)

        self._wl_page = WhitelistPage(self._cfg.get("whitelist", []))
        self._wl_page.whitelist_changed.connect(self._on_whitelist_changed)
        self._stack.addWidget(self._wl_page)

        self._settings_page = SettingsPage(self._cfg)
        self._settings_page.settings_saved.connect(self._on_settings_saved)
        self._stack.addWidget(self._settings_page)

        body.addWidget(self._stack, 1)
        sl.addLayout(body, 1)

        sep3 = QWidget(); sep3.setFixedHeight(1)
        sep3.setStyleSheet("background: rgba(255,255,255,0.06);")
        sl.addWidget(sep3)

        self._log_panel = LogPanel(shell)
        self._log_panel.setFixedHeight(138)
        sl.addWidget(self._log_panel)

        MullvadCLI.log_callback = self._log_panel.append

        root.addWidget(shell)

    def _build_nav(self) -> QWidget:
        nav = QWidget(); nav.setFixedWidth(80)
        nav.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        col = QVBoxLayout(nav)
        col.setContentsMargins(6, 10, 6, 10); col.setSpacing(2)
        mini = ShieldWidget(24)
        col.addWidget(mini, 0, Qt.AlignmentFlag.AlignCenter)
        col.addSpacing(8)
        self._nav_btns: list[NavBtn] = []
        pages = [("⬡", "Home"), ("⊕", "Connect"), ("☰", "Devices"), ("✓", "Whitelist"), ("⚙", "Settings")]
        for i, (icon, label) in enumerate(pages):
            btn = NavBtn(icon, label)
            btn.clicked.connect(lambda idx=i: self._nav_to(idx))
            if i == 0: btn.set_active(True)
            self._nav_btns.append(btn)
            col.addWidget(btn)
        col.addStretch()
        return nav

    def _nav_to(self, idx: int) -> None:
        for i, b in enumerate(self._nav_btns):
            b.set_active(i == idx)
        self._stack.setCurrentIndex(idx)


    def _toggle(self) -> None:
        if self._worker and self._worker.isRunning():
            self._stop()
        else:
            self._start()

    def _start(self) -> None:
        cfg = self._cfg
        w = GuardianWorker(
            account_num=cfg.get("account_num", ""),
            whitelist=self._wl_page.get_names(),
            discord_webhook=cfg.get("discord_webhook", ""),
            check_interval=cfg.get("check_interval", 3),
            max_retries=cfg.get("max_retries", 3),
            backoff_base=cfg.get("backoff_base", 30),
            session_refresh=cfg.get("session_refresh", 3600),
            auto_reconnect=cfg.get("auto_reconnect", True),
            persistent_connect=cfg.get("persistent_connect", True),
        )
        w.log_emitted.connect(self._log_panel.append)
        w.status_changed.connect(self._on_status)
        w.devices_updated.connect(self._on_devices)
        w.expiry_updated.connect(self._dash_page.set_expiry)
        w.stats_updated.connect(self._on_stats)
        w.self_detected.connect(self._on_self_detected)
        w.self_removed.connect(self._on_self_removed)
        w.start()
        self._worker = w
        self._dash_page.set_status("authenticating", True)

    def _stop(self) -> None:
        if self._worker:
            self._worker.stop()
            self._worker.wait(4000)
            self._worker = None
        self._on_status("idle")


    def _on_status(self, s: str) -> None:
        running = bool(self._worker and self._worker.isRunning())
        self._dash_page.set_status(s, running)
        self._title.set_status(s)

    def _on_devices(self, data: list) -> None:
        self._dev_page.update_devices(data)
        self._dash_page.set_device_count(len(data))

    def _on_stats(self, scans: int, removed: int) -> None:
        self._dash_page.set_stats(scans, removed)

    def _on_self_detected(self, name: str) -> None:
        self._log_panel.append("INFO", f"Auto-detected own device: '{name}' — auto-protected.")
        self._dev_page.set_my_device(name)
        self._wl_page.set_auto_protected(name)

    def _on_self_removed(self) -> None:
        self._log_panel.append("WARNING", "Own device was removed from account — reconnecting…")

    def _on_whitelist_changed(self, names: list) -> None:
        self._cfg["whitelist"] = names
        _save_cfg(self._cfg)
        if self._worker:
            self._worker.update_whitelist(names)

    def _on_settings_saved(self, cfg: dict) -> None:
        self._cfg = cfg
        if self._worker:
            self._worker.update_interval(cfg.get("check_interval", 3))
            self._worker.update_webhook(cfg.get("discord_webhook", ""))


    def closeEvent(self, e) -> None:
        self._connect_page.stop_worker()
        if self._worker:
            self._worker.stop()
            self._worker.wait(4000)
        e.accept()

    def paintEvent(self, _) -> None:
        p = QPainter(self)
        p.setCompositionMode(QPainter.CompositionMode.CompositionMode_Source)
        p.fillRect(self.rect(), QColor(0, 0, 0, 0))



def main() -> None:
    app = QApplication(sys.argv)
    app.setApplicationName("Mullvad Guardian")
    app.setStyle("Fusion")
    pal = QPalette()
    pal.setColor(QPalette.ColorRole.Window,     QColor(12, 14, 26))
    pal.setColor(QPalette.ColorRole.WindowText, _WHITE)
    pal.setColor(QPalette.ColorRole.Base,       QColor(18, 20, 34))
    pal.setColor(QPalette.ColorRole.Text,       _WHITE)
    pal.setColor(QPalette.ColorRole.Button,     QColor(30, 32, 50))
    pal.setColor(QPalette.ColorRole.ButtonText, _WHITE)
    app.setPalette(pal)
    win = MainWindow()
    win.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
