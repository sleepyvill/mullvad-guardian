
import sys
import time
import signal
import argparse
import platform
import threading
import select
import termios
import tty
from pathlib import Path
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent))
from gui import GuardianWorker, _load_cfg, _save_cfg, MullvadCLI



class Colors:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"

    BLACK = "\033[30m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"

    BRIGHT_BLACK = "\033[90m"
    BRIGHT_RED = "\033[91m"
    BRIGHT_GREEN = "\033[92m"
    BRIGHT_YELLOW = "\033[93m"
    BRIGHT_BLUE = "\033[94m"
    BRIGHT_MAGENTA = "\033[95m"
    BRIGHT_CYAN = "\033[96m"
    BRIGHT_WHITE = "\033[97m"

    BG_BLACK = "\033[40m"
    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_YELLOW = "\033[43m"
    BG_BLUE = "\033[44m"
    BG_MAGENTA = "\033[45m"
    BG_CYAN = "\033[46m"
    BG_WHITE = "\033[47m"


def clear_screen():
    print("\033[2J\033[H", end="")


def move_cursor(row, col):
    print(f"\033[{row};{col}H", end="")


def hide_cursor():
    print("\033[?25l", end="")


def show_cursor():
    print("\033[?25h", end="")


def box(text, width=60, color=Colors.CYAN):
    lines = text.split('\n')
    top = f"{color}╔{'═' * (width - 2)}╗{Colors.RESET}"
    bottom = f"{color}╚{'═' * (width - 2)}╝{Colors.RESET}"

    result = [top]
    for line in lines:
        padding = width - len(line) - 4
        result.append(f"{color}║{Colors.RESET} {line}{' ' * padding} {color}║{Colors.RESET}")
    result.append(bottom)

    return '\n'.join(result)


def progress_bar(current, total, width=40, color=Colors.GREEN):
    filled = int(width * current / total)
    bar = '█' * filled + '░' * (width - filled)
    percent = int(100 * current / total)
    return f"{color}{bar}{Colors.RESET} {percent}%"


def status_badge(text, status_type="info"):
    colors = {
        "success": (Colors.BG_GREEN, Colors.BLACK),
        "error": (Colors.BG_RED, Colors.WHITE),
        "warning": (Colors.BG_YELLOW, Colors.BLACK),
        "info": (Colors.BG_BLUE, Colors.WHITE),
    }
    bg, fg = colors.get(status_type, colors["info"])
    return f"{bg}{fg} {text} {Colors.RESET}"



class InteractiveCLI:
    def __init__(self, config: dict):
        self.config = config
        self.worker = None
        self.running = False
        self.logs = []
        self.max_logs = 15
        self.devices = []
        self.stats = {"scans": 0, "removed": 0}
        self.status = "idle"
        self.expiry = "Unknown"
        self.my_device = None
        self.last_update = time.time()
        self.lock = threading.Lock()
        self.show_menu = False
        self.menu_message = ""
        self.old_settings = None

    def log_handler(self, level: str, message: str):
        with self.lock:
            timestamp = datetime.now().strftime("%H:%M:%S")
            self.logs.append((timestamp, level, message))
            if len(self.logs) > self.max_logs:
                self.logs.pop(0)
            self.last_update = time.time()

    def status_handler(self, status: str):
        with self.lock:
            self.status = status
            self.last_update = time.time()

    def devices_handler(self, devices: list):
        with self.lock:
            self.devices = devices
            self.last_update = time.time()

    def expiry_handler(self, expiry: str):
        with self.lock:
            self.expiry = expiry
            self.last_update = time.time()

    def stats_handler(self, scans: int, removed: int):
        with self.lock:
            self.stats = {"scans": scans, "removed": removed}
            self.last_update = time.time()

    def self_detected_handler(self, name: str):
        with self.lock:
            self.my_device = name
            self.last_update = time.time()

    def self_removed_handler(self):
        with self.lock:
            self.last_update = time.time()

    def render_header(self):
        title = f"{Colors.BOLD}{Colors.BRIGHT_CYAN}🛡️  MULLVAD GUARDIAN{Colors.RESET}"
        subtitle = f"{Colors.DIM}Automated Device Monitoring & Removal{Colors.RESET}"

        print(f"\n{title:^80}")
        print(f"{subtitle:^70}\n")
        print(f"{Colors.BRIGHT_BLACK}{'─' * 80}{Colors.RESET}\n")

    def render_status(self):
        if self.status == "running":
            badge = status_badge("ACTIVE", "success")
        elif self.status == "error":
            badge = status_badge("ERROR", "error")
        else:
            badge = status_badge("IDLE", "info")

        vpn_status = MullvadCLI.status()
        vpn_state = vpn_status.get("state", "unknown")

        if vpn_state == "connected":
            vpn_badge = f"{Colors.GREEN}● Connected{Colors.RESET}"
            vpn_info = f"{Colors.DIM}{vpn_status.get('server', 'Unknown')} • {vpn_status.get('ip', 'N/A')}{Colors.RESET}"
        elif vpn_state == "disconnected":
            vpn_badge = f"{Colors.RED}● Disconnected{Colors.RESET}"
            vpn_info = ""
        else:
            vpn_badge = f"{Colors.YELLOW}● {vpn_state.title()}{Colors.RESET}"
            vpn_info = ""

        print(f"  {Colors.BOLD}Status:{Colors.RESET} {badge}  {Colors.BOLD}VPN:{Colors.RESET} {vpn_badge}")
        if vpn_info:
            print(f"         {vpn_info}")
        print()

    def render_config(self):
        print(f"  {Colors.BOLD}{Colors.BRIGHT_YELLOW}⚙  Configuration{Colors.RESET}")
        print(f"  {Colors.BRIGHT_BLACK}{'─' * 76}{Colors.RESET}")

        account = self.config.get("account_num", "Not set")
        masked = f"{account[:4]}...{account[-4:]}" if len(account) > 8 else account

        print(f"  {Colors.DIM}Account:{Colors.RESET}           {masked}")
        print(f"  {Colors.DIM}Check Interval:{Colors.RESET}    {self.config.get('check_interval', 3)}s")
        print(f"  {Colors.DIM}Auto-reconnect:{Colors.RESET}    {Colors.GREEN if self.config.get('auto_reconnect') else Colors.RED}{'Enabled' if self.config.get('auto_reconnect') else 'Disabled'}{Colors.RESET}")
        print(f"  {Colors.DIM}Persistent VPN:{Colors.RESET}    {Colors.GREEN if self.config.get('persistent_connect') else Colors.RED}{'Enabled' if self.config.get('persistent_connect') else 'Disabled'}{Colors.RESET}")

        whitelist = self.config.get("whitelist", [])
        if whitelist:
            print(f"  {Colors.DIM}Whitelist:{Colors.RESET}        {', '.join(whitelist)}")

        if self.my_device:
            print(f"  {Colors.DIM}Protected Device:{Colors.RESET} {Colors.GREEN}{self.my_device}{Colors.RESET}")

        print()

    def render_stats(self):
        print(f"  {Colors.BOLD}{Colors.BRIGHT_MAGENTA}📊 Statistics{Colors.RESET}")
        print(f"  {Colors.BRIGHT_BLACK}{'─' * 76}{Colors.RESET}")

        scans = self.stats["scans"]
        removed = self.stats["removed"]

        print(f"  {Colors.DIM}Total Scans:{Colors.RESET}       {Colors.CYAN}{scans}{Colors.RESET}")
        print(f"  {Colors.DIM}Devices Removed:{Colors.RESET}   {Colors.RED}{removed}{Colors.RESET}")
        print(f"  {Colors.DIM}Account Expiry:{Colors.RESET}    {Colors.YELLOW}{self.expiry}{Colors.RESET}")
        print()

    def render_devices(self):
        print(f"  {Colors.BOLD}{Colors.BRIGHT_GREEN}📱 Devices ({len(self.devices)}){Colors.RESET}")
        print(f"  {Colors.BRIGHT_BLACK}{'─' * 76}{Colors.RESET}")

        if not self.devices:
            print(f"  {Colors.DIM}No devices found yet...{Colors.RESET}")
        else:
            for device_id, name, whitelisted in self.devices[:10]:
                if whitelisted:
                    icon = f"{Colors.GREEN}✓{Colors.RESET}"
                    status = f"{Colors.DIM}Protected{Colors.RESET}"
                else:
                    icon = f"{Colors.RED}✗{Colors.RESET}"
                    status = f"{Colors.RED}Unauthorized{Colors.RESET}"

                print(f"  {icon} {name[:40]:<40} {status}")

            if len(self.devices) > 10:
                print(f"  {Colors.DIM}... and {len(self.devices) - 10} more{Colors.RESET}")

        print()

    def render_logs(self):
        print(f"  {Colors.BOLD}{Colors.BRIGHT_BLUE}📋 Activity Log{Colors.RESET}")
        print(f"  {Colors.BRIGHT_BLACK}{'─' * 76}{Colors.RESET}")

        if not self.logs:
            print(f"  {Colors.DIM}Waiting for activity...{Colors.RESET}")
        else:
            for timestamp, level, message in self.logs[-10:]:
                if level == "ERROR":
                    color = Colors.RED
                elif level == "WARNING":
                    color = Colors.YELLOW
                elif level == "INFO":
                    color = Colors.CYAN
                else:
                    color = Colors.WHITE

                if len(message) > 60:
                    message = message[:57] + "..."

                print(f"  {Colors.DIM}[{timestamp}]{Colors.RESET} {color}{message}{Colors.RESET}")

        print()

    def render_footer(self):
        print(f"{Colors.BRIGHT_BLACK}{'─' * 80}{Colors.RESET}")

        if self.menu_message:
            print(f"  {Colors.GREEN}{self.menu_message}{Colors.RESET}")

        shortcuts = [
            f"{Colors.CYAN}[I]{Colors.RESET} Interval",
            f"{Colors.CYAN}[R]{Colors.RESET} Auto-reconnect",
            f"{Colors.CYAN}[P]{Colors.RESET} Persistent VPN",
            f"{Colors.CYAN}[W]{Colors.RESET} Whitelist",
            f"{Colors.CYAN}[S]{Colors.RESET} Save Config",
            f"{Colors.CYAN}[Q]{Colors.RESET} Quit"
        ]
        print(f"  {' • '.join(shortcuts)}")
        print(f"  {Colors.DIM}Last update: {datetime.now().strftime('%H:%M:%S')}{Colors.RESET}\n")

    def render(self):
        clear_screen()
        self.render_header()
        self.render_status()
        self.render_config()
        self.render_stats()
        self.render_devices()
        self.render_logs()
        self.render_footer()

    def get_input(self):
        if sys.platform == 'win32':
            import msvcrt
            if msvcrt.kbhit():
                return msvcrt.getch().decode('utf-8').lower()
        else:
            dr, dw, de = select.select([sys.stdin], [], [], 0)
            if dr:
                return sys.stdin.read(1).lower()
        return None

    def toggle_auto_reconnect(self):
        self.config["auto_reconnect"] = not self.config.get("auto_reconnect", True)
        if self.worker:
            self.worker._auto_reconnect = self.config["auto_reconnect"]
        status = "enabled" if self.config["auto_reconnect"] else "disabled"
        self.menu_message = f"✓ Auto-reconnect {status}"
        self.last_update = time.time()

    def toggle_persistent_connect(self):
        self.config["persistent_connect"] = not self.config.get("persistent_connect", True)
        if self.worker:
            self.worker._persistent_connect = self.config["persistent_connect"]
        status = "enabled" if self.config["persistent_connect"] else "disabled"
        self.menu_message = f"✓ Persistent VPN {status}"
        self.last_update = time.time()

    def change_interval(self):
        show_cursor()
        print(f"\n  {Colors.CYAN}Enter new check interval (seconds):{Colors.RESET} ", end="", flush=True)

        try:
            interval = int(input().strip())
            if 1 <= interval <= 60:
                self.config["check_interval"] = interval
                if self.worker:
                    self.worker.update_interval(interval)
                self.menu_message = f"✓ Check interval set to {interval}s"
            else:
                self.menu_message = "✗ Interval must be between 1-60 seconds"
        except (ValueError, EOFError):
            self.menu_message = "✗ Invalid interval"

        hide_cursor()
        self.last_update = time.time()

    def add_whitelist(self):
        show_cursor()
        print(f"\n  {Colors.CYAN}Enter device name to whitelist:{Colors.RESET} ", end="", flush=True)

        try:
            device_name = input().strip()
            if device_name:
                whitelist = self.config.get("whitelist", [])
                if device_name not in whitelist:
                    whitelist.append(device_name)
                    self.config["whitelist"] = whitelist
                    if self.worker:
                        self.worker.update_whitelist(whitelist)
                    self.menu_message = f"✓ Added '{device_name}' to whitelist"
                else:
                    self.menu_message = f"✗ '{device_name}' already whitelisted"
            else:
                self.menu_message = "✗ Device name cannot be empty"
        except EOFError:
            self.menu_message = "✗ Cancelled"

        hide_cursor()
        self.last_update = time.time()

    def save_config(self):
        _save_cfg(self.config)
        self.menu_message = "✓ Configuration saved"
        self.last_update = time.time()

    def handle_input(self):
        key = self.get_input()
        if not key:
            return True

        self.menu_message = ""

        if key == 'q':
            return False
        elif key == 'r':
            self.toggle_auto_reconnect()
        elif key == 'p':
            self.toggle_persistent_connect()
        elif key == 'i':
            self.change_interval()
        elif key == 'w':
            self.add_whitelist()
        elif key == 's':
            self.save_config()

        return True

    def start(self):
        if sys.platform != 'win32' and sys.stdin.isatty():
            try:
                self.old_settings = termios.tcgetattr(sys.stdin)
                tty.setcbreak(sys.stdin.fileno())
            except:
                self.old_settings = None
        else:
            self.old_settings = None

        hide_cursor()

        try:
            self.render()

            account_num = self.config.get("account_num", "")
            if account_num and not MullvadCLI.is_logged_in():
                print(f"\n  {Colors.YELLOW}Logging in to Mullvad...{Colors.RESET}")
                if MullvadCLI.relogin(account_num):
                    print(f"  {Colors.GREEN}✓ Logged in successfully{Colors.RESET}\n")
                    time.sleep(1)
                else:
                    print(f"  {Colors.RED}✗ Login failed{Colors.RESET}\n")
                    show_cursor()
                    if sys.platform != 'win32' and self.old_settings:
                        termios.tcsetattr(sys.stdin, termios.TCSADRAIN, self.old_settings)
                    return

            self.worker = GuardianWorker(
                account_num=self.config.get("account_num", ""),
                whitelist=self.config.get("whitelist", []),
                discord_webhook=self.config.get("discord_webhook", ""),
                check_interval=self.config.get("check_interval", 3),
                max_retries=self.config.get("max_retries", 3),
                backoff_base=self.config.get("backoff_base", 30),
                session_refresh=self.config.get("session_refresh", 3600),
                auto_reconnect=self.config.get("auto_reconnect", True),
                persistent_connect=self.config.get("persistent_connect", True),
            )

            self.worker.log_emitted.connect(self.log_handler)
            self.worker.status_changed.connect(self.status_handler)
            self.worker.devices_updated.connect(self.devices_handler)
            self.worker.expiry_updated.connect(self.expiry_handler)
            self.worker.stats_updated.connect(self.stats_handler)
            self.worker.self_detected.connect(self.self_detected_handler)
            self.worker.self_removed.connect(self.self_removed_handler)

            self.worker.start()
            self.running = True

            last_render = 0
            while self.running:
                current_time = time.time()

                if not self.handle_input():
                    break

                if current_time - last_render >= 1.0 or current_time - self.last_update < 0.1:
                    self.render()
                    last_render = current_time

                time.sleep(0.1)

        except KeyboardInterrupt:
            pass
        finally:
            self.stop()
            show_cursor()
            if sys.platform != 'win32' and self.old_settings:
                termios.tcsetattr(sys.stdin, termios.TCSADRAIN, self.old_settings)

    def stop(self):
        if self.worker:
            self.worker.stop()
            self.worker.wait()
        self.running = False

        clear_screen()
        print(f"\n  {Colors.BRIGHT_CYAN}🛡️  Mullvad Guardian{Colors.RESET}")
        print(f"  {Colors.GREEN}✓ Stopped gracefully{Colors.RESET}\n")



def main():
    parser = argparse.ArgumentParser(
        description="Mullvad Guardian — Interactive CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s
  %(prog)s --account 1234567890
  %(prog)s --whitelist "My PC"
  %(prog)s --no-reconnect
  %(prog)s --interval 5