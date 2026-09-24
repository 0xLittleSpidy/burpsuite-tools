#!/usr/bin/env python3
"""
Mouse Jiggler CLI
-----------------
A cross-platform Python CLI tool to periodically move the mouse cursor
to keep the display awake, prevent screen savers, lock screens, and idle sleep.
"""

import sys
import os
import time
import math
import random
import signal
import shutil
import argparse
import subprocess
from typing import Tuple, Optional, Callable

# Version
__version__ = "1.0.0"

# --- Backend Implementations ---

class MouseBackend:
    """Abstract base class for mouse controller backends."""
    name: str = "base"

    def is_available(self) -> bool:
        raise NotImplementedError

    def get_position(self) -> Tuple[int, int]:
        raise NotImplementedError

    def move_relative(self, dx: int, dy: int) -> None:
        raise NotImplementedError

    def move_absolute(self, x: int, y: int) -> None:
        raise NotImplementedError

    def get_screen_size(self) -> Tuple[int, int]:
        return (1920, 1080)


class CtypesX11Backend(MouseBackend):
    """Native X11 / Xwayland backend via ctypes (libX11 + libXtst). No pip dependencies."""
    name = "X11 (Native Ctypes)"

    def __init__(self):
        self._display = None
        self._x11 = None
        self._xtest = None
        self._root = None
        self._screen_width = 1920
        self._screen_height = 1080
        self._init_libraries()

    def _init_libraries(self):
        try:
            import ctypes
            self._x11 = ctypes.cdll.LoadLibrary("libX11.so.6")
            self._xtest = ctypes.cdll.LoadLibrary("libXtst.so.6")
            self._display = self._x11.XOpenDisplay(None)
            if self._display:
                self._root = self._x11.XDefaultRootWindow(self._display)
                screen = self._x11.XDefaultScreen(self._display)
                self._screen_width = self._x11.XDisplayWidth(self._display, screen)
                self._screen_height = self._x11.XDisplayHeight(self._display, screen)
        except Exception:
            self._display = None

    def is_available(self) -> bool:
        return self._display is not None and self._root is not None

    def get_screen_size(self) -> Tuple[int, int]:
        return (self._screen_width, self._screen_height)

    def get_position(self) -> Tuple[int, int]:
        import ctypes
        root_ret = ctypes.c_ulong()
        child_ret = ctypes.c_ulong()
        rx, ry = ctypes.c_int(), ctypes.c_int()
        wx, wy = ctypes.c_int(), ctypes.c_int()
        mask = ctypes.c_uint()
        self._x11.XQueryPointer(
            self._display, self._root,
            ctypes.byref(root_ret), ctypes.byref(child_ret),
            ctypes.byref(rx), ctypes.byref(ry),
            ctypes.byref(wx), ctypes.byref(wy),
            ctypes.byref(mask)
        )
        return rx.value, ry.value

    def move_relative(self, dx: int, dy: int) -> None:
        self._xtest.XTestFakeRelativeMotionEvent(self._display, int(dx), int(dy), 0)
        self._x11.XFlush(self._display)

    def move_absolute(self, x: int, y: int) -> None:
        cur_x, cur_y = self.get_position()
        self.move_relative(x - cur_x, y - cur_y)

    def close(self):
        if self._display and self._x11:
            try:
                self._x11.XCloseDisplay(self._display)
            except Exception:
                pass
            self._display = None


class XdotoolBackend(MouseBackend):
    """External xdotool utility backend."""
    name = "xdotool (CLI)"

    def is_available(self) -> bool:
        return shutil.which("xdotool") is not None

    def get_screen_size(self) -> Tuple[int, int]:
        try:
            out = subprocess.check_output(["xdotool", "getdisplaygeometry"], stderr=subprocess.DEVNULL).decode()
            w, h = map(int, out.strip().split())
            return w, h
        except Exception:
            return (1920, 1080)

    def get_position(self) -> Tuple[int, int]:
        try:
            out = subprocess.check_output(
                ["xdotool", "getmouselocation", "--shell"],
                stderr=subprocess.DEVNULL
            ).decode()
            vals = {}
            for line in out.strip().splitlines():
                if "=" in line:
                    k, v = line.split("=", 1)
                    vals[k.strip()] = int(v.strip())
            return vals.get("X", 0), vals.get("Y", 0)
        except Exception:
            return (0, 0)

    def move_relative(self, dx: int, dy: int) -> None:
        subprocess.run(
            ["xdotool", "mousemove_relative", "--", str(int(dx)), str(int(dy))],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False
        )

    def move_absolute(self, x: int, y: int) -> None:
        subprocess.run(
            ["xdotool", "mousemove", "--", str(int(x)), str(int(y))],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False
        )


class PyAutoGUIBackend(MouseBackend):
    """PyAutoGUI library backend if installed."""
    name = "PyAutoGUI"

    def __init__(self):
        self._pag = None
        try:
            import pyautogui
            self._pag = pyautogui
            self._pag.FAILSAFE = False
        except ImportError:
            self._pag = None

    def is_available(self) -> bool:
        return self._pag is not None

    def get_screen_size(self) -> Tuple[int, int]:
        try:
            sz = self._pag.size()
            return sz[0], sz[1]
        except Exception:
            return (1920, 1080)

    def get_position(self) -> Tuple[int, int]:
        pos = self._pag.position()
        return pos[0], pos[1]

    def move_relative(self, dx: int, dy: int) -> None:
        self._pag.moveRel(dx, dy)

    def move_absolute(self, x: int, y: int) -> None:
        self._pag.moveTo(x, y)


class PynputBackend(MouseBackend):
    """pynput library backend if installed."""
    name = "pynput"

    def __init__(self):
        self._mouse = None
        try:
            from pynput.mouse import Controller
            self._mouse = Controller()
        except ImportError:
            self._mouse = None

    def is_available(self) -> bool:
        return self._mouse is not None

    def get_position(self) -> Tuple[int, int]:
        pos = self._mouse.position
        return int(pos[0]), int(pos[1])

    def move_relative(self, dx: int, dy: int) -> None:
        self._mouse.move(dx, dy)

    def move_absolute(self, x: int, y: int) -> None:
        self._mouse.position = (x, y)


class YdotoolBackend(MouseBackend):
    """ydotool utility backend for Wayland."""
    name = "ydotool (Wayland)"

    def is_available(self) -> bool:
        return shutil.which("ydotool") is not None

    def get_position(self) -> Tuple[int, int]:
        return (0, 0)

    def move_relative(self, dx: int, dy: int) -> None:
        subprocess.run(
            ["ydotool", "mousemove", "-x", str(int(dx)), "-y", str(int(dy))],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False
        )

    def move_absolute(self, x: int, y: int) -> None:
        self.move_relative(x, y)


def get_available_backends():
    """Detect and return instances of available backends."""
    candidates = [
        ("ctypes", CtypesX11Backend),
        ("xdotool", XdotoolBackend),
        ("pyautogui", PyAutoGUIBackend),
        ("pynput", PynputBackend),
        ("ydotool", YdotoolBackend),
    ]
    backends = {}
    for key, cls in candidates:
        try:
            b = cls()
            if b.is_available():
                backends[key] = b
        except Exception:
            pass
    return backends


# --- Screen Inhibit Helper ---

class ScreenInhibitor:
    """Uses DBus or systemd to inhibit screensaver/sleep on Linux desktops."""
    def __init__(self):
        self._dbus_cookie = None
        self._iface = None
        self._bus = None
        self.active = False
        self._init_dbus()

    def _init_dbus(self):
        try:
            import dbus
            self._bus = dbus.SessionBus()
            proxy = self._bus.get_object('org.freedesktop.ScreenSaver', '/org/freedesktop/ScreenSaver')
            self._iface = dbus.Interface(proxy, 'org.freedesktop.ScreenSaver')
            self._dbus_cookie = self._iface.Inhibit('MouseJiggler', 'Prevent display idle and sleep')
            self.active = True
        except Exception:
            self.active = False

    def release(self):
        if self.active and self._iface and self._dbus_cookie is not None:
            try:
                self._iface.UnInhibit(self._dbus_cookie)
            except Exception:
                pass
            self.active = False


# --- Helper Formatter ---

def format_duration(seconds: float) -> str:
    s = int(seconds)
    hours, remainder = divmod(s, 3600)
    minutes, secs = divmod(remainder, 60)
    if hours > 0:
        return f"{hours:02d}:{minutes:02d}:{secs:02d}"
    return f"{minutes:02d}:{secs:02d}"


def parse_duration_string(val: str) -> float:
    """Parse time string like 30s, 10m, 2h, or raw seconds."""
    val = val.strip().lower()
    if val.endswith("s"):
        return float(val[:-1])
    elif val.endswith("m"):
        return float(val[:-1]) * 60
    elif val.endswith("h"):
        return float(val[:-1]) * 3600
    elif val.endswith("d"):
        return float(val[:-1]) * 86400
    return float(val)


# --- ANSI Colors ---

class Colors:
    CYAN = "\033[36m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    RED = "\033[31m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"
    CLEAR_LINE = "\033[2K\r"


# --- Main Engine ---

class MouseJiggler:
    def __init__(
        self,
        backend: MouseBackend,
        interval: float = 2.0,
        distance: int = 96,
        mode: str = "oscillate",
        duration: Optional[float] = None,
        idle_delay: float = 0.0,
        stealth: bool = False,
        quiet: bool = False,
        inhibit: bool = True,
    ):
        self.backend = backend
        self.interval = max(0.1, interval)
        self.distance = 2 if stealth else distance
        self.mode = mode
        self.duration = duration
        self.idle_delay = idle_delay
        self.stealth = stealth
        self.quiet = quiet
        self.use_inhibit = inhibit

        self.running = False
        self.nudges_count = 0
        self.start_time = 0.0
        self.last_user_time = 0.0
        self.step_index = 0
        self.origin_pos = (0, 0)
        self.last_script_pos = (0, 0)
        self.screen_width, self.screen_height = backend.get_screen_size()
        self.inhibitor = None

    def _calculate_delta(self) -> Tuple[int, int]:
        """Calculates dx, dy for the next nudge based on selected mode."""
        d = self.distance
        if self.stealth:
            # Subtle 2-pixel oscillation
            self.step_index = (self.step_index + 1) % 2
            return (d if self.step_index == 1 else -d, 0)

        if self.mode == "oscillate":
            # Back and forth along X (or slightly angled)
            self.step_index = (self.step_index + 1) % 2
            dx = d if self.step_index == 1 else -d
            return (dx, 0)

        elif self.mode == "box":
            # Square path: right -> down -> left -> up
            steps = [(d, 0), (0, d), (-d, 0), (0, -d)]
            delta = steps[self.step_index % 4]
            self.step_index += 1
            return delta

        elif self.mode == "circle":
            # 8-point smooth circle
            angle_step = (2 * math.pi) / 8
            current_angle = self.step_index * angle_step
            next_angle = (self.step_index + 1) * angle_step
            self.step_index = (self.step_index + 1) % 8
            r = d / 2
            dx = int(r * (math.cos(next_angle) - math.cos(current_angle)))
            dy = int(r * (math.sin(next_angle) - math.sin(current_angle)))
            return (dx, dy)

        elif self.mode == "random":
            # Random angle nudge within distance radius
            angle = random.uniform(0, 2 * math.pi)
            dx = int(d * math.cos(angle))
            dy = int(d * math.sin(angle))
            return (dx, dy)

        return (d, 0)

    def _render_dashboard(self, status: str, pos: Tuple[int, int], delta: Tuple[int, int]):
        """Render a single-line or multi-line dashboard in interactive TTY."""
        if self.quiet:
            return

        elapsed = time.time() - self.start_time
        elapsed_str = format_duration(elapsed)

        remaining_str = ""
        if self.duration:
            rem = max(0.0, self.duration - elapsed)
            remaining_str = f" | Left: {Colors.BOLD}{format_duration(rem)}{Colors.RESET}"

        status_badge = (
            f"{Colors.GREEN}● RUNNING{Colors.RESET}"
            if status == "RUNNING"
            else f"{Colors.YELLOW}⏸ PAUSED (User Active){Colors.RESET}"
        )

        inhibit_badge = (
            f"{Colors.CYAN}[Sleep Inhibited]{Colors.RESET}"
            if self.inhibitor and self.inhibitor.active
            else ""
        )

        delta_str = f"({delta[0]:+d}px, {delta[1]:+d}px)" if delta != (0, 0) else "idle"
        inch_equiv = f"~{self.distance / 96.0:.1f} in"

        # Overwrite current line
        line = (
            f"\r{Colors.BOLD}{Colors.MAGENTA}MouseJiggler{Colors.RESET} "
            f"[{status_badge}] "
            f"Nudges: {Colors.BOLD}{self.nudges_count}{Colors.RESET} | "
            f"Pos: ({pos[0]}, {pos[1]}) | "
            f"Move: {delta_str} | "
            f"Time: {Colors.BOLD}{elapsed_str}{Colors.RESET}{remaining_str} "
            f"{inhibit_badge}"
        )
        # Pad with spaces to clear any previous longer text
        sys.stdout.write(line.ljust(120) + "\r")
        sys.stdout.flush()

    def run(self):
        self.running = True
        self.start_time = time.time()
        self.last_user_time = self.start_time

        if self.use_inhibit:
            self.inhibitor = ScreenInhibitor()

        # Capture starting cursor position
        try:
            self.origin_pos = self.backend.get_position()
            self.last_script_pos = self.origin_pos
        except Exception:
            self.origin_pos = (0, 0)
            self.last_script_pos = (0, 0)

        inch_equiv = self.distance / 96.0

        if not self.quiet:
            print(f"{Colors.BOLD}{Colors.CYAN}===================================================={Colors.RESET}")
            print(f"{Colors.BOLD}{Colors.CYAN}       🖱️  Mouse Jiggler v{__version__} - Active           {Colors.RESET}")
            print(f"{Colors.BOLD}{Colors.CYAN}===================================================={Colors.RESET}")
            print(f" • Backend:       {Colors.BOLD}{self.backend.name}{Colors.RESET}")
            print(f" • Interval:      {Colors.BOLD}{self.interval:.1f}s{Colors.RESET} (nudge every {self.interval} seconds)")
            print(f" • Distance:      {Colors.BOLD}{self.distance}px{Colors.RESET} (~{inch_equiv:.2f} inches at 96 DPI)")
            print(f" • Pattern Mode:  {Colors.BOLD}{self.mode}{Colors.RESET}")
            if self.idle_delay > 0:
                print(f" • Idle Delay:    {Colors.BOLD}{self.idle_delay:.1f}s{Colors.RESET} (pauses when user moves mouse)")
            if self.duration:
                print(f" • Auto-Stop:     After {Colors.BOLD}{format_duration(self.duration)}{Colors.RESET}")
            if self.inhibitor and self.inhibitor.active:
                print(f" • Sleep Lock:    {Colors.GREEN}Active (org.freedesktop.ScreenSaver){Colors.RESET}")
            print(f" • Screen Bounds: {self.screen_width}x{self.screen_height}")
            print(f"{Colors.DIM}Press Ctrl+C to pause or stop anytime.{Colors.RESET}")
            print(f"{Colors.CYAN}----------------------------------------------------{Colors.RESET}")

        last_move_time = 0.0

        try:
            while self.running:
                now = time.time()

                # Check duration limit
                if self.duration and (now - self.start_time) >= self.duration:
                    break

                # Query current mouse position
                try:
                    cur_x, cur_y = self.backend.get_position()
                except Exception:
                    cur_x, cur_y = self.last_script_pos

                # Detect manual user mouse activity
                dist_from_script = math.hypot(cur_x - self.last_script_pos[0], cur_y - self.last_script_pos[1])
                user_is_active = False

                if dist_from_script > 15:
                    # User moved the mouse manually!
                    self.last_user_time = now
                    self.last_script_pos = (cur_x, cur_y)
                    self.origin_pos = (cur_x, cur_y)
                    user_is_active = True

                # If idle_delay configured, check if we need to pause
                if self.idle_delay > 0 and (now - self.last_user_time) < self.idle_delay:
                    self._render_dashboard("USER_ACTIVE", (cur_x, cur_y), (0, 0))
                    time.sleep(0.2)
                    continue

                # Check if it's time to nudge
                if (now - last_move_time) >= self.interval:
                    dx, dy = self._calculate_delta()

                    # Screen boundary protection: don't push off screen edges
                    target_x = cur_x + dx
                    target_y = cur_y + dy

                    if self.screen_width > 0 and self.screen_height > 0:
                        margin = 20
                        if target_x <= margin or target_x >= (self.screen_width - margin):
                            dx = -dx
                        if target_y <= margin or target_y >= (self.screen_height - margin):
                            dy = -dy

                    # Move the mouse
                    try:
                        self.backend.move_relative(dx, dy)
                        self.nudges_count += 1
                        last_move_time = time.time()
                        # Update expected script position
                        self.last_script_pos = (cur_x + dx, cur_y + dy)
                    except Exception as e:
                        if not self.quiet:
                            sys.stderr.write(f"\n[Warning] Movement failed: {e}\n")

                    self._render_dashboard("RUNNING", self.last_script_pos, (dx, dy))

                time.sleep(0.1)

        except KeyboardInterrupt:
            pass
        finally:
            self.stop()

    def stop(self):
        self.running = False
        if self.inhibitor:
            self.inhibitor.release()
            self.inhibitor = None

        if hasattr(self.backend, "close"):
            try:
                self.backend.close()
            except Exception:
                pass

        elapsed = time.time() - self.start_time if self.start_time > 0 else 0
        if not self.quiet:
            print("\n")
            print(f"{Colors.BOLD}{Colors.GREEN}Mouse Jiggler stopped.{Colors.RESET}")
            print(f" • Total Time:    {format_duration(elapsed)}")
            print(f" • Total Nudges:  {self.nudges_count}")
            print(f"{Colors.DIM}Screen sleep protection released.{Colors.RESET}")


# --- CLI Parser ---

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mouse_jiggler",
        description="🖱️ Mouse Jiggler CLI: Periodically nudges mouse cursor to keep the screen awake.",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument(
        "-i", "--interval",
        type=float,
        default=2.0,
        help="Interval between movements in seconds (default: 2.0)",
    )
    parser.add_argument(
        "-d", "--distance",
        type=int,
        default=96,
        help="Distance to move in pixels (default: 96px ≈ 1.0 inch at 96 DPI)",
    )
    parser.add_argument(
        "-m", "--mode",
        choices=["oscillate", "box", "circle", "random"],
        default="oscillate",
        help=(
            "Movement pattern mode:\n"
            "  oscillate: Back-and-forth along X (default, keeps cursor in place)\n"
            "  box:       Square clockwise motion\n"
            "  circle:    Smooth 8-point circular motion\n"
            "  random:    Random direction nudges within distance"
        ),
    )
    parser.add_argument(
        "-t", "--duration",
        type=str,
        default=None,
        help="Auto-stop after duration (e.g., '30s', '15m', '2h', '3600'). Default: run until Ctrl+C",
    )
    parser.add_argument(
        "--idle-delay",
        type=float,
        default=0.0,
        help="Seconds of user inactivity required before jiggling (default: 0 = always jiggle)",
    )
    parser.add_argument(
        "-s", "--stealth",
        action="store_true",
        help="Stealth mode: move by only 2 pixels back and forth (almost invisible)",
    )
    parser.add_argument(
        "--backend",
        choices=["auto", "ctypes", "xdotool", "pyautogui", "pynput", "ydotool"],
        default="auto",
        help="Mouse automation backend to use (default: auto-detected best)",
    )
    parser.add_argument(
        "--no-inhibit",
        action="store_true",
        help="Disable Linux DBus ScreenSaver inhibition lock",
    )
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Quiet mode: suppress dashboard and non-essential output",
    )
    parser.add_argument(
        "-v", "--version",
        action="version",
        version=f"Mouse Jiggler v{__version__}",
    )
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    # Parse duration if provided
    duration_secs = None
    if args.duration:
        try:
            duration_secs = parse_duration_string(args.duration)
        except Exception:
            print(f"{Colors.RED}Error: Invalid duration format '{args.duration}'. Example formats: '30s', '10m', '1h'{Colors.RESET}", file=sys.stderr)
            sys.exit(1)

    # Detect backends
    available = get_available_backends()
    if not available:
        print(f"{Colors.RED}Error: No supported mouse automation backend found.{Colors.RESET}", file=sys.stderr)
        print("Please ensure one of the following is available:", file=sys.stderr)
        print("  - X11/Xwayland with libX11 & libXtst (standard on Linux)", file=sys.stderr)
        print("  - xdotool (`sudo apt install xdotool`)", file=sys.stderr)
        print("  - pyautogui (`pip install pyautogui`)", file=sys.stderr)
        print("  - pynput (`pip install pynput`)", file=sys.stderr)
        print("  - ydotool (`sudo apt install ydotool`)", file=sys.stderr)
        sys.exit(1)

    selected_backend = None
    if args.backend == "auto":
        # Prioritize native ctypes (0 external overhead), then xdotool, etc.
        for pref in ["ctypes", "xdotool", "pyautogui", "pynput", "ydotool"]:
            if pref in available:
                selected_backend = available[pref]
                break
    else:
        if args.backend not in available:
            print(f"{Colors.RED}Error: Requested backend '{args.backend}' is not available.{Colors.RESET}", file=sys.stderr)
            print(f"Available backends: {', '.join(available.keys())}", file=sys.stderr)
            sys.exit(1)
        selected_backend = available[args.backend]

    jiggler = MouseJiggler(
        backend=selected_backend,
        interval=args.interval,
        distance=args.distance,
        mode=args.mode,
        duration=duration_secs,
        idle_delay=args.idle_delay,
        stealth=args.stealth,
        quiet=args.quiet,
        inhibit=not args.no_inhibit,
    )

    # Signal handlers
    def handle_signal(sig, frame):
        jiggler.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    jiggler.run()


if __name__ == "__main__":
    main()
