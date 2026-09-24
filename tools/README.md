# 🖱️ Mouse Jiggler CLI

A lightweight, zero-external-dependency Python CLI tool that periodically moves the mouse cursor by a configurable distance (default: ~1 inch every 2 seconds) to keep screens awake, prevent display blanking, screensavers, and system idle sleep.

---

## ✨ Features

- **Zero pip dependencies required**: Out of the box, it uses native Linux X11/Xwayland `ctypes` (`libX11` + `libXtst`).
- **Multi-backend fallback**: Seamlessly auto-detects and falls back to `xdotool`, `pyautogui`, `pynput`, or `ydotool` (Wayland).
- **Dual Keep-Awake Protection**:
  1. Actively nudges the mouse pointer at regular intervals (default: `2.0s`).
  2. Acquires an `org.freedesktop.ScreenSaver` DBus inhibition lock to guarantee the display manager never sleeps.
- **Drift Protection**: Keeps the cursor centered in the current working area using oscillating or circular motion patterns instead of letting it wander off-screen into corners.
- **Edge Bouncing**: Detects screen boundaries and bounces the motion if close to an edge.
- **User Activity Detection**: Can pause automatically when you are actively moving the mouse (`--idle-delay`).
- **Stealth Mode**: Moves by 2 pixels back and forth for invisible keep-awake without disturbing your work (`-s` / `--stealth`).
- **Interactive Dashboard**: Displays live status, coordinates, movement delta, nudge counter, and elapsed/remaining time.

---

## 🚀 Quick Start

From `/home/littlespidy/myextra/burpsuite/tools`:

```bash
# Run with default settings (moves ~1 inch every 2 seconds)
./mouse_jiggler.py
```
*(Or use `./mouse-jiggler`)*

To stop, simply press <kbd>Ctrl</kbd> + <kbd>C</kbd>. The tool cleanly releases any sleep locks and shows an activity summary.

---

## 🛠️ Usage & Examples

### 1. Default (1 inch every 2 seconds)
```bash
./mouse_jiggler.py
```

### 2. Custom Interval and Distance
Move 150 pixels every 5 seconds:
```bash
./mouse_jiggler.py -i 5.0 -d 150
```

### 3. Timed Session (Auto-Stop)
Run for a specific duration (e.g., 30 minutes, 2 hours, 45 seconds):
```bash
# Run for 30 minutes then stop
./mouse_jiggler.py -t 30m

# Run for 2 hours
./mouse_jiggler.py -t 2h
```

### 4. Movement Modes
Choose between different motion patterns:
```bash
# Back-and-forth oscillation (default)
./mouse_jiggler.py -m oscillate

# Square / box motion
./mouse_jiggler.py -m box

# Smooth circular motion
./mouse_jiggler.py -m circle

# Random nudges
./mouse_jiggler.py -m random
```

### 5. Stealth Mode
Nudges the cursor by only 2 pixels back and forth (virtually imperceptible to the human eye, but keeps the screen active):
```bash
./mouse_jiggler.py --stealth
# or
./mouse_jiggler.py -s
```

### 6. Pause When User is Working
Only move the mouse after you have been away/idle for at least 10 seconds:
```bash
./mouse_jiggler.py --idle-delay 10
```

---

## 📋 Command-Line Options

| Option | Flag | Description | Default |
|---|---|---|---|
| `--interval` | `-i` | Interval between movements in seconds | `2.0` |
| `--distance` | `-d` | Movement distance in pixels (96px ≈ 1.0 inch) | `96` |
| `--mode` | `-m` | Pattern (`oscillate`, `box`, `circle`, `random`) | `oscillate` |
| `--duration` | `-t` | Auto-stop after duration (`30s`, `15m`, `2h`) | Indefinite (`Ctrl+C`) |
| `--idle-delay` | | Inactivity seconds before jiggling starts | `0` (immediate) |
| `--stealth` | `-s` | 2-pixel subtle jiggle mode | `False` |
| `--backend` | | Force backend (`auto`, `ctypes`, `xdotool`, etc.) | `auto` |
| `--no-inhibit` | | Disable Linux DBus sleep inhibition | `False` |
| `--quiet` | `-q` | Suppress terminal dashboard output | `False` |
| `--version` | `-v` | Display tool version | `1.0.0` |
| `--help` | `-h` | Show help message | |
