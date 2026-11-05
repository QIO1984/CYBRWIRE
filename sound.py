"""
Optional alert sounds for CybrWire, off by default

The retro tones are generated here rather than shipped as recordings, so there is
nothing to license. Where no audio player exists, as over SSH or in a container,
the terminal's own bell is used instead.
"""

import atexit
import logging
import math
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import threading
import wave
from typing import Callable, Dict, List, Optional, Tuple

RATE = 22050
VOLUME = 0.25
FADE_SECONDS = 0.003  # Stops the click a sudden start or end makes
PLAYERS = ("pw-play", "paplay", "aplay", "afplay")
PLAY_TIMEOUT = 5

OFF = "off"
TERMINAL_BELL = "bell"


def _square(freq: float, t: float) -> float:
    return 1.0 if math.sin(2 * math.pi * freq * t) >= 0 else -1.0


def pc_speaker() -> List[float]:
    """The classic IBM PC beep: an 800 Hz square wave for a quarter second"""
    return [_square(800, i / RATE) for i in range(int(RATE * 0.25))]


def teletype_bell() -> List[float]:
    """A small mechanical bell: two inharmonic tones ringing down"""
    samples = []
    for i in range(int(RATE * 0.7)):
        t = i / RATE
        ring = math.sin(2 * math.pi * 1760 * t) + 0.5 * math.sin(2 * math.pi * 2640 * t)
        samples.append(ring / 1.5 * math.exp(-6 * t))
    return samples


def modem_chirp() -> List[float]:
    """A dial-up flavored warble between 1200 and 2400 Hz"""
    samples = []
    for i in range(int(RATE * 0.42)):
        t = i / RATE
        samples.append(_square(1200 if int(t / 0.06) % 2 == 0 else 2400, t))
    return samples


# What b cycles through, in order
TONES: Dict[str, Tuple[str, Optional[Callable[[], List[float]]]]] = {
    OFF: ("Off", None),
    "pc": ("PC speaker", pc_speaker),
    "teletype": ("Teletype bell", teletype_bell),
    "modem": ("Modem chirp", modem_chirp),
    TERMINAL_BELL: ("Terminal bell", None),
}


def next_tone(current: str) -> str:
    names = list(TONES)
    return names[(names.index(current) + 1) % len(names)] if current in TONES else OFF


def label(name: str) -> str:
    return TONES.get(name, TONES[OFF])[0]


def write_wav(path: str, samples: List[float]) -> None:
    fade = max(1, int(RATE * FADE_SECONDS))
    count = len(samples)
    frames = bytearray()
    for i, sample in enumerate(samples):
        edge = min(1.0, i / fade, (count - 1 - i) / fade)
        frames += struct.pack("<h", int(sample * edge * VOLUME * 32767))
    with wave.open(path, "wb") as f:
        f.setnchannels(1)
        f.setsampwidth(2)
        f.setframerate(RATE)
        f.writeframes(bytes(frames))


_files: Dict[str, str] = {}
_folder: Optional[str] = None


def tone_file(name: str) -> str:
    """The tone as a WAV in a private temp folder, made the first time it's needed"""
    global _folder
    if name not in _files:
        if _folder is None:
            _folder = tempfile.mkdtemp(prefix="cybrwire-sound-")
            atexit.register(shutil.rmtree, _folder, ignore_errors=True)
        path = os.path.join(_folder, f"{name}.wav")
        write_wav(path, TONES[name][1]())
        _files[name] = path
    return _files[name]


def find_player() -> Optional[str]:
    return next((p for p in PLAYERS if shutil.which(p)), None)


def _run_player(player: str, path: str) -> None:
    try:
        subprocess.run([player, path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=PLAY_TIMEOUT)
    except (OSError, subprocess.SubprocessError) as e:
        logging.warning(f"Could not play alert sound: {type(e).__name__}")


def play(name: str, bell: Callable[[], None]) -> None:
    """Play a tone without blocking. Falls back to the terminal bell."""
    if name == OFF or name not in TONES:
        return
    if name == TERMINAL_BELL:
        bell()
        return
    if sys.platform == "win32":
        import winsound
        winsound.PlaySound(tone_file(name), winsound.SND_FILENAME | winsound.SND_ASYNC)
        return
    player = find_player()
    if not player:
        bell()
        return
    threading.Thread(target=_run_player, args=(player, tone_file(name)), daemon=True).start()
