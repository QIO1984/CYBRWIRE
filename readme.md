# C Y B R W I R E // Legendary Edition

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rich](https://img.shields.io/badge/Powered%20by-Rich-brightgreen)](https://github.com/Textualize/rich)

**A real-time cyber threat intelligence dashboard in your terminal.**

C Y B R W I R E pulls the latest alerts from top security sources (CISA KEV, The Hacker News, Krebs, BleepingComputer, ZDI, Kaspersky, VulDB, and many more), classifies them by severity, and displays them in a continuously updating, color-rich TUI built with **[Rich](https://github.com/Textualize/rich)**.

It’s designed for security analysts, red teamers, blue teamers, and anyone who wants to keep an eye on the threat landscape without leaving the terminal.

## Features

- **20+ curated threat intelligence sources** including CISA, NSA, FBI, SANS, Microsoft, Cisco, Kaspersky, and more
- **Multi-format feed support** – JSON, RSS, and plain text feeds
- **Configurable feeds** – define curated, custom, and community intelligence sources via YAML
- **Color-coded severity tagging** (Critical/KEV, Zero-Day, Ransomware, APT, Exploit)
- **Real-time metrics dashboard** with threat heat level, alert rates, top sources, and trend graph
- **Live scrolling ticker** displaying latest threats and alerts
- **Audible + visual alerts** on fresh critical/zero-day events
- **Multiple theme support** – cycle through GNOME Dark, Green/Black High Contrast, Solarized Dark, Solarized Light
- **Customizable recency window** (24h / 48h / 7 days) – press `1`, `2`, or `3` anytime
- **Advanced filtering** – view alerts only, posts only, or all items
- **Cold War Mode** – toggle a stark, minimal aesthetic
- **Interactive browsing** – click links to open sources in your browser
- **Manual refresh** with `R` and feed cycling controls
- **Seamless scrolling ticker** with flashing borders on high-impact events
- **Minimal dependencies** – runs with just `rich`, `httpx`, `feedparser`, `pyyaml`, and `textual`

## Screenshots

### GNOME Dark Theme
![GNOME Dark Theme](screenshots/gnomedark.png)

### Green/Black High Contrast
![Green/Black High Contrast](screenshots/greenblack_HC.png)

### Solarized Dark
![Solarized Dark](screenshots/solarizeddark.png)

### Solarized Light
![Solarized Light](screenshots/solarizedlight.png)

## Installation & Usage

```bash
# Clone the repo
git clone https://github.com/yourusername/threattape.git
cd cybrwire

# Recommended: create a virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install rich httpx feedparser

# Run it!
python cybrwire.py
