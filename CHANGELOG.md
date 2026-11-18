# Changelog

## Unreleased

### Added
- **Threat map** as the opening main view (`v` cycles views, `m` opens it full window). A world map drawn in braille dots with four marker layers: ransomware victims, attributed nation-state activity, national advisories and active outages. Under it: a legend line per layer, the latest strong alerts and an alerts-per-hour scope with a sweeping point. The app remembers the view you leave it on.
- **Atmosphere effects**, all switched by `x`: map markers pulse and a radar sweep crosses the land; the window edge pulses when something urgent arrives (plus a FLASH banner in Cold War mode).
- **Neon Noir**, a near-black theme with vivid pink, cyan, blue and violet, now the default for new installs. Saved choices of the older themes are kept.

### Changed
- Internal: `app.py` split into screens, window chrome and one module per panel. No behaviour change.

## 1.1.0 (2026-11-17)

### Added
- **Browser and Docker mode.** `cybrwire-web` serves the app in a browser, and a Dockerfile and `compose.yaml` run it in the background. A real sign-in page protects it (a cookie lasts 30 days), and the server refuses to listen on the network without a password. The page follows the address your browser used, so IP addresses and reverse proxies (Caddy, nginx) both work. Links open in a new tab.
- **World clock** under the title: your local time plus six reference cities by default. `z` toggles it. Set cities with `CYBRWIRE_CLOCKS` (Docker) or `clocks:` in `usrwire.yaml`; `cybrwire.env.example` lists one city per time zone.
- **Outages.** Ten status-page feeds (cloud, mail, chat and more) in a new Outages group. Active incidents appear in Alerts and the all-clear moves to history.
- **Metasploit modules** as a public-exploit signal for CVEs.
- **Settings in `cybrwire.env`** for Docker: `CYBRWIRE_WATCHLIST`, `CYBRWIRE_NOTIFY_TRIGGERS`, `CYBRWIRE_AI_AUTO_BRIEFING`, as well as `TZ` and `CYBRWIRE_CLOCKS`. Only your own feeds still need `usrwire.yaml`.
- `cybrwire --version`.
- Readme: "Where Settings Live" tables, Data Sources and Credits, and Docker, Compose and proxy notes.

### Changed
- The Live Wire dot breathes calmly between checks; the title and feed text stay steady and are no longer repainted by the pulse.
- Packaged for `pipx install`: user data lives in `~/.config/cybrwire` (or `CYBRWIRE_HOME`).
- Feeds now identify themselves as `CybrWire/<version>`, taken from the one version number in `cybrwire/__init__.py`.
- Provider terms respected: credits for Spamhaus, DShield, HIBP, NVD, FIRST EPSS and Ransomware.live, and the NVD notice on the CVE card.

### Fixed
- Feeds that lost their query string (VulDB, Cyber.gc.ca, GitHub advisories, Ars Technica, Dr.Web, ENISA) work again.
- Duplicate and stale status-page incidents no longer flood Outages.

### Removed
- Dead or unusable feeds: Android Security Bulletins, OpenPhish (its terms bar threat-intelligence use) and the ACSC feeds (the site never answers CybrWire). An ACSC example remains, commented out, in `usrwire.yaml`.

### Planned
- Easier editing of custom feeds in Docker.

## 1.0.0

First public version: terminal dashboard with the Live Wire, evidence-ranked alerts, CVE cards with EPSS and CVSS, watchlist, notifications, AI briefings, themes and history.
