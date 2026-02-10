# CyntricaVIZ

A desktop network packet analyzer and visualizer. Drop a `.pcap` or `.pcapng` file to get an interactive dashboard with network graphs, protocol breakdowns, timeline heatmaps, TCP state tracking, threat IoC matching, alert rules, and dark web port detection. All processing happens locally — no uploads, no servers.

Built with [Tauri v2](https://v2.tauri.app/) for native performance on macOS, Windows, and Linux.

![License](https://img.shields.io/badge/license-BSD--3--Clause-blue)

---

## Features

### Visualization
- **Network Graph** — Interactive force-directed graph with L2/L3/L4 layer switching, subnet grouping, and adjustable host limit (10–500 nodes)
- **Timeline & Heatmap** — Packet timeline with heatmap mode for temporal traffic analysis
- **Protocol Breakdown** — Pie and bar charts showing protocol distribution
- **IO Graph** — Stacked area throughput charts (packets/sec or bytes/sec) with configurable intervals
- **GeoIP Map** — World map visualization with traffic volume-based node sizing
- **Flow Diagrams** — MSC-style message sequence charts between host pairs

### Analysis
- **Packet Table** — Sortable, searchable packet list with virtual scrolling and protocol color-coding
- **Advanced Filtering** — Display filter language with 20+ fields (`ip.src`, `tcp.port`, `dns.qname`, etc.), operators (`==`, `!=`, `contains`, `matches`), and boolean logic
- **Protocol Statistics** — Tabbed stats for General, TCP, DNS, and HTTP with per-protocol metrics
- **Conversations Table** — IP pair table with packet counts, bytes, duration, and protocol breakdown
- **TCP Stream Reconstruction** — Bidirectional payload reassembly with color-coded client/server display
- **Packet Diff** — Side-by-side comparison with field diff and hex-level byte coloring
- **Connection State Machine** — TCP lifecycle tracking (Complete/Established/Half-Open/Reset) with event flow visualization
- **Latency & RTT Analysis** — TCP handshake RTT and DNS resolution latency with quality ratings
- **Capture Comparison** — Load two captures for side-by-side statistics comparison

### Security
- **IoC Matching** — Paste IP/domain threat indicators and scan captures for matches
- **Alert Rules Engine** — Custom rule-based alerting on packet properties
- **Dark Web Port Detection** — Built-in recognition of Tor, I2P, and proxy ports
- **Credential Extraction** — Detects HTTP Basic Auth, Bearer tokens, cookies, FTP/SMTP credentials in cleartext traffic
- **HTTP Object Export** — Reconstructs HTTP response bodies from unencrypted traffic
- **Tunnel/VPN Detection** — Flags Tor, WireGuard, OpenVPN, SSH tunnels, and DNS tunneling
- **Passive OS Fingerprinting** — Identifies OS from TTL, window size, and MSS heuristics
- **Anomaly Detection** — Filters for TCP RSTs, retransmissions, SYN/RST/ICMP floods, and jumbo frames

### Workflow
- **Packet Bookmarking** — Star and annotate packets for filtered viewing
- **Coloring Rules** — Customizable packet coloring with profiles (Default/Security/Web/Custom)
- **Keyboard Shortcuts** — Full keyboard navigation (see guide for bindings)
- **Dark Theme** — Purpose-built dark UI for extended analysis sessions

---

## Getting Started

### Prerequisites

- [Node.js](https://nodejs.org/) (v18+)
- [Rust](https://www.rust-lang.org/tools/install) (1.77+)
- Platform-specific Tauri dependencies — see [Tauri Prerequisites](https://v2.tauri.app/start/prerequisites/)

### Install & Run

```bash
# Clone the repo
git clone https://github.com/cyntrica/VIZ.git
cd VIZ

# Install dependencies
npm install

# Run in development mode (hot reload)
npm run tauri dev

# Build production desktop app
npm run tauri build
```

Production bundles are output to `src-tauri/target/release/bundle/`:
- **macOS** — `.app` + `.dmg`
- **Windows** — `.msi` + `.exe`
- **Linux** — `.deb` + AppImage

### Usage

1. Launch the app
2. Click **Open File** or drag-and-drop a `.pcap` / `.pcapng` file
3. Explore the dashboard — switch between views using the sidebar or keyboard shortcuts
4. Use the filter bar for targeted analysis (e.g. `ip.src == 192.168.1.1 && tcp.port == 443`)

A sample capture (`capturedemo.pcapng`) is included for testing.

---

## Project Structure

```
CyntricaVIZ/
├── app.js              # Core application logic
├── pcap-parser.js      # Binary PCAP/PCAPNG parser
├── index.html          # Main UI
├── style.css           # Dark theme styling
├── guide.html          # User documentation
├── package.json        # Node dependencies
├── capturedemo.pcapng  # Sample capture file
└── src-tauri/          # Tauri / Rust backend
    ├── Cargo.toml      # Rust dependencies
    ├── tauri.conf.json # App configuration
    └── src/            # Rust source (file I/O, security)
```

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Desktop Runtime | Tauri 2.10 (Rust) |
| Frontend | Vanilla JS, HTML5, CSS3 |
| Visualizations | D3.js v7.9.0, Canvas API, SVG |
| Packet Parsing | Custom binary parser (client-side) |
| Build | Cargo + npm + Tauri CLI |

All packet processing runs client-side in the system WebView — nothing leaves your machine.

---

## License

[BSD 3-Clause](LICENSE) — Copyright (c) 2025, Cyntrica
