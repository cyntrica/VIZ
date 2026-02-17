# Changelog

## v0.1.3

### Features
- Two-level drill-down protocol charts — top level shows transport groups (TCP/UDP/ICMP/ARP/Other), click to drill into application-layer protocols
- Pie chart leader-line labels for small slices (<3%) with clamped positioning to prevent overflow
- Swapped Timeline and Protocol Breakdown panel positions — protocol charts beside network graph, timeline full-width below

### Parser
- Expanded protocol registry to 100+ protocols with 3-tier dispatch (TCP/UDP port, IP protocol number, EtherType)
- Fixed TextDecoder encoding bug (replaced 'ascii' with default UTF-8)

## v0.1.2

### Security
- Tooltip rendering hardened with explicit safe/raw HTML modes
- Tunnel flag values escaped in packet detail view
- CSV export now escapes quotes and neutralizes formula injection
- Fixed annotation storage key collision for similarly-named files

### Performance
- Protocol statistics cached per modal session (no re-filtering on tab switch)
- HTTP object reconstruction reuses pre-built stream index
- TCP connection state analysis reuses stream index (eliminates redundant packet scan)

## v0.1.1

### Security
- Hardened IoC results rendering against potential XSS via escaped badge markup

### Performance
- Single-pass packet filtering — eliminates intermediate array allocations
- O(1) TCP stream lookup via pre-built stream index

### Maintainability
- Split monolithic 2,049-line app.js into 5 focused ES modules
- Native ES module loading — no bundler required

## v0.1.0

- Initial release
