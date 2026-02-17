# Changelog

## v0.1.4

### Security
- Fixed DNS name pointer validation — pointers now bounds-checked and cycle-detected to prevent out-of-bounds reads
- Added pcapng block count limit (10M) to prevent DoS from crafted files with millions of tiny blocks
- Added packet count limit (2M) to both pcap and pcapng parsers to prevent memory exhaustion
- XSS fix: protocol names now HTML-escaped in protocol filter dropdown and conversations table
- Race condition fix: table click handler now awaits lazy-loaded features module before using exports

### Performance
- Shared single TextDecoder instance across all protocol parsers (eliminated ~25 allocations per packet)
- Replaced all bytes.slice() with bytes.subarray() in parsers — zero-copy views instead of data copies
- Packet rawBytes now copied to release original file ArrayBuffer for garbage collection

### Parser
- Fixed IPv6 AH extension header length calculation — AH uses (len+2)×4, not (len+1)×8
- Fixed TCP/UDP port lookup short-circuit — both srcPort and dstPort candidates now checked
- Fixed PostgreSQL wire protocol duplicate tag keys (0x44, 0x45, 0x53 now show combined names)
- Removed debug logging (console.log/warn, window._pcapDebug globals)

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
