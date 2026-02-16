# Changelog

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
