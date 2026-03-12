# Changelog

All notable changes to this project will be documented in this file.

## [1.0.0] - 2026-03-12

### Added
- Initial release of OpenClaw Piper
- 8 built-in Prompt Injection detection rule categories
- Real-time monitoring via OpenClaw transcript files
- SQLite database for persistent alert storage
- Web UI dashboard with severity classification
- WebSocket real-time event streaming
- Command-line interface with configuration options
- Test suite with 21 test cases

### Detection Rules
- Role Bypass (Critical)
- System Prompt Leak (Critical)
- Jailbreak Attempts (Critical)
- Instruction Injection (High)
- Data Exfiltration (High)
- Privilege Escalation (High)
- Persistence Attempts (Medium)
- Suspicious Context Patterns (Medium)

### Technical
- Uses `ws` library for reliable WebSocket handling
- Uses `better-sqlite3` for database operations
- Monitors `~/.openclaw/agents/*/sessions/*.jsonl` files
- Supports historical message scanning on startup