# 🛡 DNS Shield

A fast, privacy-first DNS firewall in Python. Blocks ads, trackers and malware at DNS level, with a live dashboard.

Built from scratch with stdlib sockets. No dnslib / dnspython in the core engine.

[Python](https://img.shields.io/badge/Python-3.10+-blue)
[License](https://img.shields.io/badge/License-MIT-green)
[Tests](https://img.shields.io/badge/Tests-48%2F48%20passing-brightgreen)
[Rules](https://img.shields.io/badge/Rules-450k-orange)

**Production:** DNS on Port 53 (UDP + TCP) | Dashboard on Port 8081

---

## Screenshots

### Dashboard

<img width="1365" height="597" alt="Dashboard with graph and no. of total and blocked quesries" src="https://github.com/user-attachments/assets/391a65e5-a3d6-4024-8f73-208418e3c705" />

Live overview - total queries, blocked ratio, cache hit ratio, latency and 24-hour volume. All stats come from `/api/stats`, nothing is hardcoded.

### Query Logs

<img width="1365" height="602" alt="Logs of the quesr with the diffrent type like A,AAAA,HTTPS and also withe both udp and tcp" src="https://github.com/user-attachments/assets/8028989b-ce57-42b7-81c3-1373337e2884" />

Every query in real time - domain, type (A / AAAA / HTTPS), transport (UDP / TCP), status, latency and upstream. Blocked queries answer in ~1ms, forwarded queries take network time.

### Blocklists

<img width="1365" height="594" alt="Total four type of the like domain tha we block ads,malware,tracker,custom" src="https://github.com/user-attachments/assets/20a22fa4-63b2-4008-b28e-e8a3ad5e4a1a" />

4 lists, 450,312 unique rules. Toggle any list on/off without restart. Auto-update every 24h.

- **Ads** - 232,202 rules - OISD Big
- **Trackers** - 187,566 rules - incl. Windows telemetry
- **Malware** - 175,286 rules - URLhaus + Phishing Army + HaGeZi
- **Custom** - 9 rules - your own overrides

### Watchlist

<img width="1365" height="603" alt="Watchlist" src="https://github.com/user-attachments/assets/9ad81ab9-5d4f-4fef-815c-c26e58e2d64f" />

The feature that makes this different from Pi-hole / AdGuard.

Pin important domains. Type `YouTube`, `Meta`, `Claude` and it resolves to the correct domain. It checks for typo-squatting and parked domains, and pins A + AAAA + HTTPS together for zero-latency resolution.

---

## Why this exists

Pi-hole and AdGuard are great, but they don't catch this:

`youtub.com` or `cluadeai.com` looks almost right, but it's a typo-squat. Watchlist catches it before you open a fake site.

---

## Features

- **Blocking** - 450k rules, suffix matching, blocked queries never cached
- **Watchlist** - Brand map + typo check (Damerau-Levenshtein) + parked domain check + A/AAAA/HTTPS pinning
- **Smart Cache** - Key is (domain, qtype, qclass). Prefetch 60s before expiry. Serve-stale 60s on upstream failure
- **Core DNS** - UDP + TCP fallback, EDNS0, parallel race 8.8.8.8 vs 1.1.1.1, SERVFAIL on failure, never silent drop
- **Privacy** - Private IPs shown full, public IPs masked. Bind to 127.0.0.1 only
- **Dashboard** - Live stats, logs, lookup, blocklists, allowlist, watchlist, analytics

---

## Quick Start

```powershell
git clone https://github.com/Man09691/Dns-Shield.git
cd Dns-Shield
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

Run as Admin (Port 53 needs Admin):

```powershell
python main.py
```

Open http://localhost:8081

Set Windows DNS to 127.0.0.1 and disable Chrome Secure DNS for real browser blocking.

---

## How it works

```text
Client
  |
  v
server.py - UDP socket, threaded
  |
  +-- parser.py - parse question
  +-- blocklist.py - suffix walk, 450k check
  +-- watchlist.py - brand map, typo, parked check
  +-- cache.py - (domain, qtype, qclass) LRU
  +-- forwarder.py - race 8.8.8.8 vs 1.1.1.1
  +-- builder.py - 0.0.0.0 for BLOCKED
  |
  v
Dashboard 8081
  |
  v
SQLite (WAL)
```

---

## Performance

Real test - 5015 queries

| Metric | DNS Shield |
| :--- | :--- |
| BLOCKED | 1.08ms |
| CACHED | 2.09ms |
| FORWARDED | 213ms (hotspot network) |
| Cache Hit | 29.3% (blocked not cached, expected) |
| Blocked | 45.3% |

Forwarded is network latency, not server time. Cached proves server is fast.

---

## Testing

```powershell
python tests/test_integrity_port53.py
python tests/test_watchlist.py
```

- Integrity 48/48 passed
- Watchlist 19/19 passed
- Flood 1000, Fuzz malformed packets, Load 3000 - stable

---

## Project Structure

```text
DNS-port53/
├── main.py
├── dns/ - server, parser, blocklist, cache, watchlist, dashboard, stats
├── templates/ - dashboard, logs, blocklists, watchlist, analytics
├── blocklists/ - ads, trackers, malware, custom
├── tests/
├── screenshots/
└── README.md
```

---

## API

```text
GET /api/stats - total, blocked, cache, rules, top blocked
GET /api/logs?limit=100
GET /api/check?domain=x
GET /api/watchlist, POST /api/watchlist
GET /api/allowlist, POST /api/allowlist
```

---

## Roadmap

- [ ] Docker support - Dockerfile + docker-compose (coming next)
- [ ] DoT Port 853 for Android Private DNS
- [ ] CNAME uncloaking
- [ ] Per-client rules
- [ ] Regex / wildcard custom rules

---

## Contributing

Contributions welcome. This is a college project, but built to be production-ready.

**Good first issues:**
- Docker setup
- Better Watchlist typo suggestions
- UI polish for Analytics

**How to contribute:**
1. Fork the repo
2. Create a branch
3. Make your change, add a test if possible
4. Open a PR with a short description

If you want to help, open an Issue. I am actively maintaining this.

---

## Author

**Man Varmora** - 3rd Sem, Computer Networks
Stack: Python, Flask, SQLite WAL, stdlib socket

Core engine, Watchlist, cache and tests are my work. Dashboard UI was AI-assisted and fixed to use real DB data.

---

## License

MIT - Free to use for learning and college projects.
