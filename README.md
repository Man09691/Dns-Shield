🛡️ DNS SHIELD - Network Defender
A Pi-hole clone in Python - Blocks Ads, Trackers, Malware at DNS level with real-time dashboard

Python
DNS
Dashboard
Blocklist
Tests

📸 Dashboard Preview
┌─────────────────────────────────────────────────────────┐
│  DNS SHIELD  │  LIVE  Server: 5053  Dashboard: 8080     │
├──────────┬──────────────────────────────────────────────┤
│ Dashboard│  Total: 1,247  Blocked: 42%  Cache: 33%      │
│ Query Logs│  Avg Speed: 0.2ms BLOCKED | 47ms FORWARDED  │
│ Domain Lookup│ [24h Graph: Allowed vs Blocked] [Top 10] │
│ Blocklists 235k│  Logs: facebook.com BLOCKED 0.2ms      │
│ Allowlist│       youtube.com FORWARDED 65ms             │
│ Analytics│       doubleclick.net BLOCKED 0.2ms          │
│ Settings │                                              │
└──────────┴──────────────────────────────────────────────┘
🚀 Features
⚡ Ultra Fast: BLOCKED/CACHED queries in 0.2ms (139μs) - RAM hash lookup O(1)
🚫 Ad Blocking: 235,974 domains blocked (oisd big list) - suffix walk + hot-reload
💾 Smart Cache: LRU cache with deque O(1), 1ms cache hit, WAL mode SQLite
📊 Real Dashboard: 8 pages - Dashboard, Logs, Lookup, Blocklists, Allowlist, Analytics, Settings
🔄 Parallel Forwarding: Race between 8.8.8.8 vs 1.1.1.1 - fastest wins, no timeouts
🛡️ Safe Fail: SERVFAIL RCODE=2 on upstream fail, never silent drop
📈 Retention: Auto purge logs older than 5 days (configurable 1/5/7/30/Keep All), hourly stats
🔒 Privacy: Anonymize Client IP toggle (xxx.xxx.xxx.1), Clear Logs, DB VACUUM
⚙️ Rate Limit: 100 qps per client protection
🏗️ Architecture
Client (Browser)
    ↓ UDP 5053
┌──────────────┐
│  server.py   │ ← UDP socket, threaded
├──────────────┤
│ parser.py    │ → Extract domain, QTYPE A/AAAA/NS
│ blocklist.py │ → Suffix walk: ads.example.com → example.com check (235k list)
│ cache.py     │ → LRU O(1) deque + dict
│ ratelimit.py │ → Token bucket per IP
│ forwarder.py │ → stdlib socket parallel race 8.8.8.8 vs 1.1.1.1 (no dnspython)
│ builder.py   │ → Build 0.0.0.0 for BLOCKED, SERVFAIL for fail
│ stats.py     │ → Munim ji: Counter, deque, Lock, Singleton, queries.db WAL
└──────────────┘
    ↓
Dashboard 8080 (Flask + Tailwind + Chart.js)
    ↓
queries.db (SQLite WAL, timeout=10, hourly rollup)
Why stdlib socket forwarder?
Local dns/ package collides with dnspython dns.message → ModuleNotFoundError. Pure stdlib avoids collision + true parallel race.

📦 Installation
# Clone
git clone https://github.com/yourname/DNS-Shield.git
cd DNS-Project-3rd-CN/DNS
# Venv
python -m venv venv
venv\Scripts\activate  # Windows
# source venv/bin/activate # Linux/Mac
# Install
pip install -r requirements.txt
# dnspython, flask
# Run DNS Server (Port 5053)
python main.py
# Output: Loaded 235974 domains, Listening 0.0.0.0:5053
# Run Dashboard (Port 8080) - new terminal
python -m dns.dashboard
# Open http://localhost:8080
🧪 Testing
# Unit Tests - 42 tests
python -m unittest discover tests -v
# test_blocklist, test_cache, test_parser, test_ratelimit, test_stats, test_retention, test_forwarder
# Manual URL Test (Port 5053)
python tests/RandomURL_test.py
Expected Result:

🟢 hdhub4u.fast              => FORWARDED -> 172.67.209.31 (79ms)
🟢 new9.hdhub4u.cl           => FORWARDED -> 172.67.189.12 (68ms) [CACHED 2ms]
🔴 facebook.com              => BLOCKED [0.0.0.0] (0.2ms)
🟢 hdhub4u.com               => FORWARDED -> 172.98.192.102 (686ms)
🟡 ads.example.com           => FORWARDED (NXDOMAIN - domain doesn't exist) (96ms)
🟢 youtube.com               => FORWARDED (65ms)
RESULT: 2 Blocked | 4 Forwarded | 0 Timeouts
Test Real DNS:

# NS record
python -c "import dns.message, dns.query; q=dns.message.make_query('youtube.com','NS'); r=dns.query.udp(q,'127.0.0.1',port=5053,timeout=3); print(r)"
# A record
python -c "import dns.message, dns.query; q=dns.message.make_query('youtube.com','A'); r=dns.query.udp(q,'127.0.0.1',port=5053,timeout=3); print(r)"
🌐 Port 53 Real Browser Test (Copy Project)
Main project uses 5053 to avoid admin rights. For real browser ad-blocking:

# 1. Copy folder
xcopy /E /I Q:\MAN-PROJECT\DNS-Project-3rd-CN\DNS Q:\DNS-Port53
# 2. Change port in Q:\DNS-Port53\config.json: 5053 -> 53
# 3. Run as Admin
.\START_DNS_Port53.ps1
# 4. Set Windows DNS to 127.0.0.1
Set-DnsClientServerAddress -InterfaceAlias "Wi-Fi" -ServerAddresses 127.0.0.1 -Validate $false
ipconfig /flushdns
# 5. Disable Chrome Secure DNS: chrome://settings/security -> Use secure DNS OFF
# 6. Test: nslookup facebook.com 127.0.0.1 -> 0.0.0.0
# 7. Restore after test
.\STOP_Restore_Internet.ps1
📊 Performance
Metric	DNS Shield	Pi-hole	AdGuard Home
BLOCKED Avg	0.2ms (139μs)	0.5-1ms	0.8ms
CACHED Avg	0.2-1ms	1-2ms	1-3ms
FORWARDED Avg	47-96ms	20-80ms	30-90ms
Cache Hit	33.5%	25-40%	30%
Blocklist	235,974	100k-5M	100k+
Timeouts	0	0-1%	0-1%
Why 139μs is NOT high?
139μs = 0.139ms → RAM hash lookup. <1ms = excellent. Forwarded 20-80ms is network latency to Google/Cloudflare.

🔌 API Endpoints
GET  /api/stats          → {total, blocked, blocked_pct, cache_pct, avg_ms, top_blocked, top_clients, cache{live,hits,ratio}, upstream[]}
GET  /api/logs?limit=100 → [{time, client_ip, domain, type, status, timetaken, upstream}]
GET  /api/hourly?hours=24→ [{hour, total, blocked, cached}]
GET  /api/settings       → {retention_days, anonymize_ip}
POST /api/settings       → {retention_days, anonymize_ip}
POST /api/clear          → Delete all logs + VACUUM
POST /api/purge          → purge_old_logs() DELETE WHERE < now-5days
GET  /api/check?domain=x → {domain, blocked, category, source}
GET  /api/blocklists     → [{name, count, enabled, last_updated}]
GET  /api/allowlist      → [domains]
POST /api/allowlist      → {domain}
📁 Project Structure
DNS/
├── main.py                 # Entry point, UDP 5053 listener
├── config.json             # port, upstreams, blocklist paths
├── queries.db              # SQLite WAL (gitignored)
├── dns/
│   ├── server.py           # UDP server, SERVFAIL safety
│   ├── parser.py           # DNS packet parser
│   ├── blocklist.py        # 235k suffix walk + hot-reload
│   ├── cache.py            # LRU O(1) deque
│   ├── forwarder.py        # stdlib socket parallel race (FIXED)
│   ├── builder.py          # 0.0.0.0, ::, SERVFAIL builder
│   ├── ratelimit.py        # Token bucket
│   ├── stats.py            # Counter, deque, Lock, Singleton + retention
│   └── dashboard.py        # Flask 8080, 8 routes, real DB reads
├── templates/
│   ├── base.html           # Sidebar #0f172a, top bar Live dot
│   ├── dashboard.html      # 4 cards + 24h line + Top10
│   ├── logs.html           # Table + search + filter + pagination
│   ├── lookup.html         # Domain check + Allow/Block
│   ├── blocklists.html     # 4 cards with toggle
│   ├── allowlist.html      # Add/Remove
│   ├── analytics.html      # Hourly bar + category pie
│   └── settings.html       # Retention slider + anonymize toggle
├── blocklists/
│   ├── ads.txt, trackers.txt, malware.txt, custom.txt (235974 total)
│   └── allowlist.txt
├── tests/
│   ├── RandomURL_test.py   # Fixed logic: 0.0.0.0= BLOCKED else FORWARDED
│   ├── test_blocklist.py
│   ├── test_cache.py
│   ├── test_stats.py
│   └── test_retention.py
└── requirements.txt
🐛 Root Causes Fixed
1. Namespace Collision: dns/ folder shadows dnspython → Used pure stdlib socket in forwarder
2. Silent Drop: Upstream timeout → no response → client hangs 3s → Now SERVFAIL RCODE=2
3. Blacklist Bug: 3 fails → blacklist 8.8.8.8 & 1.1.1.1 for 60s → Removed
4. Test Logic Bug: ads.example.com NXDOMAIN (empty answer) treated as BLOCKED → Fixed: only 0.0.0.0 = BLOCKED

🎓 Viva Questions - Ready Answers
Q: Avg speed 139μs high hai?
A: Nahi sir, 139μs = 0.139ms BLOCKED/CACHED ka hai, RAM lookup. Pi-hole 0.5ms deta hai. Forwarded 47ms hai jo network latency hai.

Q: Cache ratio kaise nikala?
A: hits / (hits + forwarded) - pehle hits/total galat tha, kyunki blocked ko cache me count nahi karna.

Q: Port 53 kyun nahi?
A: Port 53 admin rights mangta hai. Main 5053 pe dev kiya, Port53 copy real test ke liye alag hai.

Q: ads.example.com FORWARDED kyun?
A: Wo domain exist hi nahi karta, NXDOMAIN aata hai upstream se. Blocklist me nahi hai toh forward hoga. Agar block karna hai toh custom.txt me add karna padega.

Q: Real Pi-hole se difference?
A: Pi-hole me CNAME cloaking nahi pakadta easily, maine suffix walk + AAAA :: blocking + parallel race + retention add kiya.

🔮 Future Ideas
 CNAME Cloaking Detection (track.example.com → CNAME → doubleclick.net)
 AAAA → :: blocking (IPv6 bypass stop)
 Per-client stats & Rate limit graph
 Dashboard Basic Auth (admin/dns123)
 Open Resolver Protection (only 127.0.0.1 + LAN allow)
 Export CSV + Dark/Light mode
 DoH Upstream (DNS over HTTPS)
👨‍💻 Author
College Project - 3rd Sem CN
Stack: Python, Flask, SQLite WAL, Tailwind, Chart.js, dnspython (test only), stdlib socket

Integrity: Core DNS engine (parser, cache O(1), blocklist suffix walk, ratelimit, forwarder race) + tests + integration = My work. Dashboard UI boilerplate = AI assisted, fixed to real DB data.

📜 License
MIT - College Project

Run & Test:

python main.py
python -m dns.dashboard
# http://localhost:8080
python tests/RandomURL_test.py
