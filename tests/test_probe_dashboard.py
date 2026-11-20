import os
import sys
import threading
import time
import urllib.request
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dns.dashboard import app

server_thread = threading.Thread(
    target=lambda: app.run(host='127.0.0.1', port=8081, debug=False, use_reloader=False),
    daemon=True
)
server_thread.start()
time.sleep(1.0)

endpoints = [
    ('/', 'DNS SHIELD'),
    ('/logs', 'Query Logs'),
    ('/lookup', 'Domain Blocklist Inspector'),
    ('/blocklists', 'Active Blocklists'),
    ('/allowlist', 'Trusted Allowlist'),
    ('/analytics', 'DNS Analytics'),
    ('/settings', 'System Settings'),
    ('/api/stats', None),
    ('/api/logs?limit=5', None),
    ('/api/hourly?hours=24', None),
    ('/api/settings', None),
    ('/api/check?domain=facebook.com', None),
    ('/api/blocklists', None),
    ('/api/allowlist', None),
]

for ep, keyword in endpoints:
    url = f'http://127.0.0.1:8081{ep}'
    req = urllib.request.urlopen(url, timeout=5)
    body = req.read().decode('utf-8')
    status = req.getcode()
    if keyword:
        assert keyword in body, f'Keyword {keyword} not in {ep}'
        print(f'OK {status} -> {ep:32} (matched "{keyword}")')
    else:
        parsed = json.loads(body)
        print(f'OK {status} -> {ep:32} (valid JSON, {len(parsed)} keys/items)')

# Check stats values from queries.db
req_stats = urllib.request.urlopen('http://127.0.0.1:8081/api/stats', timeout=5)
stats_data = json.loads(req_stats.read().decode('utf-8'))
print(f"\nLive Stats from DB:")
print(f"  Total Queries: {stats_data['total']}, Blocked: {stats_data['blocked']}, Cached: {stats_data['cached']}")
print(f"  Blocked Pct: {stats_data['blocked_pct']}%, Cache Pct: {stats_data['cache_pct']}%")
print(f"  Top Blocked Domains: {stats_data['top_blocked']}")
print(f"  Blocklist Size: {stats_data['blocklist_size']}")

# Check logs from queries.db
req_logs = urllib.request.urlopen('http://127.0.0.1:8081/api/logs?limit=5', timeout=5)
logs_data = json.loads(req_logs.read().decode('utf-8'))
print(f"\nRecent Logs from DB (count={len(logs_data)}):")
for log in logs_data[:3]:
    print(f"  [{log['time']}] {log['client']} queried {log['domain']} -> {log['status']} in {log['latency']}ms")

print("\nALL HTTP 8081 PROBES COMPLETED SUCCESSFULLY!")
