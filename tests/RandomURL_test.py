import sys
import time

# Ensure UTF-8 output encoding for Windows terminal
try:
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
except Exception:
    pass

import dns.message
import dns.query

MANUAL_URLS = [
    "hdhub4u.fast",
    "new9.hdhub4u.cl",
    "facebook.com",
    "connect.facebook.net",
    "hdhub4u.com",
    "ads.example.com",
    "youtube.com",
    "doubleclick.net",
    "google.com"
]

def test_one(domain):
    clean = domain.strip().replace("https://","").replace("http://","").split("/")[0]
    try:
        q = dns.message.make_query(clean, 'A')
        start = time.perf_counter()
        r = dns.query.udp(q, '127.0.0.1', port=53, timeout=4)
        elapsed = (time.perf_counter() - start) * 1000

        rcode = r.rcode()
        blocked = False
        for rrset in r.answer:
            for rr in rrset:
                if str(rr) in ('0.0.0.0', '::'):
                    blocked = True

        if blocked:
            print(f"[BLOCKED]   {clean:38} => 0.0.0.0 ({elapsed:.0f}ms)")
            return "BLOCKED"
        else:
            if rcode == 3:
                print(f"[NXDOMAIN]  {clean:38} => FORWARDED ({elapsed:.0f}ms)")
                return "FORWARDED"
            elif len(r.answer) == 0:
                print(f"[FORWARDED] {clean:38} => No answer (rcode={rcode}) ({elapsed:.0f}ms)")
                return "FORWARDED"
            else:
                ip = str(r.answer[0][0]) if len(r.answer) > 0 else "no-ip"
                cached = " [CACHED]" if elapsed < 5 else ""
                print(f"[FORWARDED] {clean:38} => {ip} ({elapsed:.0f}ms){cached}")
                return "FORWARDED"
    except Exception as e:
        print(f"[ERROR]     {clean:38} => {e}")
        return "ERROR"

print("=" * 75)
print("MANUAL URL TEST - DNS SHIELD Port 53")
print("BLOCKED = 0.0.0.0 / :: | FORWARDED = Upstream answer")
print("=" * 75)
blocked = 0
forwarded = 0
for d in MANUAL_URLS:
    res = test_one(d)
    if res == "BLOCKED":
        blocked += 1
    elif "FORWARDED" in res:
        forwarded += 1
    time.sleep(0.05)
print("=" * 75)
print(f"RESULT: {blocked} Blocked | {forwarded} Forwarded | Total {len(MANUAL_URLS)}")
print("Dashboard http://localhost:8081/ pe check karo")
print("=" * 75)
