import dns.message, dns.query, time

MANUAL_URLS = [
    "hdhub4u.fast",
    "new9.hdhub4u.cl",
    "facebook.com",
    "hdhub4u.com",
    "ads.example.com",
    "youtube.com",
    "doubleclick.net",
    "google.com"
]

def test_one(domain):
    domain = domain.strip().replace("https://","").replace("http://","").split("/")[0]
    try:
        q = dns.message.make_query(domain, 'A')
        start = time.perf_counter()
        r = dns.query.udp(q, '127.0.0.1', port=5053, timeout=4)
        elapsed = (time.perf_counter()-start)*1000
        
        # Sahi logic: sirf 0.0.0.0 ya :: aaye toh BLOCKED
        ans_str = str(r.answer)
        rcode = r.rcode()
        
        is_blocked_ip = '0.0.0.0' in ans_str or '0.0.0.0' in str(r) and len(r.answer)>0
        
        # Check karein - agar answer me 0.0.0.0 hai toh BLOCKED
        blocked = False
        for rrset in r.answer:
            for rr in rrset:
                if str(rr) == '0.0.0.0' or str(rr) == '::':
                    blocked = True
        
        if blocked:
            print(f"🔴 {domain:40} => BLOCKED [0.0.0.0] ({elapsed:.0f}ms)")
            return "BLOCKED"
        else:
            if rcode == 3:
                print(f"🟡 {domain:40} => FORWARDED (NXDOMAIN - domain exist nahi karta) ({elapsed:.0f}ms)")
                return "FORWARDED"
            elif len(r.answer) == 0:
                print(f"🟡 {domain:40} => FORWARDED (No answer, rcode={rcode}) ({elapsed:.0f}ms)")
                return "FORWARDED"
            else:
                ip = str(r.answer[0][0]) if len(r.answer)>0 else "no-ip"
                cached = " [CACHED]" if elapsed < 5 else ""
                print(f"🟢 {domain:40} => FORWARDED -> {ip} ({elapsed:.0f}ms){cached}")
                return "FORWARDED"
    except Exception as e:
        print(f"⚠️  {domain:40} => ERROR: {e}")
        return "ERROR"

print("="*75)
print("MANUAL URL TEST - FIXED LOGIC - Port 5053")
print("BLOCKED = sirf 0.0.0.0 aaye toh | FORWARDED = upstream se aaya")
print("="*75)
blocked=0; forwarded=0
for d in MANUAL_URLS:
    res = test_one(d)
    if res=="BLOCKED": blocked+=1
    elif "FORWARDED" in res: forwarded+=1
    time.sleep(0.1)
print("="*75)
print(f"RESULT: {blocked} Blocked | {forwarded} Forwarded | Total {len(MANUAL_URLS)}")
print("Dashboard http://localhost:8080/logs pe check karo - wahi sahi hai")
print("="*75)
