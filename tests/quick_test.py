import dns.message, dns.query

def test(domain):
    try:
        q = dns.message.make_query(domain, 'A')
        r = dns.query.udp(q, '127.0.0.1', port=53, timeout=3)
        print(f"{domain} -> {r.answer[0] if r.answer else r}")
        if '0.0.0.0' in str(r) or 'BLOCK' in str(r) or len(r.answer)==0 or '0.0.0.0' in str(r.answer):
            print(f"  => BLOCKED [OK]")
        else:
            print(f"  => ALLOWED [OK]")
    except Exception as e:
        print(f"{domain} -> ERROR: {e}")

test("google.com")
test("doubleclick.net")
test("facebook.com")
test("ads.facebook.com")