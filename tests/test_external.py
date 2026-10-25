import sys, os
# Ye line sabse upar add karni hai
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from dns.blocklist import Blocklist
import time, random, string

b = Blocklist()
b.load_all_blocklists("blocklists")

# bahar ke 10k random domain jo list me nahi hai
external = [''.join(random.choices(string.ascii_lowercase, k=10)) + ".com" for _ in range(10000)]

start = time.time()
for d in external:
    b.is_blocked(d)
print(f"External 10k avg: {(time.time()-start)/10000*1e6:.2f} micro sec")