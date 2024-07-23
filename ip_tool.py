nodes = '''
i-074a30234bc5ddf58	54.174.96.31	172.31.95.191
i-09ee6ca7b69b2f74b	44.204.176.82	172.31.93.44
i-02c3b2cc96af2cfa9	107.21.32.100	172.31.92.182
i-031d0383e4574c3cd	54.145.138.175	172.31.92.212
i-0166255d7b995e5e8	54.173.192.102	172.31.89.137
i-03de63f20bf15d4f0	3.83.255.243	172.31.94.248
i-0289ea432c84c0be0	3.93.10.153	172.31.88.40
i-0f867478c2a5bcdc6	3.81.172.82	172.31.42.181
i-0a7b3a87cfeb940c7	54.196.124.178	172.31.46.85
i-0b636182151641311	3.89.6.182	172.31.35.104
i-04df36215a0060d37	34.226.198.71	172.31.47.215
i-0a8394c6e12919f12	54.147.186.41	172.31.32.235
i-00c3def13c34e6a2f	54.226.24.205	172.31.38.184
i-0793053df271f9dd2	54.156.44.174	172.31.47.172
i-0692d3aa2705e8c6b	52.91.177.129	172.31.46.220
i-071ac8d2136ba7499	54.236.4.124	172.31.33.17


'''

num_regions = 16
N = 16

n = int(N / num_regions)
r = N - num_regions * n

each_region_n = []
for i in range(num_regions):
    if r > 0:
        each_region_n.append(n + 1)
        r -= 1
    else:
        each_region_n.append(n)
print(each_region_n)

public_ips = []
private_ips = []

for line in nodes.splitlines():
    try:
        _, public, private = line.split()
        public_ips.append(public)
        private_ips.append(private)
    except:
        pass

print("N=%d" % len(public_ips))

print("# public IPs")
print("pubIPsVar=(", end='')
for i in range(len(public_ips) - 1):
    print("[%d]=\'%s\'" % (i, public_ips[i]))
i = len(public_ips) - 1
print("[%d]=\'%s\')" % (i, public_ips[i]))

print("# private IPs")
print("priIPsVar=(", end='')
for i in range(len(private_ips) - 1):
    print("[%d]=\'%s\'" % (i, private_ips[i]))
i = len(private_ips) - 1
print("[%d]=\'%s\')" % (i, private_ips[i]))