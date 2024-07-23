nodes = '''
i-074a30234bc5ddf58	3.86.211.148	172.31.95.191
i-09ee6ca7b69b2f74b	34.203.217.123	172.31.93.44
i-02c3b2cc96af2cfa9	35.175.243.33	172.31.92.182
i-031d0383e4574c3cd	54.210.246.158	172.31.92.212
i-0166255d7b995e5e8	18.205.243.23	172.31.89.137
i-03de63f20bf15d4f0	44.210.87.113	172.31.94.248
i-0289ea432c84c0be0	44.201.131.39	172.31.88.40
i-0f867478c2a5bcdc6	35.171.83.180	172.31.42.181
i-0a7b3a87cfeb940c7	52.23.180.3	172.31.46.85
i-0b636182151641311	52.90.72.208	172.31.35.104
i-04df36215a0060d37	18.232.103.166	172.31.47.215
i-0a8394c6e12919f12	52.71.64.53	172.31.32.235
i-00c3def13c34e6a2f	34.229.114.15	172.31.38.184
i-0793053df271f9dd2	52.90.181.39	172.31.47.172
i-0692d3aa2705e8c6b	54.86.6.193	172.31.46.220
i-071ac8d2136ba7499	54.198.29.30	172.31.33.17

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