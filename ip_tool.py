nodes = '''
i-074a30234bc5ddf58 	3.86.187.236 	172.31.95.191
i-0880c827eb1b01eb5 	3.141.13.254 	172.31.27.67
i-061d489292cc90cf4 	54.193.50.204 	172.31.12.144
i-095c636146a4309f7 	54.149.245.140 	172.31.36.250
i-0d62bee5646c5a7f7 	15.206.174.162 	172.31.7.17
i-09c881d6aa92c128a 	43.200.7.252 	172.31.2.43
i-0d02526aa649fb5f0 	47.129.60.78 	172.31.19.169
i-0fc2609f6529489b7 	3.26.238.122 	172.31.35.67
i-0c58b05dcbadc209e 	54.199.17.4 	172.31.5.195
i-09711fd1619f38fe2 	15.222.253.79 	172.31.4.169
i-000203521ff9c656b 	3.66.166.103 	172.31.25.167
i-0ed1f5de2d607f3b1 	34.254.194.202 	172.31.28.202
i-06c176ed2626c8705 	3.10.58.134 	172.31.25.183
i-01568722f76370491 	35.180.73.140 	172.31.21.18
i-0f9b4cb7d2186f9a2 	13.60.34.46 	172.31.45.254
i-0de3c060f5a79a58c 	18.229.124.247 	172.31.1.14
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