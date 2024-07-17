nodes = '''
i-074a30234bc5ddf58 	3.86.187.236 	172.31.95.191
i-09ee6ca7b69b2f74b 	52.55.240.91 	172.31.93.44
i-02c3b2cc96af2cfa9 	44.201.150.149 	172.31.92.182
i-031d0383e4574c3cd 	54.210.193.230 	172.31.92.212
i-0880c827eb1b01eb5 	3.141.13.254 	172.31.27.67
i-0fc35818627ff4480 	18.191.220.233 	172.31.16.161
i-0674a7063a4e4c329 	3.17.151.128 	172.31.21.83
i-08dc228ab1a55b6a6 	13.58.177.183 	172.31.26.21
i-061d489292cc90cf4 	54.193.50.204 	172.31.12.144
i-091be4d33973771ae 	54.153.50.209 	172.31.1.249
i-0cda4f263b880c501 	54.177.168.42 	172.31.11.120
i-00fbfd54e65a029e7 	13.52.213.68 	172.31.3.176
i-095c636146a4309f7 	54.149.245.140 	172.31.36.250
i-093b6eab7f6960ea9 	34.220.46.42 	172.31.36.173
i-07540a6e9098f4ef6 	54.203.94.100 	172.31.34.30
i-0188cf923c088cd22 	54.200.131.81 	172.31.33.158
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