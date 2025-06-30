from datasketch import HyperLogLog
import pandas as pd
import hashlib
import math
import numpy as np
import glob
import time

# Load all CSV files
def load_csv_files(path):
    all_files = glob.glob(path + "/*.csv")
    dataframes = [pd.read_csv(file) for file in all_files]
    return pd.concat(dataframes, ignore_index=True)

class CountMinSketch:
    def __init__(self, width=1000, depth=5):
        self.width = width
        self.depth = depth
        self.tables = np.zeros((depth, width), dtype=int)

    def _hash(self, x, i):
        key = f"{x}_{i}".encode('utf-8')
        h = hashlib.md5(key).hexdigest()
        return int(h, 16) % self.width

    def update(self, x, count=1):
        for i in range(self.depth):
            idx = self._hash(x, i)
            self.tables[i][idx] += count

    def estimate(self, x):
        return min(self.tables[i][self._hash(x, i)] for i in range(self.depth))

class BloomFilter:
    def __init__(self, capacity, error_rate=0.01):
        self.capacity = capacity
        self.error_rate = error_rate
        self.size = self._get_size(capacity, error_rate)
        self.hash_count = self._get_hash_count(self.size, capacity)
        self.bit_array = [0] * self.size

    def _hashes(self, item):
        for i in range(self.hash_count):
            digest = hashlib.md5((item + str(i)).encode('utf-8')).hexdigest()
            yield int(digest, 16) % self.size

    def add(self, item):
        for i in self._hashes(item):
            self.bit_array[i] = 1

    def __contains__(self, item):
        return all(self.bit_array[i] for i in self._hashes(item))

    def _get_size(self, n, p):
        return int(-(n * math.log(p)) / (math.log(2)**2))

    def _get_hash_count(self, m, n):
        return int((m / n) * math.log(2))

# Load dataset
df = pd.read_csv("./network_data/network_analysis_data1.csv")
df.fillna("", inplace=True)

# Unique IP Estimation (HyperLogLog vs Exact)
hll = HyperLogLog(p=13)
ips = np.concatenate((df['source'].unique(), df['destination'].unique()))
start = time.time()
for ip in ips:
    hll.update(ip.encode('utf8'))
hll_time = time.time() - start

start = time.time()
exact_unique_ips = np.unique(ips)
exact_count = len(exact_unique_ips)
exact_time = time.time() - start

hll_estimate = len(hll)
error_rate = abs(hll_estimate - exact_count) / exact_count * 100

print("--- Unique IP Estimation ---")
print("Estimated unique IPs (HyperLogLog):", hll_estimate)
print("Exact unique IPs:", exact_count)
print("Error (%):", error_rate)
print(f"Time taken (HLL): {hll_time:.4f}s, (Exact): {exact_time:.4f}s\n")

# Frequent Destination IPs (Count-Min Sketch vs Exact)
cms = CountMinSketch(width=1000, depth=10)
for ip in df['destination']:
    cms.update(ip.encode('utf8'))

top_real = df['destination'].value_counts().head(5)
top_approx = {ip: cms.estimate(ip.encode('utf8')) for ip in top_real.index}

print("--- Frequent Destination IPs ---")
print("Top real:")
print(top_real)
print("Top approx:")
print(top_approx)

for ip in top_real.index:
    approx = top_approx[ip]
    real = top_real[ip]
    approx_error = abs(approx - real) / real * 100
    print(f"IP: {ip}, Real: {real}, Approx: {approx}, Error: {approx_error:.2f}%")

# Membership Testing (Bloom Filter vs Exact)
bloom = BloomFilter(capacity=10000, error_rate=0.01)
seen_set = set()

for ip in df['source']:
    bloom.add(ip)
    seen_set.add(ip)

test_ip = '192.168.5.0'
print("\n--- Membership Testing ---")
print(f"Was {test_ip} seen before (bloom)?", test_ip in bloom)
print(f"Was {test_ip} seen before (exact)?", test_ip in seen_set)

# False Positive Rate Testing
fp_test_ips = [f"10.0.0.{i}" for i in range(1000, 1100)]
false_positives = sum([1 for ip in fp_test_ips if ip in bloom])
false_positive_rate = false_positives / len(fp_test_ips) * 100

print(f"False Positive Rate of Bloom Filter: {false_positive_rate:.2f}%")
