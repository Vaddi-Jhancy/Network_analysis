import pandas as pd
import numpy as np
import base64
from collections import defaultdict
import glob

def load_csv_files(path):
    all_files = glob.glob(path + "/*.csv")
    dataframes = [pd.read_csv(file) for file in all_files]
    return pd.concat(dataframes, ignore_index=True)

# Load dataset
df = load_csv_files("./network_data")
# Load dataset
# path = "./network_data/network_analysis_data3.csv"
# df = pd.read_csv(path)
df.fillna("", inplace=True)

# Convert date columns
print("Converting start and stop times to datetime format...")
df['startDateTime'] = pd.to_datetime(df['startDateTime'], errors='coerce')
df['stopDateTime'] = pd.to_datetime(df['stopDateTime'], errors='coerce')
df['duration'] = (df['stopDateTime'] - df['startDateTime']).dt.total_seconds()
df['duration'].fillna(0, inplace=True)

print("Dataset loaded with", len(df), "flows")

# (a) Detecting Complex Attack Patterns
print("\n(a) Detecting Complex Attack Patterns")

# Stealthy Port Scan Detection
print("Detecting stealthy port scans...")
port_scan_threshold = 20
scan_sources = df.groupby('source')['destinationPort'].nunique()
stealthy_scanners = scan_sources[scan_sources > port_scan_threshold]
print("Stealthy port scanners detected:")
print(stealthy_scanners)

# Slow DDoS Detection
print("Identifying possible slow DDoS patterns...")
low_rate_ddos = df[(df['totalSourceBytes'] < 500) & (df['duration'] > 300)]
ddos_targets = low_rate_ddos['destination'].value_counts()
print("Potential slow DDoS targets:")
print(ddos_targets.head())

# IP Hopping Detection
print("Checking for IP hopping behavior...")
dest_per_src = df.groupby('destination')['source'].nunique()
ip_hopping = dest_per_src[dest_per_src > 20]
print("Destinations contacted by many different sources:")
print(ip_hopping)

# (b) Malicious Payload Identification
print("\n(b) Malicious Payload Identification")

# Extract base64 payloads and detect anomalies
print("Analyzing payloads for anomalies...")
def decode_base64(payload):
    try:
        if isinstance(payload, str) and payload:
            return base64.b64decode(payload).decode('utf-8', errors='ignore')
        return ""
    except:
        return ""

df['decoded_source_payload'] = df['sourcePayloadAsBase64'].apply(decode_base64)
df['decoded_dest_payload'] = df['destinationPayloadAsBase64'].apply(decode_base64)

anomalous_payloads = df[(df['decoded_source_payload'].str.contains('cmd|powershell|wget|curl|\bin\sh', case=False, na=False)) |
                        (df['decoded_dest_payload'].str.contains('cmd|powershell|wget|curl|\bin\sh', case=False, na=False))]
print("Flows with suspicious command patterns:", len(anomalous_payloads))

# Encrypted traffic behavior check
print("Checking encrypted traffic that doesn't match normal patterns...")
encrypted_anomaly = df[(df['protocolName'].str.lower().str.contains("ssl|tls")) & (df['totalDestinationBytes'] == 0)]
print("Suspicious encrypted flows:", len(encrypted_anomaly))

# C2 pattern detection (repeated connections to same destination)
print("Detecting potential command-and-control communication patterns...")
c2_suspects = df.groupby(['source', 'destination']).size()
c2_suspects = c2_suspects[c2_suspects > 10]
print("Repeated communication pairs:")
print(c2_suspects)

# (c) Threat Attribution and Risk Analysis
print("\n(c) Threat Attribution and Risk Analysis")

def assign_risk(row):
    if row['source'] in stealthy_scanners.index:
        return "High", "Stealthy port scan"
    elif row['destination'] in ddos_targets.index:
        return "Medium", "Slow DDoS detected"
    elif row['destination'] in ip_hopping.index:
        return "High", "IP hopping behavior"
    elif row.name in anomalous_payloads.index:
        return "High", "Suspicious payload command detected"
    elif row.name in encrypted_anomaly.index:
        return "Medium", "Unusual encrypted traffic"
    elif (row['source'], row['destination']) in c2_suspects:
        return "High", "Repeated C2-style traffic"
    else:
        return "Low", "Normal"

print("Assigning risk categories to flows...")
df[['RiskLevel', 'RiskReason']] = df.apply(assign_risk, axis=1, result_type="expand")

# Summary report
print("\nThreat Summary Report:")
print(df['RiskLevel'].value_counts())

print("\nSample High-Risk Events:")
print(df[df['RiskLevel'] == 'High'][['source', 'destination', 'RiskReason']].head())
