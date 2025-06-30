import pandas as pd
import numpy as np
import glob

# Load all CSV files
def load_csv_files(path):
    all_files = glob.glob(path + "/*.csv")  # Modify path as needed
    dataframes = [pd.read_csv(file) for file in all_files]
    return pd.concat(dataframes, ignore_index=True)

# Load dataset
df = load_csv_files("./network_data")  # Change this path accordingly
# df = pd.read_csv("./network_data/network_analysis_data6.csv")
df.fillna("", inplace=True)

# Convert to datetime
df['startDateTime'] = pd.to_datetime(df['startDateTime'], errors='coerce')
df['stopDateTime'] = pd.to_datetime(df['stopDateTime'], errors='coerce')

# Pre-calculate totals and packet sizes
total_packets = df['totalSourcePackets'] + df['totalDestinationPackets']
total_bytes = df['totalSourceBytes'] + df['totalDestinationBytes']
packet_sizes = (total_bytes / total_packets).replace([np.inf, -np.inf], np.nan)
df['packet_size'] = packet_sizes

# ------------------ (a) Statistical Traffic Analysis ------------------

# Thresholds for anomalies in packet size
mean = packet_sizes.mean()
std = packet_sizes.std()
thresh1 = mean + 2 * std
median = packet_sizes.median()
mad = np.median(np.abs(packet_sizes - median))
thresh2 = median + 2 * mad
print("Anomalies (high packet sizes using mean+std):\n", df[packet_sizes > thresh1][['source', 'destination']])
print("Anomalies (high packet sizes using median+mad):\n", df[packet_sizes > thresh2][['source', 'destination']])

# Anomalies in flow counts
flow_counts = df.groupby('source').size()
flow_thresh = flow_counts.mean() + 2 * flow_counts.std()
outlier_flows = flow_counts[flow_counts > flow_thresh]
print("Outlier sources by flow count:\n", outlier_flows)

# Protocol distribution analysis
protocol_counts = df['protocolName'].value_counts(normalize=True)
print("Protocol distribution:\n", protocol_counts)

# Traffic comparison per hour vs per day
df['hour'] = df['startDateTime'].dt.hour
df['day'] = df['startDateTime'].dt.date
hourly_bytes = df.groupby('hour')['totalSourceBytes'].sum()
daily_bytes = df.groupby('day')['totalSourceBytes'].sum()
print("Hourly traffic:\n", hourly_bytes)
print("Daily traffic:\n", daily_bytes)

# Flag IPs with abnormally high/low traffic
byte_sums = df.groupby('source')['totalSourceBytes'].sum()
byte_thresh_hi = byte_sums.mean() + 2 * byte_sums.std()
byte_thresh_lo = byte_sums.mean() - 2 * byte_sums.std()
outlier_ips = byte_sums[(byte_sums > byte_thresh_hi) | (byte_sums < byte_thresh_lo)]
print("Outlier IPs (high/low volume):\n", outlier_ips)

# ------------------ (b) Behavioral Analysis ------------------

# Identify IPs with sudden spike in traffic
source_groups = df.groupby('source')
sudden_spikes = []
for ip, group in source_groups:
    daily_traffic = group.groupby(group['startDateTime'].dt.date)['totalSourceBytes'].sum()
    if len(daily_traffic) < 2:
        continue
    avg_traffic = daily_traffic.mean()
    for day in daily_traffic.index:
        if daily_traffic[day] > avg_traffic * 3:
            sudden_spikes.append((ip, day, daily_traffic[day]))
print("IPs with sudden traffic spikes:\n", sudden_spikes)

# Multiple IPs contacting common destination
recent_window = df[df['startDateTime'] > df['startDateTime'].max() - pd.Timedelta(minutes=10)]
common_targets = recent_window['destination'].value_counts()
popular_targets = common_targets[common_targets > 5].index
print("Common targets in short window:\n", popular_targets)

# Destination IP contacted by many sources
dst_contact_counts = recent_window.groupby('destination')['source'].nunique()
flagged_dsts = dst_contact_counts[dst_contact_counts > 10]
print("Destination IPs contacted by many sources:\n")
print(flagged_dsts)

# ------------------ (c) Suspicious Communication Patterns ------------------

# Long duration flows
df['duration'] = (df['stopDateTime'] - df['startDateTime']).dt.total_seconds()
long_flows = df[df['duration'] > df['duration'].quantile(0.99)]
print("Long duration flows:\n", long_flows[['source', 'destination', 'duration']])

# IPs using multiple protocols in short time
recent_df = df[df['startDateTime'] > df['startDateTime'].max() - pd.Timedelta(minutes=10)]
protocol_variety = recent_df.groupby('source')['protocolName'].nunique()
flagged_multi_protocol = protocol_variety[protocol_variety > 3]
print("Sources using multiple protocols quickly:\n", flagged_multi_protocol)
