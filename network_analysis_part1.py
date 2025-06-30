import pandas as pd
import glob
from collections import Counter
import numpy as np

# Load all CSV files
def load_csv_files(path):
    all_files = glob.glob(path + "/*.csv")  # Modify path as needed
    dataframes = [pd.read_csv(file) for file in all_files]
    return pd.concat(dataframes, ignore_index=True)

# Compute total network flows
def total_flows(df):
    return len(df)

# Identify top 5 most used protocols
def top_protocols(df):
    return df['protocolName'].value_counts().head(5)

# Identify top 10 most active source and destination IPs
def top_active_ips(df):
    source_ips = df['source'].value_counts().head(10)
    dest_ips = df['destination'].value_counts().head(10)
    return source_ips, dest_ips

# Compute average packet size
def average_packet_size(df):
    total_bytes = df['totalSourceBytes'].sum() + df['totalDestinationBytes'].sum()
    total_packets = df['totalSourcePackets'].sum() + df['totalDestinationPackets'].sum()
    return total_bytes / total_packets if total_packets else 0

# Find the most common source-destination pair
def common_src_dest_pair(df):
    pairs = df.groupby(['source', 'destination']).size()
    return pairs.idxmax(), pairs.max()

# Identify consistently communicating IPs
def frequent_communication(df):
    ip_pairs = df.groupby(['source', 'destination']).size()
    return ip_pairs[ip_pairs > 797]

# Detect traffic spikes
def detect_traffic_spikes(df, time_col='startDateTime', threshold=5):
    df[time_col] = pd.to_datetime(df[time_col])
    df['time_bin'] = df[time_col].dt.floor('min')  # Group by minute
    traffic_over_time = df.groupby('time_bin').size()
    mean_traffic = traffic_over_time.mean()
    print("mean_traffic: ",mean_traffic)
    std_traffic = traffic_over_time.std()
    spikes = traffic_over_time[traffic_over_time > mean_traffic + threshold * std_traffic]
    return spikes

# Compute variance of packet sizes
def packet_size_variance(df):
    packet_sizes = pd.concat([df['totalSourceBytes'],df['totalDestinationBytes']], ignore_index=True)
    return packet_sizes.var()
    # return np.var(packet_sizes)

def packet_size_variance_separate(df):
    source_packet_sizes = df['totalSourceBytes']
    dest_packet_sizes = df['totalDestinationBytes']
    
    source_variance = source_packet_sizes.var()
    dest_variance = dest_packet_sizes.var()
    
    return source_variance, dest_variance


# Load and analyze CSV data
data = load_csv_files("./network_data")  # Change this path accordingly
# data = pd.read_csv("./network_data/network_analysis_data6.csv")
print("Total Network Flows:", total_flows(data))
print("Top 5 Protocols:", top_protocols(data))
source_ips, dest_ips = top_active_ips(data)
print("Top 10 Active Source IPs:", source_ips)
print("Top 10 Active Destination IPs:", dest_ips)
print("Average Packet Size:", average_packet_size(data))
print("Most Common Source-Destination Pair:", common_src_dest_pair(data))
print("Consistently Communicating IPs:", frequent_communication(data))
print("Traffic Spikes Detected:", detect_traffic_spikes(data))
print("Packet Size Variance:", packet_size_variance(data))
src_var, dst_var = packet_size_variance_separate(data)
print("Source Packet Size Variance:", src_var)
print("Destination Packet Size Variance:", dst_var)
