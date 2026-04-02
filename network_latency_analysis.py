import os
import json
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
from scapy.all import rdpcap, IP, TCP

# --- CONFIGURATION ---
IP_MAP = {
    "192.168.187.3": "DT1",
    "192.168.187.6": "Edge",
    "192.168.187.5": "DT2"
}

SCENARIOS = {
    'No Crypto': 'no_crypto_',
    'Auth Only': 'auth_only_',
    'Enc Only': 'enc_only_',
    'Full System': 'full_latest_'
}

TARGET_LEGS = [
    ("DT1", "Edge"),
    ("Edge", "DT2"),
    ("DT2", "Edge"),
    ("Edge", "DT1")
]

# --- 1. PCAP PROCESSING LOGIC ---
def analyze_pcap_sessions(pcap_path, scenario_prefix):
    print(f"[*] Processing {pcap_path} for TCP Session Latency...")
    try:
        packets = rdpcap(pcap_path)
    except Exception as e:
        print(f"Error: {e}")
        return

    # Dictionary to track start and end times of unique TCP streams
    # Key: (src_ip, src_port, dst_ip, dst_port)
    sessions = {}

    for pkt in packets:
        if IP in pkt and TCP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
            ts = float(pkt.time)

            # Create a unique session key (bidirectional)
            session_key = tuple(sorted([(src_ip, sport), (dst_ip, dport)]))

            if session_key not in sessions:
                # [Start Time, End Time, Initial Source, Initial Destination]
                sessions[session_key] = [ts, ts, src_ip, dst_ip]
            else:
                # Update the last seen timestamp for this session
                sessions[session_key][1] = ts

    # Organize into the 4 logical legs
    leg_stats = {f"{src}_to_{dst}": [] for src, dst in TARGET_LEGS}

    for key, (start, end, s_ip, d_ip) in sessions.items():
        duration_ms = (end - start) * 1000
        
        # Filter: Ignore empty connections or long-running background noise
        if 0.1 < duration_ms < 1000:
            src_name = IP_MAP.get(s_ip)
            dst_name = IP_MAP.get(d_ip)
            
            leg_key = f"{src_name}_to_{dst_name}"
            if leg_key in leg_stats:
                leg_stats[leg_key].append(round(duration_ms, 4))

    # Save to JSON
    output_fn = f"{scenario_prefix}network_stats_tcp.json"
    with open(output_fn, "w") as f:
        json.dump(leg_stats, f, indent=4)
    print(f"[SUCCESS] Data saved to {output_fn}")

# --- 2. PLOTTING LOGIC ---
def plot_comparative_analysis():
    all_data = []

    for label, prefix in SCENARIOS.items():
        filename = f"{prefix}network_stats_tcp.json"
        if not os.path.exists(filename):
            print(f"Warning: {filename} not found. Run analysis first.")
            continue
            
        with open(filename, 'r') as f:
            data = json.load(f)
            for leg, values in data.items():
                for val in values:
                    all_data.append({
                        'Scenario': label,
                        'Leg': leg.replace('_', ' '),
                        'Latency (ms)': val
                    })

    if not all_data:
        print("No data available to plot.")
        return

    df = pd.DataFrame(all_data)

    plt.figure(figsize=(14, 8))
    sns.set_theme(style="whitegrid")
    
    # Using a Boxenplot to show distribution clearly across 4 scenarios
    ax = sns.boxenplot(x='Leg', y='Latency (ms)', hue='Scenario', data=df, palette="husl")
    
    plt.title('True Network Latency: TCP Session Duration Comparison', fontsize=16)
    plt.ylabel('Duration (ms) - Handshake to Final ACK')
    plt.xlabel('Communication Path')
    
    output_img = 'final_network_comparison_tcp.png'
    plt.savefig(output_img, dpi=300)
    plt.close()
    print(f"[SUCCESS] Final comparison plot saved: {output_img}")

# --- EXECUTION ---
if __name__ == "__main__":
    # Step 1: Process all PCAPs
    # Update these filenames to match your local directory
    pcaps = [
        ("no_crypto_edge_server_traffic.pcapng", "no_crypto_"),
        ("auth_only_edge_server_traffic.pcapng", "auth_only_"),
        ("enc_only_edge_server_traffic.pcapng", "enc_only_"),
        ("edge_server_traffic.pcapng", "full_latest_")
    ]

    for pcap_file, prefix in pcaps:
        if os.path.exists(pcap_file):
            analyze_pcap_sessions(pcap_file, prefix)
        else:
            print(f"File not found: {pcap_file}")

    # Step 2: Generate the Graph
    plot_comparative_analysis()