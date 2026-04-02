import json
import os
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

# Configuration
SCENARIOS = {
    'No Crypto': 'no_crypto_',
    'Auth Only': 'auth_only_',
    'Enc Only': 'enc_only_',
    'Full System': 'full_latest_'
}

def load_json(filepath):
    if not os.path.exists(filepath):
        return None
    with open(filepath, 'r') as f:
        return json.load(f)

def get_stats(data_list):
    if not data_list or len(data_list) == 0:
        return 0.0, 0.0, 0
    return np.mean(data_list), np.std(data_list), len(data_list)

def analyze_and_plot():
    results = []

    # Define a consistent format string for headers and rows
    # Col widths: Scenario(15), Flow(12), Sender(10), NetL1(10), Edge(10), NetL2(10), Recv(10), Total(10)
    row_fmt = "{:<15} | {:<12} | {:>10} | {:>10} | {:>10} | {:>10} | {:>10} | {:>10}"
    
    header = row_fmt.format("SCENARIO", "FLOW", "SENDER", "NET L1", "EDGE", "NET L2", "RECV", "TOTAL")
    separator = "-" * len(header)

    print("\n" + "=" * len(header))
    print("MAJOR PROJECT: BIDIRECTIONAL END-TO-END PERFORMANCE REPORT")
    print("=" * len(header))
    print(header)
    print(separator)

    for label, prefix in SCENARIOS.items():
        dt1 = load_json(f"{prefix}stats_DT_1.json")
        edge = load_json(f"{prefix}stats_edge.json")
        dt2 = load_json(f"{prefix}stats_DT_2.json")
        net = load_json(f"{prefix}network_stats_tcp.json")

        if not all([dt1, edge, dt2, net]):
            continue

        # --- Forward Flow Data ---
        f_comp_s, _, _ = get_stats(dt1['sender_stats']['raw_ms'])
        f_net_l1, _, _ = get_stats(net['DT1_to_Edge'])
        f_comp_e, _, _ = get_stats(edge['raw_data_ms'])
        f_net_l2, _, _ = get_stats(net['Edge_to_DT2'])
        f_comp_r, _, _ = get_stats(dt2['receiver_stats']['raw_ms'])
        f_total = f_comp_s + f_net_l1 + f_comp_e + f_net_l2 + f_comp_r
        
        results.append({
            'Scenario': label, 'Direction': 'Forward (DT1->DT2)',
            'Sender Comp': f_comp_s, 'Net Leg 1': f_net_l1, 
            'Edge Comp': f_comp_e, 'Net Leg 2': f_net_l2, 'Recv Comp': f_comp_r
        })

        # --- Reverse Flow Data ---
        r_comp_s, _, _ = get_stats(dt2['sender_stats']['raw_ms'])
        r_net_l1, _, _ = get_stats(net['DT2_to_Edge'])
        r_net_l2, _, _ = get_stats(net['Edge_to_DT1'])
        r_comp_r, _, _ = get_stats(dt1['receiver_stats']['raw_ms'])
        r_total = r_comp_s + r_net_l1 + f_comp_e + r_net_l2 + r_comp_r

        results.append({
            'Scenario': label, 'Direction': 'Reverse (DT2->DT1)',
            'Sender Comp': r_comp_s, 'Net Leg 1': r_net_l1, 
            'Edge Comp': f_comp_e, 'Net Leg 2': r_net_l2, 'Recv Comp': r_comp_r
        })

        # Print with perfect alignment
        print(row_fmt.format(label, "Forward", f"{f_comp_s:.2f}ms", f"{f_net_l1:.2f}ms", f"{f_comp_e:.2f}ms", f"{f_net_l2:.2f}ms", f"{f_comp_r:.2f}ms", f"{f_total:.2f}ms"))
        print(row_fmt.format("", "Reverse", f"{r_comp_s:.2f}ms", f"{r_net_l1:.2f}ms", f"{f_comp_e:.2f}ms", f"{r_net_l2:.2f}ms", f"{r_comp_r:.2f}ms", f"{r_total:.2f}ms"))
        print(separator)

    # --- PLOTTING ---
    df = pd.DataFrame(results)
    
    # Create a unique label for each bar (Scenario + Direction)
    df['PlotLabel'] = df['Scenario'] + "\n(" + df['Direction'].str.extract(r'\((.*)\)')[0] + ")"
    
    plt.figure(figsize=(14, 8))
    bottom = np.zeros(len(df))
    components = ['Sender Comp', 'Net Leg 1', 'Edge Comp', 'Net Leg 2', 'Recv Comp']
    colors = ['#2c3e50', '#3498db', '#e67e22', '#2ecc71', '#9b59b6']
    
    for i, col in enumerate(components):
        plt.bar(df['PlotLabel'], df[col], bottom=bottom, label=col, color=colors[i], edgecolor='white', width=0.6)
        bottom += df[col]

    plt.title('Total End-to-End Latency Breakdown: Bidirectional Flow Analysis', fontsize=16)
    plt.ylabel('Latency (ms)', fontsize=12)
    plt.xticks(rotation=0)
    plt.legend(title="Latency Components", bbox_to_anchor=(1.05, 1), loc='upper left')
    plt.grid(axis='y', linestyle='--', alpha=0.6)
    
    plt.tight_layout()
    plt.savefig('e2e_stacked_latency_analysis.png', dpi=300)
    plt.close()
    print("\n[SUCCESS] Final E2E Stacked Graph saved as 'e2e_stacked_latency_analysis.png'")

if __name__ == "__main__":
    analyze_and_plot()