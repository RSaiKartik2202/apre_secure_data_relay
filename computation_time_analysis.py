import json
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
import os

SCENARIOS = {
    'No Crypto': 'no_crypto_',
    'Auth Only': 'auth_only_',
    'Enc Only': 'enc_only_',
    'Full System': 'full_latest_' 
}

# The Edge only has one type of stat, DTs have two.
ENTITIES = {
    'DT1': 'stats_DT_1.json',
    'Edge': 'stats_edge.json',
    'DT2': 'stats_DT_2.json'
}

def plot_bidirectional_analysis():
    all_data = []

    for scen_label, prefix in SCENARIOS.items():
        for entity_label, filename in ENTITIES.items():
            full_path = f"{prefix}{filename}"
            
            if not os.path.exists(full_path):
                continue
                
            with open(full_path, 'r') as f:
                data = json.load(f)
                
                # 1. Check for Sender Stats (DTs)
                s_raw = data.get('sender_stats', {}).get('raw_ms', [])
                for val in s_raw:
                    all_data.append({'Scenario': scen_label, 'Entity': entity_label, 
                                     'Latency (ms)': val, 'Activity': 'Sending'})
                
                # 2. Check for Receiver Stats (DTs)
                r_raw = data.get('receiver_stats', {}).get('raw_ms', [])
                for val in r_raw:
                    all_data.append({'Scenario': scen_label, 'Entity': entity_label, 
                                     'Latency (ms)': val, 'Activity': 'Receiving'})
                
                # 3. Check for Edge Stats (Generic)
                e_raw = data.get('raw_data_ms', [])
                for val in e_raw:
                    all_data.append({'Scenario': scen_label, 'Entity': entity_label, 
                                     'Latency (ms)': val, 'Activity': 'Re-Encryption'})

    df = pd.DataFrame(all_data)

    # We create a 'Task' column for cleaner X-axis labels: e.g., "DT1 (Sending)"
    df['Task'] = df['Entity'] + "\n(" + df['Activity'] + ")"

    plt.figure(figsize=(14, 8))
    sns.set_theme(style="whitegrid")
    
    # Using 'Task' as the X-axis handles the bidirectional nature perfectly
    ax = sns.barplot(
        x='Task', 
        y='Latency (ms)', 
        hue='Scenario', 
        data=df, 
        capsize=.1, 
        palette="magma"
    )

    plt.title('Computation Time per Exchange', fontsize=16)
    plt.ylabel('Mean Latency (ms)')
    plt.xlabel('Entity & Role')
    plt.legend(title='Security Scenario', bbox_to_anchor=(1.05, 1), loc='upper left')
    
    plt.tight_layout()
    plt.savefig('bidirectional_computation.png')
    plt.show()

if __name__ == "__main__":
    plot_bidirectional_analysis()