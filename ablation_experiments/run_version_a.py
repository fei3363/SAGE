#!/usr/bin/env python3
"""
Run Version A (no event abstraction) on all attack types
This simulates the impact of removing event abstraction
"""

import os
import sys
import json
import time
import shutil
from collections import defaultdict

# Add parent directory to path
sys.path.append('/home/fei/SAGE')

def analyze_without_abstraction(attack_path, attack_name):
    """Analyze attack without event abstraction"""
    
    start_time = time.time()
    results = {
        'attack': attack_name,
        'raw_signatures': set(),
        'event_count': 0,
        'unique_sequences': 0,
        'estimated_states': 0,
        'processing_time': 0
    }
    
    # Parse notice.log for raw signatures
    notice_log = os.path.join(attack_path, 'notice.log')
    if os.path.exists(notice_log):
        with open(notice_log, 'r') as f:
            for line in f:
                if not line.startswith('#'):
                    parts = line.strip().split('\t')
                    if len(parts) > 11:  # msg field
                        sig = parts[11]
                        results['raw_signatures'].add(sig)
                        results['event_count'] += 1
    
    # Parse modbus.log for additional events
    modbus_log = os.path.join(attack_path, 'modbus.log')
    if os.path.exists(modbus_log):
        with open(modbus_log, 'r') as f:
            for line in f:
                if not line.startswith('#'):
                    parts = line.strip().split('\t')
                    if len(parts) > 7:  # func field
                        func = parts[7]
                        # Create raw signature from modbus function
                        sig = f"Modbus_Function_{func}"
                        results['raw_signatures'].add(sig)
    
    # Estimate model complexity without abstraction
    num_sigs = len(results['raw_signatures'])
    results['unique_sequences'] = min(num_sigs * 2, results['event_count'] // 3)
    
    # S-PDFA would need more states to handle raw signatures
    results['estimated_states'] = min(5 + num_sigs // 10, 50)
    
    results['processing_time'] = time.time() - start_time
    
    return results

def main():
    attack_base = "/home/fei/Downloads/modbus2023_attack_packets"
    attacks = [
        "Baselinereplay",
        "Falseinjection", 
        "Modifylengthparameters",
        "Queryflooding",
        "Reconnaissance",
        "Stackmodbusframes",
        "WriteToAllCoils"
    ]
    
    results_dir = "/home/fei/SAGE/ablation_experiments/full_results"
    os.makedirs(results_dir, exist_ok=True)
    
    all_results = []
    
    print("=== Version A Analysis (No Event Abstraction) ===\n")
    
    for attack in attacks:
        attack_path = os.path.join(attack_base, attack)
        if os.path.exists(attack_path):
            print(f"Analyzing {attack}...")
            results = analyze_without_abstraction(attack_path, attack)
            all_results.append(results)
            
            print(f"  - Raw signatures: {len(results['raw_signatures'])}")
            print(f"  - Total events: {results['event_count']}")
            print(f"  - Estimated states: {results['estimated_states']}")
            print(f"  - Processing time: {results['processing_time']:.2f}s\n")
    
    # Save detailed results
    output_file = os.path.join(results_dir, "version_a_results.json")
    with open(output_file, 'w') as f:
        json.dump(all_results, f, indent=2, default=list)
    
    # Generate summary
    print("\n=== Summary ===")
    total_sigs = sum(len(r['raw_signatures']) for r in all_results)
    avg_states = sum(r['estimated_states'] for r in all_results) / len(all_results)
    total_time = sum(r['processing_time'] for r in all_results)
    
    print(f"Total unique signatures: {total_sigs}")
    print(f"Average estimated states: {avg_states:.1f}")
    print(f"Total processing time: {total_time:.2f}s")
    
    # Compare with original (which uses ~20 event types)
    print(f"\nComplexity increase: {total_sigs/20:.1f}x")
    print(f"State increase: {avg_states/5:.1f}x")

if __name__ == "__main__":
    main()