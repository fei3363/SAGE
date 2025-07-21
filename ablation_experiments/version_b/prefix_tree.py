#!/usr/bin/env python3
"""
Prefix Tree implementation for Ablation Study Version B
Replaces S-PDFA with a simple prefix tree for sequence learning
"""

class PrefixTree:
    def __init__(self):
        self.root = {'state': 0, 'children': {}}
        self.state_counter = 1
        self.state_map = {0: self.root}
        
    def add_sequence(self, sequence):
        """Add a sequence to the prefix tree"""
        node = self.root
        for symbol in sequence:
            if symbol not in node['children']:
                new_state = self.state_counter
                node['children'][symbol] = {
                    'state': new_state, 
                    'children': {},
                    'symbol': symbol
                }
                self.state_map[new_state] = node['children'][symbol]
                self.state_counter += 1
            node = node['children'][symbol]
            
    def traverse(self, sequence):
        """Traverse the tree with a sequence, return state path"""
        states = [0]  # Start from root state
        node = self.root
        
        for symbol in sequence:
            if symbol in node['children']:
                node = node['children'][symbol]
                states.append(node['state'])
            else:
                # Unknown transition, return -1
                states.append(-1)
                break
                
        return states
    
    def get_num_states(self):
        """Return the total number of states in the prefix tree"""
        return self.state_counter
    
    def save_model(self, filepath):
        """Save the prefix tree model in a format similar to FlexFringe output"""
        with open(filepath, 'w') as f:
            f.write(f"# Prefix Tree Model\n")
            f.write(f"# Number of states: {self.state_counter}\n")
            f.write(f"initial state: 0\n")
            
            # Write states
            for state_id in range(self.state_counter):
                f.write(f"state {state_id}\n")
            
            # Write transitions
            for state_id, node in self.state_map.items():
                for symbol, child in node.get('children', {}).items():
                    f.write(f"transition {state_id} -> {child['state']} on {symbol}\n")
    
    def build_from_traces_file(self, traces_file):
        """Build prefix tree from FlexFringe format traces file"""
        with open(traces_file, 'r') as f:
            lines = f.readlines()
            
        # Skip header line
        for line in lines[1:]:
            parts = line.strip().split()
            if len(parts) >= 3:
                # Format: class_label length symbol1 symbol2 ...
                length = int(parts[1])
                sequence = parts[2:2+length]
                self.add_sequence(sequence)
                
        return self