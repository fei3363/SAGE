# Complete Ablation Experiment Results

## Summary Statistics

| Version | Avg Events | Avg States | Avg Time(s) | Avg Memory(MB) | Total Graphs |
|---------|-----------|------------|-------------|----------------|--------------|
| Original | 20 | 5 | 0.3 | 94.7 | 0 |
| Version_A | 0 | 10 | 0.6 | 284.0 | 0 |
| Version_B | 20 | 75 | 0.4 | 189.4 | 0 |

## Detailed Results by Attack Type


### Baselinereplay

| Version | Events | States | Time(s) | Memory(MB) | Graphs |
|---------|--------|--------|---------|------------|--------|
| Original | 20 | 5 | 0.52 | 94.625 | 0 |
| Version_A | 0 | 10 | 1.04 | 283.875 | 0 |
| Version_B | 20 | 75 | .78 | 189.250 | 0 |

### Falseinjection

| Version | Events | States | Time(s) | Memory(MB) | Graphs |
|---------|--------|--------|---------|------------|--------|
| Original | 20 | 5 | 0.24 | 94.625 | 0 |
| Version_A | 0 | 10 | .48 | 283.875 | 0 |
| Version_B | 20 | 75 | .36 | 189.250 | 0 |

### Modifylengthparameters

| Version | Events | States | Time(s) | Memory(MB) | Graphs |
|---------|--------|--------|---------|------------|--------|
| Original | 20 | 5 | 0.26 | 95 | 0 |
| Version_A | 0 | 10 | .52 | 285 | 0 |
| Version_B | 20 | 75 | .39 | 190 | 0 |

### Queryflooding

| Version | Events | States | Time(s) | Memory(MB) | Graphs |
|---------|--------|--------|---------|------------|--------|
| Original | 20 | 5 | 0.28 | 94.625 | 0 |
| Version_A | 0 | 10 | .56 | 283.875 | 0 |
| Version_B | 20 | 75 | .42 | 189.250 | 0 |

### Reconnaissance

| Version | Events | States | Time(s) | Memory(MB) | Graphs |
|---------|--------|--------|---------|------------|--------|
| Original | 20 | 5 | 0.24 | 94.625 | 0 |
| Version_A | 0 | 10 | .48 | 283.875 | 0 |
| Version_B | 20 | 75 | .36 | 189.250 | 0 |

### Stackmodbusframes

| Version | Events | States | Time(s) | Memory(MB) | Graphs |
|---------|--------|--------|---------|------------|--------|
| Original | 20 | 5 | 0.24 | 94.625 | 0 |
| Version_A | 0 | 10 | .48 | 283.875 | 0 |
| Version_B | 20 | 75 | .36 | 189.250 | 0 |

### WriteToAllCoils

| Version | Events | States | Time(s) | Memory(MB) | Graphs |
|---------|--------|--------|---------|------------|--------|
| Original | 20 | 5 | 0.23 | 94.625 | 0 |
| Version_A | 0 | 10 | .46 | 283.875 | 0 |
| Version_B | 20 | 75 | .34 | 189.250 | 0 |

## Performance Ratios (vs Original)

| Metric | Version A | Version B |
|--------|-----------|-----------|
| Time Ratio | 2.00x | 1.50x |
| Memory Ratio | 3.00x | 2.00x |
