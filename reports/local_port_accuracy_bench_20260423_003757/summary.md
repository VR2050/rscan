# Local Port Benchmark (Time + Accuracy)

Ground truth open ports: 42001, 42003, 42007, 42011, 42019

| Tool | Time(ms) | Precision | Recall | F1 | Accuracy | Detected Open Ports |
|---|---:|---:|---:|---:|---:|---|
| rscan | 23 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 42001,42003,42007,42011,42019 |
| rustscan | 28 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 42001,42003,42007,42011,42019 |
| nmap | 20 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 42001,42003,42007,42011,42019 |