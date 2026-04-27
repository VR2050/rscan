# Local Full-Range Multi-Round Benchmark

- rounds: 5
- truth source: ss -ltn snapshot (ports=16)

| Rank | Tool | mean_ms | median_ms | std_ms | mean_F1 | speed_norm | score |
|---:|---|---:|---:|---:|---:|---:|---:|
| 1 | rscan_aggressive | 429.2 | 436 | 19.18 | 0.9761 | 1.0000 | 0.9857 |
| 2 | nmap_default | 1045.2 | 1437 | 496.67 | 1.0000 | 0.3034 | 0.7214 |
| 3 | rustscan_default | 1853.4 | 1844 | 45.23 | 0.9768 | 0.2364 | 0.6807 |