# CH6 Live Report (Target: 192.168.8.145)

- Date: 2026-04-16
- Binary: `target/release/rscan`
- Raw artifacts: this directory (`*.out/*.err/*.rc/*.ms`, `summary.json`, `summary_enriched.json`)

## Timing

- host_quick_json: 42 ms
- host_tcp_common_json: 39 ms
- host_tcp_1_1024_json: 209 ms
- host_udp_common_json: 6028 ms
- web_live_http_https: 30389 ms
- web_dir_small_fixed: 67 ms

## Host Findings

- quick open ports: `21,22,25,80,445,3306,3389`
- tcp common open ports: `21,22,25,80,139,445,3306,3389`
- tcp 1-1024 open ports: `21,22,25,80,88,139,389,445,464,749`
- udp common open ports: `<none in this run>`

## Web Findings

- `web live`: HTTP alive on `http://192.168.8.145`
- `web dir`:
  - `200`: `/robots.txt`
  - `302`: `/`, `/admin`, `/login`, `/index.php`
  - `404`: `/phpinfo.php`
- `web crawl`: reachable seed URL returned

## Notes

- HTTPS check in `web live` increased total elapsed time due to fail/retry path.
- This report is intended for Chapter 6 empirical appendix/figure source.
