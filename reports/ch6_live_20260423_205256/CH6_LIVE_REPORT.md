# CH6 Live Report (Target: 192.168.8.145)

- Generated at: 2026-04-23T20:53:40.033476
- Binary: `target/release/rscan`
- Raw artifacts dir: `/home/vr2050/RUST/rscan_codex/reports/ch6_live_20260423_205256`

## Timing

- host_quick_json: 1362 ms (rc=0)
- host_tcp_common_json: 6373 ms (rc=0)
- host_tcp_1_1024_json: 10844 ms (rc=0)
- host_udp_common_json: 6021 ms (rc=0)
- web_live_http_https: 5029 ms (rc=1)
- web_dir_small_fixed: 1073 ms (rc=1)
- web_crawl_small: 12400 ms (rc=0)
- reverse_smoke: 236 ms (rc=0)

## Host Findings

- quick open ports: `<none>`
- tcp common open ports: `<none>`
- tcp 1-1024 open ports: `<none>`
- udp common open ports: `<none in this run>`

## Web Findings

- web live:
  - `ERR GET http://192.168.8.145 error sending request for url (http://192.168.8.145/)`
  - `ERR GET https://192.168.8.145 error sending request for url (https://192.168.8.145/)`
- web dir:
  - `<no parsed status buckets>`
- web crawl reachable urls: `<none>`

## Reverse Chain
- reverse_smoke rc=0 ms=236
- reverse smoke chain executable in this environment

## Figure Capture Pointers
- Figure 6-9: screenshot `Timing + Host Findings + Web Findings` in this file.
- Figure 6-13: screenshot Host Findings block.
- Figure 6-14: screenshot Web Findings block.
- Figure 6-15: combine `reverse_smoke.out` and malware assessment doc page.
