# CH6 Live Report (Target: 192.168.8.128)

- Generated at: 2026-04-23T21:00:03.785024
- Binary: `target/release/rscan`
- Raw artifacts dir: `/home/vr2050/RUST/rscan_codex/reports/ch6_live_20260423_205953`

## Timing

- host_quick_json: 102 ms (rc=0)
- host_tcp_common_json: 30 ms (rc=0)
- host_tcp_1_1024_json: 2064 ms (rc=0)
- host_udp_common_json: 6018 ms (rc=0)
- web_live_http_https: 1698 ms (rc=1)
- web_dir_small_fixed: 103 ms (rc=1)
- web_crawl_small: 508 ms (rc=0)
- reverse_smoke: 177 ms (rc=0)

## Host Findings

- quick open ports: `22`
- tcp common open ports: `22`
- tcp 1-1024 open ports: `22`
- udp common open ports: `<none in this run>`
- udp common filtered ports: `53,67,68,69,123,137,138,139,161,162,500,514,520,4500`

## Web Findings

- web live:
  - `ERR GET http://192.168.8.128 error sending request for url (http://192.168.8.128/)`
  - `ERR GET https://192.168.8.128 error sending request for url (https://192.168.8.128/)`
- web dir:
  - `<no parsed status buckets>`
  - `error`: ERROR 网络错误: error sending request for url (http://192.168.8.128/admin)
  - `error`: ERROR 网络错误: error sending request for url (http://192.168.8.128/)
  - `error`: ERROR 网络错误: error sending request for url (http://192.168.8.128/index.php)
  - `error`: ERROR 网络错误: error sending request for url (http://192.168.8.128/login)
- web crawl reachable urls: `<none>`

## Reverse Chain
- reverse_smoke rc=0 ms=177
- reverse smoke chain executable in this environment

## Figure Capture Pointers
- Figure 6-9: screenshot `Timing + Host Findings + Web Findings` in this file.
- Figure 6-13: screenshot Host Findings block.
- Figure 6-14: screenshot Web Findings block.
- Figure 6-15: combine `reverse_smoke.out` and malware assessment doc page.
