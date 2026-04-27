# CH6 Live Report (Target: 192.168.8.145)

- Generated at: 2026-04-23T20:57:47.402154
- Binary: `target/release/rscan`
- Raw artifacts dir: `/home/vr2050/RUST/rscan_codex/reports/ch6_live_20260423_205706`

## Timing

- host_quick_json: 1329 ms (rc=0)
- host_tcp_common_json: 6376 ms (rc=0)
- host_tcp_1_1024_json: 10872 ms (rc=0)
- host_udp_common_json: 6020 ms (rc=0)
- web_live_http_https: 708 ms (rc=1)
- web_dir_small_fixed: 3076 ms (rc=1)
- web_crawl_small: 12397 ms (rc=0)
- reverse_smoke: 223 ms (rc=0)

## Host Findings

- quick open ports: `<none>`
- quick filtered ports (network path hint): `21,22,23,25,53,80,110,143,443,445,993,995,1723,3306,3389,5900,8080,8443`
- tcp common open ports: `<none>`
- tcp common filtered ports: `21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,3306,3389`
- tcp 1-1024 open ports: `<none>`
- tcp 1-1024 filtered ports(sample): `1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32`
- udp common open ports: `<none in this run>`
- udp common filtered ports: `53,67,68,69,123,137,138,139,161,162,500,514,520,4500`

## Web Findings

- web live:
  - `ERR GET http://192.168.8.145 error sending request for url (http://192.168.8.145/)`
  - `ERR GET https://192.168.8.145 error sending request for url (https://192.168.8.145/)`
- web dir:
  - `<no parsed status buckets>`
  - `error`: ERROR 网络错误: error sending request for url (http://192.168.8.145/)
  - `error`: ERROR 网络错误: error sending request for url (http://192.168.8.145/robots.txt)
  - `error`: ERROR 网络错误: error sending request for url (http://192.168.8.145/admin)
  - `error`: ERROR 网络错误: error sending request for url (http://192.168.8.145/login)
- web crawl reachable urls: `<none>`

## Reverse Chain
- reverse_smoke rc=0 ms=223
- reverse smoke chain executable in this environment

## Figure Capture Pointers
- Figure 6-9: screenshot `Timing + Host Findings + Web Findings` in this file.
- Figure 6-13: screenshot Host Findings block.
- Figure 6-14: screenshot Web Findings block.
- Figure 6-15: combine `reverse_smoke.out` and malware assessment doc page.
