# CH6 6.2.5 Table

| 用例 | 命令摘要 | 耗时(ms) | 关键结果 |
|---|---|---:|---|
| host_quick_json | `/home/vr2050/RUST/rscan_codex/target/release/rscan host quick -H 192.168.8.128 -o json` | 102 | 开放端口: 22 |
| host_tcp_common_json | `/home/vr2050/RUST/rscan_codex/target/release/rscan host tcp -H 192.168.8.128 -p 21\,22\,23\,25\,53\,80\,110\,111\,135\,139\,143\,443\,445\,993\,995\,3306\,3389 --tcp-mode turbo-adaptive -o json` | 30 | 开放端口: 22 |
| host_tcp_1_1024_json | `/home/vr2050/RUST/rscan_codex/target/release/rscan host tcp -H 192.168.8.128 -p 1-1024 --tcp-mode turbo-adaptive -o json` | 2064 | 开放端口: 22 |
| host_udp_common_json | `/home/vr2050/RUST/rscan_codex/target/release/rscan host udp -H 192.168.8.128 -p 53\,67\,68\,69\,123\,137\,138\,139\,161\,162\,500\,514\,520\,4500 -o json` | 6018 | 开放端口: <none> |
| web_live_http_https | `/home/vr2050/RUST/rscan_codex/target/release/rscan web live -u http://192.168.8.128 -u https://192.168.8.128 -o raw` | 1698 | ERR GET http://192.168.8.128 error sending request for url (http://192.168.8.128/) |
| web_dir_small_fixed | `/home/vr2050/RUST/rscan_codex/target/release/rscan web dir -b http://192.168.8.128 -o raw -p / -p /robots.txt -p /admin -p /login -p /phpinfo.php -p /index.php` | 103 | <see .out> |
| web_crawl_small | `/home/vr2050/RUST/rscan_codex/target/release/rscan web crawl -s http://192.168.8.128 -d 2 -c 4 -o raw` | 508 | <none> |
| reverse_smoke | `/home/vr2050/RUST/rscan_codex/scripts/reverse_smoke.sh /home/vr2050/RUST/rscan_codex/reports/ch6_live_20260423_205953/reverse_smoke_ws` | 177 | 链路可执行 |
