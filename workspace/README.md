# workspace

建议将本地扫描输出和临时文件写入该目录，避免污染项目根目录。

示例：

```bash
rscan host tcp --host 127.0.0.1 --ports 22,80 --output json --out ./workspace/host_tcp.json
rscan web dir --base http://127.0.0.1:8080 --paths /admin --stream-to ./workspace/dir_scan.log
```
