# rscan Linux Offline Pack (Debian / Ubuntu)

## Included
- bin/rscan
- install-deps-debian-ubuntu.sh
- third_party/ghidra_core_headless_x86_min

## Usage
1. 解压并进入目录
2. 首次在 Debian/Ubuntu 上执行：`sudo ./install-deps-debian-ubuntu.sh`
3. 运行：`./bin/rscan --help`

## Notes
- 该包为离线运行包，不要求目标机再做源码编译。
- 若目标机 glibc 太旧，请在更低版本系统重新构建 rscan 后，用 `RSCAN_BIN` 指定再打包。
