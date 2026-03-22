# rscan Project

Template: reverse

建议流程:
1. 把样本放进 binaries/，或在 Reverse picker 中选择任意二进制
2. picker 会为样本绑定独立 reverse project；viewer 默认不再自动分析
3. 在 viewer 或 surface 中手动发起 full/index/analyze；Tasks/Results 只跟踪样本级 reverse jobs

目录:
- binaries/      放 ELF / PE / APK / DEX / SO 等目标
- jobs/          reverse job metadata
- reverse_out/   decompile 产物
- analysis/      analyze 与 workbench 辅助输出
