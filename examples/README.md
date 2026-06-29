# Examples

演示脚本按编号排列，命名规则：`demo_<序号>_<主题>.py`。

| 脚本 | 说明 | 依赖 |
|------|------|------|
| `demo_01_analyzer_basic.py` | Wa1kPcap 基础流分析 | 核心引擎 |
| `demo_02_analyzer_features.py` | 序列/统计/YAML 协议字段 | 核心引擎 |
| `demo_03_custom_features.py` | 注册自定义增量特征 | 核心引擎 |
| `demo_04_export_formats.py` | 导出 CSV / JSON / DataFrame | 核心引擎 + pandas |
| `demo_05_native_batch_extract.py` | C++ 批量提取 CIC/seq/TLS 等 | `_wa1kpcap_nvers` |
| `demo_06_native_protocols.py` | TLS/DNS/序列协议 API | `_wa1kpcap_nvers` |
| `demo_07_pcap_split.py` | 按五元组切分 pcap | `_wa1kpcap_nvers` |
| `demo_08_unified_sequences.py` | wa1kpcap + native 序列合并 JSONL | 核心 + `_wa1kpcap_nvers` |

## 运行方式

在项目根目录执行（需先 `pip install -e .`）：

```bash
# 核心分析（使用 test/ 下样例 pcap）
python examples/demo_01_analyzer_basic.py
python examples/demo_02_analyzer_features.py

# 原生 C++ 特征提取（需 libpcap-dev、libssl-dev）
python examples/demo_05_native_batch_extract.py test/multi.pcap /tmp/out
python examples/demo_06_native_protocols.py test/multi.pcap
python examples/demo_07_pcap_split.py test/single.pcap
python examples/demo_08_unified_sequences.py test/single.pcap
```

## 输出目录

`demo_04_export_formats.py` 会在 `examples/output/` 写入 `flows.csv`、`flows.json` 等文件。

原生提取 demo 默认在 pcap 同目录或指定目录下生成 `<pcap名>_cic.csv`、`<pcap名>_tls.log` 等，详见 [API 文档](../docs/API_EXTRACT_CN.md)。
