# wa1kpcap 项目上下文

## 项目目标

网络流量分析库，从 pcap/pcapng 文件中提取双向流（Flow）及其特征，用于流量分类、异常检测等机器学习场景。

## 技术栈

- Python 3.10（conda env: web）
- 可选 C++ native 引擎：pybind11 + CMake + scikit-build-core
- C++17，yaml-cpp 0.8.0（FetchContent）
- 平台：Windows 11 / MSVC

## 双引擎架构

| 引擎 | 入口 | 解析路径 |
|------|------|---------|
| dpkt（默认） | `_process_reader()` | dpkt 库 → handler classes in `wa1kpcap/protocols/` |
| native（C++） | `_process_native()` | `NativeEngine.read_and_parse()` → C++ `parse_to_dataclass()` |

两个引擎共享同一套 Python 流管理管线：FlowManager → FeatureExtractor → Exporters。

## 关键模块

### Python 侧

| 模块 | 职责 |
|------|------|
| `wa1kpcap/core/analyzer.py` | 主入口 `Wa1kPcap`，编排读取、流管理、特征提取、重组 |
| `wa1kpcap/core/flow.py` | `FlowKey`（5元组）、`Flow`（双向流+TCP状态机）、`FlowManager` |
| `wa1kpcap/core/packet.py` | `ParsedPacket` dataclass，协议层信息容器 |
| `wa1kpcap/protocols/` | dpkt 路径的协议处理器（link/network/transport/application） |
| `wa1kpcap/features/extractor.py` | `FlowFeatures`（序列特征）、`FeatureExtractor`（统计特征） |
| `wa1kpcap/native/engine.py` | `NativeEngine`，封装 C++ Reader + Parser + Filter |
| `wa1kpcap/reassembly/` | IP分片重组、TCP流重组、TLS记录重组 |

### C++ 侧 (`src/cpp/`)

| 文件 | 职责 |
|------|------|
| `protocol_engine.cpp/h` | 核心解析引擎，8种解析原语，协议层链式解析 |
| `parsed_packet.h` | `NativeParsedPacket` 及子结构体（嵌入式，零堆分配） |
| `yaml_loader.cpp/h` | YAML 协议配置加载 |
| `bindings.cpp` | pybind11 绑定；`parse_to_dataclass` 快速路径；`compute_array_stats` |
| `pcap_reader.cpp/h` | pcap/pcapng 文件读取（内存映射） |
| `bpf_filter.cpp/h` | BPF 过滤器（原始字节快速匹配 + 解析后匹配） |
| `flow_buffer.cpp/h` | FlowBuffer，TCP重组桥接（当前未完整实现） |
| `hardcoded_parsers.cpp/h` | DNS 名称解压缩等硬编码解析器 |
| `expression_eval.cpp/h` | computed 字段的表达式求值器 |

### YAML 协议配置 (`wa1kpcap/native/protocols/`)

8 种解析原语：`fixed`、`bitfield`、`length_prefixed`、`computed`、`tlv`、`counted_list`、`rest`、`hardcoded`。

## Profiling 结果

### 基准数据（最近一次测量）

```
dpkt   | FTP.pcap   | 23.832s | 100000 flows
native | FTP.pcap   | 23.805s | 100000 flows
dpkt   | Skype.pcap |  2.998s |   6321 flows
native | Skype.pcap |  0.751s |   6321 flows
```

### FTP.pcap native 引擎耗时分布

| 阶段 | 耗时 | 占比 |
|------|------|------|
| 特征计算 | 7.7s | 32% |
| 流管理 | 6.6s | 27% |
| C++ 读取+解析 | 5.7s | 23% |
| 其他（重传检测、过滤等） | ~4.4s | 18% |

### 历史优化记录

| 阶段 | FTP native | Skype native |
|------|-----------|-------------|
| 初始 | 26.3s | 3.2s |
| 上一轮优化后 | ~24.4s | 0.73s |
| 当前测量 | 23.8s | 0.75s |

### 特征计算细节

- 每个 flow 调用 `_compute_array_stats()` 最多 7 次（packet_lengths, ip_lengths, trans_lengths, app_lengths, iats, payload_bytes, tcp_window_sizes）
- 每次调用是一次 Python→C++ 边界穿越
- `compute_statistics()` 在 C++ 已返回 sum/max/min 后，又用 numpy 重复计算了 total_bytes 和 duration

### native 路径 TLS 现状

- `_handle_tcp_reassembly()` 中 native 路径直接 return，只处理 HTTP 端口
- C++ `parse_packet_struct()` 只能从 link_type 开始链式解析，无法从中间协议开始
- TLS 扩展解析在 `protocol_engine.cpp` 中硬编码（`parse_tls_extensions()`），解析 SNI/supported_groups/signature_algorithms/ALPN 四种
