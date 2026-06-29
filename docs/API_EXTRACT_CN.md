# 原生特征提取 API 参考

本文档描述 wa1kpcap 中 **C++ 原生提取管线**（原 nvers）的 Python API。  
解析、特征计算与落盘均在 C++ 中完成；Python 只负责传参与路径管理。

---

## 1. 代码布局

所有 C/C++ 源码统一放在 `src/cpp/` 下：

```
src/cpp/
├── CMakeLists.txt              # 核心引擎 _wa1kpcap_native
├── bindings.cpp                # 核心 pybind11 绑定
├── pcap_reader.cpp             # 自研 pcap 读取
├── flow_manager.cpp            # YAML 协议 + 流管理
├── …
└── nvers/                      # 高性能 libpcap 提取器 → _wa1kpcap_nvers
    ├── CMakeLists.txt
    ├── bindings.cpp            # nvers pybind11 绑定
    ├── nvers_api.h / .cpp      # 统一 C++ API（批量调度、默认文件名）
    ├── flow_limit.h            # -n 0 = 全流
    ├── cic_flow.h / cic_extractor.cpp
    ├── cicext_flow.h / cicext_extractor.cpp
    ├── seq_flow.h / seq_extractor.cpp
    ├── payload_flow.h / payload_extractor.cpp
    ├── tls_flow.h / tls_extractor.cpp
    ├── dns_flow.h / dns_extractor.cpp
    ├── smtp_flow.h / dhcp_flow.h / ftp_flow.h / …
    ├── http_flow.h / ssh_flow.h / mqtt_flow.h / sip_flow.h / quic_flow.h / rdp_flow.h / vnc_flow.h
    ├── l7_extractors.cpp         # 上述仅 .h 协议的 JSONL 提取器
    ├── protocol_common.h / protocol_json_emit.h
    ├── pcap_split.cpp
    └── Makefile                # 可选：独立编译 CLI 工具
```

**两套引擎的分工：**

| 模块 | Python 入口 | C++ 模块 | 适用场景 |
|------|-------------|----------|----------|
| YAML 协议引擎 | `Wa1kPcap` | `_wa1kpcap_native` | 细粒度多层协议字段、QUIC、自定义 YAML |
| libpcap 提取器 | `wa1kpcap.extract` | `_wa1kpcap_nvers` | CIC/CICext、序列、负载、TLS/DNS 等批量特征 |

---

## 2. 构建与依赖

```bash
# 系统依赖（Debian/Ubuntu）
sudo apt install libpcap-dev libssl-dev

# 安装（同时编译两个 native 模块）
cd wa1kpcap
pip install -e .
```

CMake 选项（`pyproject.toml` 默认开启）：

- `BUILD_NATIVE=ON` — 核心引擎
- `BUILD_NVERS=ON` — libpcap 提取器（需 libpcap + OpenSSL）

---

## 3. 快速开始

### 3.1 一键批量提取

```python
from wa1kpcap.extract import extract_all

paths, stats = extract_all(
    "traffic.pcap",
    output_dir="out/",
    features=["cic", "cicext", "seq", "payload", "tls", "dns"],
    n_packets=0,      # 每条流分析的全部包
    workers=4,        # 并行 worker 数，0=自动
    return_stats=True,
)

print(stats.flows, stats.packets, stats.elapsed_sec)
for name, path in paths.items():
    print(name, path)
```

### 3.2 单项提取

```python
from wa1kpcap.extract import extract, extract_cic, extract_tls

extract_cic("traffic.pcap", output_path="out/cic.csv")
extract_tls("traffic.pcap", filter_port=443)

path, stats = extract(
    "traffic.pcap", "seq",
    output_path="out/seq.log",
    n_packets=30,
    return_stats=True,
)
```

### 3.3 协议 API

```python
from wa1kpcap.protocols import tls_features, dns_features, seq_features

tls_features("traffic.pcap", output_path="tls.log")
rows = dns_features("traffic.pcap", load=True)
path, stats = seq_features("traffic.pcap", n_packets=0, return_stats=True)
```

---

## 4. `wa1kpcap.extract` 模块

### 4.1 数据类型

#### `FeatureSpec`

| 字段 | 类型 | 说明 |
|------|------|------|
| `name` | str | 规范名称，如 `cic` |
| `aliases` | tuple[str] | 别名 |
| `output_format` | str | `csv` / `jsonl` / `json` / `pcap_dir` |
| `default_suffix` | str | 默认输出后缀 |
| `description` | str | 中文简述 |

#### `ExtractStats`

| 字段 | 类型 | 说明 |
|------|------|------|
| `exit_code` | int | 0 表示成功 |
| `message` | str | 状态信息 |
| `flows` | int | 输出流数 |
| `packets` | int | 处理包数 |
| `elapsed_sec` | float | 耗时（秒） |
| `output_path` | Path | 输出路径 |
| `ok` | bool | 属性，`exit_code == 0` |

### 4.2 函数

#### `list_features() -> list[FeatureSpec]`

返回所有已注册原生提取器的元数据。

#### `resolve_feature(name: str) -> str`

将用户输入（含别名）规范化为 canonical 名称。

#### `default_output_path(pcap, feature, output_dir=None) -> Path`

计算默认输出路径。规则：`<output_dir>/<pcap基名><suffix>`。

#### `extract(pcap_path, feature, *, output_path=None, n_packets=0, workers=0, filter_port=0, verbose=False, return_stats=False)`

运行单个提取器。

| 参数 | 默认 | 说明 |
|------|------|------|
| `pcap_path` | — | 输入 pcap 路径 |
| `feature` | — | 特征名（见下表） |
| `output_path` | 空 | 输出文件/目录；空则使用默认路径 |
| `n_packets` | 0 | 每流包数上限，**0=全流** |
| `workers` | 0 | 并行线程（cic/cicext/seq/payload），0=自动 |
| `filter_port` | 0 | TLS 端口过滤，0=全部 TCP |
| `verbose` | False | DNS 等额外 stderr 统计 |
| `return_stats` | False | 为 True 时返回 `(Path, ExtractStats)` |

#### `extract_all(pcap_path, output_dir, features=None, *, …, return_stats=False)`

批量提取。`features` 默认为 `("cic","cicext","seq","payload","tls","dns")`。

#### `split_pcap(pcap_path, output_dir=None, *, return_stats=False)`

按 **canonical 五元组** 切分 pcap。命名：`<基名>_<srcip>_<sport>_<dstip>_<dport>_<proto>.pcap`

#### `read_jsonl(path) -> Iterator[dict]`

读取 JSON Lines 输出。

#### 快捷函数

`extract_cic`, `extract_cicext`, `extract_seq`, `extract_payload`, `extract_tls`, `extract_dns`, `extract_smtp`, `extract_dhcp`, `extract_ftp`, `extract_http`, `extract_ssh`, `extract_mqtt`, `extract_sip`, `extract_quic`, `extract_rdp`, `extract_vnc`, `extract_vpn`, `extract_im`, `extract_flow`

#### `extract_unified_seq(pcap_path, output_path=None, *, n_packets=0, workers=0, bpf_filter=None, return_stats=False)`

**合并序列（单文件 JSONL）**：先跑 native `seq`（C++），再跑 `Wa1kPcap` 内置序列，按 canonical 五元组对齐，写入一个文件。

输出每行结构：

```json
{
  "file": "traffic.pcap",
  "flow_id": "1.2.3.4:443->10.0.0.1:52431/TCP",
  "five_tuple": {"src_ip": "...", "src_port": 443, ...},
  "sequences": {
    "direction": [...], "pkt_len": [...], "tls_type": [...],
    "packet_lengths": [...], "iats": [...], "tcp_flags": [...]
  }
}
```

默认输出：`<pcap基名>_seq_unified.log`

### 4.3 支持的特征

| 名称 | 别名 | 输出 | 默认文件名 |
|------|------|------|------------|
| `cic` | — | CSV | `<基名>_cic.csv` |
| `cicext` | `cic_ext` | CSV | `<基名>_cicext.csv` |
| `seq` | `sequence` | JSONL | `<基名>_seq.log` |
| `payload` | — | JSONL | `<基名>_payload.log` |
| `tls` | — | JSONL | `<基名>_tls.log` |
| `dns` | — | JSONL | `<基名>_dns.log` |
| `smtp` | — | JSONL | `<基名>_smtp.log` |
| `dhcp` | — | JSONL | `<基名>_dhcp.log` |
| `ftp` | — | JSONL | `<基名>_ftp.log` |
| `http` | — | JSONL | `<基名>_http.log` |
| `ssh` | — | JSONL | `<基名>_ssh.log` |
| `mqtt` | — | JSONL | `<基名>_mqtt.log` |
| `sip` | — | JSONL | `<基名>_sip.log` |
| `quic` | — | JSONL | `<基名>_quic.log` |
| `rdp` | — | JSONL | `<基名>_rdp.log` |
| `vnc` | `rfb` | JSONL | `<基名>_vnc.log` |
| `pcap_split` | `split` | 目录 | `<基名>_flows/` |
| `vpn` | — | 文本 log | `<基名>_vpn.log` |
| `im` | — | 文本 log | `<基名>_im.log` |
| `flow` | — | JSON | `<基名>_flow.json` |

---

## 5. `wa1kpcap.protocols` 模块

| 函数 | 说明 | 特有参数 |
|------|------|----------|
| `tls_features` | TLS 握手/证书/SNI/ALPN | `filter_port` |
| `dns_features` | DNS 查询与响应 | `verbose` |
| `smtp_features` | SMTP 命令序列 | — |
| `dhcp_features` | DHCP 消息与选项 | — |
| `ftp_features` | FTP 控制通道 | — |
| `http_features` | HTTP/1.x、HTTP/2 头域与统计 | — |
| `ssh_features` | SSH Banner 与 KEX 协商 | — |
| `mqtt_features` | MQTT 连接与主题 | — |
| `sip_features` | SIP 信令与 SDP | — |
| `quic_features` | QUIC 版本与传输参数 | — |
| `rdp_features` | RDP 协商与客户端信息 | — |
| `vnc_features` | VNC/RFB 握手与桌面参数 | — |
| `seq_features` | 包级序列特征 | `n_packets`, `workers` |
| `payload_features` | 负载 hex 快照 | `n_packets`, `workers` |
| `vpn_features` | VPN 协议识别 | `verbose` |
| `im_features` | 即时通讯识别 | `verbose` |
| `flow_features` | NetFlow/IPFIX/Argus | `n_packets`, `verbose` |

公共参数：`output_path`, `load=False`, `return_stats=False`

### 序列字段并集

```python
from wa1kpcap.protocols import sequence_fields_union, wa1k_nvers_seq_mapping

sequence_fields_union()
# wa1kpcap: packet_lengths, ip_lengths, …, tcp_window_sizes
# native:   direction, pkt_len, pay_len, iat_us, tls_type, burst, payload_hex
```

---

## 6. 输出格式

- **CIC CSV**：80 列 CIC-FlowMeter 特征
- **CICext CSV**：272 列（CIC + 序列分布扩展）
- **JSONL**：seq/payload/TLS/DNS/SMTP/HTTP/SSH/MQTT/SIP/QUIC/RDP/VNC 等，每行一条流

---

## 7. C++ 底层 API

头文件 `src/cpp/nvers/nvers_api.h`，命名空间 `wa1kpcap::nvers`：

- `ExtractConfig` / `ExtractResult`
- `run_cic`, `run_cicext`, `run_seq`, …, `run_batch`

Python 绑定：`_wa1kpcap_nvers`

---

## 8. 与 Wa1kPcap 配合

- **Wa1kPcap**：内存中 YAML 协议字段 + 8 种内置序列
- **extract_all**：磁盘上大规模 CIC/序列/TLS 特征

序列命名对齐：`sequence_fields_union()` / `wa1k_nvers_seq_mapping()`

---

## 9. 示例

| 脚本 | 内容 |
|------|------|
| `demo_05_native_batch_extract.py` | 批量提取 |
| `demo_06_native_protocols.py` | 协议 API |
| `demo_07_pcap_split.py` | pcap 切分 |
| `demo_08_unified_sequences.py` | 合并序列单文件 |

---

## 10. 常见问题

**ImportError: _wa1kpcap_nvers** — 安装 libpcap-dev、libssl-dev 后重新 `pip install -e .`

**n_packets=0** — 分析每条流的全部包

**独立 CLI：**

```bash
cd src/cpp/nvers && make && ./build/cic_extractor -r file.pcap -n 0 -w out.csv
```
