# 优化计划上下文

## 目标

实现 4 项性能优化（建议顺序：4→2→1→3）：

1. **读取→筛选→解析合并到 C++ 管线**：消除每包两次 Python↔C++ 边界跨越
2. **_make_flow_key 移入 C++**：在 C++ 解析阶段预计算 flow key，避免 pybind11 属性访问开销
3. **特征计算批量化**：将每流 7 次 `compute_array_stats` 调用合并为 1 次
4. **方案A：投机 TLS 解析**：在 C++ TCP 解析后，若 payload 含完整 TLS record 则直接解析

## 基线性能

```
engine   | file         | time     | flows
dpkt     | Skype.pcap   | 2.619s   | 6321
native   | Skype.pcap   | 0.772s   | 6321
dpkt     | FTP.pcap     | 24.979s  | 100000
native   | FTP.pcap     | 17.927s  | 100000
```

Profiling 结果（native engine）：
- Skype.pcap (1.19s)：TLS 重组 ~20%，特征提取 ~33%
- FTP.pcap (22.0s)：read_and_parse 迭代器 #1 瓶颈 23.8%，特征提取 ~25%，_make_flow_key ~6%
- Skype.pcap 中 100% 的 TLS record 在单个 TCP 段内完成（无跨段分片）

---

## 当前架构：关键代码路径

### 优化 4：投机 TLS 解析（方案A）

**问题**：TCP YAML 没有 `next_protocol` 到 `tls_record`，TLS 完全靠 Python 侧重组解析。

**当前 TLS 解析路径**：
```
C++ read_and_parse: eth → ip → tcp → yield pkt (不含TLS)
Python analyzer: 收到 pkt，做流管理
Python _handle_native_tls_reassembly: 缓冲 TCP payload，拼完整 TLS record
C++ parse_tls_record: 解析完整 TLS record（单独一次调用）
Python _parse_native_tls_record: 合并 TLS 信息到 flow
```

**方案A**：在 `parse_packet_struct()` 中 TCP 解析后，检查 TCP payload 是否以合法 TLS record 开头且完整，若是则直接解析填充 `NativeParsedPacket.tls`。Python 侧重组作为分片回退保留。

**插入点** — `src/cpp/protocol_engine.cpp` 第 746-757 行：
```cpp
} else if (current_proto == "tcp") {
    if (pr.bytes_consumed < remaining) {
        app_len_val = static_cast<int64_t>(remaining - pr.bytes_consumed);
    }
    fill_tcp(pkt, pr.fields, app_len_val);
    // Store raw TCP payload
    if (app_len_val > 0) {
        pkt._raw_tcp_payload.assign(
            reinterpret_cast<const char*>(cur + pr.bytes_consumed),
            static_cast<size_t>(app_len_val));
    }
    // ← 在这里插入 TLS 投机解析
}
```

**TLS 探测逻辑**：
- TCP payload 第 1 字节 content_type ∈ {20,21,22,23}
- 字节 [1:3] 版本 0x0301-0x0304
- 字节 [3:5] record_len，且 5 + record_len ≤ payload_len
- 满足则调用 `parse_from_protocol_struct("tls_record", payload, payload_len)` 填充 TLS

**已有的 `parse_from_protocol_struct`** — protocol_engine.cpp 第 789-835 行，从指定协议开始解析，返回 `NativeParsedPacket`（只填 TLS 部分）。

---

### 优化 2：_make_flow_key 移入 C++

**当前实现** — `wa1kpcap/core/flow.py` 第 1081-1123 行：
```python
def _make_flow_key(self, pkt: ParsedPacket) -> tuple[tuple, FlowKey] | tuple[None, None]:
    ip = pkt.ip          # pybind11 property access
    ip6 = pkt.ip6        # pybind11 property access
    if not ip and not ip6:
        return None, None
    if ip:
        src_ip = ip.src   # pybind11 property access
        dst_ip = ip.dst
        protocol = ip.proto
    elif ip6:
        src_ip = ip6.src
        dst_ip = ip6.dst
        protocol = ip6.next_header
    src_port, dst_port = 0, 0
    if pkt.tcp:
        src_port = pkt.tcp.sport
        dst_port = pkt.tcp.dport
    elif pkt.udp:
        src_port = pkt.udp.sport
        dst_port = pkt.udp.dport
    canonical = _make_canonical_key(src_ip, dst_ip, src_port, dst_port, protocol)
    key = FlowKey(src_ip=src_ip, dst_ip=dst_ip, src_port=src_port, dst_port=dst_port, protocol=protocol)
    return canonical, key
```

**canonical key 规范化** — flow.py 第 991-995 行：
```python
def _make_canonical_key(src_ip, dst_ip, src_port, dst_port, protocol):
    if (src_ip, src_port) <= (dst_ip, dst_port):
        return (src_ip, src_port, dst_ip, dst_port, protocol)
    return (dst_ip, dst_port, src_ip, src_port, protocol)
```

**方案**：在 `NativeParsedPacket` 中新增 flow key 字段，在 `parse_packet_struct()` 末尾（IP/TCP/UDP 都已解析后）计算并填充：
- `flow_src_ip`, `flow_dst_ip`, `flow_src_port`, `flow_dst_port`, `flow_protocol` — 原始方向
- `canonical_key` — 规范化后的 5-tuple，作为 `py::tuple` 暴露

Python 侧 `_make_flow_key` 改为直接读取预计算值，避免 6+ 次 pybind11 属性访问。

**FlowKey** — `wa1kpcap/core/flow.py` 第 40-107 行，frozen dataclass：
```python
@dataclass(frozen=True)
class FlowKey:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int
    vlan_id: int = 0
```

---

### 优化 1：读取→筛选→解析合并到 C++ 管线

**当前两次边界跨越**：

第一次（`NativePcapReader.__next__`，bindings.cpp 第 345-351 行）：
```cpp
.def("__next__", [](NativePcapReader& self) -> py::tuple {
    auto pkt = self.next();
    if (!pkt.has_value()) throw py::stop_iteration();
    auto& [ts, data, caplen, wirelen, link_type] = *pkt;
    return py::make_tuple(ts, py::bytes(reinterpret_cast<const char*>(data.data()), data.size()),
                          caplen, wirelen, link_type);
})
```
→ mmap 数据 copy 到 `vector<uint8_t>` → copy 到 `py::bytes` → 返回 5-tuple 到 Python

第二次（`parse_to_dataclass`，bindings.cpp 第 372-513 行）：
```
Python 传 py::bytes 回 C++ → 转 std::string → 解析 → 构造 5-8 个 Python dataclass → 返回
```

**方案**：新建 `NativePipeline` C++ 类，封装 `NativePcapReader` + `ProtocolEngine` + `NativeFilter`：
```cpp
class NativePipeline {
    NativePcapReader reader_;
    ProtocolEngine& engine_;
    NativeFilter* filter_;  // nullable
    bool save_raw_bytes_;
    // ...
};
```

`__next__` 内部循环：
1. `reader_.next()` 获取 `(ts, vector<uint8_t>, caplen, wirelen, link_type)`
2. 若有 BPF filter 且 `can_match_raw()`，直接在 raw bytes 上过滤（跳过不匹配的包）
3. 直接用 `uint8_t*` 指针调用 `engine_.parse_packet_struct()`（零拷贝，不经过 py::bytes）
4. 构造 Python dataclass（复用现有 `parse_to_dataclass` 的 ClassCache + 构造逻辑）
5. 返回 Python dataclass

**关键**：需要把 bindings.cpp 第 378-511 行的 dataclass 构造逻辑从 lambda 中抽出为独立函数，供 `NativePipeline::__next__` 和原有 `parse_to_dataclass` 共用。

**NativeFilter 集成**：
- `NativeFilter::matches_raw(buf, len, link_type)` — bpf_filter.h 第 106 行
- `NativeFilter::can_match_raw()` — bpf_filter.h 第 109 行
- 对于 app-layer filter（`can_match_raw()=false`），需要先 `parse_packet()` 返回 dict 再 `matches(dict)`

**Python 侧改动** — `wa1kpcap/native/engine.py` 第 32-73 行的 `read_and_parse` 简化为：
```python
def read_and_parse(self, pcap_path, save_raw_bytes=False) -> Iterator:
    pipeline = self._native.NativePipeline(
        str(pcap_path), self._parser, self._filter, save_raw_bytes)
    with pipeline:
        yield from pipeline
```

**NativePcapReader** — `src/cpp/pcap_reader.h`：
- `next()` 返回 `optional<RawPacket>`，其中 `RawPacket = tuple<double, vector<uint8_t>, uint32_t, uint32_t, uint32_t>`
- 使用 mmap（Windows: CreateFileMapping/MapViewOfFile）
- `reader_.next()` 内部从 mmap 拷贝到 `vector<uint8_t>`

---

### 优化 3：特征计算批量化

**当前实现** — `wa1kpcap/features/extractor.py` 第 88-135 行：
```python
def compute_statistics(self) -> dict[str, Any]:
    stats = {}
    if len(self.packet_lengths) > 0:
        stats['packet_lengths'] = self._compute_array_stats(self.packet_lengths)  # C++ 调用 1
    if len(self.ip_lengths) > 0:
        stats['ip_lengths'] = self._compute_array_stats(self.ip_lengths)          # C++ 调用 2
    if len(self.trans_lengths) > 0:
        stats['trans_lengths'] = self._compute_array_stats(self.trans_lengths)     # C++ 调用 3
    if len(self.app_lengths) > 0:
        stats['app_lengths'] = self._compute_array_stats(self.app_lengths)        # C++ 调用 4
    if len(self.iats) > 0:
        stats['iats'] = self._compute_array_stats(self.iats)                      # C++ 调用 5
    if len(self.payload_bytes) > 0:
        stats['payload_bytes'] = self._compute_array_stats(self.payload_bytes)    # C++ 调用 6
    if len(self.tcp_window_sizes) > 0:
        stats['tcp_window'] = self._compute_array_stats(self.tcp_window_sizes)    # C++ 调用 7
    # ...
```

每流最多 7 次 Python→C++→Python 跨越，每次构造 21 个 key 的 `py::dict`。

**C++ 现有 `compute_array_stats`** — bindings.cpp 第 39-152 行：
- 接受 `py::array_t<double>`，单遍计算 21 个统计量
- 返回 `py::dict`（21 个 key-value）

**方案**：新增 `compute_multi_array_stats(dict_of_arrays)` C++ 函数：
- 接受 `py::dict`，key 为名称（如 "packet_lengths"），value 为 `py::array_t<double>`
- 对每个数组计算统计量
- 返回 `py::dict` of `py::dict`（嵌套字典）
- 一次 C++ 调用替代 7 次

---

## 关键文件清单

| 文件 | 角色 | 优化涉及 |
|------|------|---------|
| `src/cpp/bindings.cpp` | pybind11 绑定，parse_to_dataclass lambda，compute_array_stats | 1,2,3,4 |
| `src/cpp/protocol_engine.h` | ProtocolEngine/NativeParser 声明 | 1,4 |
| `src/cpp/protocol_engine.cpp` | parse_packet_struct, fill_tls, parse_from_protocol_struct | 2,4 |
| `src/cpp/parsed_packet.h` | NativeParsedPacket 及子结构体定义 | 2,4 |
| `src/cpp/pcap_reader.h` | NativePcapReader 声明 | 1 |
| `src/cpp/bpf_filter.h` | NativeFilter 声明 | 1 |
| `wa1kpcap/native/engine.py` | NativeEngine.read_and_parse | 1 |
| `wa1kpcap/core/flow.py` | FlowKey, FlowManager._make_flow_key, _make_canonical_key | 2 |
| `wa1kpcap/core/analyzer.py` | _process_native 主循环, _handle_native_tls_reassembly | 1,4 |
| `wa1kpcap/features/extractor.py` | FlowFeatures.compute_statistics, _compute_array_stats | 3 |

## NativeParsedPacket 结构体（parsed_packet.h）

```cpp
struct NativeParsedPacket {
    double timestamp = 0.0;
    std::string raw_data;
    int64_t link_layer_type = 0;
    int64_t caplen = 0, wirelen = 0;
    int64_t ip_len = 0, trans_len = 0, app_len = 0;

    NativeEthernetInfo eth;   // src, dst, type
    NativeIPInfo ip;          // version, src, dst, proto, ttl, len, id, flags, offset
    NativeIP6Info ip6;        // version, src, dst, next_header, hop_limit, flow_label, len
    NativeTCPInfo tcp;        // sport, dport, seq, ack_num, flags, win, urgent
    NativeUDPInfo udp;        // sport, dport, len
    NativeTLSInfo tls;        // version, content_type, handshake_type, sni, cipher_suites, ...
    NativeDNSInfo dns;        // queries, response_code, ...

    bool has_eth/has_ip/has_ip6/has_tcp/has_udp/has_tls/has_dns = false;
    bool is_client_to_server = true;
    int64_t packet_index = -1, flow_index = -1;
    std::string _raw_tcp_payload;
};
```

## 构建与测试

```bash
# 编译 native 模块
rm -rf build/cp310-cp310-win_amd64/*
"D:/miniconda3/envs/web/python.exe" -m pip install ".[native]" --force-reinstall --no-deps --no-cache-dir
cp "/d/miniconda3/envs/web/Lib/site-packages/wa1kpcap/_wa1kpcap_native.cp310-win_amd64.pyd" "/d/MyProgram/wa1kpcap1/wa1kpcap/"

# 运行测试
"D:/miniconda3/envs/web/python.exe" -m pytest tests/ -x -q

# 性能基准
"D:/miniconda3/envs/web/python.exe" benchmark.py
```

## MSVC 注意事项

- `NOMINMAX` 必须在所有 Windows 头文件之前定义
- 用 `Py_ssize_t` 代替 `ssize_t`
- bindings.cpp 用 `dabs()`/`dmax()` 替代 `abs()`/`max()` 避免宏冲突
