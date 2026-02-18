# wa1kpcap Native C++ Engine 设计文档

## 项目约束

- Python 环境：conda，名为 `web`，Python 路径 `D:/miniconda3/envs/web/python.exe`
- 测试命令：`"D:/miniconda3/envs/web/python.exe" -m pytest "D:/MyProgram/wa1kpcap1/tests/" -x -q`
- **绝对不能影响现有的 dpkt 引擎逻辑**，所有新增代码独立于现有代码
- 文件影响范围限定在项目根目录 `D:\MyProgram\wa1kpcap1\` 内
- 每次上下文压缩后必须重新读取本文件以恢复上下文

## 目标

在不引入 libpcap / npcap 的情况下，用 C++ (pybind11) 实现：

1. **pcap/pcapng 文件读取** — 直接解析文件格式，逐包返回 (timestamp, raw_bytes)
2. **协议解析** — 配置文件驱动，8 种解析原语覆盖绝大多数协议
3. **简化版 BPF filter** — 在解析后的字段上做条件匹配（proto/host/port/and/or/not）

## 架构：方案 A（先行）→ 方案 B（后续优化）

### 方案 A（当前实施）

C++ 解析引擎返回 Python dict，Python 侧用 PacketView 包装提供属性访问：

```
C++ 侧                              Python 侧
──────                               ──────
pcap 读取                            PacketView 包装 dict
协议解析（8种原语，YAML配置驱动）     FlowManager（五元组、TCP状态机、UDP超时）
BPF filter                           特征提取（numpy）
返回 Python dict                     导出（DataFrame/CSV/JSON）
```

```python
class PacketView:
    __slots__ = ('_d',)
    def __init__(self, d: dict):
        self._d = d
    def __getattr__(self, name):
        try:
            return self._d[name]
        except KeyError:
            raise AttributeError(name)
```

### 方案 B（后续优化）

去掉 dict 中间层，C++ 通过 pybind11 直接暴露 struct，Python 消费代码不变（属性访问接口一致）。

### 切换方式

Python 消费侧统一用 `pkt.src_ip`、`pkt.transport.flags` 属性风格。A→B 切换时只替换底层类型，上层代码不改。

## 配置格式：YAML

选择 YAML 而非 TOML，因为协议定义涉及深层嵌套列表和字典，YAML 处理这类结构更自然。

## 8 种解析原语

| # | 原语 | 说明 | 典型场景 |
|---|------|------|----------|
| 1 | `fixed` | 固定 N 字节，可选 `consume: false` 做 peek | IP地址(4B)、端口(2B)、版本号 |
| 2 | `bitfield` | 从已解析的 fixed 字段中按 bit 提取 | IP version+IHL, TCP flags |
| 3 | `length_prefixed` | 先读 L 字节得到长度值，再读该长度的数据 | TLS session_id, cipher_suites |
| 4 | `computed` | 长度由表达式引用其他字段计算 | IP options (`ihl*4-20`) |
| 5 | `tlv` | Type-Length-Value 循环直到区域耗尽 | TCP Options, TLS Extensions |
| 6 | `counted_list` | 由计数字段决定重复几次，每项按子结构解析 | DNS question/answer sections |
| 7 | `rest` | 消费剩余全部字节 | 最终 payload |
| 8 | `hardcoded` | 调用 C++ 硬编码函数，声明式无法表达的 | DNS 域名压缩指针 |

### 原语详细定义

#### 1. fixed

```yaml
- name: src_ip
  type: fixed
  size: 4
  endian: big
  format: ipv4        # 可选，控制输出格式

# peek 模式：读但不移动偏移量
- name: version_byte
  type: fixed
  size: 1
  consume: false
```

#### 2. bitfield

```yaml
- name: version
  type: bitfield
  source: version_ihl    # 引用已解析的 fixed 字段
  offset: 4              # 从第几 bit 开始（高位起）
  bits: 4
```

#### 3. length_prefixed

```yaml
# TLS Handshake: 3字节长度
- name: handshake_body
  type: length_prefixed
  length_size: 3
  endian: big

# 内部等长项自动切分
- name: cipher_suites
  type: length_prefixed
  length_size: 2
  endian: big
  item_size: 2           # 可选：内部每项2字节，自动切分成列表
```

#### 4. computed

```yaml
- name: options
  type: computed
  expr: "ihl * 4 - 20"
```

表达式引擎只需支持 `+ - * /` 和字段名引用。

#### 5. tlv

```yaml
- name: options
  type: tlv
  type_size: 1
  length_size: 1
  length_includes_header: true
  single_byte_types: [0, 1]       # 没有 L+V 的特殊类型
  known_types:
    2: { name: mss, value_format: uint16 }
    3: { name: window_scale, value_format: uint8 }
    8: { name: timestamps, value_format: raw }
```

#### 6. counted_list

```yaml
- name: questions
  type: counted_list
  count_from: qdcount
  item_structure:
    - name: qname
      type: hardcoded
      function: dns_name
    - name: qtype
      type: fixed
      size: 2
      endian: big
```

#### 7. rest

```yaml
- name: payload
  type: rest
```

#### 8. hardcoded

```yaml
- name: qname
  type: hardcoded
  function: dns_name    # 对应 C++ 中注册的函数名
```

C++ 侧预注册硬编码解析函数：
- `dns_name` — DNS 域名压缩指针
- `bsd_loopback_af` — 主机字节序地址族

## DLT → 入口协议映射

```yaml
# link_types.yaml
link_types:
  1: ethernet
  113: linux_sll
  101: raw_ip
  0: bsd_loopback
  108: bsd_loopback
  239: nflog
```

## 下一层协议分发

```yaml
next_protocol:
  field: protocol          # 根据哪个字段决定下一层
  mapping:
    6: tcp
    17: udp
  fallback_field: src_port # 可选：主字段没命中时的备选
```

## 解析失败处理

若某层解析失败，返回之前层的解析结果 + 该层开始的原始字节。

## 原始字节返回

由 `Wa1kPcap(save_raw_bytes=True/False)` 控制，C++ 引擎据此决定是否在返回的 dict 中包含 `raw_bytes` 字段。

## 安装方式

- `pip install wa1kpcap` — 仅安装 dpkt 引擎（纯 Python）
- `pip install wa1kpcap[native]` — 安装含 C++ 引擎的版本

## 引擎选择

```python
analyzer = Wa1kPcap(engine="dpkt")    # 默认，使用现有 dpkt 逻辑
analyzer = Wa1kPcap(engine="native")  # 使用 C++ 引擎
```
