# 后续协议添加计划 / Protocol Addition Plan

## 当前已有协议 / Currently Supported

| 协议 | 类型 | 路径 |
|---|---|---|
| Ethernet | Built-in | Fast-path |
| IPv4 | Built-in | Fast-path |
| IPv6 | Built-in | Fast-path |
| TCP | Built-in | Fast-path |
| UDP | Built-in | Fast-path |
| ARP | Built-in | Fast-path |
| ICMP | Built-in | Fast-path |
| ICMPv6 | Built-in | Fast-path |
| DNS | Built-in | Fill-path |
| TLS (record/handshake/hello/cert) | Built-in | Fill-path |
| VLAN (802.1Q) | YAML-only | Slow-path |
| Linux SLL / SLL2 | YAML-only | Slow-path |
| Raw IP / BSD Loopback / NFLOG | YAML-only | Slow-path |

---

## 明文可解析性分类说明 / Plaintext Parsability

- **全明文**: 所有包均可完整解析字段
- **部分明文**: 仅首包/握手阶段可解析，后续为密文
- **仅识别**: 无法解析内容，只能通过特征识别协议 + 计算密文指纹

对于"部分明文"和"仅识别"的协议，密文部分的处理策略：
- C++ 侧或 YAML 中增加 `fingerprint` 原语/字段，对密文 payload 计算指纹（如长度分布、熵值、首 N 字节 hash）
- Python 侧 `ProtocolInfo` 子类存储指纹结果，用于流量分类

---

## 待添加协议列表 / Protocols To Add

### 优先级 P0 — 核心协议，现代网络必备

| # | 协议 | 路径 | 明文 | 难度 | 说明 |
|---|---|---|---|---|---|
| 1 | **QUIC** | Fill-path (hardcoded) | 部分明文 | ★★★★ | Initial 包 Long Header 明文可解析（version, DCID, SCID, token）；Short Header 仅 1 字节 flags + DCID；payload 全加密。需要 hardcoded parser 处理 Variable-Length Integer。UDP:443 启发式 + 首字节 bit pattern 识别 |
| 2 | **DTLS** | Fill-path | 部分明文 | ★★★ | Record 头 13 字节明文（content_type + version + epoch + sequence + length）。Handshake 阶段明文，可复用 TLS 子协议链（client_hello/server_hello/certificate）。Application Data 加密。UDP 上 TLS 首字节启发式识别 |
| 3 | **HTTP** (请求/响应) | Fill-path (hardcoded) | 全明文 | ★★★ | 文本协议，需逐行解析 request line / status line / headers。TCP:80/8080 端口映射 + 启发式（首字节 "GET "/"POST"/"HTTP"）。目前 Python 侧有 HTTPInfo 但 C++ 无 parser |
| 4 | **GRE** | Fast-path | 全明文 | ★★ | 固定 4-16 字节头（取决于 C/R/K/S flags），封装内层协议（通常是 IPv4/IPv6/Ethernet）。IP proto 47。解析后递归进入内层协议栈 |
| 5 | **VXLAN** | Fast-path | 全明文 | ★ | 固定 8 字节头 `flags(1) + reserved(3) + VNI(3) + reserved(1)`，封装完整以太网帧。UDP:4789。解析后递归进入内层 Ethernet |
| 6 | **MPLS** | Fast-path | 全明文 | ★ | 固定 4 字节标签栈 `label(20bit) + TC(3bit) + S(1bit) + TTL(8bit)`，逐标签剥离直到 S=1，然后根据首字节判断内层 IPv4/IPv6 |

### 优先级 P1 — 常用协议，网络分析高频需求

| # | 协议 | 路径 | 明文 | 难度 | 说明 |
|---|---|---|---|---|---|
| 7 | **DHCP** (v4) | Fill-path | 全明文 | ★★ | 固定头 236 字节 + 变长 options (TLV)。YAML 的 TLV 原语适用。UDP:67/68 |
| 8 | **DHCPv6** | Fill-path | 全明文 | ★★ | 全 TLV 结构，msg_type(1) + transaction_id(3) + options。UDP:546/547 |
| 9 | **SCTP** | Fast-path (头) + Fill-path (chunks) | 全明文 | ★★★ | 12 字节固定头可 fast-path；chunk 列表是变长 TLV，需 YAML。IP proto 132 |
| 10 | **NTP** | Fast-path | 全明文 | ★ | 固定 48 字节头，字段全是固定偏移。UDP:123 |
| 11 | **IGMP** | Fast-path | 全明文 | ★ | 固定 8 字节（v2）/ 12 字节（v3）。IP proto 2 |
| 12 | **SOCKS5** | Fill-path (hardcoded) | 部分明文 | ★★★ | 握手阶段明文（版本协商、认证、CONNECT 请求含目标地址）。数据转发阶段取决于内层协议（可能是 TLS 密文）。TCP:1080 |
| 13 | **SSH** | Fill-path (hardcoded) | 部分明文 | ★★★ | Banner 交换明文（"SSH-2.0-xxx"），Key Exchange Init 明文（算法列表）。New Keys 之后全加密。TCP:22 |
| 14 | **STUN** | Fast-path | 全明文 | ★★ | 固定 20 字节头 `type(2) + length(2) + magic(4) + transaction_id(12)` + TLV attributes。UDP:3478。WebRTC 场景必需 |

### 优先级 P2 — 隧道/VPN 协议

| # | 协议 | 路径 | 明文 | 难度 | 说明 |
|---|---|---|---|---|---|
| 15 | **ESP** (IPSec) | Fast-path | 仅头部 | ★ | 固定 8 字节头 `SPI(4) + Sequence(4)`，payload 全加密。IP proto 50。SPI 可用于流关联，密文部分计算指纹 |
| 16 | **AH** (IPSec) | Fast-path | 全明文 | ★ | `next_header(1) + length(1) + reserved(2) + SPI(4) + seq(4) + ICV(variable)`。IP proto 51。头部后是原始 payload（未加密，仅认证） |
| 17 | **IKEv2** | Fill-path | 全明文 (Phase 1) | ★★★ | 28 字节固定头 + 变长 payload 链（TLV-like）。UDP:500/4500。Phase 1 明文，Phase 2 加密 |
| 18 | **WireGuard** | Fast-path | 部分明文 | ★★ | 固定格式 `type(1) + reserved(3) + sender_index(4) + ...`。4 种消息类型都是固定长度头。Handshake Initiation/Response 头部明文，Transport Data payload 加密。UDP:51820 |
| 19 | **L2TP** | Fast-path | 全明文 | ★★ | 固定头 2-12 字节（取决于 flags），封装 PPP 帧。UDP:1701 |
| 20 | **IPinIP** | Fast-path | 全明文 | ★ | 无额外头，直接内嵌 IPv4 包。IP proto 4 |
| 21 | **IPv6inIPv4** (6to4/6in4) | Fast-path | 全明文 | ★ | 无额外头，直接内嵌 IPv6 包。IP proto 41 |
| 22 | **GTP-U** | Fast-path | 全明文 | ★★ | 固定 8 字节基础头 `flags(1) + type(1) + length(2) + TEID(4)`，封装内层 IP。移动核心网。UDP:2152 |
| 23 | **GTP-C** | Fill-path | 全明文 | ★★★ | 控制面消息，变长 IE (TLV)。UDP:2123 |
| 24 | **Geneve** | Fast-path | 全明文 | ★★ | 固定 8 字节头 + 变长 TLV options，封装以太网帧。UDP:6081 |
| 25 | **OpenVPN** | Fill-path | 部分明文 | ★★★ | `opcode(1, 高5位+低3位key_id) + session_id(8) + ...`。P_CONTROL 有 HMAC + packet_id + ack，格式复杂。控制通道部分明文，数据通道加密。UDP:1194 |
| 26 | **PPPoE** | Fast-path | 全明文 | ★ | 固定 6 字节头 `ver(4bit) + type(4bit) + code(1) + session_id(2) + length(2)`，封装 PPP。EtherType 0x8863/0x8864 |
| 27 | **ERSPAN** (Type II/III) | Fast-path | 全明文 | ★★ | 固定 8/12 字节头，GRE 封装，用于远程端口镜像 |

### 优先级 P3 — 应用层协议

| # | 协议 | 路径 | 明文 | 难度 | 说明 |
|---|---|---|---|---|---|
| 28 | **MQTT** | Fill-path | 全明文 | ★★ | 变长头部编码（remaining length 用 1-4 字节变长整数）。TCP:1883（明文）/ 8883（TLS）。IoT 场景 |
| 29 | **RTP/RTCP** | Fast-path | 全明文 (RTP头) | ★★ | RTP 固定 12 字节头；RTCP 固定 8 字节头。UDP 动态端口，需 STUN/SDP 协商或启发式识别 |
| 30 | **SIP** | Fill-path (hardcoded) | 全明文 | ★★★ | 文本协议，类 HTTP。UDP:5060 / TCP:5060 |
| 31 | **RTSP** | Fill-path (hardcoded) | 全明文 | ★★ | 文本协议，类 HTTP。TCP:554 |
| 32 | **SMB/SMB2** | Fill-path (hardcoded) | 全明文 | ★★★★ | 固定 magic `\xfeSMB` + 64 字节头，命令种类多。TCP:445 |
| 33 | **RDP** | Fill-path | 部分明文 | ★★★★ | TPKT(4) + X.224 + MCS 多层封装。连接阶段明文，NLA 之后加密。TCP:3389 |
| 34 | **Modbus/TCP** | Fast-path | 全明文 | ★ | 固定 7 字节 MBAP 头 `transaction_id(2) + protocol_id(2) + length(2) + unit_id(1)`。TCP:502。工控场景 |
| 35 | **RADIUS** | Fill-path | 全明文 | ★★ | 固定 20 字节头 + TLV attributes。UDP:1812/1813 |
| 36 | **BGP** | Fill-path | 全明文 | ★★★ | 固定 19 字节 marker + 头，UPDATE 消息含变长 path attributes (TLV)。TCP:179 |
| 37 | **OSPF** | Fill-path | 全明文 | ★★ | 固定 24 字节头 + 变长 LSA。IP proto 89 |
| 38 | **SNMP** | Fill-path (hardcoded) | 全明文 (v1/v2c) | ★★★ | ASN.1 BER 编码。v3 有加密选项。UDP:161/162 |
| 39 | **Kerberos** | Fill-path (hardcoded) | 部分明文 | ★★★★ | ASN.1 DER 编码。AS-REQ/AS-REP 部分明文，TGS 票据加密。TCP/UDP:88 |
| 40 | **LDAP** | Fill-path (hardcoded) | 全明文 | ★★★★ | ASN.1 BER 编码。TCP:389（明文）/ 636（LDAPS = TLS） |

### 优先级 P4 — 加密代理协议（部分明文 + 密文指纹）

这类协议的共同特点：**仅首包/握手有可解析的明文头部，后续 payload 全加密**。
密文部分建议在 YAML 中增加 `fingerprint` 原语，C++ 侧计算：
- payload 长度
- 熵值 (Shannon entropy)
- 首 N 字节 hash
- 包间时序特征（由 Python 侧 Flow 层计算）

| # | 协议 | 路径 | 明文 | 难度 | 说明 |
|---|---|---|---|---|---|
| 41 | **VLESS** | Fill-path (hardcoded) | 部分明文 | ★★ | 首包头明文：`version(1) + uuid(16) + addons_len(var) + command(1) + port(2) + addr_type(1) + addr`。后续全加密。可提取 UUID、目标地址、命令类型 |
| 42 | **VMess** | Fill-path (hardcoded) | 仅识别 | ★★★ | 16 字节 auth_id（基于时间戳 + 用户 ID 的 HMAC），其余全 AES-128-CFB 加密。无密钥时只能提取 auth_id 做指纹。可通过包长分布和时序特征识别 |
| 43 | **Trojan** | Fill-path | 仅识别 | ★★★ | 外层是标准 TLS 1.3，内层 `sha224_hex(56) + \r\n + command(1) + addr + \r\n`。无 TLS 解密时只能做 TLS 指纹（JA3/JA4），与正常 HTTPS 几乎无法区分 |
| 44 | **Shadowsocks (SS)** | Fill-path | 仅识别 | ★★ | 首包 `[IV/Salt][encrypted payload]`，全加密。只能通过流量特征识别：首包大小、payload 熵值（接近 8.0）、无明显协议特征。密文指纹为主 |
| 45 | **ShadowsocksR (SSR)** | Fill-path | 仅识别 | ★★ | 同 SS，额外有 protocol/obfs 插件层。部分 obfs 模式伪装为 HTTP，可解析伪装头。密文指纹为主 |
| 46 | **Hysteria2** | Fill-path | 部分明文 | ★★★★ | 基于 QUIC，外层 QUIC Initial 包可解析。通过 ALPN ("h3") + SNI 特征识别。需要先实现 QUIC 解析 |
| 47 | **Tuic** | Fill-path | 部分明文 | ★★★ | 基于 QUIC，QUIC 层面可通过 ALPN 识别。需要先实现 QUIC 解析 |
| 48 | **naiveproxy** | Fill-path | 仅识别 | ★★★★ | 外层是标准 HTTP/2 或 HTTP/3 (QUIC)，伪装为正常 HTTPS。只能通过流量统计特征区分（包长分布、时序） |
| 49 | **Reality** | Fill-path | 仅识别 | ★★★★ | VLESS 的 TLS 伪装变体，TLS 握手与正常 TLS 1.3 几乎无法区分。需要 TLS 指纹 + 统计特征 |
| 50 | **HTTP CONNECT** (代理隧道) | Fill-path (hardcoded) | 部分明文 | ★★ | CONNECT 请求明文（含目标地址），建立隧道后内层取决于被代理协议。TCP:8080/3128 等 |

### 优先级 P5 — 低频 / 补充协议

| # | 协议 | 路径 | 明文 | 难度 | 说明 |
|---|---|---|---|---|---|
| 51 | **FTP** (控制通道) | Fill-path (hardcoded) | 全明文 | ★★ | 文本协议。TCP:21 |
| 52 | **SMTP** | Fill-path (hardcoded) | 全明文 | ★★ | 文本协议。TCP:25/587 |
| 53 | **POP3** | Fill-path (hardcoded) | 全明文 | ★ | 文本协议。TCP:110 |
| 54 | **IMAP** | Fill-path (hardcoded) | 全明文 | ★★ | 文本协议。TCP:143 |
| 55 | **Telnet** | Fill-path | 全明文 | ★★ | 文本 + IAC 命令序列。TCP:23 |
| 56 | **CAPWAP** | Fill-path | 全明文 | ★★★ | 无线 AP 管理隧道。UDP:5246/5247 |
| 57 | **Bitcoin/Ethereum P2P** | Fill-path | 全明文 | ★★ | 固定 magic + command(12) + length(4) + checksum(4) + payload |

---

## 密文指纹原语设计草案 / Ciphertext Fingerprint Primitive

对于 P4 类加密代理协议，建议在 YAML 中增加 `fingerprint` 字段类型：

```yaml
# 示例：用于加密 payload 的指纹计算
- name: payload_fingerprint
  type: fingerprint
  features:
    - length              # payload 字节数
    - entropy             # Shannon 熵 (0.0 ~ 8.0)
    - head_hash           # 首 32 字节的 hash
    - byte_distribution   # 字节值分布直方图 (256 bins, 可选)
```

C++ 侧实现 `parse_fingerprint()` 原语，输出一个 `FingerprintInfo` 结构：

```cpp
struct PayloadFingerprint {
    size_t length;
    double entropy;
    uint64_t head_hash;       // 首 32 字节 xxhash
};
```

Python 侧 Flow 层补充时序特征：
- 包间到达时间 (IAT) 分布
- 上下行包长序列
- 首 N 包的长度/方向序列

这些特征组合后可用于 ML 分类器做加密流量识别。

---

## 依赖关系 / Dependencies

```
QUIC ← Hysteria2, Tuic, naiveproxy (HTTP/3)
TLS (已有) ← Trojan, Reality, naiveproxy (HTTP/2)
GRE ← ERSPAN, PPTP
STUN ← RTP/RTCP (端口发现)
SCTP ← 部分电信协议 (Diameter, S1AP)
fingerprint 原语 ← SS, SSR, VMess, Trojan, Reality, naiveproxy
```

## 建议实施顺序 / Suggested Implementation Order

1. **第一批 (基础隧道 + 核心应用)**:
   GRE → VXLAN → MPLS → PPPoE → IPinIP/IPv6inIPv4 → HTTP → DHCP → NTP
   （全明文、难度低、收益高）

2. **第二批 (安全/VPN)**:
   ESP → AH → WireGuard → IKEv2 → L2TP → QUIC → DTLS
   （QUIC 难度最高，但重要性也最高，可与简单协议穿插进行）

3. **第三批 (应用层扩展)**:
   SSH → SOCKS5 → MQTT → STUN → RTP → SIP → SCTP → Modbus
   （按使用场景选择性实现）

4. **第四批 (fingerprint 原语 + 加密代理)**:
   先实现 fingerprint 原语 → VLESS → VMess → SS/SSR → Trojan → Reality
   （依赖 fingerprint 基础设施）

5. **第五批 (企业/补充)**:
   SMB → RDP → Kerberos → LDAP → BGP → OSPF → RADIUS → SNMP
   （按需实现）
