# Task Plan

## Status: COMPLETE — 全部阶段完成

## 概述

六大工作块：git 保存、文档补全、5个内置协议、默认过滤器、应用层解析开关、全量测试。

## Phases

### Phase 0: Git 保存当前状态
- [x] 提交当前所有修改（skill、文档、CLAUDE.md 等）

### Phase 1: 文档补全 — merge() 和 Info 类继承说明
- [x] `docs/protocol-overview.md` — 添加 Info 类架构对比（_SlottedInfoBase vs ProtocolInfo）、merge 机制说明
- [x] `.claude/skills/add-custom-protocol/SKILL.md` — 添加 merge() 说明，明确继承 ProtocolInfo
- [x] `.claude/skills/add-yaml-protocol/SKILL.md` — 说明通用 ProtocolInfo 的默认 merge 行为
- [x] `docs/add-custom-protocol-guide.md` — 添加 merge() 章节

### Phase 2: 新增 5 个 built-in 协议

每个协议需要：YAML 定义、C++ 代码（Type A 需 fast-path）、Python Info 类（_SlottedInfoBase）、父协议路由、converter 路径、单元测试

#### 2a: GRE — Type A fast-path
- IP proto 47，4字节基础头（flags + protocol_type）+ 可选 checksum(4B)/key(4B)/sequence(4B)
- 下层路由：protocol_type 字段 → ethernet(0x6558)/ipv4(0x0800)/ipv6(0x86DD)
- 支持 GRE v0 和 v1
- 文件：gre.yaml, C++ fast-path, GREInfo(_SlottedInfoBase), converter, tests

#### 2b: VXLAN — Type A fast-path
- UDP port 4789，8字节头（flags(1B) + reserved(3B) + VNI(3B) + reserved(1B)）
- 下层路由：递归回 ethernet 解析内层帧
- 文件：vxlan.yaml, C++ fast-path, VXLANInfo(_SlottedInfoBase), converter, tests

#### 2c: MPLS — Type A fast-path
- ethertype 0x8847(unicast)/0x8848(multicast)，4字节/标签条目
- 标签栈：解析所有标签直到 S=1（栈底），保存标签列表 + 栈深度
- 栈底后按首字节判断 IPv4(0x4_)/IPv6(0x6_) 递归解析
- 文件：mpls.yaml, C++ fast-path, MPLSInfo(_SlottedInfoBase), converter, tests

#### 2d: DHCP — Type B fill-only
- UDP port 67/68，BOOTP 固定头(236B) + magic cookie(4B) + options TLV
- 解析字段：op, htype, hlen, xid, client_mac, client_ip, your_ip, server_ip, gateway_ip
- Options 解析：message_type(53), requested_ip(50), server_id(54), hostname(12), domain_name(15), dns_servers(6), lease_time(51), subnet_mask(1), router(3)
- 文件：dhcp.yaml, DHCPInfo(_SlottedInfoBase), converter, tests

#### 2e: DHCPv6 — Type B fill-only
- UDP port 546/547，msg_type(1B) + transaction_id(3B) + options TLV
- Options 解析：client_id(1), server_id(2), ia_na(3), ia_addr(5), dns_servers(23), domain_list(24), status_code(13)
- 文件：dhcpv6.yaml, DHCPv6Info(_SlottedInfoBase), converter, tests

### Phase 3: 默认过滤器参数
- [x] Analyzer 新增 `default_filter` 参数
- [x] 默认值：`"not arp and not icmp and not icmpv6 and not dhcp and not dhcpv6"`
- [x] 与用户 `bpf_filter` 是 AND 关系：最终 = `(default_filter) and (bpf_filter)`
- [x] `default_filter=None` 或 `default_filter=""` 禁用
- [x] PacketFilter 和 NativeFilter 两条路径都支持
- [x] BPF 修复：dhcp/dhcpv6/gre/vxlan 关键字支持 raw-byte 匹配

### Phase 4: 应用层解析开关
- [x] Analyzer 新增 `app_layer_parsing` 参数，类型 str，可选 `"full"` / `"port_only"` / `"none"`
- [x] `"full"`（默认）— 当前行为，启发式 + 端口匹配
- [x] `"port_only"` — 只按端口映射（field-based mapping），跳过 heuristics
- [x] `"none"` — TCP/UDP 之后停止，不解析应用层
- [x] C++ 引擎：NativeParser 构造/parse 传递 mode，ProtocolEngine::parse_layer() 中判断
- [x] Python dpkt 引擎：analyzer.py 中根据 mode 跳过应用层
- [x] 原 4 档（full/fast/port_only/none）简化为 3 档，benchmark 证实 fast 与 port_only 无差异

### Phase 5: 全量测试 + 基准测试
- [x] 运行全部单元测试确认无回归（363 passed, 2 skipped）
- [x] 运行 benchmark 确认性能（full=20.7s, port_only=20.4s, none=20.2s）
- [ ] 最终 git 提交

## Decisions Log

| # | Decision | Rationale | Date |
|---|----------|-----------|------|
| 1 | GRE/VXLAN/MPLS 用 Type A fast-path | ✅ 用户确认。隧道协议在数据路径上，影响后续所有层解析 | confirmed |
| 2 | DHCP/DHCPv6 用 Type B fill-only | ✅ 用户确认。应用层协议，不影响后续解析链 | confirmed |
| 3 | VXLAN/MPLS 支持递归解析内层 | ✅ 用户确认。VXLAN→ethernet→IP/TCP/UDP，MPLS→IPv4/IPv6 | confirmed |
| 4 | DHCP 解析扩展字段集 | ✅ 用户确认。基础 + domain_name/dns_servers/lease_time/subnet_mask/router | confirmed |
| 5 | app_layer_parsing 三档设计 | ✅ 用户确认。full/port_only/none | confirmed |
| 6 | default_filter 用端口/协议号实现 | DHCP/DHCPv6 用 UDP 端口过滤 | confirmed |

## Blocked / Open Questions

_(All resolved)_
