# Dict-Based 架构重构要点

## 核心决策

C++ 侧返回 `dict[str, dict]`，Python 侧通过 ProtocolRegistry 组装协议类。

## 动机

1. **性能**：benchmark 显示 dict 路径比 struct + pybind11 属性访问快 46%
2. **通用性/可扩展性**：dict 是通用格式，新增协议只需加 YAML + Python 协议类，不需要改 C++ struct/bindings
3. **简化 C++ 侧**：去掉 `NativeParsedPacket` struct、`NativeXxxInfo` struct、所有 `has_xxx` 标志、`build_dataclass_from_struct` — C++ 只负责解析，不关心 Python 类型系统

## 架构设计

### C++ 侧
- `parse_packet()` 返回 `dict[str, dict]` 作为唯一输出路径
- 不再暴露 `NativeParsedPacket` struct 及子 struct
- 单一代码路径，所有协议统一处理

### Python 侧
- `ProtocolInfo` 基类：`_fields: dict` 存储，typed properties 访问
- `ProtocolRegistry`：协议名 → Info 类的映射，支持运行时注册
- 内置协议（L2-L4）预注册，应用层可扩展
- `ParsedPacket.layers: dict[str, ProtocolInfo]` 持有所有解析层
- `eth`/`ip`/`tcp` 等作为 property 别名指向 `layers`
- `Flow.layers` 同样模式，`_aggregate_flow_info()` 用通用 merge 循环替代

### 关键约束
- dpkt 引擎不受影响
- 公共 API 不变：`pkt.tcp.sport`、`flow.tls.sni` 等
- 所有 272 个现有测试通过
- TLS 重组路径保持工作

## 实施计划（7 Phase）

详见 `refactored-squishing-hennessy.md`

| Phase | 内容 | 状态 |
|-------|------|------|
| 1 | ProtocolInfo 基类 + Registry | 待做 |
| 2 | 迁移 Info 类继承 ProtocolInfo | 待做 |
| 3 | 重构 ParsedPacket + Converter | 待做 |
| 4 | 重构 Flow 聚合 | 待做 |
| 5 | Native Engine 切换 dict 路径 | 待做 |
| 6 | 更新测试 + 导出 | 待做 |
| 7 | 最终验证 | 待做 |
