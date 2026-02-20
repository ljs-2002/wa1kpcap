# Task Plan

## Status: READY — 待用户确认执行

## 概述

四大工作块：默认引擎切换（native 默认 + dpkt 可选）、项目文件清理、PyPI 发布指南、GitHub Actions CI/CD 指南。

## Phases

### Phase 1: 默认引擎切换 — native 默认，dpkt 可选

#### 1a: pyproject.toml 依赖反转
- [ ] `dependencies` 移除 `dpkt>=1.9`，只保留 `PyYAML>=6.0`（native 引擎 YAML 解析需要）
- [ ] 新增 `[project.optional-dependencies] dpkt = ["dpkt>=1.9"]`
- [ ] 移除原 `native` optional-dependencies（pybind11 是构建依赖不是运行依赖，PyYAML 已移入核心）
- [ ] 用户安装方式变为：`pip install wa1kpcap`（native）、`pip install wa1kpcap[dpkt]`（额外装 dpkt）

#### 1b: analyzer.py 引擎默认值 + fallback
- [ ] `engine` 参数默认值从 `"dpkt"` 改为 `"native"`
- [ ] 当 `engine="dpkt"` 但 dpkt 未安装时：`warnings.warn("dpkt not installed, falling back to native engine")` 并自动切换
- [ ] 更新 docstring

#### 1c: `__init__.py` 延迟导入 dpkt 协议模块
- [ ] `wa1kpcap/__init__.py`：将 `from wa1kpcap.protocols.base import ...` 和 `from wa1kpcap.protocols.registry import ...` 保留（不依赖 dpkt）
- [ ] `wa1kpcap/__init__.py`：移除顶层 `from wa1kpcap.protocols.base import BaseProtocolHandler, ProtocolContext, ParseResult`（这些从 base.py 来，不依赖 dpkt，可保留）
- [ ] `wa1kpcap/protocols/__init__.py`：将 link/network/transport/application 的导入改为延迟导入（try/except 或函数内导入），避免 `import wa1kpcap` 时因缺少 dpkt 而崩溃
- [ ] 确保 `register_protocol` / `get_global_registry` 不触发 dpkt 导入

#### 1d: 测试验证
- [ ] 全量测试通过（native 引擎）
- [ ] 验证：卸载 dpkt 后 `import wa1kpcap` 正常、`Wa1kPcap()` 默认用 native
- [ ] 验证：卸载 dpkt 后 `Wa1kPcap(engine="dpkt")` 打 warning 并 fallback

### Phase 2: 项目根目录清理

#### 确认删除（开发临时文件）：
- [ ] `benchmark_construction.py` — 构造性能测试（一次性）
- [ ] `benchmark_dispatch.py` — 调度表性能测试（一次性）
- [ ] `benchmark_pyobj.py` — Python 对象性能测试（一次性）
- [ ] `benchmark_slots.py` — __slots__ 性能测试（一次性）
- [ ] `gen_tls_report.py` — TLS 报告生成器（一次性）
- [ ] `profile_breakdown.py` — 性能分析（一次性）
- [ ] `profile_cpp_detail.py` — 性能分析（一次性）
- [ ] `profile_cpp_real.py` — 性能分析（一次性）
- [ ] `profile_native.py` — 性能分析（一次性）
- [ ] `profile_wa1kpcap.py` — 性能分析（一次性）
- [ ] `run_tests.py` — 测试运行器（pytest.ini 已替代）
#### 用户要求保留的旧报告：
- `benchmark_report_old.md`
- `benchmark_report_old_old.md`
- `benchmark_report_speed.md`
- [ ] `tls_report.md` — TLS 报告（一次性产物）
- [ ] `refactored-squishing-hennessy.md` — 临时文档
- [ ] `dict_based.md` — 临时设计文档

#### 用户确认保留：
- `context.md`, `plan_context.md`, `task_plan.md`, `findings.md`, `progress.md` — 全部保留

#### 保留不动：
- `benchmark.py` — 主基准测试（用户明确保留）
- `benchmark_report.md` — 当前报告（用户明确保留）
- `README.md` — 项目说明
- `CLAUDE.md` — Claude Code 指令
- `pyproject.toml` / `CMakeLists.txt` / `pytest.ini` / `.gitignore` — 构建配置

### Phase 3: PyPI 发布指南（仅文档，不改代码）

需要告知用户的内容：
- [ ] pyproject.toml 补充：`license`, `authors`, `readme`, `classifiers`, `urls` 等元数据
- [ ] scikit-build-core 的 wheel 构建：C++ 扩展会编译进 wheel
- [ ] `wa1kpcap[dpkt]` extras 机制说明
- [ ] sdist 发布：没有预编译 wheel 的平台会从源码编译（需要 CMake + C++17 编译器）
- [ ] 发布命令：`python -m build` + `twine upload`

### Phase 4: GitHub Actions CI/CD 指南（仅文档，不改代码）

需要告知用户的内容：
- [ ] cibuildwheel 配置：跨平台构建 wheel（Linux/macOS/Windows × x86_64/arm64）
- [ ] GitHub Actions workflow 文件结构
- [ ] PyPI trusted publisher 配置（无需 API token）
- [ ] sdist 发布：源码分发包供无预编译 wheel 的平台本地编译
- [ ] 触发条件：tag push（如 `v0.1.0`）

## Decisions Log

| # | Decision | Rationale | Status |
|---|----------|-----------|--------|
| 1 | native 为默认引擎 | C++ 引擎性能更好，不依赖第三方 Python 包 | pending |
| 2 | dpkt 降为 optional dependency | 通过 `wa1kpcap[dpkt]` 安装 | pending |
| 3 | protocols/__init__.py 延迟导入 | 避免 import wa1kpcap 时因缺少 dpkt 崩溃 | pending |
| 4 | Phase 3/4 仅提供指南不改代码 | 用户要求"告诉我需要做什么" | pending |

## Blocked / Open Questions

1. 根目录 `context.md`, `plan_context.md`, `task_plan.md`, `findings.md`, `progress.md` 是否删除？
