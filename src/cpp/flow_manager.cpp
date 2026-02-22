#include "flow_manager.h"

// Currently all NativeFlowManager logic is header-only (inlined in flow_manager.h).
// This file exists for:
// 1. CMake build system (needs a .cpp to compile)
// 2. Future: process_file() entry point that reads pcap + parses + manages flows
// 3. Future: protocol aggregation (merge) logic
// 4. Future: retransmission detection logic
