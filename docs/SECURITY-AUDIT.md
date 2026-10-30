# SecScope v1.0 Linux 安全审计

审计日期：2026-08-02。对象：SecScope v1.0 Linux 的全部脚本、helper、测试、fixture、配置和文档。SecScope v1.0 Linux 是只读、永久离线巡检器；不声称能检测所有 WebShell、内存马、RAT 或内核 Rootkit。

## v1.0 原问题、风险与修复

| 原问题 | 风险 | 修改位置 | 实施结果 |
| --- | --- | --- | --- |
| 只有 Web/Unix 静态启发式，缺少 PE/ELF 结构化证据 | Loader、异常 SO/DLL 和加壳文件只剩单字符串弱信号 | `helpers/binary_analyzer.py:172 parse_pe`、`:260 parse_elf`、`:340 analyze_path`；`secscope.sh:3884 run_binary_analyzers` | 单次顺序读取同时哈希和保留有界解析窗口；输出 Header、Section/熵、Import/Export、Resource/Overlay、字符串与 API 组合。无签名、高熵、临时路径不能单独定性。 |
| 磁盘候选未优先覆盖正在执行/映射的文件 | 总配额可被 Web 目录占满，活跃 Loader/SO 未复核 | `secscope.sh:3732 append_runtime_binary_candidates` | 将 `/proc/PID/exe` 与可执行 maps 路径先合并、去重并保留运行时预算；deleted mapping 仍进入内存证据而不当作磁盘文件。 |
| 异常文件、连接、Beacon、注入和持久化缺少 RAT 专用同实体门禁 | 容易全主机凑证据，或将正常更新器/JIT 误报为 RAT | `secscope.sh:4166 publish_rat_snapshot_events`、`:4208 run_rat_detection_engine`；`helpers/rat_engine.py:130 correlate` | 仅以 boot ID + PID + starttime + exe 进程实例聚合；最小三个同实体行为域才是高置信，强注入事件可直接升级；JVM/CLR/V8 JIT 保留反证。 |
| 连接快照不能表达周期性 | 低频 Beacon 和正常长连接无法区分 | `helpers/rat_engine.py:88 build_profiles`、`secscope.sh:4166` | 使用跨轮时间序列中位数、MAD、目标和连接次数建立 `connection_profile`；数据不足时不伪造 Beacon 结论。 |
| 旧 Webhook 能够通过 `curl` 出站 | 与永久离线边界冲突，可意外发送状态 | `secscope.sh:6867 enforce_offline_network_policy`、`secscope.service` | 删除出站调用和 `network-online.target`。旧配置键仅为 CLI/配置兼容而被忽略；`status.json` 记录 `PERMANENT_OFFLINE` 与 `ABSENT_BY_DESIGN`。 |
| “无本地 IOC 命中”可被误读为安全 | 可见性与威胁结论混淆 | `helpers/threat_intel.py:40 main`、`rules/ioc-*.txt` | 只读本地 IOC/白名单；空库或缺失为 `THREAT_INTEL_UNAVAILABLE`，`NO_LOCAL_MATCH` 也明确不等于安全。 |

## 历史演进中保留并复核的关键修复

- Web 链由 `secscope.sh:3954 correlate_web_attack_chain` 使用稳定实体和有界时窗；无 PID 的 HTTP 记录仍只是上下文。
- `secscope.sh:3638 collect_socket_snapshot_once` 每轮只采集一次 `ss`；`secscope.sh:5046 normalize_audit_events` 按 serial 重组 audit；`secscope.sh:5003 normalize_falco_events` 保留 JSON 字段。
- `secscope.sh:5308 collect_native_memory_mappings` 和 `:5345 collect_ebpf_kernel_inventory` 保留 memfd/deleted/RX-RWX/eBPF/内核模块有界可见性，不用户态结果排除 Rootkit。

## 安全边界

- helper 只读字节和 Mock/JSON 事件，不执行、import、attach、解密执行或加载未知样本。
- 不抓包，不主动 DNS，不发起 HTTP，不上传文件、哈希、日志、内存或状态。
- 不杀进程、删文件、修改业务配置或安装 auditd/Falco/bpftool。
- Gh0st RAT、PlugX 等名称只能在多域结构与本地 IOC 同时支持时作为 `family_hypotheses`，不作无样本确认。
