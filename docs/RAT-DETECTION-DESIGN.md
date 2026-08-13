# RAT Detection Engine 设计

## 数据流

```text
公平文件候选 + 运行中 exe/模块
  -> 只读 PE/ELF 结构、哈希、字符串、API 组合
系统快照 + audit/Falco/Sysmon/已有运行时日志
  -> 稳定 process/file/network/memory/persistence 实体
跨轮连接历史
  -> process + destination 中位数/MAD 画像
本地 IOC/白名单
  -> OFFLINE_ONLY 命中或 THREAT_INTEL_UNAVAILABLE
同实体门禁
  -> finding + causal_edges + counter_evidence + visibility_gaps
```

## 实体与门禁

- Linux process：`boot_id + pid + /proc/PID/stat starttime + exe`。Windows process：ProcessGuid，否则 `boot_id + pid + creation_time + image`。
- file：规范路径 + SHA-256 + 时间，Linux 额外保留 device/inode。network：process instance + 五元组。
- 无签名、高熵、临时路径、加壳、单 API 或单端口只是弱 FILE/NETWORK 证据。
- 两个同实体独立行为域最高中危；三个及以上可为高置信。远程线程、进程篡改等强行为可直接升级。
- JVM/CLR/V8/浏览器 JIT、CGLIB/ByteBuddy/动态代理、有签名稳定更新器是反证，但不会覆盖强注入或组织确认 IOC。

## 输出与边界

- `binary/pe-analysis*.jsonl`：文件静态证据。
- `rat-findings.jsonl`：最终评分、理由、反证、缺口和家族假设。
- `rat-evidence-graph.json`：实体节点与因果边。`rat-connection-profiles.jsonl`：连接画像。
- 引擎不运行、加载、attach、解密执行或上传未知样本；不抓包、不 HTTP/DNS 查询、不自动处置。
