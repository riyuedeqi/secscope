# SecScope v1.0 Linux

状态：**支持** = 当前可直接采集/分析；**部分支持** = 依赖可选本地数据源或只有限可见；**不可见** = 只报告缺口，不生成伪结论。

| 能力 | Linux v1.0 | Windows v1.0 | 真实实现、可选依赖与边界 |
| --- | --- | --- | --- |
| WebShell 多语言静态结构 | 支持 | 支持 | PHP/JSP/Java/.NET/Node/Python 共享有界解码、能力组合、数据流边和安全归档。当前是启发式 token/bytecode/IL 特征，不是每种语言的完整 AST/CFG。 |
| YARA-X / classic YARA | 支持（可选） | 支持（可选） | Linux 优先 `yr`、回退 `yara`，支持分层模式、有界本地规则、meta 风险映射、finding 提升和文件/Web/进程/网络/持久化/容器上下文关联；扫描器或规则不存在时为 `UNAVAILABLE`。 |
| PE 结构分析 | 支持 | 支持 | 共享原始字节解析 Header、Section/熵、Import/Export、Resource/Overlay、编译时间和 API 组合。Windows 额外读 Authenticode/Publisher/VersionInfo；绝不 `Assembly.Load`。 |
| ELF 结构分析 | 支持 | 支持（文件输入） | 解析 ELF Header/Section/Dynamic/Symbol 与字符串；不执行或动态链接目标。 |
| 高风险 API 组合 | 支持 | 支持 | 只对 OpenProcess+VirtualAllocEx+WriteProcessMemory+RemoteThread 等组合赋能；单个 `socket/cmd/powershell/connect`、高熵或无签名不定性。Import/字符串仍只是静态能力证据，不证明已执行。 |
| RAT/Loader 同实体证据图 | 支持 | 支持 | 稳定 process/file/network/memory/registry/service/dns 实体，关联文件、进程、网络、Beacon、注入和持久化。家族名称只是有条件 hypothesis，不声称样本归因。 |
| Beacon 连接画像 | 部分支持 | 部分支持 | 使用跨轮连接时间、固定目标、中位数和 MAD。普通快照没有包字节、SNI 或长时间序列时不伪造这些字段。 |
| 威胁情报 | 部分支持 | 部分支持 | **永久离线**：只读本地 IOC/白名单/历史基线。无 HTTP、DNS、VT、AbuseIPDB、ThreatFox、GreyNoise、ASN 或域名年龄查询；空库为 `THREAT_INTEL_UNAVAILABLE`。 |
| Windows 远程线程/篡改 | 不适用 | 支持（可选数据源） | Sysmon 8+10 同源/目标/时窗相关，Event 25 直接强证据。无 Sysmon 时为 `UNAVAILABLE`，不从快照排除注入。 |
| Windows 手工映射 PE/线程 StartAddress | 不适用 | 不可见 | 未向进程注入或自动 attach 内存 helper。无模块 MZ 头和 StartAddress 属性在当前只是明确 gap。 |
| 异常 DLL/原生模块 | 部分支持 | 支持（可选数据源） | Linux 来自 `/proc/maps`；Windows 来自 Sysmon 7 和进程模块快照，含路径、哈希、签名和加载时间。权限/位数不匹配会形成 gap。 |
| Linux memfd/deleted/anonymous RX-RWX | 支持 | 不适用 | `/proc/fd/maps/smaps/map_files`；JVM/V8/CLR/数据库 JIT 是反证，匿名执行内存不单独定性。 |
| JVM/PHP/CLR/IIS 运行时 | 部分支持 | 部分支持 | 基础模式只读命令行、模块、配置和已有日志。Java 深度 helper 必须显式启用；不自动 Heap Dump/attach。CLR Location/MVID/ALC 完整实时清单仍依赖预部署只读源。 |
| 持久化 | 支持 | 支持 | Linux cron/systemd/rc.local/profile/LD_PRELOAD/authorized_keys；Windows Run、服务、计划任务、WMI、Startup、DLL 侧加载线索。“修改进程”只在事件源含 PID/Guid 时声称。 |
| Sysmon 增量/覆盖 | 不适用 | 支持（可选） | RecordId 书签；1/3/7/8/10/11/12–14/17–18/22/23/25/26 分项覆盖；达上限为 `PARTIAL`。 |
| auditd/Falco | 支持（可选） | 不适用 | audit 按 serial 重组并保留 PARTIAL 原文；Falco 保留 rule/priority/tags/output_fields。 |
| Web access log 归一化 | 支持 | 支持（IIS/常见 Web 日志） | Linux 自动发现 Nginx/Apache/OpenResty/Caddy/Tomcat；Windows 同时解析 IIS W3C `#Fields` 与 Nginx/Apache/Tomcat/Caddy common/combined/JSON。失败行保留哈希并标记 `PARTIAL_PARSE`，无 PID 仅作 WEB 上下文。 |
| 容器/Kubernetes 上下文 | 支持 | 不适用 | Linux 读取 cgroup、container runtime/ID、Pod UID、namespace inode、运行时 Socket、ServiceAccount 和宿主路径；正常控制面/节点组件保留反证，多域同实体才升级。 |
| eBPF/内核模块/Rootkit 可见性 | 部分支持 | 部分支持 | Linux 读 bpftool/pinned/ftrace/模块签名/包/哈希；Windows 读驱动/Code Integrity/签名。两者的用户态扫描都不能完全排除内核 Rootkit。 |
| HTTP→文件→进程→网络→持久化 | 部分支持 | 部分支持 | 只通过稳定实体和有界时间边连接；无 PID 访问日志只作上下文。缺失写入 PID 时链会主动少连而不强绑。 |
| 报告/状态/证据/跨轮基线 | 支持 | 支持 | 保留 CLI、HTML、status/findings/raw/manifest/SHA-256/白名单/脱敏包字段，增加 RAT 总览、实体图、反证、因果边和 gap。 |
| 出站网络、自动处置 | 不支持（设计边界） | 不支持（设计边界） | 永久离线；无 HTTP/DNS/上传/Webhook。扫描不自动杀进程、删文件、修改配置或安装组件。 |
| 显式高危进程处置 | 支持（Native） | 不适用 | 操作员提供 0600 请求、原始 `findings.json` 和 0600 审计路径；只接受 HIGH 置信的 HIGH/CRITICAL `SECURITY_THREAT`，并校验 boot ID、PID、start ticks、exe、受保护进程和 pidfd。支持 `contain/release/terminate/kill`，默认不被扫描或定时任务调用。 |
