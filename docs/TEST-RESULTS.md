# SecScope v1.0 Linux

测试日期：2026-08-05。环境：macOS 26.5.2 arm64、Colima Ubuntu 24.04 VM（GNU Bash 5.2.21、Python 3.12.3）、Debian 12 bookworm-slim 容器（GNU Bash 5.2.15）。

## 已执行并通过

本轮查询/遍历优化与 HTML 报告重构后追加验证：

- `bash tests/test_scan_optimization.sh`：Ubuntu 24.04 VM Bash 5.2 通过，验证单轮 `/proc`、Socket、持久化候选反向索引、运行中可执行文件关联和固定模式单遍查询。
- `bash tests/test_file_monitoring.sh`：Ubuntu 24.04 VM 通过，变化优先、哈希复用、配置权重和报告字段保持不变。
- `python3 tests/test_html_report.py`：报告完整内容区、摘要导航锚点、搜索/筛选控件、打印样式和响应式断点通过。
- 浏览器视觉回归：桌面和 390px 移动视口通过；搜索 `SSH Wrapper` 命中 3 条，重置后恢复 165 条可搜索内容。
- Ubuntu 24.04 VM 实际 `fast-hunt`：root 执行成功，覆盖率 90%，原始证据 56 个，`real 17.344s / user 14.322s / sys 6.167s`。

- `bash -n secscope.sh`。
- `bash secscope.sh --self-test`：证据域门禁、Web 静态误报、JSON/脱敏、完整性、HTML 时间线和定时配置通过。
- `bash tests/regression.sh`：30/30，覆盖威胁门禁、强行为、文件实体哈希变化、过期白名单、维护窗和 Hunt 视图；同时通过模块篡改、YARA 提升、规则目录上限、品牌和命名测试。
- `bash tests/test_file_monitoring.sh`：Ubuntu VM 与 Debian 12 容器均通过，覆盖 Profile 独立状态、变化优先、哈希复用和配置权重校验。
- `bash tests/test_scan_optimization.sh`：Ubuntu VM 与 Debian 12 容器均通过，验证单次全局文件事实遍历、稳定排序、活跃候选和变化候选优先合并。
- `bash tests/test_branding.sh`、`python3 tests/test_project_naming.py`：宽/窄终端 Banner 通过，项目代码、文档和部署文件无旧产品名或旧入口名。
- `bash tests/test_yara_rule_discovery.sh`：规则目录只遍历一次仍能正确统计总数并执行确定性上限。
- `python3 tests/test_static_analyzer.py`：PHP/Java/.NET/Node/Python 正、反、hard-negative 和有界解混淆。
- `python3 tests/test_candidate_discovery.py`：多根目录/类型公平配额、总上限和 scanner/report/state 排除。
- `python3 tests/test_yara_normalizer.py`：规则名、namespace、tags、metadata 与解析状态。
- `python3 tests/test_security_contracts.py`：PID 重用、HTTP 时间不匹配、同实体真实链、JIT/内存 Mock 和关键源码契约。
- `python3 tests/test_binary_analyzer.py`：无害 PE/ELF 最小头、非二进制输入、组合风险与单 API 不升级。
- `python3 tests/test_rat_engine.py`：正常 TLS 更新不误报；未知文件+周期连接+启动项成高风险；远程线程强证据；JIT 反证；PID 重用不合并。
- `python3 tests/test_offline_intel.py`：情报 helper 无网络库/URL，主入口无出站 `curl`、无心跳函数、无 `network-online.target`，并输出永久离线策略。
- `python3 tests/test_web_access_parser.py`：combined、JSON、失败行 `PARTIAL_PARSE`、原文哈希和 TSV 输出。
- `python3 -m py_compile helpers/*.py tests/*.py`：全部 Python helper/测试编译通过。
- Linux-only 契约入口：`python3 tests/cross_platform_contract.py` 输出 `LINUX_CONTRACT_OK`；本项目仅交付 Linux 版本。
- Ubuntu VM 真实 `--install/--uninstall`：systemd 单元通过 `systemd-analyze verify`；安装目录 `0700`、入口/模块 `0500`、清单 `0400`、配置 `0600`；卸载保留配置和状态。
- `bash tests/benchmark.sh 5`：稳态 user CPU `0.48 s`、system CPU `0.65-0.66 s`、最大 RSS `10,752 KiB`；品牌迁移和算法优化未造成回退。
- 交互式入口：本地伪终端和 Ubuntu 服务器真实 SSH TTY 均通过上下键移动、回车确认、Esc 返回；主菜单进入“运行自检”并成功完成自检，终端状态恢复正常。
- 远端发布验收：当前 `secscope-v1.0-linux.tar.gz` 上传到 Ubuntu 测试机后，包 SHA-256、主脚本和两个必需模块校验、`bash -n`、交互菜单自检均通过；未安装服务或修改远端系统配置。
- 进度输出回归：保留大 Logo，将框线面板改为“两行动态摘要 + sqlmap 风格 `[INFO]` 历史记录”；本地伪终端验证摘要刷新不会覆盖已完成模块，窄终端退化逻辑、语法、自检和回归测试通过。远端已有 full 任务占用全局锁时，fast-hunt 按并发策略正常跳过，未中断已有任务。

结果：已执行项失败 0。`tests/fixtures/` 共 9 个文件，全为不可执行文本、最小非可运行结构或 Mock JSON。

## 尚未覆盖

- CentOS 7、Ubuntu 18.04/20.04/22.04、Debian 10/11 的完整主机扫描。
- 有/无 auditd、Falco、YARA-X/YARA、bpftool、jcmd 的真实数据源矩阵。
- 真实 Web 根、大容量 JAR/WAR、数千运行映射文件与跨三轮 RAT/Beacon 基线。
- 大规模真实 YARA 规则集下的 full/forensic 吞吐和误报率。

实机验收预期：本地可选源存在时是 `SUCCESS/NO_RESULTS`，不存在或达到配额时是 `UNAVAILABLE/PARTIAL`；无数据绝不能解释为安全。

## Native 迁移阶段结果（2026-08-05）

- `tests/test_native_scanner.sh`：Ubuntu 24.04.4 远端使用 G++ 13 编译，`capabilities`、`self-test` 和 fixture scan 通过。
- `tests/test_native_cache.sh`：Unix socket 协议、`ping`、`update_hash`、`get_cached_hash` 契约通过；daemon 未暴露 TCP。
- `helpers/native_parity.py`：结构化 JSON parity 比较器，忽略 run ID、时间、耗时和缓存来源等动态字段，对 severity、finding type、lifecycle、实体关联保留严格比较。
- 已修复并回归：目录句柄递归、worker pool 启动/收尾死锁、哈希 worker 栈溢出、特殊文件哈希阻塞。
- 当前阶段门禁：native 只做预检和 shadow 能力记录，Bash 仍是正式报告路径；完整 Bash/native parity 和生产阶段 benchmark 未完成。
- `tests/test_native_memory_safety.sh`：Ubuntu 24.04.4 使用 ASan、UBSan、LeakSanitizer 编译并运行 scanner/cache；覆盖超大请求预算、并发哈希、超限协议帧、129 MiB 损坏 cache 快照和 SIGTERM 退出，未检测到泄漏、越界、use-after-free 或未定义行为。

## 显式进程处置验收（2026-08-17）

- Ubuntu 24.04 WSL、G++ 13 完成 Native 全量编译，`capabilities` 输出 `native_process_control`。
- `tests/test_process_control.sh` 使用无害 `sleep` 进程，通过正式 `secscope.sh` 入口和 Native 子命令验证 `SIGSTOP` 隔离、`SIGCONT` 恢复、`SIGTERM` 终止和显式授权的 `SIGKILL`。
- 连续 20 轮隔离/恢复全部成功，进程状态每轮均由 `/proc/PID/status` 复核。
- PID start ticks 不匹配、低危请求、错误确认、PID 1、请求权限 0644、审计符号链接和风险降级 Finding 均被拒绝，测试进程保持运行。
- 审计日志权限为 0600，每个授权动作均先写 `ATTEMPT`、再写 `RESULT`；44 个动作形成 88 条可解析 JSONL 记录。
- 非对象 JSON、`RESOLVED` Finding、显式 `SIGKILL`、Linux schema/platform 与活跃生命周期门禁均已回归通过；Windows 侧源码契约、30 个 Python 源文件编译、Native 重编译和 ASan/UBSan/LeakSanitizer 复验均通过。
- Windows 上 `test_static_candidate_router.py` 和 `test_yara_promoter.py` 当前会因 Linux-only 语义失败：前者依赖 `O_NOFOLLOW` 拒绝符号链接，后者只接收 `/` 开头的 Linux Web 根；测试文件已可读取执行，不再是安全软件拦截。

## 依赖清单验收（2026-08-18）

- `requirements.txt` 明确 Python 层仅使用标准库；`tests/test_dependency_manifest.py` 输出 `DEPENDENCY_MANIFEST_OK`。
- `requirements-native-ubuntu-24.04.txt` 覆盖 Bash/Python、C++17、Make/CMake、OpenSSL、zlib、libarchive 和 nlohmann-json 构建依赖。
- Ubuntu 24.04.3、Python 3.12.3、G++ 13.3.0、GNU Make 4.3 和 Native Make 构建链已验证；CMake 需在目标环境另行安装 3.16+。
