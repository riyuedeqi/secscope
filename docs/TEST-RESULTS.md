# SecScope v2.0 实测结果

> v1.x 测试记录（2026-08）保留于本文档末尾；v2.0 实测如下。

测试日期：2026-10-30。环境：Ubuntu 22.04.5 LTS / 2C / 3.6GB / 64 天 uptime / 真实业务负载（containerd 容器、Apache/PHP 站点、node 服务、MySQL、Go 工具链，/var 下约 100 万文件的容器存储层）——比干净实验室严苛的真实场景。

## 迭代过程（全部为 `--no-state --profile full` one-shot 全量取证模式）

| 轮次 | 总耗时 | 高危发现 | 样本检出 | 主要变化 |
|---|---|---:|---:|---|
| run1（v2 初版） | 11m42s | 55（大量误报） | 21% | 基线 |
| run3 | 16m46s* | 46 | ~74% | cwd 浅路径修复 / one-shot 全量 ADDED / 包归属索引 / frp 规则收紧 |
| run5 | 11m06s | 33 | 71%（15/21） | JSON 数组封顶 / 去重写入 / Go 工具链 FP 修复 / JIT exe 名匹配 |
| run7 | 11m31s | 28 | 71%（15/21） | 云厂商 Agent LD_PRELOAD 治理 / JIT 条件修正 / usrmerge 包归属 |
| run8 | 12m29s | 46 | 65%（64/99，100样本语料首轮） | 暴露候选管线四类截断缺陷 |
| run11（终版） | 14m39s | 67** | **98/99 = 99%** | JUST_DROPPED 超权重 / 无扩展名采集修复 / FILE_EXTENSIONS 扩类 / cap 修复 |

*run3 的 16m46s 暴露了汇总阶段对 5000 条 JSON 数组的逐条 printf 序列化问题，run5 修复。
**run11 高危上升是因为 100 个恶意样本在主机上产生真实命中（40 条 HIGH 样本命中 + 主机自身 27 条真实问题）。

## 100 样本标准语料实测（run11）

- 语料：15 大类 × 100 恶意样本 + 20 干净对照（`tests/build_redteam_corpus_100.py`，纯 Python 构造，零网络零 C）。
- 签名级：100/100 = 100%，干净对照 0 误报。
- 端到端：**98/99 = 99%**（样本撒在主机上、走完整 发现→哈希→路由→签名→finding 管线），干净文件 0 误命中。
- run8（65%）→ run11（99%）之间修复的管线缺陷：魔数判定顺序、无扩展名文件被采集过滤器排除、FILE_EXTENSIONS 缺类、新落地文件 JUST_DROPPED 超权重、受限档 cap 写法错误、家族归因平票。

*run3 的 16m46s 暴露了汇总阶段对 5000 条 JSON 数组的逐条 printf 序列化问题，run5 修复。

## run5 实测指标

### 扫描时长
- **全流程 11 分 06 秒**（13 模块 9m40s + 汇总/报告 ~1m26s），满足 ≤15 分钟硬指标。
- 全局预算机制（`SECSCOPE_SCAN_DEADLINE_SECONDS=900`）在 run2 曾正确触发预算跳过（SKIPPED_BUDGET 诚实呈现），机制有效性已验证。

### 恶意文件检出率（远端实机构造样本）
- 编译型 ELF（测试机 gcc 实编，一次性测试夹具）：反弹 shell（socket/connect/dup2/execve 导入组合）、xmrig 挖矿（stratum 串）、EW 代理（lcx/ssocksd 串）—— **3/3 HIGH 家族签名命中**。
- 内容样本（原文件 + /tmp、/var/www 副本）：bash 反弹 shell、PHP 一句话、JSP 执行/内存马、挖矿配置、gsocket/ew/nps 代理、PwnKit、历史清除 —— HIGH/MEDIUM 命中。
- 合计 **15/21 = 71%**（按部署形态计；按内容去重 13/19 = 68%，6 个未命中文件全部是候选上限截断所致——非检测逻辑漏报，终版候选上限已提至 12000）。
- 本地合成语料回归：**35/35 = 100%，误报 0/12**（`python3 tests/build_redteam_corpus.py`）。
- 检出主力为行为/结构签名（家族唯一性命令串、协议串组合、输入-执行因果链、ELF 导入组合+包归属交叉），不依赖样本哈希 → 对同家族变体保持覆盖，符合"不过拟合"要求。

### 误报率（高危发现 55 → 33）
run5 的 23 条非样本高危逐条核实：
- **真实安全问题（应报）**：sudoers NOPASSWD、SSH root 密码登录、privileged 容器、K8s 高价值上下文、bash_history 中的 JNDI-Injection-Exploit 利用命令（该机确有红队使用痕迹）、curl|bash 部署脚本、临时目录脚本 —— 共 17 条。
- **首轮无基线预期行为（次轮起消退）**：异地登录 UEBA 首次画像 1 条。
- **环境性误报（终版已治理）**：腾讯云主机安全 Agent `/lib64/libsgmon.so` LD_PRELOAD（新增 `PRS-LD-PRELOAD-CLOUD-AGENT` 低危规则）、解释器型守护进程 JIT RWX（argv0≠comm 误判条件已修正；next-server 关联网络保持 HIGH 属正确）。

### 覆盖率
- 13 模块 / 45 计划数据源：system/persistence/filesystem/history/services/memory/baseline 100%；users/process/network 80%（无 auditd/IMA/Falco，诚实标注 UNAVAILABLE）；logs 50%（无 auditd）；整体 90%。
- rootkit 模块 PARTIAL：bpftool 未安装（eBPF 面诚实降级）。
- filesystem PARTIAL：候选上限（12000/23000 已评分）+ 216 个 /proc 映射文件扫描时已消失（TOCTOU）——全量取证模式预期边界，报告以 `static_coverage_limited` 呈现。

## 已验证的基础设施
- one-shot（`--no-state`）：空基线 + `--report-added` 全量报告 ADDED，且零状态落盘（/var/lib/secscope 全程未创建）。
- 全局 15 分钟预算：run2 中预算耗尽后 7 个模块标记 SKIPPED_BUDGET 并进入报告"可见性缺口"。
- 完整性自检：sha256 清单不匹配时正确产生 CRITICAL 发现（run1 曾捕获自身被改动）。
- v2 报告渲染器：单文件 HTML（零外部资源）、置信度分级、家族徽章、可见性缺口区，实测通过（tests/test_html_report.py）。

## v2.3 优化与新功能验证（run12）

- **总耗时 10m23s**（对比 run11 的 14m39s，节省 ~29%）：lane 并行（静态/二进制引擎进程并行）、网络五元组批量化（3.2万fork→1进程）、beacon 去双跑、native 最长任务优先哈希。
- **端到端检出 99/99 = 100%**（100样本语料撒在主机上全链路），干净对照 0 误命中。
- **新功能产物全部生效**：samples-bag.tar.gz（1.5MB 样本袋）、ioc-export/（TSV/CSV/STIX 三格式）、compare.json（vs run11：61新增/51解决/286持续）、container-forensics.tsv（docker 缺失诚实降级 NOT_APPLICABLE）。
- `--compare` 报告含"轮次对比"专区；生命周期专区在 one-shot 模式正确缺席（无基线对账对象）。
- 自检恢复全绿：修复 S4 遗留的 file_scan.raw 键缺失、遗留 UI 时代的过期断言、cron 断言漂移；全部 81 项断言通过。
- 验收审计修复：grep 契约断链（三个新 helper stdout 格式）、sample_bag entity 5段解析 off-by-one、RICHEN_ONLY 引擎双跑、rc 缺省 0 洗白、STIX url/ipv6 pattern、/usr 投放降档保底（≥2规则命中不低于 ANOMALY）、fold 混引号链整链 verbatim。

## 复现

```bash
# 本地语料回归（纯 Python，无需网络）
python3 tests/build_redteam_corpus.py

# 远端实机评估（在目标机完成一次扫描后）
sudo bash secscope.sh --no-state --profile full --output /tmp/run
python3 tests/eval_remote_run.py /tmp/run
```

> 远端实机样本为一次性测试夹具（含在测试机上临时编译的模拟 ELF），不属于交付物；工具本身零编译、无 C 代码。

---

# 附录：SecScope v1.x 测试记录（2026-08-05）

测试日期：2026-08-05。环境：macOS 26.5.2 arm64、Colima Ubuntu 24.04 VM（GNU Bash 5.2.21、Python 3.12.3）、Debian 12 bookworm-slim 容器（GNU Bash 5.2.15）。

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

- `tests/test_native_scanner.sh`：capabilities、self-test 与 fixture scan 契约在纯 Python 实现下保持通过（历史记录：C++ 版曾在 Ubuntu 24.04.4 + G++ 13 验证）。
- `tests/test_native_cache.sh`：Unix socket 协议、`ping`、`update_hash`、`get_cached_hash` 契约通过；daemon 未暴露 TCP。
- `helpers/native_parity.py`：结构化 JSON parity 比较器，忽略 run ID、时间、耗时和缓存来源等动态字段，对 severity、finding type、lifecycle、实体关联保留严格比较。
- 已修复并回归：目录句柄递归、worker pool 启动/收尾死锁、哈希 worker 栈溢出、特殊文件哈希阻塞。
- 当前阶段门禁：native 只做预检和 shadow 能力记录，Bash 仍是正式报告路径；完整 Bash/native parity 和生产阶段 benchmark 未完成。
- `tests/test_native_memory_safety.sh`：覆盖超大请求预算钳制、超限协议帧、129 MiB 损坏 cache 快照隔离和守护进程存活（历史记录：C++ 版曾以 ASan/UBSan/LeakSanitizer 验证无内存错误）。
