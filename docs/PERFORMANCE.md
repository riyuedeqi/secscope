# SecScope v1.0 Linux

测量日期：2026-08-02。构建机：macOS 26.5.2 arm64。数字只比较纯逻辑自检，不代表 Linux/Windows 生产主机全量扫描。

## 修改前后可重复基准

命令：`bash tests/benchmark.sh 3`，每轮执行 `secscope.sh --self-test`并采集 wall/user/system/max RSS。

| 版本 | wall 平均 | user CPU 平均 | system CPU 平均 | 最大 RSS | fixture 文件 | 超时 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 历史实现（前） | 5.17 s | 3.00 s | 1.88 s | 10.5 MiB | 8 | 0 |
| SecScope v1.0 Linux（后） | 5.00 s | 2.89 s | 1.79 s | 10.5 MiB | 9 | 0 |
| 变化 | -3.3% | -3.7% | -4.8% | 约 0% | +1 | 0 |

SecScope v1.0 Linux 最终代码原始三轮：wall 5/5/5 s（该基准脚本以整秒记录），user 2.85/2.91/2.91 s，system 1.79/1.79/1.79 s，max RSS 均为 10,752 KiB。虽然增加 PE/ELF、RAT、注入和离线契约，二进制 helper 将哈希和有界解析采样合并为一次顺序读取，自检 CPU 没有回退。

2026-08-05 品牌迁移与候选算法优化后的五轮复测：wall 为 `2/1/1/1/1 s`（首轮冷启动且按整秒取整），稳态 user CPU `0.48 s`、system CPU `0.65-0.66 s`，最大 RSS 均为 `10,752 KiB`，与迁移前稳态持平。12,000 文件、4 根目录、选择 8,000 候选的合成发现基准由 `0.0785 s` 降至 `0.0714 s`，约减少 9%；该数字只表示候选排序器，不代表生产主机完整扫描耗时。

## Linux 全量端到端实测

同一 Colima Ubuntu 24.04.4 arm64 环境执行 `--mode full`，保持 12 个模块、90% 覆盖率和 85 个 raw 证据文件：

| 阶段 | wall | 模块完成到最终结论 |
| --- | ---: | ---: |
| 优化前 | 约 69 s | 约 19 s |
| 文件与清单缓存优化后 | 约 66 s | 约 19 s |
| 本轮最终优化 | **约 50 s** | **约 1 s** |

最终优化的主要收益来自 JSON 清单序列化：普通字段不再逐字段启动 Python，特殊字符仍使用 Python 严格转义；同时复用已生成的 raw/report SHA-256，并由 Python 完整清单校验成功后跳过重复 Shell 哈希循环。清单成员增删和已列文件篡改回归均保持失败可检出。

## 扫描器算法与限制

### 2026-08-05 查询/遍历优化

- 文件变化研判在每轮候选排序完成后建立一次反向上下文索引：`file -> PID`、`PID -> Socket` 和“候选路径 -> 持久化配置命中”。后续每个变化文件使用关联数组和本地命中缓存查询，不再为每个文件重新遍历 `/proc`、Socket 快照和 systemd/cron 目录。
- `/proc` 索引同时保留运行中可执行文件的全局映射，并对候选命令参数建立精确路径索引；因此临时目录执行文件和解释器参数路径仍可关联，已删除但仍被运行进程引用的基线路径也保留在索引模式集合中。
- 持久化配置使用 `grep -F -f` 一次编译候选模式并单遍扫描目标目录，保留原有固定字符串匹配和前 5 条证据语义；包归属查询增加本轮文件缓存，重复查询不再重复启动 `dpkg-query`/`rpm`。
- 这组优化没有减少 `MaxFiles`、扫描根、深度、YARA 候选、规则源或超时预算；Bash 4.2+ Linux 路径启用，旧 Bash 仅保留脚本加载和旧查询回退。

Ubuntu 24.04 VM（Bash 5.2）专项结果：`tests/test_scan_optimization.sh` 和 `tests/test_file_monitoring.sh` 通过；实际 `fast-hunt` root 扫描 `real 17.344s / user 14.322s / sys 6.167s`，覆盖率 90%、原始证据 56 个。由于此前版本没有在同一 VM、同一状态和同一运行规模下保存查询热点基线，本次不伪造“整体提升百分比”；后续生产验收应分别记录索引构建、候选研判和报告生成阶段耗时。

### 2026-08-05 报告样式验收

- HTML 使用无外部依赖的响应式工作台布局：主机态势摘要、风险数字、快速导航、可检索/可筛选发现表格、证据展开和原始证据索引全部保留。
- 桌面视口和 390px 移动视口均完成截图检查；移动端摘要单列、导航横向滚动、长表格保留横向滚动，未发现标题、按钮、摘要数字和证据文本重叠。
- 搜索交互实测：搜索 `SSH Wrapper` 返回 3 条匹配；重置后恢复 `可搜索 165 条内容`。打印 CSS 会展开隐藏证据并隐藏交互控件，便于离线归档。

- 2026-08-05 优化不缩减任何 Profile 的扫描文件数、目录深度、规则源或超时预算。静态/YARA 候选按“新增/修改、运行中 exe/maps、公平根目录发现”顺序合并，高价值变化和活跃文件更早进入同一预算。
- YARA 规则目录从 `find + wc` 和 `find + sort` 两次遍历合并为一次；总超时使用 Bash `SECONDS`，不再针对每个文件和规则执行外部 `date`。
- Python 候选发现器改用 `time.monotonic()`、`deque.popleft()` 和预规范化排除前缀；Bash 增量监测预编译根目录、扩展名和排除规则，减少热循环进程创建与重复字符串解析。
- Linux 增量文件监测先对变化、活跃进程文件、Web/临时/持久化路径、近期文件和高关注扩展计算可配置分数；同分按 mtime、大小、路径稳定排序。元数据未变化时复用基线 MD5/SHA-256，新增或变化文件才重新计算。
- 每文件超时检查、扩展名匹配和路径取值使用 Bash 内建操作，不再为每个候选启动 `date`、`tr` 和 `basename`；1600 文件全哈希复用合成基准由 6.728 s 降至 2.159 s（约 -67.9%）。
- SUID/SGID、异常目录 SUID、无属主和大文件共用一次 `find / -xdev` 遍历；最近系统文件的终端展示直接复用 raw 证据，不再重复扫描。
- 进程资源基线按“路径 + 文件实体元数据”缓存 SHA-256，并将历史状态预载为关联数组；每个进程的均值、阈值和偏离判断合并为一次 `awk` 计算。
- 二进制文件只顺序遍历一次，同时计算 MD5/SHA-256，只保留有界前缀用于 PE/ELF/字符串分析，前后 `lstat` 做 TOCTOU 检查。
- 运行中 exe/映射模块有独立优先预算，再与按站点/根目录/文件类型公平分配的静态候选合并，不使用全局 `head/Select-Object -First` 造成固定偏置。
- Linux `ss -Htanup` 每轮仅采集一次；RAT 引擎对输入 JSONL 默认最多 200,000 条，不反复遍历全量 Socket。
- YARA 默认单文件 8 s、总时间 120 s、最多 600 候选；二进制/解混淆/归档分别有文件数、字节、递归、压缩比和总体积上限。
- 连接画像对每个 process+destination 使用排序后间隔、中位数和 MAD；不对单次快照计算伪周期。
- coverage 记录 scanned/skipped/depth/quota/timed_out；未完成目录进入 `visibility_gaps`，不将“无数据”作为安全结论。

## 尚未测量

当前仍未测量生产规模 Web 根文件数、完整 YARA 规则集吞吐、bpftool/jcmd 延迟、大 Sysmon 日志吞吐、Windows 32/64 位 w3wp 模块枚举或完整扫描 PeakWorkingSet；已完成的 Ubuntu 24.04 VM 结果仅代表隔离测试环境，不替代生产主机基线。

实机命令：Linux 使用 `/usr/bin/time -v sudo bash secscope.sh --mode full --output <新空目录>`；Windows 使用 `powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\benchmark.ps1 -Iterations 3`。生产验收应连续三轮保存 wall/CPU/RSS、candidate/scanned/skipped、timeout 和每根 coverage。

## 2026-08-05 Bash 基线（Ubuntu 24.04.4）

结果写入 `work/native-results/bash-baseline-20260805/baseline-partial.json`。fast-hunt 和 daily-hunt 完成冷态 3 轮、稳态 5 轮；full 仅完成 1 个冷态轮次，按要求跳过剩余数小时的重复测量。

| profile | cold wall 中位数 | warm wall 中位数 | user/system（warm） | max RSS |
| --- | ---: | ---: | ---: | ---: |
| fast-hunt | 221.50 s | 209.49 s | 71.18 / 125.24 s | 47,068 KiB |
| daily-hunt | 523.72 s | 466.03 s | 278.03 / 189.43 s | 92,532 KiB |
| full（单轮） | 3595.94 s | 未测 | 2014.28 / 1394.39 s | 108,440 KiB |

native scanner/cache 现为纯 Python 实现（免编译），已完成自测与 fixture 契约验证；协议与输出契约和原 C++ 实现保持一致。
