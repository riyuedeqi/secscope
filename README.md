# SecScope v1.1.0 Linux

SecScope 是一个面向 Linux 主机的只读、离线、分层安全巡检与威胁狩猎工具。它通过 Bash 主控、Python 分析器和可选 C++17 Native 加速组件，对文件变化、进程与内存映射、网络连接、持久化、Web 日志、YARA、WebShell/RAT 候选、容器上下文和本地基线进行关联分析，并输出可归档的 HTML 与结构化证据。

> 设计目标：**只读巡检、永久离线、证据可追溯、无自动处置**。SecScope 不主动发起 HTTP/DNS 情报请求，不执行被检测文件，不杀进程、不删文件、不修改业务配置。扫描不完整、模块失败或关键数据源不可用时，报告会明确降级为 `PARTIAL`、`INCONCLUSIVE` 或 `UNAVAILABLE`。

## v1.1.0 重点变化

- 候选发现采用按 root 公平配额和优先级调度，优先覆盖 Web 根、临时目录、用户目录、隐藏文件及无扩展名文件。
- 文件与 YARA 报告增加 `expected_files`、`scanned_files`、`skipped_files`、`error_count` 和 `skip_reasons`，不再把扫描失败统计为“未发现”。
- ELF 分析增加 program segment、RWX、静态链接/去符号、高熵及可疑 API/配置线索。
- RAT 结果采用严格归因：威胁 Finding 必须能够绑定样本路径、SHA-256、稳定进程实例及运行时或网络证据。
- WebShell 内容识别扩展到 PHP、JSP/Jakarta、ASP/ASPX、Node.js 和 Python，并覆盖隐藏、改名和无扩展名文件。
- audit 事件补充 `memfd_create`、`ptrace`、`process_vm_writev` 等行为归一化。
- Java agent 增加顶层异常隔离及 `SUCCESS/PARTIAL/UNAVAILABLE` 状态，helper 故障不会再被解释为阴性结果。

## 项目特点

- **离线安全巡检**：默认不联网，不上传样本、哈希、日志或状态。
- **分层扫描 Profile**：生产扫描支持 `fast-hunt`、`daily-hunt`、`full`；另提供显式清单驱动的测试专用 `corpus-validation`。
- **跨轮基线**：识别新增、修改、移动、删除文件，并保留生命周期状态。
- **多源关联**：把文件、进程、socket、内存映射、Web 日志、持久化和本地 IOC/YARA 结果关联到同一实体。
- **WebShell/RAT 候选分析**：内置 Python 静态分析器、二进制分析器和 RAT 证据图规则。
- **Native 可选加速**：C++17 scanner/cache 可在目标 Linux 主机上本地编译。
- **可审计输出**：生成 HTML、`findings.json`、`status.json`、`raw/` 证据和 SHA-256 清单。
- **可见性缺口透明**：缺少 auditd、Falco、YARA、bpftool、jcmd 等可选数据源时报告为 `UNAVAILABLE`、`PARTIAL` 或 `NOT_APPLICABLE`，不把“无数据”解释为安全。

## 适用场景

- Linux 主机安全基线巡检
- Web 服务器入侵排查与 WebShell 候选筛查
- 临时目录执行、异常持久化、异常外连和可疑内存映射排查
- 离线环境、内网环境或不允许上传日志/样本的客户现场
- SRC/应急响应中的只读证据收集和报告归档

## 快速开始：源码运行

本仓库是**未编译源码版**。源码仓库不提交 `dist/`、`prebuilt/`、`runtime/`、历史报告和工作日志。

```bash
git clone https://github.com/riyuedeqi/secscope.git
cd secscope
bash secscope.sh --help
sudo bash secscope.sh --self-test
```

运行扫描：

```bash
sudo bash secscope.sh --profile fast-hunt
sudo bash secscope.sh --profile daily-hunt
sudo bash secscope.sh --profile full --output /secure/secscope/full-$(date +%Y%m%d)
```

首次确认主机状态正常后，可初始化基线：

```bash
sudo bash secscope.sh --init-state --profile daily-hunt
```

一次性调查、不使用跨轮状态：

```bash
sudo bash secscope.sh --no-state --profile full --output /secure/secscope/snapshot
```

## Native 组件编译

Native scanner/cache 使用 C++17。构建需要：

- GCC 7+/Clang 6+ 或等效 C++17 工具链
- OpenSSL development headers
- zlib development headers
- libarchive development headers
- nlohmann-json headers
- GNU Make 或 CMake 3.16+

Make 构建：

```bash
make -C native/secscope-scanner -j2
make -C native/secscope-cache -j2
native/secscope-scanner/scanner capabilities
native/secscope-scanner/scanner self-test
```

CMake 构建：

```bash
cmake -S native/secscope-scanner -B /tmp/secscope-scanner-build
cmake --build /tmp/secscope-scanner-build -j2
cmake -S native/secscope-cache -B /tmp/secscope-cache-build
cmake --build /tmp/secscope-cache-build -j2
```

如果没有编译环境，可以暂时关闭 Native 路径，使用 Bash/Python 兼容路径：

```bash
sudo SECSCOPE_NATIVE_SCANNER=off bash secscope.sh --profile daily-hunt
```

## YARA 与规则

SecScope 优先使用仓库或发行包中的 YARA-X `yr`，否则回退到系统 `yr` 或 classic `yara`。源码仓库不提交编译好的 `yr` 运行时；如需 YARA 扫描，请在目标主机安装 `yr`/`yara`，或使用发行包提供的离线运行时。

```bash
SECSCOPE_YARA_MODE=auto
SECSCOPE_YARA_RULES=/opt/secscope/rules/yara-forge-core-20260809
SECSCOPE_YARA_FILE_TIMEOUT=8
SECSCOPE_YARA_TOTAL_TIMEOUT=120
SECSCOPE_YARA_MAX_FILES=600
```

`SECSCOPE_YARA_MODE` 支持：`auto|disabled|lite|standard|full|forensic`。`auto` 映射为：`fast-hunt=disabled`、`daily-hunt=standard`、`full/corpus-validation=full`。

## 扫描 Profile

| Profile | 建议频率 | 重点内容 | 典型预算 |
|---|---:|---|---|
| `fast-hunt` | 10 分钟至 1 小时 | 文件变化、异常进程、外连、临时目录执行、持久化、轻量日志 | 800 文件、深度 4、哈希 30 MB、45 秒 |
| `daily-hunt` | 1 至 6 小时 | fast 内容 + 内存轻量取证、WebShell 静态分析、ELF/PE、限量 YARA、扩展日志 | 3000 文件、深度 5、哈希 100 MB、120 秒 |
| `full` | 1 至 7 天 | 全模块、深度文件扫描、包完整性、完整 YARA、详细报告 | 12000 文件、深度 10、哈希 512 MB、900 秒 |
| `corpus-validation` | 测试验收，不用于生产巡检 | 仅显式清单的静态、二进制和 YARA 分析；不合并主机候选 | 最多 100000 文件、1800 秒 |

### 测试专用 corpus profile

`corpus-validation` 仅用于隔离 fixture、规则回归和版本验收。它只有在显式选择该 profile，并同时提供 corpus root 与 manifest 时才会启用；systemd 默认服务和定时任务不会选择它。

该 profile 不遍历 `/`、生产 Web 根、临时目录、运行时进程或网络状态，因此其结果只表示清单内文件的静态覆盖，**不能作为真实主机“未发现威胁”的结论，也不能与生产 profile 的检出率直接比较**。

```bash
sudo bash secscope.sh --profile corpus-validation \
  --corpus-root /tmp/secscope-corpus \
  --corpus-manifest /tmp/secscope-corpus-manifest.jsonl \
  --output /secure/secscope/corpus-validation
```

manifest 使用 JSONL，每行必须包含 `path`，可选 `sha256`、`sample_id` 和 `lane`。重复、越界、符号链接、缺失、不可读或哈希不匹配的条目会被拒绝，并将覆盖状态降级为 `PARTIAL/INCONCLUSIVE`。

## 输出目录

默认报告位置：

```text
reports/fast/
reports/daily/
reports/full/
```

状态目录：

```text
/var/lib/secscope
```

典型输出文件：

```text
report_*.html
findings.json
status.json
raw/file-changes.tsv
raw/suspicious-files.tsv
raw/process-context.tsv
raw/container-context.tsv
raw/kubernetes-context.tsv
raw/web-access-normalized.tsv
raw/events-normalized.jsonl
raw/yara-results.jsonl
raw/yara-findings.tsv
raw/yara-summary.json
```

`raw/` 可能包含命令行、账户、IP、环境变量或 Token，应限制访问和传输范围。

## 目录结构

```text
secscope/
├── secscope.sh                  # Bash 主入口
├── install.sh                   # 预编译发行包安装/校验入口
├── modules/                     # Bash 模块：Profile、YARA 调度等
├── helpers/                     # Python/Java 辅助分析器
├── native/                      # C++17 scanner/cache 源码
├── rules/                       # 本地 IOC、allowlist 和规则
├── config/examples/             # 示例配置
├── systemd/                     # systemd service/timer unit
├── packaging/                   # 发行包构建脚本
├── tests/                       # 回归、契约、Native parity 和安全测试
├── docs/                        # 设计、性能、审计和测试文档
└── DIRECTORY-LAYOUT.md          # 更详细的目录说明
```

未提交到源码仓库的本地产物：

- `dist/`：发行压缩包
- `prebuilt/`：预编译交付包
- `runtime/`：编译好的 YARA-X 等运行时
- `archive/`：历史整理快照和工作日志
- `reports/`：主机扫描报告
- `work/`：临时工作目录和基准产物

## 常用命令

```bash
# 帮助和自检
bash secscope.sh --help
sudo bash secscope.sh --self-test

# 扫描
sudo bash secscope.sh --profile fast-hunt
sudo bash secscope.sh --profile daily-hunt --host-role web-server
sudo bash secscope.sh --profile full --output /secure/secscope/full

# 状态
sudo bash secscope.sh --init-state --profile daily-hunt
sudo bash secscope.sh --reset-state --profile daily-hunt
sudo bash secscope.sh --no-state --profile full

# systemd 调度，适合发行包或已准备好本地运行时的部署目录
sudo bash secscope.sh --install
sudo bash secscope.sh --uninstall
```

旧 `--mode`、`--schedule-interval`、`--schedule-time` 和 `--schedule-cron` 参数保留兼容。

## 配置示例

示例配置位于：

```text
config/examples/secscope.conf.example
config/examples/file-scan.config.example
config/examples/context.allow.example
config/examples/process.allow.example
config/examples/path.allow.example
config/examples/ip.allow.example
config/examples/port.allow.example
```

本地 IOC 与允许列表：

```text
rules/ioc-local.txt
rules/ioc-allow.txt
```

允许列表不能覆盖组织确认的恶意哈希、明确注入、凭据转储、日志清除、恶意引擎命中或 Web 网络 Shell。

## 测试

```bash
bash tests/regression.sh
bash tests/test_file_monitoring.sh
python3 tests/test_candidate_discovery.py
python3 tests/test_binary_analyzer.py
python3 tests/test_rat_engine.py
python3 tests/test_static_analyzer.py
python3 tests/test_corpus_profile.py
bash tests/test_java_agent.sh
python3 -m py_compile helpers/*.py tests/*.py
```

Native 相关测试需在具备 Linux 构建依赖的主机上执行：

```bash
bash tests/test_native_scanner.sh
bash tests/test_native_runtime.sh
bash tests/test_native_cache.sh
bash tests/test_native_memory_safety.sh
```

## 文档

- [文档索引](docs/README.md)
- [能力矩阵](docs/CAPABILITY-MATRIX.md)
- [安全审计](docs/SECURITY-AUDIT.md)
- [性能记录](docs/PERFORMANCE.md)
- [测试结果](docs/TEST-RESULTS.md)
- [RAT 检测设计](docs/RAT-DETECTION-DESIGN.md)
- [Web 恶意行为检测设计](docs/WEB-MALWARE-DETECTION-DESIGN.md)

## 安全边界

- helper 只读字节、Mock 或 JSON 事件，不执行、import、attach、解密执行或加载未知样本。
- 不抓包，不主动 DNS，不发起 HTTP，不上传文件、哈希、日志、内存或状态。
- 不杀进程、删文件、修改业务配置或安装 auditd/Falco/YARA/bpftool。
- “未发现”仅表示在当前权限、数据源、扫描范围和时间窗口内没有形成规则证据，不代表确认主机绝对安全。
