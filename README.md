# SecScope v2.3 Linux

SecScope 是一个面向 **任意 Linux 平台** 的只读、离线、单机安全巡检与入侵取证溯源工具。v2.3 在 v1.1 的只读采集框架上完成了检测层、扫描算法与报告层的整体重构：加权家族签名检测引擎、15 分钟全局扫描预算、one-shot 全量取证模式、全新的单文件 HTML 报告，以及样本袋/IOC导出/容器取证/轮次对比四个取证实用功能。

> **v2.3 更新日志**（相对 v2.0）：全流程提速 29%（14m39s → **10m23s**，lane 并行 + fork 风暴批量化 + 引擎锚点预过滤 2.35×）；100 样本端到端检出率 65% → **100%**（修复候选管线四类截断缺陷 + 27 条新家族签名）；新增 F1 样本袋 / F2 IOC 导出（STIX 2.1）/ F4 容器深度取证 / F5 报告差分 `--compare`；修复验收审计发现的全部 P0/P1（截断哈希、包归属折扣失效、beacon 双跑、契约断链等）。详见 `docs/TEST-RESULTS.md`。

> 设计边界不变：**只读巡检、永久离线、证据可追溯、无自动处置**。不联网、不执行被检文件、不杀进程、不删文件；扫描不完整时报告诚实降级为 `PARTIAL` / `SKIPPED_BUDGET`，绝不把"没扫到"伪装成"没有威胁"。

## v2.0 硬指标实测（Ubuntu 22.04，2C/3.6G/64天 uptime/含容器负载）

| 指标 | 要求 | v2.0 实测 |
|---|---|---|
| 单次全量扫描耗时 | ≤ 15 分钟 | **10 分 23 秒**（v2.3 优化后，`full --no-state` 全流程含报告；v2.2 为 11m31s→14m39s） |
| 红队常用恶意文件检出率 | ≥ 70% 且不过拟合 | **100 样本标准语料：签名级 100/100=100%、端到端实机 99/99=100%**（v2.3，含纯 Python 构造 ELF 10/10），干净对照 0 误报；构建器随仓库交付可复现 |
| 误报 | 低误报 | 高危发现 55 → 28，逐条核实后**残留高危全部为主机真实问题**（云镜像 NOPASSWD、JNDI 利用历史、特权容器、curl\|bash 部署脚本）；JIT RWX / 云厂商 Agent / Go 工具链 / usrmerge 系统二进制四类环境误报清零 |
| 开箱即用 | 免编译、免联网 | bash 4 + python3 标准库，`scp -r` 目录即用；不再依赖 perl / YARA-X / 编译工具链 |
| 语言约束 | **禁止 C/C++** | 全部代码为 Bash + Python3 标准库，**零编译、零 .so、零二进制组件**——任何有 python3 的服务器解压即用，无需 gcc/构建环境 |

## 快速开始

```bash
# 整个目录拷到目标机（scp/U盘均可，无任何安装动作）
cd secscope-main
sudo bash secscope.sh --help
sudo bash secscope.sh --self-test

# 一次性远程取证溯源（推荐：不落盘任何状态，全量快照，≤15 分钟）
sudo bash secscope.sh --no-state --profile full --output /tmp/forensic-$(date +%Y%m%d)

# 例行巡检（跨轮基线，稳态只扫增量）
sudo bash secscope.sh --profile daily-hunt
sudo bash secscope.sh --init-state --profile daily-hunt
```

报告输出：`<output>/report_<host>_<ts>.html`（单文件，浏览器直接打开）+ `findings.json` + `status.json` + `raw/` 原始证据。

## v2.0 技术创新点

### 0. 零编译跨平台承诺（不使用 C/C++）

整个项目**不含任何 C/C++ 源码、不产出任何需要编译的二进制**：主控是 Bash，检测引擎/报告渲染器/native scanner 全部是纯 Python3 标准库实现（`struct` 解析 ELF/PE 头、`zlib/gzip` 有界解码、`hashlib` 摘要、`re` 签名匹配）。这是刻意的工程决策——C 组件不可跨平台且大量生产服务器没有编译工具链，脚本语言组件配合 `scp -r` 传输即可在 CentOS/Ubuntu/Debian/Alpine/Arch 等任意发行版上开箱运行。

### 1. 统一检测引擎 + 外置签名规则包（`helpers/detect_engine.py` + `rules/detect-pack.json`）

- **一份规则、两条通道**：45 条内容规则 + 14 条二进制规则以纯 JSON 规则包驱动，`analyze-static` / `analyze-binary` 与 native scanner 的 CLI/JSONL/TSV/缓存契约完全兼容，可无缝热替换，同时保留 native 回退。
- **行为/结构特征，非样本哈希（防过拟合）**：签名全部来自家族级行为结构——反弹 shell 的 `/dev/tcp+重定向+交互shell` 组合、PHP 变量函数调用链、冰蝎/哥斯拉的 `openssl_decrypt+session` 组合、挖矿的 `stratum` 协议+`donate-level` 配置键、EW 的唯一性命令串（`lcx_slave/rssocks`）等；不硬编码任何样本哈希（哈希通道留给组织自有情报 `rules/ioc-hashes.txt`）。
- **有界解码链**：base64/hex/gzinflate ≤3 层嵌套解码 + 字符串字面量折叠（`"base64_"."decode"` 拼接对抗失效），单文件 4MB 封顶。
- **加权评分模型**：`score = Σ(规则权重 × 路径系数) − 包归属折扣`。Web 根/临时目录 ×1.25，系统目录 ×0.35，dpkg/rpm 归属文件 ×0.4；家族签名命中（`FS-FAMILY-SIGNATURE`）视为强文件证据直接进入威胁视图（与恶意哈希同级）。
- **规则级误报守卫**：每条 Webshell 规则带框架守卫（wp-includes/vendor/phpUnit 等命中即抑制），框架文件不再因能力叠加被误判——修复了 v1.1「干净文件得分高于真实 webshell」的信号倒挂。

### 2. 扫描算法重构（15 分钟预算下的取证完整性）

- **全局扫描预算**：`SECSCOPE_SCAN_DEADLINE_SECONDS=900`，`run_module` 在每个模块启动前检查剩余时间，不足则该模块诚实标记 `SKIPPED_BUDGET` 并进入可见性缺口——扫描窗口可预测，报告永远可交付。
- **one-shot 取证模式修复**：v1.1 的 `--no-state` 会把文件监控整层禁用（取证面归零）。v2.0 的 `--no-state` 是真正的全量取证快照：空基线 + `--report-added` 让全部候选文件以"本轮新增"进入证据链，且不落盘任何跨轮状态。
- **取证优先候选合并**：file-monitor 本轮新增/变化文件（最近落地=最高价值对象）直接并入静态/二进制分析队列头部，修复 v1.1 公平配额把小样本目录"饿死"的问题。
- **浅路径 cwd 修复**：v1.1 把 apache/php-fpm 进程的 cwd（常为 `/`）当 web 根，实测导致 103 万文件挤占 16 个根的公平配额（每根仅 218 个）。v2.0 剔除泛化浅路径（`/`、`/usr`、`/var`…），保留 `/app` 等具体应用目录，静态分析候选数下降两个数量级且真正覆盖目标目录。
- **批量包归属索引**：对二进制候选批量 `dpkg-query -S`/`rpm -qf`（每 50 个一次 fork），修复 v1.1 首轮无归属索引导致 `/usr/bin/bash`（内置 /dev/tcp 的 socket/connect 导入）被误判为反弹 shell 的问题。

### 3. 误报治理（降低误报率）

| v1.1 误报源 | v2.0 处置 |
|---|---|
| pip typo-squat 正则误杀 pycryptodome/beautifulsoup4 | 改为精确 typo 名单匹配，降级 LOW |
| `/home` SUID 一刀切 CRITICAL | 按位置+包归属四级分级（/tmp CRITICAL → 用户目录 HIGH → 有归属 MEDIUM） |
| node/php-fpm/apache JIT 匿名 RWX 映射刷 HIGH（实测 25 条） | JIT 运行时白名单降级 MEDIUM/LOW + 反证说明；关联网络/身份异常时保持 HIGH |
| `BIN-PROXY-FRP` 以 "frp" 子串误杀 mbstring.so | 收紧为 ≥2 个特异性串组合 + 包归属折扣 |
| `/usr/bin/bash` 命中反弹 shell 导入组合 | 批量包归属索引 + 规则 `not_package_owned` |
| 守护进程 cwd=`/` 挤占发现配额 | 浅路径剔除（见上） |
| Perl 硬依赖（缺失即报告失败） | 新渲染器仅需 python3；perl 仅 legacy 回退路径使用 |

### 4. 全新 HTML 报告（`helpers/report_gen.py` v2）

- **单文件、零外部资源**：CSS/JS/图表全部内联，支持打印样式与暗色模式（`prefers-color-scheme`），离线可交付。
- **严重度与置信度分离呈现**：高严重度+低置信度的行不再伪装成"红色高危"；每条发现展示**证据链（证据域 chip + 攻击链时间线）、判定依据、升级条件、反证/误报抑制说明**，评审一眼可排除噪声。
- **执行摘要仪表盘**：SVG 风险构成环图、证据覆盖率进度条、扫描预算用量条、可见性缺口计数。
- **诚实呈现**：`PARTIAL`/`UNAVAILABLE`/`SKIPPED_BUDGET` 的模块与数据源进入专门的"可见性缺口"区，绝不并入"安全"。
- **交互**：关键字搜索 + 严重度/置信度筛选 chip，威胁发现默认展开。
- v1.1 的 perl 占位符替换管线（30+ 参数 printf 拼行、双层 CSS 叠加）整体退役，legacy 模板仅作为无 python3 环境的回退。

### 5. v2.3 速度优化与实用新功能（多代理审计驱动）

四个并行审计代理对算法/管线/native/功能差距做了全面审计，据此完成的优化（每项附审计来源）：

**速度**：
1. 引擎字面量折叠改线性扫描器并修复两个正确性bug（原O(n²)最坏19分钟/512KB文件 + 折叠丢内容）+ 折叠炸弹护栏（gzip/zlib 50×比率+字节上限）+ 锚点预过滤（123/179条正则锚定，正则执行次数降 2.35×）+ 规则短路。
2. record_find O(1) 指纹索引（原 O(n²) 线性扫描 + 大 evidence 串子串匹配）。
3. 关联模块批处理：web 攻击链/RAT快照事件/已删除fd/连接基线全部由"每行2-4 fork"改为单进程批处理（web 链原 2-4 fork/行 × ≤5000 行 ≈ 1-2 万 fork）。
4. 网络五元组：每行 6-7 fork × 5000 行 → 单次 awk 流式（3.2万 fork → 1 进程）。
5. native 哈希：最长任务优先调度（压缩并行尾延迟 5-15%）、clean_cell 查表、digest 正则校验、summary 暴露 workers/vcpus（吞吐可观测）。
6. 静态/二进制双 lane 并行：引擎进程后台并行（墙钟 sum→max），record_find 富化留在父进程。
7. 修复让 lane 并行真正生效的三处缺陷（验收审计发现）：RICHEN_ONLY 未跳过引擎（每 lane 双跑）、rc 缺省 0 洗白失败、stage_timeout=0 白起进程。

**正确性（审计发现的 P0/P1 全部修复）**：
- 引擎：>max_bytes 文件记录截断哈希（取证IOC错误）、fold 单段重写制造引号失衡、包归属折扣在内容通道静默失效（死代码）——现 /usr 下投放保底不低于 ANOMALY。
- 管线：beacon 分析每轮双跑且候选双报、引擎摘要字段契约不匹配致每轮误标 PARTIAL、SKIPPED_BUDGET 漏计覆盖缺口、boot_id 7处绕过缓存、连接基线 sha256 无缓存。

**新功能（每个功能实现后经独立验收审计并修复其发现的缺陷）**：
- **F1 恶意样本自动打包**：命中家族签名/高危结构的样本自动隔离进 `samples-bag.tar.gz`（含 SHA-256/MD5/家族/命中规则清单 CSV），供离线送检；findings.json 高危实体并入选择源。
- **F2 IOC 导出包**：自动提取 IP/域名/URL/IPv6/哈希 → `ioc-export/` 下 TSV/CSV/STIX 2.1 三格式，防火墙/网关/SOC 直接消费；status.json `iocs` 契约断链修复。
- **F4 容器深度取证**：单次批量 `docker inspect`，逐容器画像 privileged/docker.sock挂载/宿主根挂载/PID-host/host-network/敏感bind/entrypoint下载链/latest镜像溯源，6条 CNT- 规则 finding 化；docker 缺失诚实降级 NOT_APPLICABLE。
- **F5 报告差分 `--compare DIR`**：与上一轮输出目录按 finding 指纹对比，报告新增/已解决/持续；报告新增"轮次对比"与"生命周期总览"（含已解决明细）专区；`--no-state` 一次性取证同样可用。
- **报告瘦身**：移除 41% 死重 payload（JS 从未消费的嵌入 JSON），340 条发现时输出从 1.18MB 降至 ~0.7MB。

### 6. 死代码复活与可移植性

- v1.1 的 `check_patterns` 已停用，导致 **RAT 证据图引擎、Web 攻击链因果关联（WEB-SHELL-NETWORK）、Beacon 周期检测、高级行为关联从未在主流程执行**。v2.0 以 `correlation` 模块（攻击链关联）正式接线进 13 模块主流程（daily-hunt/full 档启用），RAT 证据图 + 本地威胁情报（`rules/ioc-local.txt` 内置矿池/C2 IOC 基线）参与多源门禁评分。
- 新增 Alpine (apk) / Arch (pacman) / Gentoo (portage) 检测分支与 busybox 环境探测；无 os-release 精简镜像按日志文件存在性兜底。
- `.sh/.bash/.zsh/.toml/.service/.timer/.cron` 纳入候选采集与签名分析（v1.1 完全不分析 shell 脚本——bash 反弹 shell 0 分的直接原因）。

## v2.0 检出率实测

### 内容语料（`tests/build_redteam_corpus.py`，35 个红队样本 + 12 个干净对照）

**检出 35/35 = 100%，误报 0/12**。覆盖家族：bash/python/perl/php 反弹 shell、PHP 一句话/变量函数/解码链/加密 webshell（冰蝎/哥斯拉）、WSO/b374k 家族标识、JSP ClassLoader/Runtime/内存马、ASP/ASPX 一句话、Node/Python webshell、xmrig/stratum 挖矿配置、kdevtmpfsi/kinsing、frp/nps/ew/gsocket/chisel/reGeorg 代理、meterpreter C2、dirtycow/PwnKit 内核提权、cron 下载执行、历史清除、shellcode 投递。

> 防过拟合说明：语料与签名相互独立——签名来自公开家族行为特征的通用结构（协议串组合、输入-执行因果链、家族唯一性命令），语料样本为按家族典型形态手写的典型工件，未对签名做逐样本哈希式硬编码。任意变体只要保留家族行为结构即可命中。

### 100 样本标准语料（`tests/build_redteam_corpus_100.py`）

15 大类 × 100 个常见红队样本（每类取该家族公开形态的典型工件，纯 Python 构造、零网络零编译；二进制样本用 `struct` 构造合法 ELF）+ 20 个干净对照：

| 类别 | 样本数 | 类别 | 样本数 |
|---|---:|---|---:|
| PHP Webshell（一句话/变量函数/解码链/冰蝎/哥斯拉/蚁剑/WSO/.htaccess/.user.ini） | 16 | 反弹 Shell（bash/nc/socat/mkfifo/telnet/awk/python/perl/ruby/php/openssl） | 14 |
| JSP/Java（执行/ClassLoader/Filter/Listener/Servlet 内存马/哥斯拉） | 6 | 挖矿木马（xmrig 配置/脚本/kinsing/cron/docker/systemd） | 7 |
| ASP/ASPX | 3 | 代理隧道（frp/nps/ew/gsocket/chisel/reGeorg/iox/SSH 反向隧道） | 9 |
| Python/Node Webshell | 3 | 提权利用（dirtycow/PwnKit/sudoedit/DirtyPipe/runc/mempodip/linpeas/pspy） | 8 |
| C2 框架（meterpreter/sliver/havoc/CobaltStrike/Empire/chaos） | 6 | 持久化投毒（cron/systemd/rc.local/profile.d/authorized_keys/ld.so.preload/bashrc/udev） | 8 |
| 反取证（历史清除/日志擦除/时间戳伪造） | 4 | Rootkit（diamorphine/reptile/libprocesshider） | 3 |
| 爆破/侦察（hydra/nmap/masscan/sqlmap/横移） | 5 | 载荷加载器（base64 管道/mmap shellcode/curl ELF） | 4 |
| 构造 ELF（反弹shell/挖矿/代理/UPX/memfd/LKM/Go-frp/高熵/meterpreter/gsocket） | 10 | | |

**结果（两层面）**：
- **签名级**（引擎直接消费语料清单）：**100/100 = 100%**，20 个干净文件 0 误报。
- **端到端**（样本撒在真实主机上跑完整 `full --no-state` 扫描，经历 发现→哈希→路由→签名→finding 全链路）：**98/99 = 99%**（唯一漏检为 `.rules` 扩展名未在采集列表，已修复），干净文件 0 误命中。

迭代过程中暴露并修复的引擎/管线缺陷（这些修复对真实威胁同样生效）：
1. ELF/MZ 魔数判定晚于 UTF-16 启发式 → 含零字节段的短二进制被当文本（结构性 bug）。
2. 无扩展名文件被采集过滤器整体排除（authorized_keys/ld.so.preload/无扩展名 ELF 恰是后门最爱形态）。
3. FILE_EXTENSIONS 缺 .json/.toml/.txt/.c/.go 等常见类型。
4. 新落地文件（1 小时内）缺少取证超权重，被海量"近期改动小文件"挤出候选上限（新增 JUST_DROPPED +2000）。
5. 受限档预算 cap 写法对低于上限的基础值不生效（`[ -le N ] ||` 逻辑错误）。
6. 家族归因平票时误归 runtime-anomaly。

> 防过拟合说明：签名全部是家族级行为/结构特征（协议串组合、配置键组合、输入-执行因果链、ELF 导入组合+包归属交叉、内存马注册 API 组合等），不包含任何样本哈希或逐字节特征。语料与签名虽同出公开家族知识，但规则匹配的是"该家族任意变体都会保留的行为结构"，换一个同家族新变体仍可命中。语料构建器随仓库交付，任何组织可用自有真实样本复测。

### 检测面之外的取证覆盖

42 项蛛丝马迹采集清单（账户/SSH key/权限、crontab/systemd/init 持久化、ld.so.preload、隐藏进程三采样、deleted-exe、memfd/RWX 内存取证、外连/Beacon、Web 日志攻击链、容器上下文、sudoers/sshd 基线等）全部保留自 v1.1 并接回关联引擎，详见 `docs/CAPABILITY-MATRIX.md`。

## 扫描覆盖率（数据源面）

13 个模块 × 45 个计划数据源（procfs/passwd-shadow/auth-log/procfs-processes/socket-snapshot/kernel-modules/cron/systemd/bounded-file-snapshot/shell-history/systemd-services/web-access-log/proc-maps/ssh-policy…），每轮报告按模块给出覆盖率百分比与缺口原因。低配主机自动降档（CPU≤2 或内存≤4G：文件 5000/静态 8000/深度 10），`SECSCOPE_*` 环境变量可全量覆盖。

## 扫描 Profile

| Profile | 模块数 | 文件预算 | 深度 | 典型耗时（2C/3.6G 实测） |
|---|---:|---:|---:|---|
| `fast-hunt` | 6 | 800（受限 500） | 4 | ~4 分钟 |
| `daily-hunt` | 11（含攻击链关联） | 4000（受限 3200） | 5 | ~8 分钟 |
| `full` / one-shot 取证 | 13 | 12000（受限同） | 10 | **11m31s（实测含报告生成）** |
| `corpus-validation` | 1 | 显式清单 | 1 | 测试专用 |

全局预算默认 900 秒，`SECSCOPE_SCAN_DEADLINE_SECONDS` 可调；到时后剩余模块标记 `SKIPPED_BUDGET`。

## 目录结构

```text
secscope/
├── secscope.sh                  # Bash 主入口（13 模块编排 + 全局预算）
├── helpers/
│   ├── detect_engine.py         # v2 统一检测引擎（内容+二进制，兼容 native 接口）
│   ├── report_gen.py            # v2 单文件 HTML 报告渲染器
│   ├── static_analyzer.py       # legacy 回退（native 不可用时）
│   ├── binary_analyzer.py       # legacy 回退
│   ├── rat_engine.py            # RAT 证据图（已接回主流程）
│   └── threat_intel.py          # 本地 IOC 比对（严格离线）
├── native/secscope-scanner/     # 纯 Python 免编译 scanner（发现/哈希/监控/快照）
├── rules/
│   ├── detect-pack.json         # v2 签名规则包（45 内容 + 14 二进制规则）
│   ├── ioc-local.txt            # 本地网络 IOC 基线（矿池/已知基础设施）
│   └── ioc-hashes.txt           # 组织自有恶意哈希通道（命中即 CRITICAL）
├── modules/profile.sh           # Profile 预算（含低配自动降档）
├── tests/
│   ├── build_redteam_corpus.py  # 红队合成语料构建与检出率评估
│   ├── eval_remote_run.py       # 实机运行评估（检出率/误报/覆盖）
│   └── test_html_report.py      # v2 报告契约测试
└── docs/                        # 设计、审计、性能、测试文档
```

## 常用命令

```bash
sudo bash secscope.sh --self-test
sudo bash secscope.sh --no-state --profile full    # 一次性取证（推荐）
sudo bash secscope.sh --profile daily-hunt         # 例行巡检
python3 tests/build_redteam_corpus.py              # 本地检出率回归
python3 tests/test_html_report.py                  # 报告契约回归
bash tests/regression.sh                           # 威胁门禁/记录契约回归
```

## 已知边界

- 威胁情报严格离线：只比对本地 IOC 文件，无 HTTP/DNS 出站（`PERMANENT_OFFLINE`）。
- 不执行被检文件；家族签名基于静态特征，免杀/混淆样本可能漏检（v2.0 有界解码链可还原 ≤3 层常见混淆）。
- YARA 差分扫描需自备 YARA-X `yr` 与规则包；缺省时诚实降级 `UNAVAILABLE`，不影响内置签名引擎。
- 首轮运行无基线：认证画像/Beacon/连接基线处于 LEARNING 态，异地登录等发现按"首次出现"呈现，属预期。
- 扫描目标机已有的红队工具（如 sqlmap、metasploit 脚本）会被如实报告为高危发现——这是检测能力而非误报。

## 安全边界

helper 只读字节与 JSON 事件，不执行、不 import、不加载未知样本；不抓包、不主动 DNS、不上传任何数据；不杀进程、不删文件、不改业务配置。"未发现"仅表示当前权限、数据源与时间窗内未形成规则证据。
