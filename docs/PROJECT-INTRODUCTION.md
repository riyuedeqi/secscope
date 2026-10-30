# SecScope 项目介绍

SecScope 是面向 Linux 主机的离线安全巡检与威胁狩猎工具，定位于应急响应、客户现场检查、内网主机基线复核和 Web 服务器入侵排查。

## 一句话介绍

SecScope 在不联网、不执行样本、不修改业务配置的前提下，采集 Linux 主机上的文件变化、进程、网络连接、内存映射、持久化、Web 日志和本地 IOC 证据，并生成结构化报告。

## 核心能力

1. **文件变化监控**：识别新增、修改、移动、删除文件，并结合 mtime、inode、hash、路径和运行时引用做关联。
2. **进程与网络关联**：采集进程上下文、socket、运行中 executable、maps、FD 和命令行，定位临时目录执行、deleted mapping、memfd、异常外连等现象。
3. **Web 入侵线索**：归一化 Nginx、Apache、OpenResty、Caddy、Tomcat 等访问日志，保留失败行哈希和可见性状态。
4. **WebShell/RAT 候选**：使用静态启发式、二进制结构解析、IOC 和跨轮连接画像建立同实体证据图。
5. **持久化检查**：覆盖 cron、systemd、rc.local、profile、LD_PRELOAD、authorized_keys 等 Linux 常见持久化入口。
6. **离线报告**：输出 HTML、JSON、TSV、JSONL 和 SHA-256 清单，便于审计、归档和交付。

## 技术架构

- `secscope.sh`：Bash 主控流程、权限、状态、报告和模块调度。
- `modules/`：Profile 扫描档位与预算策略。
- `helpers/`：Python/Java 辅助分析器，用于静态分析、二进制分析、RAT 关联、威胁情报和报告处理。
- `native/`：纯 Python scanner/cache（免编译），用于候选发现、哈希、文件监控、runtime snapshot 和本地缓存。
- `rules/`：本地 IOC 与允许列表。
- `tests/`：回归、契约、安全边界和 Native 相关测试。

## 设计边界

- 不主动联网，不做云端情报查询。
- 不执行被检测文件，不加载未知二进制。
- 不自动杀进程、删文件或改配置。
- 不把缺失数据源或无命中解释为主机安全。

## 推荐交付方式

- 源码协作：使用 GitHub 仓库。
- 客户现场离线交付：使用 `packaging/` 生成发行包；Native 组件为纯 Python，目标主机无需编译。
- 证据交付：使用扫描输出目录中的 HTML、`findings.json`、`status.json` 和 `raw/`，必要时先脱敏。
