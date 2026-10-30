# SecScope directory layout

顶层只保留入口和主要目录；零散文件已按用途归类。

- `README.md`: 项目说明。
- `secscope.sh`: 主程序入口。
- `install.sh`: 安装入口。
- `secscope.sh.sha256`: 主程序完整性校验。
- `config/examples/`: 示例配置和 allowlist 示例。
- `systemd/`: systemd service/timer unit 文件。
- `packaging/`: 发行包构建脚本。
- `scripts/`: 本地维护脚本。
- `modules/`: `secscope.sh` 加载的 Shell 模块。
- `helpers/`: Python 辅助分析器。
- `native/`: 纯 Python native scanner/cache（免编译，仅标准库）。
- `rules/`: 规则和 IOC 数据。
- `tests/`: 测试集。
- `docs/`: 设计、审计和测试文档。
- `dist/`: 当前 installer 发行物。
- `prebuilt/`: 已校验的预编译交付包。
- `archive/`: 旧产物、历史工作记录和整理快照。
- `reports/`: 运行报告占位目录。

为兼容旧脚本，根目录保留了若干符号链接指向 `config/examples/`、`systemd/` 和 `packaging/`。
