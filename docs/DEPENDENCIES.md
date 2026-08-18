# SecScope 依赖清单

本项目是 Linux Bash/Python/C++17 工具。依赖分为 Python 标准库、Native 源码构建依赖和可选数据源；可选数据源缺失时，SecScope 会报告 `UNAVAILABLE`、`PARTIAL` 或 `NOT_APPLICABLE`，不会伪造安全结论。

## 清单文件

- `requirements.txt`：Python 运行时和测试依赖。当前仅使用标准库，文件有意不包含第三方 pip 包。
- `requirements-native-ubuntu-24.04.txt`：Ubuntu 24.04 源码构建和完整测试所需的 apt 包名。

## Python 环境

- 最低支持：Python 3.8。
- 已验证基线：Python 3.12.3。
- 运行时和测试代码只导入标准库；不需要联网执行 `pip install`。

可以用以下命令验证 Python 层：

```bash
python3 tests/test_dependency_manifest.py
python3 -m py_compile helpers/*.py tests/*.py
```

## Native 和系统环境

`requirements-native-ubuntu-24.04.txt` 覆盖 Bash 主入口、Python helper、Make/CMake 构建、Native scanner/cache 以及 Linux 专项测试。安装命令：

```bash
sudo apt-get update
grep -Ev '^[[:space:]]*(#|$)' requirements-native-ubuntu-24.04.txt | xargs sudo apt-get install --no-install-recommends
```

Native scanner 使用 OpenSSL、zlib、libarchive 和 nlohmann-json；Make 和 CMake 两条构建路径都使用 C++17。CMake 路径要求 CMake 3.16 或更高版本，Make 路径只要求 GNU Make。

## 已验证基线

| 组件 | 版本 |
| --- | --- |
| OS | Ubuntu 24.04.3 LTS |
| Bash | 5.2.21 |
| Python | 3.12.3 |
| GCC/G++ | 13.3.0 |
| GNU Make | 4.3 |
| pkg-config | 1.8.1 |
| OpenSSL | 3.0.13 |
| zlib development package | 1.3 |
| libarchive development package | 3.7.2 |
| nlohmann-json development package | 3.11.3 |

当前验证环境已完成 Make 构建；若使用 CMake，请确保本机安装 CMake 3.16+。版本号随 Ubuntu 安全更新可能变化，精确重现需要固定 apt 仓库快照。

## 可选数据源

以下工具不是核心安装依赖，仅在启用相应采集能力时使用：

- `yr` 或 `yara`：YARA 扫描。
- `auditd`：audit 事件。
- `falco`：运行时事件。
- `bpftool`：eBPF/内核可见性。
- `jcmd`：Java 运行时只读辅助信息。
- `jq`、`sqlite3`、`strace`：诊断、基准或便利工具。

## 复现步骤

```bash
python3 tests/test_dependency_manifest.py
make -C native/secscope-scanner -j2
make -C native/secscope-cache -j2
bash tests/test_native_scanner.sh
bash tests/test_native_cache.sh
bash tests/test_process_control.sh
```
