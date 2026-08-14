# Java 深度模式 helper

该源码只用于显式授权的 JVM 启动时 `-javaagent` 模式，或由运维人员显式调用的 `agentmain` attach fallback。SecScope 默认不编译、不加载、不自动附加到目标 JVM，也不生成 Heap Dump。初始化或 transformer 异常会被隔离并输出 `PARTIAL` 或 `UNAVAILABLE`，不得解释为“未发现内存马”。

构建后 JAR 的 manifest 需包含：

```text
Premain-Class: secscope.runtime.SecScopeRuntimeInspector
Agent-Class: secscope.runtime.SecScopeRuntimeInspector
Can-Retransform-Classes: true
```

参数必须是已存在、本地、受保护目录下的 JSONL 输出文件路径。现有已加载类默认只记录元数据；为避免对业务 JVM 造成额外影响，helper 不主动对其执行 retransform。
