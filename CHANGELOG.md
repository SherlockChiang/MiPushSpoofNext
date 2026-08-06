# Changelog

## 0.1.0 - 2026-08-05

- 首个纯 Zygisk MVP。
- 按包/子进程精确 allow/deny 与内置安全排除。
- root companion 配置快照，支持 String/primitive/handle SystemProperties JNI。
- 可配置安全 Build 字符串字段。
- MIUI 14、HyperOS 1 与历史 Riru 兼容 profile。
- APK MiPush 标记扫描、CLI、观察模式与扫描日志。
- 四 ABI、16 KiB 最大页对齐、CI、静态校验和精确 ZIP/源码验证。
- BusyBox standalone CLI、失败保留 last-known-good 扫描规则、许可证随包交付和对应源码包。
- FastNative 观察记录改为无锁队列，companion IPC 增加截止时间与协议边界校验。
- 默认扫描改用 PackageManager 组件标记快速预筛选；深扫显式启用并受 APK 大小上限约束，
  修复 dexlist/ZIP 失败误报、重启后 PID 复用锁和跨目录 SELinux 标签问题。
- 在 Sony XQ-CQ72 / Android 16 / KernelSU + ReZygisk 515 上完成首轮 MiPush/XMSF 冒烟。
