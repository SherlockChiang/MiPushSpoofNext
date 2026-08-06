# Changelog

## 0.1.1 - 2026-08-06

- Action 按钮新增音量键应用管理：自动、始终启用、始终禁用三态，并可选择立即强停应用使设置生效。
- KernelSU/APatch 模块 WebUI 新增图形化扫描、筛选、手动添加和三态开关。
- 新增事务化 `app` / `app-status` 命令；整包切换会清理冲突的包级与子进程手工规则。
- `enable` / `disable` / `auto` 成为清晰的精确规则命令，保留 `add` / `deny` / `remove` 兼容别名。
- `list` 改为带状态标签的可读输出，内置保护包会拒绝通过整包入口修改。
- 增加标准 `updateJson`，从 GitHub Release 获取版本 ZIP 与更新说明。
- 推送版本标签时，GitHub Actions 自动创建或更新 Release 并上传已验证的安装包/源码包。

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
