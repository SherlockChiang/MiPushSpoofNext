# Changelog

## 0.1.2 - 2026-11-04

- 新增 `package_modes.conf` 包级能力模式：`inherit`、`full`、`properties`、`build`、`observe`、
  `excluded`，以及 `mipushctl mode <规则> [模式] [--apply]`。模式只决定选中后的能力，不会单独
  选中包；`excluded` 与未知模式值都会排除进程。
- WebUI 每个应用新增“伪装模式”按钮，点按后从底部弹出带说明的模式面板；“跟随全局”直接显示
  当前等效模式（如“完整伪装”），加固应用显示标签并在“仅 Build”上标注推荐，被排除的已启用应用
  标注“不注入”。`mipushctl apps` 增加模式、加固类型和进程级模式数三列，新增
  `mipushctl inherit-mode` 输出 options.conf 下“跟随全局”的等效模式。
- companion 为每个进程输出最终策略日志（`policy ... mode= reason= source=`），区分内置 deny、
  显式 deny、无 allow、模式排除、手工 allow 与自动 allow。
- `SystemProperties` 改为逐签名挂钩，清理 provider 遗留的 JNI 异常，记录每个签名的结果，并防止
  原函数未知时自递归；每进程只安装一次。
- 没有任何 JNI hook 生效（例如 `build` 模式）时在 specialize 后卸载模块库。
- Build 日志增加 applied/missing/failed 计数。
- 扫描器记录发现原因、人工规则与模式下的最终动作，并在 `scan.log` 和输出中标注 360 加固、
  乐固、梆梆、爱加密、百度加固等商用壳（仅提示，不改变策略）。
- 记录 Android 17 上起点读书（360 加固）注入后被杀的问题与 A/B 结果：任何 `SystemProperties`
  hook 都会触发加固杀进程，`build` 模式可正常启动并连接 XMSF；扫描提示优先建议 `build`。

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
