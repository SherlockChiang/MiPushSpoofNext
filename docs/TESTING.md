# 测试清单

## 构建期

- `scripts/lint_project.py`：profile namespace、长度/数量限制、Build 白名单、LF/BOM、模块元数据，
  以及 `module.prop` / `update.json` / GitHub Release 文件名的一致性。
- `tests/test_rule_model.py`：规则/data-dir 语义、内置 deny、primitive 解析、synthetic handle
  fallback 与默认 profile 安全面的行为规格模型。它不直接加载 Android C++ 模块；NDK 编译、
  静态分析和实机冒烟仍分别承担实现级验证。
- NDK r27d 四 ABI 编译，链接器设置 `max-page-size=16384`。
- `scripts/verify_zip.py`：精确安装文件清单、源码/生成 so 逐字节一致、路径安全、CRC、ELF
  magic/class/machine、16 KiB 对齐、Zygisk 导出入口和 native 依赖。
- 默认扫描先查询 PackageManager 组件标记；`scan_deep=true` 才启用 dexlist 与压缩 dex
  回退。扫描结果在状态目录内创建新 inode 后原子替换，避免跨目录 rename 的标签问题。

## 实机冒烟

1. 确认 XMSF/MiPushFramework 单独可启动且获得必要权限。
2. 安装模块、启用 Zygisk、重启。
3. `mipushctl scan`，人工审核候选。
4. 分别执行 `mipushctl app <包名> disable`、`enable`、`auto`，确认 `app-status` 输出依次为
   `disabled`、`enabled`、`auto-enabled`（扫描命中时），且旧包级/子进程冲突规则被清理。
   再通过 Action 按钮验证音量键循环状态、确认以及“立即应用”强停提示。
5. 在 KernelSU/APatch 管理器打开 WebUI：点击扫描、筛选包名、切换自动/启用/禁用、手动
   添加包名，并验证“立即停止应用”复选框；关闭 WebUI 后重新打开，状态应保持。
6. 打开观察模式，清空日志并强停目标 app：

   ```sh
   su -c '/data/adb/modules/mipush-spoof-next/bin/mipushctl observe on'
   adb logcat -c
   adb shell am force-stop com.example.app
   adb shell monkey -p com.example.app 1
   adb logcat -d -s MiPushSpoofNext
   ```

7. 日志应包含 `target selected`、至少一个兼容的 String property hook、`Build profile applied`；
   不应有 JNI exception 或 crash。
8. 在 XMSF 管理端确认 app 注册，发送测试消息，分别验证前台、后台、强停前后的行为。
9. 关闭模块并重启，确认目标 app 行为恢复，排除 XMSF/ROM 自身问题。

发布前还应确认 `update.json` 的 `versionCode` 高于上一版本，`zipUrl` 对应的 GitHub Release
附件已经存在，并对下载文件重新计算 SHA-256；不要先公开会指向尚不存在附件的更新元数据。

## 已完成的设备冒烟

2026-08-06：Sony XQ-CQ72，Android 16/API 36，4 KiB 页，KernelSU + ReZygisk 515，
arm64/arm32，XMSF `0.3.11-366-g40ba88c`。

- 默认快速扫描约 7 秒完成，识别 `com.autonavi.minimap`、`com.coolapk.market`、
  `com.netease.cloudmusic`、`com.qidian.QDReader`、`com.sankuai.meituan`、
  `com.tencent.mobileqq`、`tv.danmaku.bili`；18 个无组件标记的包以
  `package_fast_scan_no_marker` 记录为跳过。
- 手工 allow 的 Coolapk 与 Qidian 均命中；Qidian 主进程和 `:pushcore` 均完成注入，日志
  命中 String/int/long/boolean/handle hooks、Build profile 及 `ro.miui.ui.version.name/code`。
- XMSF 日志出现 `com.xiaomi.mipush.SEND_MESSAGE`、`SECMSG` 收发和
  `normal_client_config_update`；未观察到 FATAL EXCEPTION、ANR 或模块错误。

这只是单设备冒烟，不替代不同 ROM、页大小、Zygisk provider 和 MiPush SDK 的兼容矩阵。

## 兼容矩阵建议

记录以下维度：Android 版本/页大小、ABI、root 管理器、Zygisk provider 与版本、XMSF 版本、目标
MiPush SDK 版本、主进程/推送子进程、MIUI14/HyperOS profile、DenyList 状态。

这是需要真实设备完成的验证；CI 和本仓库构建不能替代 MiPush 服务端注册与后台保活测试。
