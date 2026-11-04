# 测试清单

## 构建期

- `scripts/lint_project.py`：profile namespace、长度/数量限制、Build 白名单、LF/BOM、模块元数据，
  以及 `module.prop` / `update.json` / GitHub Release 文件名的一致性。
- `tests/test_rule_model.py`：规则/data-dir 语义、内置 deny、primitive 解析、synthetic handle
  fallback 与默认 profile 安全面的行为规格模型；`PolicyModelTest` 覆盖最终策略原因（显式 deny
  覆盖自动命中、重扫不重新注入、邻近包名不误匹配、内置 deny 不可绕过）、`package_modes.conf`
  的范围优先级与能力 flags，并核对 `module.cpp` 的模式/原因表、`mipushctl` 与默认模式文件一致。
  它不直接加载 Android C++ 模块；NDK 编译、静态分析和实机冒烟仍分别承担实现级验证。
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
   添加包名，并验证“立即停止应用”复选框；关闭 WebUI 后重新打开，状态应保持。点按“伪装模式”
   从底部面板选择模式后，`mipushctl mode <包名>` 应输出同一模式，冷启动日志的
   `policy ... override=` 一致；取消、点遮罩或选当前模式都不应执行命令。“跟随全局”显示的等效模式
   应与 `mipushctl inherit-mode` 一致；加固应用显示标签，选“排除注入”的已启用应用显示“模式排除，不注入”。
6. 打开观察模式，清空日志并强停目标 app：

   ```sh
   su -c '/data/adb/modules/mipush-spoof-next/bin/mipushctl observe on'
   adb logcat -c
   adb shell am force-stop com.example.app
   adb shell monkey -p com.example.app 1
   adb logcat -d -s MiPushSpoofNext
   ```

7. 日志应先有 companion 的 `policy package=... reason=... mode=...`，再有 `target selected ... mode=`、
   `SystemProperties hooks ... installed=N/10` 与 `Build profile applied ... failed=0`；不应有
   `hook_failure`、JNI exception 或 crash。被排除的包只应出现 `policy ... mode=excluded`。
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

2026-11-03：同一 Sony XQ-CQ72 升级到 Android 17/API 37，模块 `v0.1.1`，起点读书
`com.qidian.QDReader` 7.9.482（`assets/libjiagu*.so`、`lib/*/libjiagu_vip.so`，360 加固）。

- 注入后日志依次出现 `target selected ... flags=0x3`、`SystemProperties hooks`、`Build profile
  applied`；随后加载 `libjiagu_vip.so`，进程以 `signal 9` 结束，无 Java `FATAL EXCEPTION`。
- `packages.txt` 加入 `!com.qidian.QDReader` 后 `SplashActivity` 恢复、进程存活。

2026-11-04：同一设备，KernelSU 3.3.1 + Zygisk Next 1.5.2（864），模块 `v0.1.2`，按下文步骤 A/B：

| 起点读书模式 | 结果 | 关键日志 |
| --- | --- | --- |
| `excluded` | 存活，进入 `MainGroupActivity` | 只有 `policy ... reason=mode_excluded`；仅走 JPush，无 XMSF 连接 |
| `inherit`（= full） | 加载 `libjiagu_vip.so` 后约 90 ms 被 `signal 9` 杀死 | hooks `installed=9/10`（`legacy=0`），Build `applied=2 failed=0` |
| `properties` | 同上被杀 | hooks `installed=9/10` |
| `observe` | 同上被杀，观察线程尚未输出任何 key | hooks `installed=9/10`，不改任何值 |
| `build` | 存活，冷启动进入 `MainGroupActivity`，热启动同 PID 恢复 | Build `applied=2`；主进程持有到 XMSF `XMPushService` 的连接，XMSF 记录 `com.xiaomi.mipush.SEND_MESSAGE`/`ENABLE_PUSH_MESSAGE`；`MessageHandleService`、`PushMessageHandler` 运行 |

- `Failed to register native method com.stub.StubApp.interface99(...)` 在 `excluded`/`build` 等存活的
  启动中同样出现，与崩溃无关，不能作为冲突证据。
- 结论：360 加固检测的是 `SystemProperties` JNI hook（或为其常驻的模块映射），与伪装值无关；
  只伪装 `Build.BRAND/MANUFACTURER` 已足以让起点读书的阅文推送路由选择 MiPush 并连接 XMSF。
  该设备上的推荐配置为 `mipushctl mode com.qidian.QDReader build`。尚未实测收到/点击推送。
- 同轮 QQ（主进程、`:MSF`、`:qzone`）与酷安（主进程、`:xg_vip_service`）仍为 `full`，
  hooks `installed=9/10`、Build `applied=2`，进程稳定；本轮未核对它们的 XMSF 注册。

## 加固应用 A/B 定位

每次只改一个因素，并先备份状态文件：

```sh
su -c 'cp /data/adb/mipush-spoof-next/packages.txt /data/adb/mipush-spoof-next/packages.txt.bak'
su -c 'cp /data/adb/mipush-spoof-next/package_modes.conf /data/adb/mipush-spoof-next/package_modes.conf.bak'
```

1. 基线：清空 logcat，冷启动，记录 PID、首屏和是否存活。
2. 显式排除：`mipushctl app <包名> disable --apply`；预期只出现 `policy ... reason=explicit_deny`。
3. 恢复选中（`mipushctl app <包名> auto`），只给 Build：`mipushctl mode <包名> build --apply`。
   此模式不装 JNI hook，库在 specialize 后卸载，与第 2 步唯一的差别是 Build 字段写入；第 2 步存活
   而此步崩溃，说明 Build 字段是触发点。
4. 只给属性：`mipushctl mode <包名> properties --apply`。
5. 只观察：`mipushctl mode <包名> observe --apply`。hook 与常驻库映射存在但不改值；仍崩说明被检测
   的是 hook/映射本身，而不是伪装值。
6. 若 3、4 都能启动、`full` 才崩，检查两组能力的组合；若任一单组就崩，再缩小 profile 字段。

全局 `options.conf` 开关仍可用于对照，但会影响所有 `inherit` 应用。日志抓取不要只看 Java 异常：

```sh
adb logcat -c
adb shell am force-stop <包名>
adb shell monkey -p <包名> 1
adb shell pidof <包名>
adb logcat -d -v threadtime | grep -E 'MiPushSpoofNext|jiagu|StubApp|FATAL EXCEPTION|signal|native_get|AndroidRuntime'
```

## 兼容矩阵建议

记录以下维度：Android 版本/页大小、ABI、root 管理器、Zygisk provider 与版本、XMSF 版本、目标
MiPush SDK 版本与目标 APK 版本、是否加固（`scan.log` 的 `hardening=`）、主进程/推送子进程、
包级模式、MIUI14/HyperOS profile、DenyList 状态。

| 场景 | 预期 |
| --- | --- |
| 被排除的加固应用冷/热启动 | 进程存活并进入首页；只有 `policy ... mode=excluded` 日志 |
| QQ/酷安/京东/闲鱼推送 | 注册、收到通知、点击进入、冷启动各一次 |
| 主进程与冒号子进程 | 策略一致；不能只排除主进程而注入子进程 |
| 重新扫描与重启后首次启动 | 扫描不覆盖人工排除；`scan.log` 的 `candidate=` 行说明最终动作与来源 |
| 单个签名或字段失败 | 回退原实现，进程不被杀死 |
| 关闭模块 | 目标应用恢复未注入行为 |

每次记录模块版本/commit、`options.conf`、`packages.txt`、`package_modes.conf`、目标包与进程、
`policy` 行、PID、首屏结果和关键 logcat 片段。

这是需要真实设备完成的验证；CI 和本仓库构建不能替代 MiPush 服务端注册与后台保活测试。
