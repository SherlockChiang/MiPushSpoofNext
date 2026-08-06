# MiPush Spoof Next

面向类原生 Android 的按进程 Xiaomi/MIUI 身份虚拟化模块，用于配合
[NihilityT/MiPushFramework](https://github.com/NihilityT/MiPushFramework)（原组织仓库的活跃 fork）
或兼容 XMSF 服务，
让集成了 MiPush SDK 的应用在非小米 ROM 上选择系统级 MiPush 通道。

这是纯 Zygisk 实现：不依赖 LSPosed、LSPlant、Dobby 或 ByteHook，不全局修改真实
`ro.*` 属性，也不会修改 `/system`。

维护者：SherlockChiang。

> 本模块只负责目标应用进程内的“机型/系统判定”。它不包含 XMSF，不实现 MiPush
> 注册、长连接、消息转发或通知服务。没有可用的 MiPushFramework/XMSF 服务时，单装本模块
> 不会产生推送能力。

## 相比旧实现

| 能力 | MiPushEnhancement / MiPushFaker | MiPush Spoof Next |
|---|---|---|
| 注入后端 | Xposed/LSPosed | 直接 Zygisk |
| 目标选择 | 全局 scope 或简单探测 | 手工规则 + APK 自动扫描，精确包/子进程语义 |
| 配置读取 | 目标 UID 读取 world-readable 私有文件 | root companion 读取 `0600` 配置并发送快照 |
| SystemProperties | 三个旧签名 | String/int/long/boolean、旧 String 重载、现代 handle 重载 |
| primitive 类型 | 旧实现可能返回 String | 严格解析为 `int`/`long`/`boolean`，失败回原值 |
| Build 字段 | BRAND、MANUFACTURER | 安全白名单、可配置、逐字段 fail-open |
| 新系统 profile | 固定 MIUI 12 | 保守 MIUI 14 默认 + HyperOS 1 可选 |
| 诊断 | 很少 | 生命周期日志、唯一 property key 观察模式、扫描日志 |
| 更新配置 | 常需重启 | 改规则/profile 后只需强停并重启目标应用 |

## 要求

- Android 8.0+（API 26+）。
- Magisk 26.0+ 且启用内置 Zygisk；或 KernelSU/APatch 搭配兼容公开 Zygisk API v4
  的 provider。第三方 provider 不随本模块分发。
- KernelSU/APatch 请使用各自的 Manager 安装模块（两者不支持 recovery 安装）；KernelSU
  还需要 ZygiskNext 或其他兼容 provider 提供 Zygisk API。
- 已安装并可工作的 MiPushFramework/兼容 XMSF 服务。
- 首发 ABI：`arm64-v8a`、`armeabi-v7a`、`x86_64`、`x86`。同时包含 32 位 ABI，
  因为部分 64 位设备仍会启动 32 位应用进程。

## 安装

1. 在 root 管理器中安装 `MiPushSpoofNext-v0.1.0.zip`。
2. 确保 Zygisk provider 已启用，然后重启。
3. 点击模块的“操作/Action”按钮扫描已安装 APK；或执行：

   ```sh
   su -c /data/adb/modules/mipush-spoof-next/bin/mipushctl scan
   ```

4. 审核自动生成的目标列表：

   ```sh
   su -c /data/adb/modules/mipush-spoof-next/bin/mipushctl list
   ```

5. 强行停止并重新启动命中的应用。若应用处于 Magisk 强制 DenyList/卸载列表，先将其移出，
   否则 Zygisk 模块不会进入该进程。

扫描器默认检查已安装第三方包（包括 `/data/app` 中的系统化第三方）的 PackageManager
组件标记：MiPush 广播 action、`PushMessageHandler`、`MessageHandleService` 和
`XMPushService`。这条路径不解压 dex，适合日常快速扫描；将 `options.conf` 中的
`scan_system_apps=true` 可纳入全部系统包。将 `scan_deep=true` 后，未命中组件标记的包还会
运行 ART `dexlist` 和压缩 dex 回退，用于加固/动态注册或深度混淆 SDK，但会明显变慢并受
`scan_max_apk_bytes` 限制。扫描器是安全的候选生成器，不是绝对判断；拆分 APK、加固/动态
加载或深度混淆仍可能造成漏报。若包枚举、PackageManager 查询或 APK 读取失败，扫描会返回
错误并保留上一次自动规则；快速模式跳过的包会在日志中列出。可手动维护规则：

```sh
su -c '/data/adb/modules/mipush-spoof-next/bin/mipushctl add com.example.app'
su -c '/data/adb/modules/mipush-spoof-next/bin/mipushctl deny com.example.app:camera'
su -c '/data/adb/modules/mipush-spoof-next/bin/mipushctl remove com.example.app'
```

## 规则语义

配置保存在 `/data/adb/mipush-spoof-next`，权限为 `0700/0600`：

- `packages.txt`：手工规则，升级保留。
- `packages.auto.txt`：扫描器生成，每次扫描原子替换。
- `options.conf`：功能和日志开关。
- `profile.properties`：当前 profile 快照。
- `profiles/`：可切换的 profile 模板。
- `logs/scan.log`：最近一次扫描摘要。

规则 `com.example.app` 匹配从 app data dir 识别出的该包全部进程（包括自定义名称和常见的
`com.example.app:*` 子进程），但不会误匹配 `com.example.application`。包含冒号的规则只精确
匹配一个进程。以 `!` 开头的 deny 规则优先于手工和自动 allow。

系统核心 UID、`system_server`、Android 核心包、GMS/Vending、XMSF、历史上游标记为不兼容的
微信/旧 MiPush Manager，以及常见 root/模块管理器
有不可关闭的保护性 deny；Zygisk 虽会调用 server specialization 回调，但模块不会在
`system_server` 安装 hook 或保留自身 so。

## Profile 与观察模式

默认 `miui14` profile 只修改 MiPush 判定常见的 MIUI 属性、product 分区品牌/厂商属性以及
`Build.BRAND/MANUFACTURER`。它刻意不改 SDK、ABI、序列号、安全补丁和 fingerprint。
另附 `hyperos1` 和复现历史 Riru 行为的 `legacy-v11`；后者包含历史兼容所需的合成
`Build.PRODUCT=Xiaomi`，只建议旧 MiPush SDK 无法被默认 profile 触发时使用。
为保证跨 ABI 的稳定性，profile 中的字符串值目前限制为可打印 ASCII；需要非 ASCII
`Build.MODEL` 等字段时请先验证目标 ROM，再扩展配置校验。

```sh
# 查看并切换 profile
su -c '/data/adb/modules/mipush-spoof-next/bin/mipushctl profile'
su -c '/data/adb/modules/mipush-spoof-next/bin/mipushctl profile hyperos1'

# 记录目标进程读取过的唯一 property key（不记录值）
su -c '/data/adb/modules/mipush-spoof-next/bin/mipushctl observe on'
adb logcat -s MiPushSpoofNext
```

修改 profile、规则或观察开关后，强停并重启目标应用即可。已有进程不会热更新，因为配置在
specialize 时被冻结成每进程快照。

## 已验证设备

2026-08-06 在 Sony XQ-CQ72（Android 16 / API 36、4 KiB 页、KernelSU + ReZygisk 515，
arm64/arm32）完成冒烟。XMSF 为 `0.3.11-366-g40ba88c`；`com.qidian.QDReader` 主进程与
`:pushcore` 均成功注入，`com.coolapk.market` 也命中手工规则。日志确认 String/int/long/
boolean/handle hooks、MIUI 属性和 Build profile 均生效；XMSF 观察到
`com.xiaomi.mipush.SEND_MESSAGE`、`SECMSG` 收发及 `normal_client_config_update`。本轮未发现
FATAL EXCEPTION、ANR 或模块错误。该结果是单机冒烟，不代表所有 ROM、Zygisk provider 或
MiPush SDK 版本均兼容；请按 [测试清单](docs/TESTING.md) 补做自己的矩阵验证。

卸载脚本会同时删除 `/data/adb/mipush-spoof-next` 中的规则、profile 快照和日志；如需保留配置，
请在卸载前自行导出该目录。

## 安全设计

- 仅 allowlist 应用进程生效；真实系统属性不变。
- 未命中目标时立即请求卸载模块 so。
- 安装持久 JNI hook 的进程不会卸载 so，避免悬空函数指针。
- 配置、IPC、JNI 签名或字段写入失败时 fail-open，继续调用系统实现。
- Build 只接受源码内安全字符串字段白名单；`SDK_INT` 等危险字段无法通过配置开启。
- `native_find` 只有在整套 handle getter 均成功挂钩时才返回合成 handle。
- 观察模式只记录 property key，不记录真实或伪装值。

## 当前边界

- MVP 覆盖 Java `android.os.SystemProperties` 和预加载的 `android.os.Build`。若某个 SDK 的
  native so 直接调用 bionic `__system_property_*`，本版本不会拦截；先用观察模式和实机日志
  证明需求，再考虑加入目标限定的 native backend。
- 为避免 app zygote 级伪装被其所有子进程继承、绕过单进程 deny，本版会主动跳过
  `android:useAppZygote` 的 child-zygote；依赖该机制的 isolated service 暂不受支持。
- 不伪装 PackageManager、Telephony、Settings、设备标识符或 Play Integrity。若未来实测新
  MiPush SDK 确实依赖这些面，建议作为独立、可选 LSPosed adapter，而不是扩大默认 Zygisk
  攻击面。
- 目前只有上述 XQ-CQ72 的单机冒烟，尚未形成跨 ROM/页大小/SDK 的兼容矩阵。`v0.1.0` 仍是
  实验性工程基线；报告实机结果时应附 Android 版本、root/Zygisk provider、目标包、XMSF
  版本及 `MiPushSpoofNext` 日志。

更多实现细节见 [架构文档](docs/ARCHITECTURE.md)，上游审计和迁移依据见
[上游审计](docs/UPSTREAM_AUDIT.md)。

## 构建

需要 Android NDK r27d（r28+ 也应可用）和 Python 3：

```powershell
./scripts/build.ps1 -NdkPath C:\Android\android-ndk-r27d
```

或：

```bash
export ANDROID_NDK_HOME=/opt/android-ndk-r27d
bash scripts/build.sh
```

构建会先运行 profile/打包规则检查和单元测试，再在隔离目录生成四 ABI so，使用 16 KiB
最大页对齐。发布前会逐文件核对安装 ZIP 与模块源码/本次 native 输出，检查 ELF
class/machine、导出入口和动态依赖，并同时生成同版本的 `-source.zip`。CI 工作流执行同一流程。

## 许可证

项目采用 GPL-3.0-or-later。Zygisk API v4 头文件来自官方 sample 的 `7bb941a`，采用 0BSD；
详见 [NOTICE](NOTICE.md)。安装 ZIP 内也附带 LICENSE、NOTICE 与对应源码包说明。
