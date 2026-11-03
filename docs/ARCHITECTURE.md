# 架构

## 生命周期

1. Zygisk 在 fork 后、specialize 前加载模块。
2. `preAppSpecialize` 将 UID、进程名和 app data dir 发给 root companion；child app zygote
   为避免跨子进程继承而直接跳过。
3. companion 读取 options，依次应用内置保护规则、`packages.txt`/`packages.auto.txt` 和
   `package_modes.conf`（见下文“目标选择与包级模式”），输出一行 `policy` 日志；命中后读取 profile，
   返回固定大小、带 magic/version 的不可变快照，其中 flags 已是该包的最终能力。
4. 未命中或 IPC/配置错误：设置 `DLCLOSE_MODULE_LIBRARY`，不改变进程。
5. 命中且需要属性能力：用公开 Zygisk API `hookJniNativeMethods` 逐个签名替换 `SystemProperties`
   的已注册 JNI 入口。没有任何 hook 生效（例如 `build` 模式）时同样设置 `DLCLOSE_MODULE_LIBRARY`，
   库在 `postAppSpecialize` 结束后卸载，进程内不留模块映射。
6. `postAppSpecialize` 在 app sandbox 内写入安全的 `Build` 字符串字段，确保 specialization 期间的
   系统 override 已结束。

Zygisk 会调用 server specialization 回调，但模块立即请求卸载，不在 `system_server`
安装 hook 或保留自身 so；模块也不挂普通 Java/ART 方法。

## 目标选择与包级模式

`resolve_policy()` 的顺序固定，后一步永远不能把前一步的 deny 变成目标：

1. 内置 deny（系统 UID、核心包、XMSF、GMS、root/模块管理器等）→ `built_in_deny`。
2. `packages.txt` 或 `packages.auto.txt` 中任一 `!` 规则命中 → `explicit_deny`，`source` 标明
   来自 manual 还是 auto。扫描器每次重写 `packages.auto.txt` 也不会让人工排除失效。
3. 两个规则文件都没有 allow 命中 → `no_matching_allow`；否则记为 `manual_allow`（优先）或
   `auto_allow`。
4. `package_modes.conf` 决定被选中进程获得哪些能力。它不会单独选中任何包。

| 模式 | flags | 说明 |
| --- | --- | --- |
| `inherit`（默认） | 来自 `options.conf` | 未配置时使用全局开关 |
| `full` | properties + build | 不受全局 `spoof_*` 开关收窄 |
| `properties` | properties | 只装 `SystemProperties` hook |
| `build` | build | 不装 JNI hook，写完 Build 字段后卸载库 |
| `observe` | observe | 装 hook 但只记录读取的 key，不改值 |
| `excluded` | — | `mode_excluded`，等同 `!` 规则 |

包级条目覆盖该包所有进程；`包名:进程` 条目优先于包级条目；`excluded` 优先于两者；同一范围以最后
一行为准。无法识别的模式值按 `mode_invalid` 处理并排除该进程（错误级日志），而不是退回全局配置。
最终 flags 为 0（例如 `inherit` 且全局三项都关闭）时返回 `no_capabilities`，不把进程当作目标。

companion 以 `options.conf` 的 `log_level` 输出决策：命中过规则的进程用 info，内置 deny 与无规则
进程只在 debug 输出，避免每个 app 启动都刷日志。示例：

```text
policy package=com.qidian.QDReader process=com.qidian.QDReader uid=10234 mode=excluded override=inherit reason=explicit_deny source=manual flags=0x0
policy package=com.tencent.mobileqq process=com.tencent.mobileqq uid=10187 mode=full override=full reason=auto_allow source=auto flags=0x3
```

`mode` 是最终生效能力，`override` 是 `package_modes.conf` 中的原值。

## SystemProperties 覆盖

逐个签名调用 `hookJniNativeMethods`（每次 1 个方法），调用后立即清理 provider 可能遗留的 JNI
异常，再保存该签名的原函数指针。这样某个 Android/OEM 版本缺失的签名（例如旧的
`native_get(String)` 重载）不会影响其他签名，也不会把异常带回 zygote 的后续 JNI 调用。ART 对缺失
签名打印的 `Failed to register native method ... SystemProperties.native_get ...` 本身属于预期探测。每个签名在
debug 级别记录 `hook_installed`/`hook_unavailable`，异常记录为错误级 `hook_failure ...
action=fall_back`；info 级汇总为 `installed=N/10`。若 provider 返回的“原函数”就是替换函数本身，
模块将其视为未知并回退到调用方 fallback，避免自递归。每个进程只尝试安装一次，重复调用只记录日志。

尝试挂钩以下签名；不存在的 OEM/Android 版本签名会被安全跳过：

- `native_get(String,String): String`
- 旧 `native_get(String): String`
- `native_get_int(String,int): int`
- `native_get_long(String,long): long`
- `native_get_boolean(String,boolean): boolean`
- `native_find(String): long`
- `native_get(long): String`
- CriticalNative handle 型 int/long/boolean getter

每个 hook 保存 Zygisk 返回的原函数指针。未配置 key、禁用 property spoof、解析失败或不兼容时
调用原函数。布尔解析与 AOSP 接受的 `n/no/0/false/off`、`y/yes/1/true/on` 一致。

类原生 ROM 通常不存在 `ro.miui.*`，因此真实 `native_find` 会返回 0。完整 handle hook 均存在时，
模块为配置项分配高位带 `MPSN` 标记的合成 handle；任何一个 handle getter 缺失时都禁用合成，
防止合成值落入系统原函数。

## 配置协议

IPC 是固定布局二进制结构，当前协议版本为 1。请求和响应均要求 magic `MPSN` 与准确版本；
所有字符串写入定长缓冲区前检查长度。限制：

- property：64 项，key 127 bytes，value 255 bytes。
- Build：24 项，field 63 bytes，value 255 bytes。
- 进程名：191 bytes；app data dir：383 bytes。

profile 的重复 key 采用后项覆盖。未知命名空间、非法 property key 和非白名单 Build 字段会被忽略；
profile 字符串值限制为可打印 ASCII，避免 `NewStringUTF` 接收损坏编码；有效 profile 为空时
companion 返回 `CONFIG_ERROR`，app 侧 fail-open。

## 为什么不在核心中使用 LSPlant/Dobby

核心需求是系统属性读取和预加载静态字段，不需要普通 Java 方法 hook。公开 Zygisk JNI API 能保留
原函数且没有 ART 私有符号依赖。加入独立 LSPlant 会扩大 Android/OEM/页大小兼容矩阵，并可能与
设备已有 LSPosed 重复修改 ART。native `__system_property_*` inline hook 同样留待实测证明需要后再做。

PackageManager、Telephony 和 Settings 属于 Binder/Java 语义，应放进可选 LSPosed adapter；默认
核心不伪造包、IMEI、ANDROID_ID 或硬件证明。

## 威胁与故障模型

- 配置只由 root companion 读取，目标应用 UID 无权打开配置文件。
- 模块不是 root 隐藏或完整设备伪装工具；目标应用可以从其他 API 发现真实 ROM。
- 任何模块内崩溃仍会发生在目标进程，因此 native 代码不用异常/RTTI/STL，避免动态依赖，并将
  所有失败路径设计为回原实现。
- 360 加固、腾讯乐固等商用壳的反篡改初始化可能把被注入的进程直接 `SIGKILL`，此时没有 Java
  `FATAL EXCEPTION`。模块不尝试用更多 hook 绕过加固。实测 Android 17 上 360 加固只要存在
  `SystemProperties` JNI hook（连 `observe` 也算）就会杀进程，而不装 hook、库随后卸载的 `build`
  模式可以正常运行；仍不行时用 `!包名` 或 `excluded` 排除。扫描器会在 `scan.log` 中标注检测到的壳
  （`hardening=jiagu` 等），只作提示，不自动改变策略。
- companion 建立连接后，payload 收发使用单调时钟控制的 2 秒截止时间；超时或畸形响应均
  fail-open。公开 Zygisk API 的连接调用和配置文件打开不纳入这个 socket deadline。
- 配置只在进程创建时读取；观察模式在 FastNative 热路径仅写入有界无锁表，由后台线程输出
  日志，热路径不执行锁或 I/O。表按 key 尽力去重（并发首次读取可能重复），规则修改需重启
  目标进程。
