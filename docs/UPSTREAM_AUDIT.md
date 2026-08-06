# 上游审计与迁移依据

审计日期：2026-08-05。

## yin-ol/MiPushFaker

- 固定审计提交：`6f7300401a3414215313faf581e2710c115e89c8`（2022-05-25）。
- 单一 Kotlin Xposed 入口；通过 `XMPushService` / `PushMessageHandler` 类名判断 MiPush SDK，挂钩
  三个旧 `SystemProperties.native_get*` 并修改 BRAND/MANUFACTURER。
- 没有 README、release、CI 或完整 Gradle wrapper；代码自 2022 年未更新。
- `native_get_int/long` 把字符串直接作为 primitive 结果，存在类型错误；属性表还把
  `ro.product.manufacturer` 误写成 `product.manufacturer`。
- 立即 class-load 探测会漏掉 MultiDex/动态 classloader；空默认 scope、无按包配置和诊断。
- 许可证为 AGPL-3.0。新版未复制其 Kotlin 源码，只采用公开可观察的功能需求与 MiPush 类标记。

仓库：https://github.com/yin-ol/MiPushFaker

## MiPushFramework/MiPushEnhancement

- 固定审计提交：`32a0df2cb78c4d34e493fe426f67d652a28b0f9d`（2020-08-16）。
- 在 `Application.attach` 后读 INI 黑白名单，再挂三个旧 property JNI 方法并修改两个 Build 字段。
- 配置依赖目标 app 读取另一 UID 的 app-private 路径和 world-readable/chmod，现代 SELinux 下不可靠；
  仓库 issue 已有 Android 12 权限失败报告。
- 同样存在 primitive 返回 String、缺现代 overload、无 native 覆盖、旧构建依赖等问题。
- 许可证为自定义 AMTPL v1 + GPLv3，带不可删除的特定框架检测条款。新版不复制源文件，配置和
  hook 均为独立重新实现，避免把 AMTPL 条款带入新项目。

仓库：https://github.com/MiPushFramework/MiPushEnhancement

## tinkernels/zygisk-module-mipushfake

- 固定审计提交：`30c4c7eaaf076249f7ad0a971ec69f771fafcf29`（2022-04-14）。
- 已采用 Zygisk companion、包列表、ByteHook property hook 和 JNI Build 字段写入，证明直接路线
  可行，但停在 Zygisk API v3/Android 12 时代。
- 未命中 map 时日志仍解引用 end iterator，可崩溃；`__system_property_get` 命中固定返回 1 而非
  字符串长度；规则用裸前缀比较会把 `com.foo` 误命中 `com.foobar`。
- 对所有进程先初始化 ByteHook，硬编码过时 fingerprint，缺少安全 deny、类型化配置和现代构建验证。
- 仓库没有清晰的项目许可证声明。新版没有复制其实现代码。

仓库：https://github.com/tinkernels/zygisk-module-mipushfake

## MiPushFramework/MiPushFakeForRiru

- 固定审计提交：`8b6328f55f86d7a1a2042f19fb0ae84fdba1651e`。
- GPLv3 的历史 Riru 实现；默认挂钩 native `__system_property_get`，API 26+ 还处理
  `__system_property_read_callback`，按包目录启用。
- 其 V11 profile 额外包含 `ro.miui.internal.storage` 与 `ro.product.name`，并修改
  `Build.PRODUCT`。新版将这些公开行为做成非默认 `legacy-v11` profile，代码仍为独立重写。
- Riru 已不是当前主线，原仓库也明确指向此后继实现；新版以公开 Zygisk API 代替。

仓库：https://github.com/MiPushFramework/MiPushFakeForRiru

## 一手平台依据

- Zygisk API v4 header（0BSD）：
  https://github.com/topjohnwu/zygisk-module-sample/blob/7bb941ac8edfcffd1d23761e401c45ca95409dc1/module/jni/zygisk.hpp
- Magisk 模块指南：https://topjohnwu.github.io/Magisk/guides.html
- AOSP SystemProperties Java/JNI：
  https://android.googlesource.com/platform/frameworks/base/+/master/core/java/android/os/SystemProperties.java
- 小米 HyperOS 官方属性说明（V816/816、`ro.mi.os.*`）：
  https://dev.mi.com/xiaomihyperos/documentation/detail?pId=2161

## 迁移原则

- 保留：按目标进程虚拟化、不全局 resetprop；Xiaomi/MIUI 最小身份；包 allow/deny；MiPush dex 标记。
- 重写：全部 hook、配置 IPC、规则匹配、构建、打包、诊断。
- 修复：primitive 类型、包边界、现代 JNI overload、配置权限、fail-open、system_server 保护。
- 暂缓：native bionic inline hook、PackageManager/Telephony/Settings、完整 fingerprint/SDK 伪装。
