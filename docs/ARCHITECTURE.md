# 架构

## 生命周期

1. Zygisk 在 fork 后、specialize 前加载模块。
2. `preAppSpecialize` 将 UID、进程名和 app data dir 发给 root companion；child app zygote
   为避免跨子进程继承而直接跳过。
3. companion 应用内置保护规则、`packages.txt` 和 `packages.auto.txt`，命中后读取 options/profile，
   返回固定大小、带 magic/version 的不可变快照。
4. 未命中或 IPC/配置错误：设置 `DLCLOSE_MODULE_LIBRARY`，不改变进程。
5. 命中：用公开 Zygisk API `hookJniNativeMethods` 替换 `SystemProperties` 的已注册 JNI 入口。
6. `postAppSpecialize` 在 app sandbox 内写入安全的 `Build` 字符串字段，确保 specialization 期间的
   系统 override 已结束。

Zygisk 会调用 server specialization 回调，但模块立即请求卸载，不在 `system_server`
安装 hook 或保留自身 so；模块也不挂普通 Java/ART 方法。

## SystemProperties 覆盖

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
- companion 建立连接后，payload 收发使用单调时钟控制的 2 秒截止时间；超时或畸形响应均
  fail-open。公开 Zygisk API 的连接调用和配置文件打开不纳入这个 socket deadline。
- 配置只在进程创建时读取；观察模式在 FastNative 热路径仅写入有界无锁表，由后台线程输出
  日志，热路径不执行锁或 I/O。表按 key 尽力去重（并发首次读取可能重复），规则修改需重启
  目标进程。
