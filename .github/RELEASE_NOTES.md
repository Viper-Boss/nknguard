## NKNGuard 0.2.17 预览版

### 下载

| 安装包 | 用途 |
| --- | --- |
| `NKNGuard-Android-0.2.17-preview.1.apk` | Android 8.0+，保持维护者原签名，可覆盖升级既有 debug 客户端 |
| `NKNGuard-Setup-0.2.17-preview.1.exe` | Windows 10/11 x86_64 安装器 |
| `NKNGuard-Windows-x86_64-preview.zip` | Windows 便携客户端，仍需官方 WireGuard |
| `NKNGuard-fnOS-amd64-0.2.17-preview.1.fpk` | 飞牛 x86_64 应用中心安装包 |
| `NKNGuard-fnOS-arm64-0.2.17-preview.1.fpk` | 飞牛 ARM64 应用中心安装包 |
| `nknguard-linux-amd64` / `nknguard-linux-arm64` | Linux / NAS 独立服务程序 |
| `NKNGuard-NAS-Update-linux-<架构>-0.2.17-preview.1.zip` | 独立服务：面板上传更新包 |
| `NKNGuard-NAS-Update-fnos-<架构>-0.2.17-preview.1.zip` | FPK 安装：面板上传更新包 |
| `release.json` / `release.json.sig` / `SHA256SUMS` | 发布签名目录与文件校验值 |

### 本次更新

- 客户端主动发起连接请求；NAS 不再向离线客户端反复发送配置。连接期间双方在有限窗口内重试。
- 直连与 NKN 中继统一支持 90 秒断线恢复窗口，任一路径恢复后结束倒计时；超时清理通道，保留配对和设备授权。
- 手机和 NAS 面板显示连接、重连倒计时及断开状态，倒计时本地更新，不额外发送 NKN 消息。
- 正常断开前发送签名通知，NAS 清理该设备的 WireGuard、ICE 和中继；迟到的旧会话通知不会关闭新会话。
- 优先尝试最近验证且符合当前网络的直连端点，后台获取新配置。修复首次 NKN 请求被提前消耗、导致等待数分钟的问题。
- 未变的配置使用紧凑签名续期，仍验证完整记录的原始签名；缺少基准记录时限流请求完整配置。
- 连接控制消息关闭 NKN 离线缓存，配对消息仅保留 30 秒短暂递送窗口。
- 登录进入首页，配对二维码只在主动生成后显示，完成配对或过期后自动收起。移除旧账号提示。

NAS 和安卓均更新后才能完整使用恢复窗口和倒计时。升级保留账号、密钥及配对信息。

### 测试范围

Windows 的自动化测试覆盖程序、安装、覆盖升级、卸载及原生窗口启动。尚需在用户电脑验证到 NAS 的真实 VPN 连接。ARM64 独立服务在现有飞牛 NAS 验证更新；FPK 构建和生命周期校验不能替代各机型的应用中心实机安装测试。现有测试 NAS 的大盘没有应用中心存储空间，未格式化已有数据。

这是开发预览版，Windows 安装器尚未代码签名。Android 请使用这里的维护者签名安装包，Actions 原始调试 APK 的临时签名不能覆盖升级。
