## NKNGuard 0.2.15 预览版

### 下载

| 安装包 | 用途 |
| --- | --- |
| `NKNGuard-Android-0.2.15-preview.2.apk` | Android 8.0+，保持维护者原签名，可覆盖升级既有 debug 客户端 |
| `NKNGuard-Setup-0.2.15-preview.2.exe` | Windows 10/11 x86_64 安装器 |
| `NKNGuard-Windows-x86_64-preview.zip` | Windows 便携客户端，仍需官方 WireGuard |
| `NKNGuard-fnOS-amd64-0.2.15-preview.2.fpk` | 飞牛 x86_64 应用中心安装包 |
| `NKNGuard-fnOS-arm64-0.2.15-preview.2.fpk` | 飞牛 ARM64 应用中心安装包 |
| `nknguard-linux-amd64` / `nknguard-linux-arm64` | Linux / NAS 独立服务程序 |
| `NKNGuard-NAS-Update-linux-<架构>-0.2.15-preview.2.zip` | 独立服务：面板上传更新包 |
| `NKNGuard-NAS-Update-fnos-<架构>-0.2.15-preview.2.zip` | FPK 安装：面板上传更新包 |
| `release.json` / `release.json.sig` / `SHA256SUMS` | 发布签名目录与文件校验值 |

### 本次更新

- NAS、Android、Windows 增加从 GitHub 手动检查更新。
- NAS 面板可上传签名更新包，验证版本、处理器架构和文件完整性；独立服务更新失败自动恢复上一版，保留设备身份、管理密码和配对。
- Android 可下载安装更新、导入本地 APK；安装前核对应用 ID、版本与当前签名，交给系统确认安装。
- 飞牛分别构建 x86_64 与 ARM64 FPK；关闭默认文件日志，停止和卸载复用程序自身的隧道与防火墙清理，避免误杀复用 PID 的其他进程。
- 保留此前多 NAS 管理、直连优先、NKN 备用中继、NAT 仪表盘及网络动画。
- GitHub 中文介绍的赞赏区新增 USDC · ERC20，沿用 Ethereum 收款地址。

### 测试范围

Windows 的自动化测试覆盖程序、安装、覆盖升级、卸载及原生窗口启动。尚需在用户电脑验证到 NAS 的真实 VPN 连接。ARM64 独立服务在现有飞牛 NAS 验证更新；FPK 构建和生命周期校验不能替代各机型的应用中心实机安装测试。现有测试 NAS 的大盘没有应用中心存储空间，未格式化已有数据。

这是开发预览版，Windows 安装器尚未代码签名。Android 请使用这里的维护者签名安装包，Actions 原始调试 APK 的临时签名不能覆盖升级。
