## NKNGuard 0.2.16 预览版

### 下载

| 安装包 | 用途 |
| --- | --- |
| `NKNGuard-Android-0.2.16-preview.1.apk` | Android 8.0+，保持维护者原签名，可覆盖升级既有 debug 客户端 |
| `NKNGuard-Setup-0.2.16-preview.1.exe` | Windows 10/11 x86_64 安装器 |
| `NKNGuard-Windows-x86_64-preview.zip` | Windows 便携客户端，仍需官方 WireGuard |
| `NKNGuard-fnOS-amd64-0.2.16-preview.1.fpk` | 飞牛 x86_64 应用中心安装包 |
| `NKNGuard-fnOS-arm64-0.2.16-preview.1.fpk` | 飞牛 ARM64 应用中心安装包 |
| `nknguard-linux-amd64` / `nknguard-linux-arm64` | Linux / NAS 独立服务程序 |
| `NKNGuard-NAS-Update-linux-<架构>-0.2.16-preview.1.zip` | 独立服务：面板上传更新包 |
| `NKNGuard-NAS-Update-fnos-<架构>-0.2.16-preview.1.zip` | FPK 安装：面板上传更新包 |
| `release.json` / `release.json.sig` / `SHA256SUMS` | 发布签名目录与文件校验值 |

### 本次更新

- 首次打开 NAS 面板提供三步向导：设置用户名与密码、查看持久化 NKN 地址、引导手机配对。已有安装保留账号、密钥和配对。
- 网页登录替代浏览器验证弹框；安全设置支持修改用户名和密码，修改后旧登录会话失效。
- UPnP / NAT-PMP 使用实际 WireGuard 动态端口，自动续租；面板显示映射状态和公网端点，失败继续尝试其他链路。
- NAT 卡片和仪表盘统一名称，新增当前条件标记；未测定入站过滤时不误报具体锥型。
- 更新页安装包选择与上传按钮统一配色；保留签名、架构校验和失败回滚。
- 赞赏二维码采用薄荷绿与深蓝配色，复制按钮对齐；ETH / USDC · ERC20 使用原 Ethereum 收款地址。
- Android 保持原签名，Windows、两种架构的飞牛 FPK 与签名 NAS 更新包同步发布。

### 测试范围

Windows 的自动化测试覆盖程序、安装、覆盖升级、卸载及原生窗口启动。尚需在用户电脑验证到 NAS 的真实 VPN 连接。ARM64 独立服务在现有飞牛 NAS 验证更新；FPK 构建和生命周期校验不能替代各机型的应用中心实机安装测试。现有测试 NAS 的大盘没有应用中心存储空间，未格式化已有数据。

这是开发预览版，Windows 安装器尚未代码签名。Android 请使用这里的维护者签名安装包，Actions 原始调试 APK 的临时签名不能覆盖升级。
