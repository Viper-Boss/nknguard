NKNGuard Windows 0.2.20

安装器随附官方 WireGuard 1.1.1，缺少依赖时自动请求管理员授权安装，无需再手动下载。
便携版请完整解压，保留 deps 目录；客户端“安装 WireGuard”按钮可安装随附的依赖。
已有 WireGuard 不会被强制替换；卸载 NKNGuard 不卸载共享 WireGuard。

连接时仍需允许 Windows 管理员授权。请使用同一 Windows 账户，不要在 UAC 中切换为其他账户。
配对：NAS 面板生成链接 -> 粘贴到客户端 -> 核对六位验证码 -> NAS 批准。
配对期间限时重试请求，NAS 仅按需补发批准结果，超时后停止。
首次配对、授权丢包恢复需 NAS 与客户端均更新到 0.2.20。

关闭窗口会缩到托盘；请通过托盘“退出”后再升级/卸载。
身份和配对保留在 %LOCALAPPDATA%\NKNGuard，覆盖升级不会删除。
Windows 安装包尚无维护者代码签名；随附 WireGuard MSI 有官方 Authenticode 签名。
AGPL-3.0-only: https://github.com/Viper-Boss/nknguard
