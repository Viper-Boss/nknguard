# Windows 客户端（开发预览版）

NKNGuard Windows 客户端按需启动 WireGuard 隧道。连接时先尝试缓存的对端地址，同时通过 NKN 获取最新信标；直连未成功时回退到 NKN 中继。界面会显示 NAS 和本机的完整 NKN 地址，以及当前路径。关闭客户端窗口会请求断开隧道。

## 准备

1. 在 NAS 上按 [配对指南](PAIRING.md) 安装并启动 NKNGuard，打开其本地管理面板。
2. 在 Windows 10/11 上安装[官方 WireGuard for Windows](https://www.wireguard.com/install/)和 Microsoft Edge。客户端调用安装目录中的 `wireguard.exe`、`wg.exe` 管理隧道。
3. 下载并解压 `NKNGuard-Windows.zip`，运行其中的 `NKNGuard-Windows.exe`。首次建立连接时 Windows 会请求管理员授权。

客户端文件存放在当前用户的 `%LOCALAPPDATA%\NKNGuard`。不要共享其中的 `state` 目录；它包含设备身份密钥和入网材料。

预览包尚未进行代码签名。若安全软件拦截可执行文件，请保留检测名称和报告并反馈；不要为运行预览版关闭系统防护。也可从本仓库源码自行编译并核对 ZIP 的 SHA-256。

## 首次配对

1. 在 NAS 面板“配对与授权”生成二维码，复制其完整 `nknguard://pair/v1?...` 内容。
2. 在 Windows 客户端填写电脑名称并粘贴内容，点击“请求 NAS 配对”。客户端显示六位码。
3. 在 NAS 面板核对电脑名称和六位码，点击批准。客户端保存 NAS 的公钥、NKN 地址及入网凭证。
4. 核对 NAS 面板首页与 Windows 客户端显示的完整 NKN 地址。之后点击“连接 NAS”，允许 Windows 管理员授权。

二维码中的公钥用于固定 NAS 身份；二维码本身不能直接授权他人入网。每次配对仍需 NAS 管理者现场批准。Windows 版目前支持复制粘贴二维码内容，暂不支持摄像头扫码。

## 连接与断开

- 点击“连接 NAS”会在当前 Windows 用户下启动带管理员权限的后台进程，并创建按需 WireGuard 隧道。若系统弹出 UAC，请确认程序路径后授权。
- 界面显示“WireGuard 直连”或“NKN 加密中继”时，可使用飞牛客户端访问 NAS 的虚拟 IP。只向覆盖网络地址添加路由。
- 点击“断开”或关闭窗口会请求停止后台进程并移除 NKNGuard 隧道。客户端不会改动其他 WireGuard 隧道。
- 若后台启动失败，界面会显示错误。也可查看 `%LOCALAPPDATA%\NKNGuard\last-error.txt`。此文件不包含配对密钥，提交问题前仍应检查并删去个人地址。

## 自行编译

使用 Go 1.25.7 或更新版本，在仓库根目录执行：

```powershell
go test -tags "nknsdk libp2pdht" ./...
go build -tags "nknsdk libp2pdht" -trimpath -ldflags "-H=windowsgui -X main.guiBuild=1" -o NKNGuard-Windows.exe ./cmd/nknguard
```

当前版本已通过 Windows Go 单元测试与编译。实际 fnOS、Windows WireGuard 服务和多种 NAT 的端到端验证仍待完成；请先在非关键设备上试用，并通过 [安全报告](../SECURITY.md) 反馈漏洞。
