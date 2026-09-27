# Windows 客户端（开发预览版）

NKNGuard Windows 客户端是一个原生 Windows 桌面程序（Go + [walk](https://github.com/lxn/walk)，
Win32 控件），不依赖浏览器。它按需启动 WireGuard 隧道：连接时先尝试缓存的对端地址，同时通过
NKN 获取最新信标；直连未成功时回退到 NKN 中继。窗口显示当前状态和链路、NAS 与本机的完整 NKN
地址、虚拟 IP，以及 NKNGuard 使用人数。

![Windows 客户端](images/windows-client-connected.png)

## 准备

1. 在 NAS 上按 [配对指南](PAIRING.md) 安装并启动 NKNGuard，打开其本地管理面板。
2. 在 Windows 10/11 上安装[官方 WireGuard for Windows](https://www.wireguard.com/install/)。
   客户端调用安装目录中的 `wireguard.exe`、`wg.exe` 管理隧道。
3. 从 [Releases](https://github.com/Viper-Boss/nknguard/releases) 下载并解压
   `NKNGuard-Windows-preview.zip`，运行其中的 `NKNGuard-Windows.exe`。首次建立连接时 Windows
   会请求管理员授权。

客户端文件存放在当前用户的 `%LOCALAPPDATA%\NKNGuard`。不要共享其中的 `state` 目录；它包含设备
身份密钥和入网材料。

预览包尚未进行代码签名。若安全软件拦截可执行文件，请保留检测名称和报告并反馈；不要为运行预览版
关闭系统防护。也可从本仓库源码自行编译并核对 ZIP 的 SHA-256。

## 首次配对

1. 在 NAS 面板“配对与授权”生成二维码，点“复制配对链接”（面板上也直接显示这条
   `nknguard://pair/v1?...` 链接，可以手动选中复制）。
2. 在 Windows 客户端“首次配对”中填写电脑名称、粘贴链接，点击“请求 NAS 配对”。客户端显示六位码。
3. 在 NAS 面板核对电脑名称和六位码，点击批准。客户端保存 NAS 的公钥、NKN 地址及入网凭证。
4. 核对 NAS 面板首页与 Windows 客户端显示的完整 NKN 地址。之后点击“连接 NAS”，允许 Windows
   管理员授权。

![首次配对](images/windows-client-pairing.png)

配对链接中的公钥用于固定 NAS 身份；链接本身不能直接授权他人入网。每次配对仍需 NAS 管理者现场批准。

## 连接、托盘与退出

- 点击“连接 NAS”会以管理员权限启动后台进程并创建按需 WireGuard 隧道。若系统弹出 UAC，请确认程序
  路径后授权。
- 显示“已安全直连”或“已通过 NKN 中继”后，可以用 NAS 的虚拟 IP 访问飞牛。只向覆盖网络地址添加
  路由，普通上网不受影响。
- **关闭窗口不会断开**：程序缩到右下角托盘，连接保持。左键点击托盘图标打开窗口；右键菜单可以连接、
  断开或“退出”。“退出”会断开隧道并结束程序。
- 同一用户只运行一个客户端；再次启动会直接打开已有窗口。
- 客户端不会改动其他 WireGuard 隧道。
- 若后台启动失败，窗口会显示错误；也可查看 `%LOCALAPPDATA%\NKNGuard\last-error.txt`。此文件不包含
  配对密钥，提交问题前仍应检查并删去个人地址。

## 使用人数统计

窗口中的“NKNGuard 使用人数”卡片显示最近 24 小时 / 30 天 / 90 天的活跃设备数，并提供开关。开关与
后台连接进程共用同一设置。说明见 [USAGE_STATS.md](USAGE_STATS.md)。

## 自行编译

使用 Go 1.25.7 或更新版本，在仓库根目录执行（PowerShell）：

```powershell
go test -tags "nknsdk libp2pdht" ./...
cd cmd/nknguard
go run github.com/tc-hib/go-winres@v0.3.3 simply --arch amd64 --manifest gui --icon winres/icon.png --product-name NKNGuard
cd ../..
go build -tags "nknsdk libp2pdht" -trimpath -ldflags "-H=windowsgui -X main.guiBuild=1" -o NKNGuard-Windows.exe ./cmd/nknguard
```

`go-winres` 生成 `cmd/nknguard/rsrc_windows_amd64.syso`，其中包含程序图标和启用 Windows 通用控件 v6
的清单文件。**不能省略**：没有这个清单，原生控件无法正常创建。

## 测试情况

界面代码已通过 Windows 交叉编译和单元测试，并在 Wine 中运行检查过布局（上面的截图即来自 Wine，
数据为演示数据）。真实 Windows 上的托盘、UAC 授权、WireGuard 隧道，以及实际 fnOS 与多种 NAT 下的
端到端验证仍待完成；请先在非关键设备上试用，并通过 [安全报告](../SECURITY.md) 反馈漏洞。
