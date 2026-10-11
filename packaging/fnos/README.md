# 飞牛 FPK 安装包

分别发布 x86_64（`amd64`）和 ARM64（`arm64`），不要跨架构安装。安装包内置对应架构的 `wg` 与 `wireguard-go`，无需预装 wireguard-tools。需要系统 `ip`、应用中心可用的存储空间和 root 权限。首次打开网页向导由用户设置管理用户名和密码，原有身份与配置在升级时保留。

## 构建

从仓库根目录运行（fnpack 使用飞牛官方工具）：

```sh
make release VERSION=v0.2.18-preview.4
# 构建机需 gcc、aarch64-linux-gnu-gcc 与 qemu-aarch64
sh packaging/fnos/build-runtime.sh "$PWD/dist/fnos-runtime"
sh packaging/fnos/build.sh amd64 v0.2.18-preview.4 "$PWD/dist/nknguard-linux-amd64" dist "$PWD/dist/fnos-runtime/amd64"
sh packaging/fnos/build.sh arm64 v0.2.18-preview.4 "$PWD/dist/nknguard-linux-arm64" dist "$PWD/dist/fnos-runtime/arm64"
```

模板中的 `platform` 会分别设置为 `x86` 和 `arm`，每个 FPK 只包含对应二进制。构建目录不包含配置、密钥或安装过程中生成的资料。

## 安装与更新

在飞牛应用中心启用手动安装，上传对应 FPK 并选择有足够空间的数据卷。命令行也可用 `appcenter-cli install-fpk 包名.fpk --volume 数据卷编号`；已安装同一个应用时该命令执行升级，卷参数会被忽略。

安装后从飞牛桌面点击 NKNGuard，或直接打开 `http://NAS局域网IP:7878/`。启动时自动选择默认路由所在的私网 IPv4；不使用容器或 VPN 地址。首次使用按网页向导设置用户名和密码；覆盖升级保留原账号、身份和配对，无需 SSH。不要为安装 FPK 格式化已有资料的大盘；没有应用中心数据卷时使用 [独立服务](../../docs/FNOS_DISK_DEPLOY.md)。

系统更新页面接受发布页的 `NKNGuard-NAS-Update-fnos-<架构>-<版本>.zip`，验证后交给飞牛应用中心升级。应用中心也可直接上传 FPK。独立服务使用 `NAS-Update-linux` 包，两者不能混用。

默认日志仅保留在内存。停止、升级与卸载会清理程序拥有的隧道和防火墙规则；飞牛负责删除应用的 target、配置和数据目录。应用中心是否保留数据请以卸载界面的选择为准。

当前 FPK 已实现两种架构构建，仍需要在各机型的应用中心完成实机验收。现有 ARM64 测试 NAS 使用独立服务，以保留大盘已有数据。

## 0.2.18-preview.2 安装修复

修复 ARM64 和 x86_64 包的空安装向导。飞牛 1.2.0302 拒绝已有但不足 10 字节的向导文件，并提示应用包不符合系统要求；新版显示有效的只读说明，管理账号仍在首次打开网页时设置。修复 x86 包错误地只允许 ARM64 的安装脚本。

构建前后校验向导、平台、版本、ELF 架构、脚本换行与权限，以及 app.tgz 校验值。回归测试：`python3 packaging/fnos/test-packaging.py`。参考：[飞牛用户向导文档](https://developer.fnnas.com/docs/core-concepts/wizard/)。

## 0.2.18-preview.3 依赖与图标修复

内置静态编译的 WireGuard 工具及用户态备用实现，在应用目录运行，不写入系统工具目录。安装、启动、停止和升级统一使用应用工具路径，并补全系统管理工具路径。发布构建实际执行 x86 工具及 ARM64 模拟运行测试，校验两种架构和静态链接；FPK 内附第三方许可与 wg 源码。安装页与应用图标使用 NKNGuard 的蓝绿色 N 标识。

## 0.2.18-preview.4 桌面与访问修复

补齐 `desktop_uidir`、桌面入口配置和两种尺寸图标。启动使用 `--dashboard-listen auto-lan:7878`，在运行时覆盖旧版的本机监听地址，不改写已有配置和密钥。保留网页登录与 Host / Origin 校验。参考：[飞牛应用入口文档](https://developer.fnnas.com/docs/core-concepts/app-entry/)。
