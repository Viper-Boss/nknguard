# 飞牛 FPK 安装包

分别发布 x86_64（`amd64`）和 ARM64（`arm64`），不要跨架构安装。需要 `wg`、`ip`、应用中心可用的存储空间和 root 权限。安装向导让用户自己设置管理密码，原有身份与配置在升级时保留。

## 构建

从仓库根目录运行（fnpack 使用飞牛官方工具）：

```sh
make release VERSION=v0.2.15-preview.1
sh packaging/fnos/build.sh amd64 v0.2.15-preview.1 "$PWD/dist/nknguard-linux-amd64" dist
sh packaging/fnos/build.sh arm64 v0.2.15-preview.1 "$PWD/dist/nknguard-linux-arm64" dist
```

模板中的 `platform` 会分别设置为 `x86` 和 `arm`，每个 FPK 只包含对应二进制。构建目录不包含配置、密钥或安装过程中生成的资料。

## 安装与更新

在飞牛应用中心启用手动安装，上传对应 FPK 并选择有足够空间的数据卷。命令行也可用 `appcenter-cli install-fpk 包名.fpk --volume 数据卷编号`；已安装同一个应用时该命令执行升级，卷参数会被忽略。

后台默认仅监听 `127.0.0.1:7878`。从电脑建立 SSH 端口转发后打开 `http://127.0.0.1:7878`，用户名 `admin`，密码使用安装时自己设置的密码。不要为安装 FPK 格式化已有资料的大盘；没有应用中心数据卷时使用 [独立服务](../../docs/FNOS_DISK_DEPLOY.md)。

系统更新页面接受发布页的 `NKNGuard-NAS-Update-fnos-<架构>-<版本>.zip`，验证后交给飞牛应用中心升级。应用中心也可直接上传 FPK。独立服务使用 `NAS-Update-linux` 包，两者不能混用。

默认日志仅保留在内存。停止、升级与卸载会清理程序拥有的隧道和防火墙规则；飞牛负责删除应用的 target、配置和数据目录。应用中心是否保留数据请以卸载界面的选择为准。

当前 FPK 已实现两种架构构建，仍需要在各机型的应用中心完成实机验收。现有 ARM64 测试 NAS 使用独立服务，以保留大盘已有数据。
