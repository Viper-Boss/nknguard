# Android 预览包的固定签名

2026-10-09 交付的 `NKNGuard-Android-0.2.6.apk` 已由维护者固定预览证书重新签名。
包名为 `io.github.viperboss.nknguard.debug`，versionCode 为 7。

证书 SHA256：

```text
c3edab763599112cca13c9aa9ba0a5a380cdc0139030c19dab93af22df601d23
```

## 后续交付流程

1. 从成功的 GitHub Actions 运行下载 `NKNGuard-android-debug`，核对构建来源和哈希。
2. 使用维护者保管的同一把预览私钥签名；版本号递增，包名保持一致。
3. 用 `apksigner verify --verbose --print-certs` 检查签名，并核对上述指纹。
4. 交付维护者签名后的包，再验证手机覆盖安装、保留身份及配对。

CI 的 `app-debug.apk` 仍使用临时调试签名，不是持续升级的交付包。
CI 只导出公开签名工具和校验过的运行时，不持有维护者私钥。
维护者的 NAS 私有签名目录独立于应用安装目录，保留已有私钥与
`sign-apk.sh INPUT.apk OUTPUT.apk` 工具，并有管理员访问限制及本地私有备份。
不要重复生成签名证书，也不要将密钥、密码、私有备份提交到仓库或公开构件。

0.2.5 及之前的 CI 调试包与固定证书不同，需要一次迁移并重新配对。
本次已验证 APK v2/v3 签名有效，重复签名的证书指纹一致；手机上的覆盖升级
与蜂窝网络端到端稳定性仍需要实机测试。

命令及密码文件格式参考 [Android 官方 apksigner 文档](https://developer.android.com/tools/apksigner)。
