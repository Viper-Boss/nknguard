package io.github.viperboss.nknguard.ui

import android.app.Activity
import android.app.AlertDialog
import android.content.Intent
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.provider.Settings
import io.github.viperboss.nknguard.NkgApp
import org.json.JSONObject
import java.io.File
import java.net.URL
import java.security.MessageDigest
import javax.net.ssl.HttpsURLConnection

// Package signature verification also covers APKs selected from local storage.
// Network work runs independently of the VPN/session command executor.
class UpdateActions(private val activity: Activity, private val app: NkgApp, private val report: (String) -> Unit) {
    companion object { const val PICK_APK = 204; private const val MAX_SIZE = 160L * 1024 * 1024 }
    @Volatile private var busy = false
    private val packageName get() = activity.packageName
    private val directory get() = File(activity.cacheDir, "updates").apply { mkdirs() }

    private fun ui(work: () -> Unit) = activity.runOnUiThread { if (!activity.isFinishing && !activity.isDestroyed) work() }
    private fun work(task: () -> Unit) {
        if (busy) { report("更新任务正在进行，请稍候"); return }
        busy = true
        Thread({
            try { task() } catch (error: Exception) { ui { report("更新失败：${error.message ?: error.javaClass.simpleName}") } }
            finally { busy = false }
        }, "NKNGuard-updates").start()
    }

    @Suppress("DEPRECATION")
    private fun installed(): PackageInfo = activity.packageManager.getPackageInfo(packageName, certificateFlags())
    private fun certificateFlags() = if (Build.VERSION.SDK_INT >= 28) PackageManager.GET_SIGNING_CERTIFICATES else PackageManager.GET_SIGNATURES
    @Suppress("DEPRECATION")
    private fun code(info: PackageInfo) = if (Build.VERSION.SDK_INT >= 28) info.longVersionCode else info.versionCode.toLong()
    @Suppress("DEPRECATION")
    private fun certificates(info: PackageInfo): Set<String> {
        val values = if (Build.VERSION.SDK_INT >= 28) info.signingInfo?.apkContentsSigners else info.signatures
        return values?.map { signature -> MessageDigest.getInstance("SHA-256").digest(signature.toByteArray()).joinToString("") { "%02x".format(it.toInt() and 255) } }?.toSet() ?: emptySet()
    }

    fun check() {
        report("正在检查 GitHub 发布版本…")
        work {
            app.ensureCore()
            val current = installed().versionName.orEmpty().removeSuffix("-debug")
            val result = app.core.call("check_update", JSONObject().put("current", current), timeoutMillis = 50_000)
            ui {
                if (!result.optBoolean("available")) { report("当前已是最新发布版本：$current"); return@ui }
                val asset = result.optJSONObject("asset")
                if (asset == null) { report("发现 ${result.optString("latest")}，该发布未提供可验证 APK"); return@ui }
                report("发现新版本：${result.optString("latest")}")
                AlertDialog.Builder(activity).setTitle("发现新版本")
                    .setMessage("当前：$current\n最新：${result.optString("latest")}\n\n下载后由系统安装器确认升级，NAS 配对和设置会保留。")
                    .setNegativeButton("稍后", null).setPositiveButton("下载更新") { _, _ -> download(result.optString("download_url"), asset) }.show()
            }
        }
    }

    private fun download(location: String, asset: JSONObject) {
        work {
            val url = URL(location)
            val official = (url.host == "github.com" && url.path.startsWith("/Viper-Boss/nknguard/releases/download/")) ||
                (url.host == "api.github.com" && Regex("/repos/Viper-Boss/nknguard/releases/assets/[0-9]+").matches(url.path))
            require(url.protocol == "https" && url.userInfo == null && url.port == -1 && official) { "下载地址不是官方发布页" }
            val expected = asset.getLong("size")
            require(expected in 1..MAX_SIZE) { "安装包大小无效" }
            val connection = url.openConnection() as HttpsURLConnection
            connection.connectTimeout = 20_000; connection.readTimeout = 25_000
            connection.setRequestProperty("User-Agent", "NKNGuard-Android-update")
            if (url.host == "api.github.com") connection.setRequestProperty("Accept", "application/octet-stream")
            val pending = File(directory, "download.tmp")
            try {
                require(connection.responseCode == 200) { "GitHub 下载失败：${connection.responseCode}" }
                ui { report("正在下载更新…") }
                connection.inputStream.use { input -> copyLimited(input, pending) }
                require(pending.length() == expected) { "下载不完整" }
                val digest = MessageDigest.getInstance("SHA-256")
                pending.inputStream().use { input -> val buffer = ByteArray(64 * 1024); while (true) { val count = input.read(buffer); if (count < 0) break; digest.update(buffer, 0, count) } }
                val hash = digest.digest().joinToString("") { "%02x".format(it.toInt() and 255) }
                require(hash.equals(asset.getString("sha256"), ignoreCase = true)) { "安装包完整性校验失败" }
                accept(pending)
            } finally { connection.disconnect(); pending.delete() }
        }
    }

    fun chooseLocal() {
        activity.startActivityForResult(Intent(Intent.ACTION_OPEN_DOCUMENT).apply { addCategory(Intent.CATEGORY_OPENABLE); type = "application/vnd.android.package-archive" }, PICK_APK)
    }

    fun importApk(uri: Uri) {
        work {
            val pending = File(directory, "import.tmp")
            try {
                (activity.contentResolver.openInputStream(uri) ?: error("无法读取文件")).use { copyLimited(it, pending) }
                accept(pending)
            } finally { pending.delete() }
        }
    }

    private fun copyLimited(input: java.io.InputStream, target: File) {
        target.outputStream().use { output ->
            val buffer = ByteArray(64 * 1024); var total = 0L
            while (true) { val count = input.read(buffer); if (count < 0) break; total += count; require(total <= MAX_SIZE) { "安装包超过 160 MB" }; output.write(buffer, 0, count) }
        }
    }

    private fun accept(pending: File) {
        val candidate = activity.packageManager.getPackageArchiveInfo(pending.absolutePath, certificateFlags()) ?: error("不是有效的 APK")
        val current = installed()
        require(candidate.packageName == packageName) { "安装包不属于当前 NKNGuard 客户端" }
        require(code(candidate) > code(current)) { "安装包版本必须高于当前版本" }
        val signatures = certificates(candidate)
        require(signatures.isNotEmpty() && signatures == certificates(current)) { "安装包签名不同，请使用原发布渠道的安装包" }
        val target = File(directory, "latest.apk")
        target.delete()
        require(pending.renameTo(target)) { "无法暂存安装包" }
        ui { report("签名与版本验证通过，请确认系统安装窗口"); install() }
    }

    fun install() {
        if (!File(directory, "latest.apk").isFile) { report("还没有已验证的更新包"); return }
        if (!activity.packageManager.canRequestPackageInstalls()) {
            AlertDialog.Builder(activity).setTitle("允许安装应用更新")
                .setMessage("请允许 NKNGuard 安装应用，然后返回这里点击“安装已下载更新”。")
                .setNegativeButton("稍后", null).setPositiveButton("前往设置") { _, _ -> activity.startActivity(Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES, Uri.parse("package:$packageName"))) }.show()
            return
        }
        activity.startActivity(Intent(Intent.ACTION_VIEW).apply {
            setDataAndType(Uri.parse("content://$packageName.updates/latest.apk"), "application/vnd.android.package-archive")
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        })
    }
}
