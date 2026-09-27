package io.github.viperboss.nknguard.ui

import org.json.JSONObject
import java.util.Locale

/** User-facing wording and formatting, in one place. */
object Text {
    const val notificationConnecting = "正在连接 NAS…"

    fun phaseTitle(status: JSONObject): String = when (status.optString("phase")) {
        "not_paired" -> "未配对"
        "idle" -> "未连接"
        "connecting" -> "正在建立 VPN…"
        "connecting_nkn" -> "正在连接 NKN 网络…"
        "waiting" -> "等待与 NAS 握手…"
        "direct" -> "已连接 · 直连"
        "relay" -> "已连接 · NKN 中继"
        "revoked" -> "授权已失效"
        "error" -> "出错"
        else -> status.optString("phase", "未知")
    }

    fun phaseHint(status: JSONObject): String = when (status.optString("phase")) {
        "not_paired" -> "在 NAS 面板“配对与授权”中生成二维码，然后扫码或粘贴配对内容。"
        "idle" -> if (status.optBoolean("revoked")) "NAS 已撤销本机授权，请重新配对。" else "点击“连接”后才会启动 VPN。"
        "connecting", "connecting_nkn" -> "VPN 只接管 NAS 覆盖网络地址，普通上网不受影响。"
        "waiting" -> "已通过 NKN 找到 NAS，正在尝试直连；无法直连时会自动改用 NKN 中继。"
        "direct" -> "WireGuard 与 NAS 直接握手成功，流量不经过第三方。"
        "relay" -> "WireGuard 密文经 NKN 会话转发；恢复直连后会自动切回。"
        "revoked" -> "NAS 主人已撤销本机授权。本机不会再尝试连接，请解除配对后重新扫码。"
        else -> ""
    }

    fun isOnline(status: JSONObject) = status.optString("phase") in setOf("direct", "relay")

    fun notificationDetail(status: JSONObject): String = buildString {
        status.optString("nas_virtual_ip").takeIf { it.isNotEmpty() }?.let { append("NAS $it · ") }
        append("↓ ").append(bytes(status.optLong("rx_bytes"))).append("  ↑ ").append(bytes(status.optLong("tx_bytes")))
    }

    fun path(status: JSONObject): String = when (status.optString("path")) {
        "direct-wg" -> "WireGuard 直连"
        "nkn-relay" -> "NKN 中继（WireGuard 密文）"
        else -> "无"
    }

    fun bytes(value: Long): String {
        if (value < 1024) return "$value B"
        val units = listOf("KB", "MB", "GB", "TB")
        var scaled = value.toDouble() / 1024
        var index = 0
        while (scaled >= 1024 && index < units.lastIndex) {
            scaled /= 1024
            index++
        }
        return String.format(Locale.ROOT, "%.1f %s", scaled, units[index])
    }

    fun handshake(status: JSONObject): String {
        val at = status.optLong("last_handshake_unix")
        if (at <= 0) return "尚未握手"
        val seconds = (System.currentTimeMillis() / 1000 - at).coerceAtLeast(0)
        val age = when {
            seconds < 60 -> "$seconds 秒前"
            seconds < 3600 -> "${seconds / 60} 分钟前"
            else -> "${seconds / 3600} 小时前"
        }
        return if (status.optBoolean("handshake_fresh")) age else "$age（已过期）"
    }

    fun code(code: String): String = if (code.length == 6) code.substring(0, 3) + " " + code.substring(3) else code
}
