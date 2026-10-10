package io.github.viperboss.nknguard.ui

import android.Manifest
import android.app.Activity
import android.app.AlertDialog
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Intent
import android.content.pm.PackageManager
import android.content.res.Configuration
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.text.InputType
import android.util.TypedValue
import android.view.Gravity
import android.view.View
import android.view.WindowInsets
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import io.github.viperboss.nknguard.NkgApp
import io.github.viperboss.nknguard.core.StatusRecovery
import io.github.viperboss.nknguard.vpn.NkgVpnService
import org.json.JSONObject
import java.time.OffsetDateTime

class MainActivity : Activity(), NkgApp.Listener {
    private val app get() = application as NkgApp
    private val main = Handler(Looper.getMainLooper())
    private lateinit var palette: Palette

    private lateinit var deviceLine: TextView
    private lateinit var statusDot: View
    private lateinit var statusTitle: TextView
    private lateinit var statusHint: TextView
    private lateinit var connectButton: Button
    private lateinit var retryButton: Button
    private lateinit var pairCard: LinearLayout
    private lateinit var pairTitle: TextView
    private lateinit var pairCode: TextView
    private lateinit var pairDetail: TextView
    private lateinit var pairCancel: Button
    private lateinit var rows: LinearLayout
    private lateinit var scanButton: Button
    private lateinit var pasteButton: Button
    private lateinit var forgetButton: Button
    private lateinit var usageCounts: TextView
    private lateinit var usageNote: TextView
    private lateinit var nasCards: LinearLayout
    private lateinit var connectionScene: ConnectionSceneView
    private lateinit var nasHeading: TextView
    private lateinit var accessLine: TextView
    private var nasListStamp = ""

    private var status = JSONObject()
    private var pairing: JSONObject? = null
    private var busy = false

    private val ticker = object : Runnable {
        override fun run() {
            render()
            main.postDelayed(this, 1_000)
        }
    }

    // ---- lifecycle ----------------------------------------------------------

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        palette = Palette(resources.configuration.uiMode and Configuration.UI_MODE_NIGHT_MASK == Configuration.UI_MODE_NIGHT_YES)
        setContentView(buildLayout())
        handleIntent(intent)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        handleIntent(intent)
    }

    override fun onResume() {
        super.onResume()
        app.addListener(this)
        status = app.status
        pairing = app.pairStatus?.takeIf { it.optString("stage") in setOf("connecting", "waiting") }
        render()
        background {
            app.ensureCore()
            app.refreshStatus()
        }
        refreshUsage(force = false)
        main.post(ticker)
    }

    override fun onPause() {
        app.removeListener(this)
        main.removeCallbacks(ticker)
        super.onPause()
    }

    private fun handleIntent(intent: Intent?) {
        val data = intent?.data ?: return
        if (data.scheme == "nknguard") {
            intent.data = null
            startPairing(data.toString())
        }
    }

    // ---- core callbacks -------------------------------------------------------

    override fun onStatus(status: JSONObject) {
        this.status = status
        if (status.optBoolean("paired") && !status.optBoolean("revoked") && pairing?.optString("nas_id") == status.optString("nas_id")) pairing = null
        render()
    }

    override fun onPairStatus(status: JSONObject) {
        when (status.optString("stage")) {
            "approved" -> {
                pairing = null
                toast("NAS 已批准本机，可以连接了")
            }
            else -> pairing = status
        }
        background { app.refreshStatus() }
        render()
    }

    override fun onRevoked(message: String) {
        AlertDialog.Builder(this).setTitle("授权已失效").setMessage(message).setPositiveButton("知道了", null).show()
    }

    override fun onCoreProblem(message: String) {
        toast(message)
    }

    // ---- actions ------------------------------------------------------------------

    private fun onConnectClicked() {
        if (status.optString("phase") == "core_unavailable" && (!status.optBoolean("paired") || status.optBoolean("revoked"))) {
            background { app.ensureCore(); app.refreshStatus() }
            return
        }
        if (status.optBoolean("connected")) {
            NkgVpnService.disconnect(this)
            return
        }
        requestNotifications()
        val consent = VpnService.prepare(this)
        if (consent != null) {
            startActivityForResult(consent, REQUEST_VPN)
        } else {
            startVpn()
        }
    }

    private fun startVpn() {
        status = JSONObject(status.toString()).put("phase", "connecting").put("connected", true)
        render()
        NkgVpnService.connect(this)
    }

    private fun requestNotifications() {
        if (Build.VERSION.SDK_INT >= 33 && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), REQUEST_NOTIFICATIONS)
        }
    }

    private fun onScanClicked() {
        if (checkSelfPermission(Manifest.permission.CAMERA) != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(arrayOf(Manifest.permission.CAMERA), REQUEST_CAMERA)
            return
        }
        startActivityForResult(Intent(this, ScanActivity::class.java), REQUEST_SCAN)
    }

    private fun onPasteClicked() {
        val clipboard = getSystemService(ClipboardManager::class.java)
        val text = clipboard?.primaryClip?.takeIf { it.itemCount > 0 }?.getItemAt(0)?.coerceToText(this)?.toString()?.trim()
        if (text.isNullOrEmpty()) {
            toast("剪贴板为空；请先在 NAS 面板复制配对内容")
            return
        }
        startPairing(text)
    }

    override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<out String>, grantResults: IntArray) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode == REQUEST_CAMERA) {
            if (grantResults.firstOrNull() == PackageManager.PERMISSION_GRANTED) {
                onScanClicked()
            } else {
                toast("没有相机权限；可以改用“粘贴配对内容”")
            }
        }
    }

    @Deprecated("Activity result API without AndroidX")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        when (requestCode) {
            REQUEST_VPN -> if (resultCode == RESULT_OK) startVpn() else toast("需要允许 VPN 连接才能访问 NAS")
            REQUEST_SCAN -> data?.getStringExtra(ScanActivity.EXTRA_TEXT)?.let { startPairing(it) }
        }
    }

    private fun startPairing(uri: String) {
        background {
            val invite = app.core.call("parse_invite", JSONObject().put("uri", uri))
            main.post { confirmPairing(uri, invite) }
        }
    }

    private fun confirmPairing(uri: String, invite: JSONObject) {
        val name = EditText(this).apply {
            setText(app.defaultDeviceName)
            inputType = InputType.TYPE_CLASS_TEXT
            setSingleLine()
        }
        val box = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(20), dp(8), dp(20), 0)
            addView(TextView(this@MainActivity).apply {
                text = "将通过 NKN 向这台 NAS 发送配对申请：\n\nNAS 设备 ID：${invite.optString("nas_id")}\nNAS NKN 地址：${short(invite.optString("nas_address"))}\n\n在 NAS 面板上显示的设备名称："
            })
            addView(name)
        }
        AlertDialog.Builder(this)
            .setTitle("配对 NAS")
            .setView(box)
            .setNegativeButton("取消", null)
            .setPositiveButton("发送申请") { _, _ ->
                val chosen = name.text.toString().trim().ifEmpty { app.defaultDeviceName }
                pairing = JSONObject().put("stage", "connecting").put("nas_id", invite.optString("nas_id"))
                    .put("nas_address", invite.optString("nas_address")).put("expires_at", invite.optString("expires_at"))
                render()
                NkgVpnService.addAndPair(this, uri, chosen)
            }
            .show()
    }

    private fun onPairCancel() {
        val stage = pairing?.optString("stage")
        pairing = null
        render()
        if (stage == "connecting" || stage == "waiting") background { app.core.call("pair_cancel") }
    }

    private fun onForgetClicked() {
        AlertDialog.Builder(this)
            .setTitle("删除这台 NAS")
            .setMessage("将断开连接并删除这台 NAS 的本机凭据，其他 NAS 不受影响。建议同时在 NAS 面板撤销本机授权。")
            .setNegativeButton("取消", null)
            .setPositiveButton("解除配对") { _, _ ->
                NkgVpnService.removeNas(this, app.nasRegistry.active().id)
            }
            .show()
    }

    private fun onCopyDiagnostics() {
        background {
            val text = app.diagnostics()
            main.post {
                getSystemService(ClipboardManager::class.java)?.setPrimaryClip(ClipData.newPlainText("NKNGuard 诊断信息", text))
                toast("诊断信息已复制（地址和密钥已脱敏）")
            }
        }
    }

    // ---- anonymous usage statistics ---------------------------------------------------

    /** Reads the counts on a thread of its own: a slow NKN node must not hold up the worker. */
    private fun refreshUsage(force: Boolean) {
        Thread {
            try {
                app.ensureCore()
                val result = app.core.call("usage", JSONObject().put("refresh", force), timeoutMillis = 25_000)
                main.post { renderUsage(result) }
            } catch (error: Exception) {
                main.post { if (::usageNote.isInitialized) usageNote.text = "读取使用人数失败：${error.message ?: error}" }
            }
        }.apply { isDaemon = true }.start()
    }

    private fun renderUsage(result: JSONObject) {
        if (!::usageCounts.isInitialized) return
        val counts = result.optJSONObject("counts") ?: JSONObject()
        fun count(key: String) = if (!counts.has(key) || counts.isNull(key)) "—" else counts.optLong(key).toString()
        usageCounts.text = "24 小时  ${count("day")}     30 天  ${count("month")}     90 天  ${count("quarter")}"
        val enabled = result.optBoolean("enabled")
        val lastCheckIn = result.optString("last_check_in")
        usageNote.text = buildString {
            append(
                when {
                    !enabled -> "本机未参与统计，人数仍可查看。"
                    lastCheckIn.isNotEmpty() && !lastCheckIn.startsWith("0001-") -> "本机已参与统计 · 上次签到 " + lastCheckIn.take(16).replace('T', ' ')
                    else -> "本机已参与统计 · 等待首次签到"
                },
            )
            val error = counts.optString("error")
            if (error.isNotEmpty()) append("\n部分数据读取失败：").append(error)
        }
    }

    private fun copy(label: String, value: String) {
        if (value.isEmpty()) return
        getSystemService(ClipboardManager::class.java)?.setPrimaryClip(ClipData.newPlainText(label, value))
        toast("已复制$label")
    }

    private fun background(work: () -> Unit) {
        app.worker.execute {
            try {
                work()
            } catch (error: Exception) {
                main.post { toast(error.message ?: error.toString()) }
            }
        }
    }

    private fun toast(message: String) = Toast.makeText(this, message, Toast.LENGTH_LONG).show()

    // ---- rendering --------------------------------------------------------------

    private fun render() {
        if (!::statusTitle.isInitialized) return
        val phase = status.optString("phase", "idle")
        val paired = status.optBoolean("paired")
        val revoked = status.optBoolean("revoked") || phase == "revoked"
        val connected = status.optBoolean("connected")
        busy = app.profileBusy
        connectionScene.online = Text.isOnline(status)
        connectionScene.pending = connected && !connectionScene.online
        connectionScene.relay = phase == "relay"
        connectionScene.invalidate()
        nasHeading.text = app.nasRegistry.active().name
        val virtualIP = status.optString("nas_virtual_ip").ifBlank { app.nasRegistry.active().virtualIP }
        accessLine.text = if (virtualIP.isBlank()) "配对后显示你的 NAS 访问地址" else "飞牛访问地址  $virtualIP:5666  ⧉"
        accessLine.setOnClickListener { if (virtualIP.isNotBlank()) copy("NAS 访问地址", "$virtualIP:5666") }
        renderNasCards()

        deviceLine.text = app.info.optString("device_id").let { if (it.isEmpty()) "正在启动核心…" else "本机设备 ID：$it" }
        statusTitle.text = Text.phaseTitle(status)
        val error = status.optString("last_error")
        statusHint.text = listOf(Text.phaseHint(status), if (phase in setOf("waiting", "error", "connecting_nkn", "core_unavailable")) error else "")
            .filter { it.isNotEmpty() }.joinToString("\n")
        (statusDot.background as GradientDrawable).setColor(
            when {
                Text.isOnline(status) -> palette.good
                revoked || phase == "error" -> palette.bad
                connected -> palette.pending
                else -> palette.idle
            },
        )

        connectButton.visibility = if ((paired && !revoked) || phase == "core_unavailable") View.VISIBLE else View.GONE
        connectButton.text = if (connected) "断开" else if (phase == "core_unavailable" && (!paired || revoked)) "重试启动" else "连接"
        style(connectButton, primary = !connected)
        connectButton.isEnabled = !busy
        retryButton.visibility = if (connected && !revoked && status.optString("phase") != "direct") View.VISIBLE else View.GONE
        retryButton.isEnabled = !busy && !status.optBoolean("direct_attempting")
        retryButton.text = if (status.optBoolean("direct_attempting")) "正在尝试直连…" else "重试直连"

        val pairingActive = pairing != null
        scanButton.visibility = if (status.has("paired") && !pairingActive) View.VISIBLE else View.GONE
        scanButton.isEnabled = !busy
        pasteButton.isEnabled = !busy
        pasteButton.visibility = scanButton.visibility
        forgetButton.visibility = if (paired || revoked) View.VISIBLE else View.GONE

        renderPairing()
        if (rows.visibility == View.VISIBLE) renderRows(connected)
    }

    private fun renderNasCards() {
        val devices = app.nasRegistry.list()
        val active = app.nasRegistry.active().id
        val stamp = devices.toString() + active + busy + (pairing != null)
        if (stamp == nasListStamp) return
        nasListStamp = stamp
        nasCards.removeAllViews()
        devices.forEach { entry ->
            val item = card().apply {
                setPadding(dp(16), dp(14), dp(16), dp(14))
                background = GradientDrawable().apply {
                    cornerRadius = dp(18).toFloat()
                    setColor(if (entry.id == active) Color.parseColor("#173D43") else palette.card)
                    setStroke(dp(1), if (entry.id == active) palette.accent else palette.border)
                }
            }
            val line = LinearLayout(this).apply { gravity = Gravity.CENTER_VERTICAL }
            line.addView(TextView(this).apply {
                text = entry.name
                textSize = 17f
                typeface = Typeface.DEFAULT_BOLD
                setTextColor(palette.text)
            }, LinearLayout.LayoutParams(0, -2, 1f))
            line.addView(TextView(this).apply {
                text = "•••"
                textSize = 21f
                gravity = Gravity.CENTER
                setTextColor(palette.muted)
                contentDescription = "管理 ${entry.name}"
                setPadding(dp(10), dp(4), dp(10), dp(4))
                setOnClickListener { manageNas(entry.id, entry.name) }
            })
            item.addView(line)
            item.addView(TextView(this).apply {
                text = (if (entry.id == active) "当前设备" else "点按切换") + "  ·  " + entry.virtualIP.ifBlank { if (entry.nasId.isBlank()) "等待配对" else "已配对" }
                textSize = 12f
                setTextColor(if (entry.id == active) palette.accent else palette.muted)
                setPadding(0, dp(8), 0, 0)
            })
            item.isEnabled = !busy && pairing == null
            item.setOnClickListener {
                if (entry.id != active && !app.profileBusy && pairing == null) {
                    NkgVpnService.selectNas(this, entry.id)
                    toast("正在切换到 ${entry.name}")
                }
            }
            nasCards.addView(item, spaced().apply { topMargin = dp(10) })
        }
    }

    private fun manageNas(id: String, name: String) {
        if (app.profileBusy || pairing != null) return
        AlertDialog.Builder(this).setTitle(name).setItems(arrayOf("重命名", "删除本机配对")) { _, which ->
            if (which == 0) {
                val input = EditText(this).apply { setText(name); setSingleLine() }
                AlertDialog.Builder(this).setTitle("给 NAS 起个名字").setView(input).setNegativeButton("取消", null)
                    .setPositiveButton("保存") { _, _ -> background { app.nasRegistry.rename(id, input.text.toString()); main.post { renderNasCards(); nasHeading.text = app.nasRegistry.active().name } } }.show()
            } else {
                AlertDialog.Builder(this).setTitle("删除 $name？").setMessage("只删除这台 NAS 在手机上的凭据。建议同时在 NAS 面板撤销授权。")
                    .setNegativeButton("取消", null).setPositiveButton("删除") { _, _ -> NkgVpnService.removeNas(this, id) }.show()
            }
        }.show()
    }

    private fun renderPairing() {
        val current = pairing
        pairCard.visibility = if (current == null) View.GONE else View.VISIBLE
        if (current == null) return
        val expires = runCatching { OffsetDateTime.parse(current.optString("expires_at")).toEpochSecond() }.getOrDefault(0L)
        val left = (expires - System.currentTimeMillis() / 1000).coerceAtLeast(0)
        when (current.optString("stage")) {
            "connecting" -> {
                pairTitle.text = "正在连接 NKN 网络并发送申请…"
                pairCode.text = "··· ···"
            }
            "waiting" -> {
                pairTitle.text = "请在 NAS 面板核对验证码后批准"
                pairCode.text = Text.code(current.optString("code"))
            }
            "failed" -> {
                pairTitle.text = "配对未完成"
                pairCode.text = ""
            }
        }
        pairDetail.text = buildString {
            append("NAS：").append(current.optString("nas_id"))
            if (current.optString("stage") == "failed") {
                append("\n").append(current.optString("error"))
            } else if (expires > 0) {
                append("\n二维码剩余有效时间：").append(left / 60).append(" 分 ").append(left % 60).append(" 秒")
            }
        }
        pairCancel.text = if (current.optString("stage") == "failed") "关闭" else "取消配对"
    }

    private fun renderRows(connected: Boolean) {
        rows.removeAllViews()
        fun row(label: String, value: String, copyable: Boolean = false) {
            if (value.isEmpty()) return
            rows.addView(LinearLayout(this).apply {
                orientation = LinearLayout.VERTICAL
                setPadding(0, dp(8), 0, dp(8))
                addView(TextView(this@MainActivity).apply {
                    text = label
                    setTextColor(palette.muted)
                    textSize = 12f
                })
                addView(TextView(this@MainActivity).apply {
                    text = value
                    setTextColor(palette.text)
                    textSize = 15f
                    setTextIsSelectable(!copyable)
                    if (copyable) {
                        typeface = Typeface.MONOSPACE
                        setOnClickListener { copy(label, value) }
                    }
                })
            })
        }
        row("NAS NKN 地址（点按复制）", status.optString("nas_address"), copyable = true)
        row("NAS 设备 ID", status.optString("nas_id"))
        if (connected) {
            row("隧道接管网段", status.optString("route_cidr"))
            row("允许访问范围", status.optString("allowed_cidr").ifEmpty { "等待 NAS 验证信息" })
        }
        row("连接用途", "仅连接已授权 NAS；不提供互联网出口、不接管普通上网。")
        if (connected && status.optString("phase") != "direct") {
            val retryAt = runCatching { OffsetDateTime.parse(status.optString("next_direct_retry")).toInstant().toEpochMilli() }.getOrDefault(0)
            val seconds = maxOf(0, (retryAt - System.currentTimeMillis()) / 1000)
            row("自动尝试直连", if (status.optBoolean("direct_attempting")) "正在探测；失败后恢复中继" else if (seconds > 0) "约 ${seconds} 秒后再次尝试" else "等待 NAS 最新地址，后台自动重试")
            row("切换说明", "直连与中继共用同一个 NAS 虚拟 IP。探测时可能短暂停顿，失败后恢复现有中继。")
        }
        if (connected) row("DHT 发现", if (!status.optBoolean("dht_enabled")) "未启用" else "已启用 · 本机连接 ${status.optInt("dht_peers")} 个节点")
        val nasIP = status.optString("nas_virtual_ip")
        if (nasIP.isNotEmpty()) {
            row("NAS 虚拟 IP（点按复制）", nasIP, copyable = true)
            row("飞牛客户端服务器地址（点按复制）", "$nasIP:5666", copyable = true)
            row("使用方法", "NKNGuard 显示已连接后，在飞牛客户端填写上面的服务器地址。若改过飞牛端口，请替换 5666。")
        } else {
            row("飞牛客户端服务器地址", "连接后自动显示 NAS 虚拟 IP；无需填写 NKN 地址。")
        }
        if (connected) {
            row("本机虚拟 IP", status.optString("virtual_ip"))
            row("链路", Text.path(status))
            row("WireGuard 端点", status.optString("endpoint"))
            row("最近握手", Text.handshake(status))
            row("流量", "接收 ${Text.bytes(status.optLong("rx_bytes"))} · 发送 ${Text.bytes(status.optLong("tx_bytes"))}")
            row("本机 NKN 地址", status.optString("nkn_address").let { if (it.isEmpty()) "连接中…" else short(it) })
        }
    }

    private fun short(address: String): String =
        if (address.length > 28) address.take(18) + "…" + address.takeLast(8) else address

    // ---- layout -------------------------------------------------------------------

    private fun buildLayout(): View {
        val column = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(20), dp(16), dp(20), dp(24))
        }
        column.addView(TextView(this).apply {
            text = "NKNGuard"
            textSize = 30f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(palette.text)
        })
        column.addView(TextView(this).apply {
            text = "我的文件，随时在身边。"
            textSize = 13f
            setTextColor(palette.muted)
            setPadding(0, dp(5), 0, dp(6))
        })
        deviceLine = TextView(this).apply {
            textSize = 12f
            setTextColor(palette.muted)
            setTextIsSelectable(true)
        }
        column.addView(deviceLine)

        val card = card()
        nasHeading = TextView(this).apply {
            textSize = 15f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(palette.accent)
        }
        card.addView(nasHeading)
        connectionScene = ConnectionSceneView(this)
        card.addView(connectionScene, LinearLayout.LayoutParams(-1, dp(160)))
        val head = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
        }
        statusDot = View(this).apply {
            background = GradientDrawable().apply { shape = GradientDrawable.OVAL; setColor(palette.idle) }
        }
        head.addView(statusDot, LinearLayout.LayoutParams(dp(14), dp(14)).apply { marginEnd = dp(12) })
        statusTitle = TextView(this).apply {
            textSize = 22f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(palette.text)
        }
        head.addView(statusTitle)
        card.addView(head)
        statusHint = TextView(this).apply {
            textSize = 14f
            setTextColor(palette.muted)
            setPadding(0, dp(8), 0, 0)
        }
        card.addView(statusHint)
        accessLine = TextView(this).apply {
            textSize = 13f
            setTextColor(palette.accent)
            setPadding(0, dp(14), 0, dp(2))
        }
        card.addView(accessLine)
        column.addView(card, spaced())

        connectButton = button("连接") { onConnectClicked() }
        column.addView(connectButton, spaced())
        retryButton = button("重试直连") {
            background {
                app.core.call("retry_direct")
                main.post { toast("已安排直连探测，NAS 地址保持不变") }
            }
        }.also { style(it, primary = false); it.visibility = View.GONE }
        column.addView(retryButton, spaced())

        pairCard = card().apply { visibility = View.GONE }
        pairTitle = TextView(this).apply {
            textSize = 16f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(palette.text)
        }
        pairCode = TextView(this).apply {
            textSize = 44f
            typeface = Typeface.create(Typeface.MONOSPACE, Typeface.BOLD)
            setTextColor(palette.accent)
            gravity = Gravity.CENTER
            setPadding(0, dp(12), 0, dp(12))
        }
        pairDetail = TextView(this).apply {
            textSize = 13f
            setTextColor(palette.muted)
        }
        pairCancel = button("取消配对") { onPairCancel() }.also { style(it, primary = false) }
        pairCard.addView(pairTitle)
        pairCard.addView(pairCode)
        pairCard.addView(pairDetail)
        pairCard.addView(pairCancel, spaced())
        column.addView(pairCard, spaced())

        column.addView(TextView(this).apply {
            text = "我的 NAS"
            textSize = 19f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(palette.text)
            setPadding(0, dp(24), 0, 0)
        })
        nasCards = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        column.addView(nasCards)

        scanButton = button("＋ 扫码添加 NAS") { onScanClicked() }
        pasteButton = button("粘贴配对内容") { onPasteClicked() }.also { style(it, primary = false) }
        val addActions = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        addActions.addView(scanButton, LinearLayout.LayoutParams(0, -2, 1f).apply { marginEnd = dp(8) })
        addActions.addView(pasteButton, LinearLayout.LayoutParams(0, -2, 1f))
        scanButton.textSize = 14f
        pasteButton.textSize = 14f
        column.addView(addActions, spaced())

        rows = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        val detailCard = card()
        val detailsTitle = TextView(this).apply {
            text = "连接详情与访问地址  ›"
            textSize = 16f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(palette.text)
            setPadding(0, dp(4), 0, dp(4))
            setOnClickListener {
                rows.visibility = if (rows.visibility == View.VISIBLE) View.GONE else View.VISIBLE
                if (rows.visibility == View.VISIBLE) renderRows(status.optBoolean("connected"))
            }
        }
        detailCard.addView(detailsTitle)
        detailCard.addView(rows)
        rows.visibility = View.GONE
        column.addView(detailCard, spaced())

        val usageCard = card()
        usageCard.addView(TextView(this).apply {
            text = "NKNGuard 使用人数"
            textSize = 16f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(palette.text)
        })
        usageCard.addView(TextView(this).apply {
            text = "最近运行过 NKNGuard 的设备数，来自 NKN 链上的匿名订阅"
            textSize = 12f
            setTextColor(palette.muted)
        })
        usageCounts = TextView(this).apply {
            text = "24 小时  —     30 天  —     90 天  —"
            textSize = 17f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(palette.text)
            setPadding(0, dp(10), 0, dp(4))
            setOnClickListener { refreshUsage(force = true) }
        }
        usageCard.addView(usageCounts)
        usageNote = TextView(this).apply {
            text = "正在读取…"
            textSize = 12f
            setTextColor(palette.muted)
        }
        usageCard.addView(usageNote)
        usageCard.addView(TextView(this).apply {
            text = "自动参与匿名使用人数统计，每天最多提交 3 个零手续费 NKN 链上订阅。使用独立派生的统计公钥，不上传设备名、配对、文件或流量信息。点按人数可刷新。"
            textSize = 11f
            setTextColor(palette.muted)
            setPadding(0, dp(6), 0, 0)
        })
        column.addView(usageCard, spaced())

        column.addView(button("复制诊断信息") { onCopyDiagnostics() }.also { style(it, primary = false) }, spaced())
        forgetButton = button("删除当前 NAS") { onForgetClicked() }.also { style(it, primary = false, danger = true) }
        column.addView(forgetButton, spaced())

        return ScrollView(this).apply {
            setBackgroundColor(palette.background)
            isFillViewport = true
            addView(column)
            setOnApplyWindowInsetsListener { view, insets ->
                // Android 15 draws apps edge to edge; keep content clear of the
                // status and navigation bars.
                if (Build.VERSION.SDK_INT >= 30) {
                    val bars = insets.getInsets(WindowInsets.Type.systemBars() or WindowInsets.Type.displayCutout())
                    view.setPadding(bars.left, bars.top, bars.right, bars.bottom)
                } else {
                    @Suppress("DEPRECATION")
                    view.setPadding(insets.systemWindowInsetLeft, insets.systemWindowInsetTop, insets.systemWindowInsetRight, insets.systemWindowInsetBottom)
                }
                insets
            }
        }
    }

    private fun card() = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        setPadding(dp(18), dp(16), dp(18), dp(16))
        background = GradientDrawable().apply {
            cornerRadius = dp(22).toFloat()
            setColor(palette.card)
            setStroke(dp(1), palette.border)
        }
    }

    private fun button(label: String, action: () -> Unit) = Button(this).apply {
        text = label
        isAllCaps = false
        textSize = 16f
        setOnClickListener { action() }
        style(this, primary = true)
    }

    private fun style(button: Button, primary: Boolean, danger: Boolean = false) {
        button.background = GradientDrawable().apply {
            cornerRadius = dp(12).toFloat()
            if (primary) {
                setColor(palette.accent)
            } else {
                setColor(Color.TRANSPARENT)
                setStroke(dp(1), if (danger) palette.bad else palette.border)
            }
        }
        button.setTextColor(if (primary) Color.parseColor("#092A2E") else if (danger) palette.bad else palette.text)
        button.minHeight = dp(54)
    }

    private fun spaced() = LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT).apply {
        topMargin = dp(14)
    }

    private fun dp(value: Int) = TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, value.toFloat(), resources.displayMetrics).toInt()

    private class Palette(dark: Boolean) {
        val background = Color.parseColor("#091522")
        val card = Color.parseColor("#112537")
        val text = Color.parseColor("#EDF5F8")
        val muted = Color.parseColor("#96AEC1")
        val border = Color.parseColor("#20394B")
        val accent = Color.parseColor("#4DE2BE")
        val good = Color.parseColor("#2DA44E")
        val pending = Color.parseColor("#D29922")
        val bad = Color.parseColor("#CF222E")
        val idle = if (dark) Color.parseColor("#6E7681") else Color.parseColor("#8C959F")
    }

    companion object {
        private const val REQUEST_VPN = 1
        private const val REQUEST_SCAN = 2
        private const val REQUEST_CAMERA = 3
        private const val REQUEST_NOTIFICATIONS = 4
    }
}
