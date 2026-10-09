package io.github.viperboss.nknguard.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.LocalSocket
import android.net.LocalSocketAddress
import android.net.Network
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import io.github.viperboss.nknguard.NkgApp
import io.github.viperboss.nknguard.R
import io.github.viperboss.nknguard.core.CoreException
import io.github.viperboss.nknguard.core.NetworkInfo
import io.github.viperboss.nknguard.ui.MainActivity
import io.github.viperboss.nknguard.ui.Text
import org.json.JSONObject
import java.security.SecureRandom
import java.util.concurrent.Executors
import java.util.concurrent.Future
import java.util.concurrent.TimeUnit

/**
 * The VPN. It exists only between the user tapping Connect and Disconnect.
 *
 * Routing: the interface carries only the overlay prefix (10.88.0.0/16) and no
 * DNS servers, so ordinary traffic and name resolution are untouched. The app
 * itself is excluded from the VPN, which keeps the core's NKN connections and
 * WireGuard's own UDP packets on the real network — the same guarantee
 * VpnService.protect() gives, but for every socket the core's libraries open.
 *
 * The TUN file descriptor is handed to the core and this service closes its own
 * copy, so the core holds the only one: if the core dies, the kernel removes the
 * interface immediately rather than leaving a dead VPN behind.
 */
class NkgVpnService : VpnService(), NkgApp.Listener {
    private val app get() = application as NkgApp
    private val executor = Executors.newSingleThreadExecutor { Thread(it, "nkg-vpn").apply { isDaemon = true } }
    @Volatile private var connected = false
    @Volatile private var stopping = false
    private var networkCallback: ConnectivityManager.NetworkCallback? = null

    override fun onCreate() {
        super.onCreate()
        app.addListener(this)
        createChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_DISCONNECT -> {
                stopping = true
                executor.execute {
                    if (disconnect()) stopSelf()
                }
            }
            else -> {
                // Started without our action: the system restarted us, or
                // always-on VPN is configured. Only connect when paired.
                goForeground(Text.notificationConnecting)
                executor.execute { connectOrStop() }
            }
        }
        return START_NOT_STICKY
    }

    private fun connectOrStop() {
        if (stopping) return
        try {
            connect()
        } catch (error: Exception) {
            val message = error.message ?: error.toString()
            app.core.logs.add("connect failed: $message")
            val stopped = disconnect()
            reportProblem(message)
            if (stopped) stopSelf()
        }
    }

    private fun connect() {
        if (connected) return
        app.ensureCore()
        // The core may have been started on a previous Wi-Fi/mobile network
        // while the VPN was disconnected. Refresh before candidate gathering.
        app.core.call("network", NetworkInfo.describe(this))
        val prepared = app.core.call("prepare")
        val overlay = prepared.getString("route_cidr")
        val (routeAddress, routeBits) = overlay.split("/").let { it[0] to it[1].toInt() }
        val builder = Builder()
            .setSession("NKNGuard")
            .addAddress(prepared.getString("virtual_ip"), 32)
            .addRoute(routeAddress, routeBits)
            .setMtu(prepared.getInt("mtu"))
            .addDisallowedApplication(packageName)
            .setConfigureIntent(mainIntent())
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            // Follow the underlying network's metering instead of marking
            // the whole phone metered.
            builder.setMetered(false)
        }
        val tunnel: ParcelFileDescriptor = builder.establish()
            ?: throw CoreException("系统没有授予 VPN 权限，请重新点击连接")
        try {
            val token = newToken()
            val response: Future<JSONObject> = app.worker.submit<JSONObject> {
                app.core.call("connect", JSONObject().put("token", token), timeoutMillis = 30_000)
            }
            handOver(tunnel, token)
            response.get(35, TimeUnit.SECONDS)
        } catch (error: java.util.concurrent.ExecutionException) {
            throw error.cause ?: error
        } finally {
            // The core has its own copy now, or failed; either way ours goes.
            tunnel.close()
        }
        connected = true
        watchNetwork()
        app.refreshStatus()
    }

    /** Sends the TUN descriptor to the core over its private Unix socket. */
    private fun handOver(tunnel: ParcelFileDescriptor, token: String) {
        LocalSocket().use { socket ->
            socket.connect(LocalSocketAddress(app.core.fdSocket.absolutePath, LocalSocketAddress.Namespace.FILESYSTEM))
            socket.soTimeout = 5_000
            socket.setFileDescriptorsForSend(arrayOf(tunnel.fileDescriptor))
            socket.outputStream.write("$token\n".toByteArray(Charsets.US_ASCII))
            socket.outputStream.flush()
            val reply = socket.inputStream.bufferedReader().readLine()
            if (reply != "ok") throw CoreException("VPN 接口交接失败：$reply")
        }
    }

    private fun disconnect(): Boolean {
        stopping = true
        unwatchNetwork()
        if (app.core.isRunning) {
            try {
                app.core.call("disconnect", timeoutMillis = 15_000)
            } catch (error: Exception) {
                app.core.logs.add("disconnect failed: ${error.message}")
                try {
                    app.stopCore()
                } catch (stopError: Exception) {
                    reportProblem("断开失败：${stopError.message}")
                    return false
                }
            }
        }
        connected = false
        runCatching { app.refreshStatus() }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            stopForeground(STOP_FOREGROUND_REMOVE)
        } else {
            @Suppress("DEPRECATION")
            stopForeground(true)
        }
        return true
    }

    private fun watchNetwork() {
        val manager = getSystemService(ConnectivityManager::class.java) ?: return
        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) = changed()
            override fun onLinkPropertiesChanged(network: Network, linkProperties: android.net.LinkProperties) = changed()
            override fun onLost(network: Network) = changed()

            private fun changed() {
                if (stopping) return
                runCatching { executor.execute {
                    if (!connected) return@execute
                    // A queued event may describe an old network or the VPN.
                    // Use the current physical network for both operations.
                    val physical = NetworkInfo.underlying(this@NkgVpnService)
                    setUnderlyingNetworks(physical?.let { arrayOf(it) })
                    runCatching { app.core.call("network", NetworkInfo.describe(this@NkgVpnService, physical)) }
                } }
            }
        }
        // The app is outside its own VPN, so its default network is the real
        // Wi-Fi or mobile data network.
        manager.registerDefaultNetworkCallback(callback)
        networkCallback = callback
    }

    private fun unwatchNetwork() {
        val callback = networkCallback ?: return
        networkCallback = null
        runCatching { getSystemService(ConnectivityManager::class.java)?.unregisterNetworkCallback(callback) }
    }

    override fun onRevoke() {
        // Another VPN took over or the user switched ours off in Settings.
        executor.execute {
            if (disconnect()) stopSelf()
        }
    }

    override fun onDestroy() {
        stopping = true
        unwatchNetwork()
        app.removeListener(this)
        // Cleanup continues on the worker; lifecycle callbacks must never
        // wait for IPC or process termination on Android's main thread.
        executor.execute { disconnect() }
        executor.shutdown()
        super.onDestroy()
    }

    // ---- state from the core -------------------------------------------------

    override fun onStatus(status: JSONObject) {
        if (!connected) return
        if (!status.optBoolean("connected")) {
            // The core ended the session itself (for example after a
            // revocation); follow it.
            executor.execute {
                if (disconnect()) stopSelf()
            }
            return
        }
        notify(Text.phaseTitle(status), Text.notificationDetail(status))
    }

    override fun onRevoked(message: String) {
        executor.execute {
            val stopped = disconnect()
            reportProblem(message)
            if (stopped) stopSelf()
        }
    }

    override fun onCoreProblem(message: String) {
        if (!connected) return
        connected = false
        executor.execute {
            val stopped = disconnect()
            reportProblem(message)
            if (stopped) stopSelf()
        }
    }

    // ---- notification -----------------------------------------------------------

    private fun createChannel() {
        val manager = getSystemService(NotificationManager::class.java) ?: return
        manager.createNotificationChannel(
            NotificationChannel(CHANNEL, "NKNGuard 连接状态", NotificationManager.IMPORTANCE_LOW).apply {
                description = "显示 NKNGuard 与 NAS 的连接状态"
                setShowBadge(false)
            },
        )
    }

    private fun mainIntent(): PendingIntent = PendingIntent.getActivity(
        this, 0, Intent(this, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP),
        PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
    )

    private fun notification(title: String, detail: String): Notification {
        val stop = PendingIntent.getService(
            this, 1, Intent(this, NkgVpnService::class.java).setAction(ACTION_DISCONNECT),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        return Notification.Builder(this, CHANNEL)
            .setSmallIcon(R.drawable.ic_stat_tunnel)
            .setContentTitle(title)
            .setContentText(detail)
            .setContentIntent(mainIntent())
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .addAction(Notification.Action.Builder(null, "断开", stop).build())
            .build()
    }

    private fun goForeground(title: String) {
        val notification = notification(title, "")
        if (Build.VERSION.SDK_INT >= 34) {
            try {
                startForeground(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED)
            } catch (_: Exception) {
                startForeground(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
            }
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
    }

    private fun notify(title: String, detail: String) {
        getSystemService(NotificationManager::class.java)?.notify(NOTIFICATION_ID, notification(title, detail))
    }

    private fun reportProblem(message: String) {
        val manager = getSystemService(NotificationManager::class.java) ?: return
        manager.notify(
            PROBLEM_ID,
            Notification.Builder(this, CHANNEL)
                .setSmallIcon(R.drawable.ic_stat_tunnel)
                .setContentTitle(if (connected) "NKNGuard 连接问题" else "NKNGuard 已断开")
                .setContentText(message)
                .setStyle(Notification.BigTextStyle().bigText(message))
                .setContentIntent(mainIntent())
                .setAutoCancel(true)
                .build(),
        )
    }

    companion object {
        private const val CHANNEL = "tunnel"
        private const val NOTIFICATION_ID = 1
        private const val PROBLEM_ID = 2
        const val ACTION_CONNECT = "io.github.viperboss.nknguard.CONNECT"
        const val ACTION_DISCONNECT = "io.github.viperboss.nknguard.DISCONNECT"

        private fun newToken(): String {
            val bytes = ByteArray(16).also { SecureRandom().nextBytes(it) }
            return bytes.joinToString("") { "%02x".format(it) }
        }

        /** VpnService.prepare must have returned null before this is called. */
        fun connect(context: Context) {
            val intent = Intent(context, NkgVpnService::class.java).setAction(ACTION_CONNECT)
            context.startForegroundService(intent)
        }

        fun disconnect(context: Context) {
            context.startService(Intent(context, NkgVpnService::class.java).setAction(ACTION_DISCONNECT))
        }
    }
}
