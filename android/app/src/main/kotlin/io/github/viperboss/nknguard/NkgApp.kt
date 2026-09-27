package io.github.viperboss.nknguard

import android.app.Application
import android.os.Build
import android.os.Handler
import android.os.Looper
import io.github.viperboss.nknguard.core.CoreException
import io.github.viperboss.nknguard.core.CoreProcess
import io.github.viperboss.nknguard.core.NetworkInfo
import io.github.viperboss.nknguard.core.SecretVault
import org.json.JSONObject
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

/**
 * Owns the core process and the latest state it reported. Activities and the
 * VPN service observe it through [Listener]; callbacks run on the main thread.
 */
class NkgApp : Application() {
    interface Listener {
        fun onStatus(status: JSONObject) {}
        fun onPairStatus(status: JSONObject) {}
        fun onRevoked(message: String) {}
        fun onCoreProblem(message: String) {}
    }

    lateinit var core: CoreProcess
        private set
    lateinit var vault: SecretVault
        private set

    /** Background work that talks to the core. Never block the main thread. */
    val worker: ExecutorService = Executors.newSingleThreadExecutor { Thread(it, "nkg-worker").apply { isDaemon = true } }

    private val main = Handler(Looper.getMainLooper())
    private val listeners = CopyOnWriteArrayList<Listener>()
    private val initLock = Any()
    @Volatile private var initialized = false

    @Volatile var info: JSONObject = JSONObject()
        private set
    @Volatile var status: JSONObject = JSONObject().put("phase", "idle")
        private set
    @Volatile var pairStatus: JSONObject? = null
        private set

    override fun onCreate() {
        super.onCreate()
        vault = SecretVault(this)
        core = CoreProcess(this, ::handleEvent) {
            // A spurious reset only costs one extra, idempotent init.
            initialized = false
            status = JSONObject().put("phase", "idle")
            main.post { listeners.forEach { it.onCoreProblem("NKNGuard 核心已退出") } }
        }
        worker.execute { runCatching { ensureCore() } }
    }

    fun addListener(listener: Listener) = listeners.add(listener)
    fun removeListener(listener: Listener) = listeners.remove(listener)

    /** Default name the NAS dashboard shows for this phone. */
    val defaultDeviceName: String
        get() = listOf(Build.MANUFACTURER, Build.MODEL).filter { it.isNotBlank() }.joinToString(" ").take(60).ifBlank { "Android" }

    /**
     * Starts the core if needed and gives it the stored secrets. Blocking;
     * call from [worker] or the VPN service's own thread.
     */
    fun ensureCore(): JSONObject {
        synchronized(initLock) {
            if (core.isRunning && initialized) return info
            core.start()
            val secrets = try {
                vault.load()
            } catch (error: SecretVault.VaultException) {
                // The Keystore key is gone (for example after a system
                // restore); the old identity cannot be recovered.
                vault.quarantine()
                main.post { listeners.forEach { it.onCoreProblem("本机密钥已无法读取，已重新生成设备身份，需要重新配对") } }
                emptyMap()
            }
            val args = NetworkInfo.describe(this)
                .put("secrets", JSONObject(secrets))
                .put("device_name", defaultDeviceName)
            info = core.call("init", args)
            initialized = true
            refreshStatus()
            return info
        }
    }

    /** Asks the core for its status and publishes it. Blocking. */
    fun refreshStatus(): JSONObject {
        val current = try {
            core.call("status", timeoutMillis = 5_000)
        } catch (error: CoreException) {
            JSONObject().put("phase", "error").put("last_error", error.message)
        }
        publishStatus(current)
        return current
    }

    private fun publishStatus(current: JSONObject) {
        status = current
        main.post { listeners.forEach { it.onStatus(current) } }
    }

    private fun handleEvent(name: String, data: JSONObject) {
        when (name) {
            // Must finish before the next line is read: the response that
            // follows may report success that depends on this secret.
            "secrets" -> vault.save(data.getJSONObject("values").let { values ->
                values.keys().asSequence().associateWith { values.getString(it) }
            })
            "status" -> publishStatus(data)
            "pair_status" -> {
                pairStatus = data
                main.post { listeners.forEach { it.onPairStatus(data) } }
                if (data.optString("stage") == "approved") worker.execute { runCatching { info = core.call("init", JSONObject()) } }
            }
            "revoked" -> {
                val message = data.optString("message", "NAS 已撤销本机授权")
                main.post { listeners.forEach { it.onRevoked(message) } }
            }
        }
    }

    /** A redacted report the user can paste into an issue. Blocking. */
    fun diagnostics(): String {
        val core = try {
            this.core.call("diagnostics", timeoutMillis = 5_000).optString("text")
        } catch (error: Exception) {
            "core unavailable: ${error.message}\n" + this.core.logs.snapshot().takeLast(40).joinToString("\n")
        }
        val version = try {
            packageManager.getPackageInfo(packageName, 0).versionName
        } catch (_: Exception) {
            "?"
        }
        return buildString {
            append("NKNGuard Android $version\n")
            append("Android ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT}), ${Build.SUPPORTED_ABIS.firstOrNull()}\n")
            append(core)
        }
    }
}
