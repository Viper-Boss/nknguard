package io.github.viperboss.nknguard

import android.app.Application
import android.os.Build
import android.os.Handler
import android.os.Looper
import io.github.viperboss.nknguard.core.CoreException
import io.github.viperboss.nknguard.core.CoreProcess
import io.github.viperboss.nknguard.core.NetworkInfo
import io.github.viperboss.nknguard.core.NasRegistry
import io.github.viperboss.nknguard.core.SecretVault
import io.github.viperboss.nknguard.core.StatusRecovery
import io.github.viperboss.nknguard.core.CrashReport
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
    lateinit var nasRegistry: NasRegistry
        private set
    @Volatile var profileBusy = false
    @Volatile private var profileEpoch = 0L

    /** Background work that talks to the core. Never block the main thread. */
    val worker: ExecutorService = Executors.newSingleThreadExecutor { Thread(it, "nkg-worker").apply { isDaemon = true } }

    private val main = Handler(Looper.getMainLooper())
    private val listeners = CopyOnWriteArrayList<Listener>()
    private val initLock = Any()
    private val stateLock = Any()
    @Volatile private var initialized = false
    @Volatile private var deliberateStop = false

    @Volatile var info: JSONObject = JSONObject()
        private set
    @Volatile var status: JSONObject = JSONObject().put("phase", "idle")
        private set
    @Volatile var pairStatus: JSONObject? = null
        private set

    override fun onCreate() {
        super.onCreate()
        nasRegistry = NasRegistry(filesDir)
        configureCore()
        worker.execute { runCatching { ensureCore() }.onFailure { publishUnavailable(it.message ?: "核心启动失败") } }
    }

    private fun configureCore() {
        val epoch = ++profileEpoch
        val directory = nasRegistry.directory()
        val currentVault = SecretVault(this, directory)
        vault = currentVault
        core = CoreProcess(this, { name, data ->
            if (epoch == profileEpoch) handleEvent(name, data, currentVault, epoch)
        }, { generation ->
            if (epoch == profileEpoch && generation == core.generation) {
                initialized = false
                if (!deliberateStop) {
                    publishUnavailable("NKNGuard 核心已退出，可点击连接恢复")
                    main.post { if (epoch == profileEpoch) listeners.forEach { it.onCoreProblem("NKNGuard 核心已退出") } }
                }
            }
        }, directory)
    }

    /** Called only after the VPN service has completed tunnel teardown. */
    fun selectNas(id: String) {
        synchronized(initLock) {
            if (nasRegistry.active().id == id) return
            deliberateStop = true
            try {
                core.stop()
                initialized = false
                synchronized(stateLock) {
                    nasRegistry.select(id)
                    configureCore()
                    info = JSONObject()
                    status = JSONObject().put("phase", "idle")
                    pairStatus = null
                }
                ensureCore()
            } finally { deliberateStop = false }
        }
    }

    fun addAndPair(uri: String, name: String) {
        val invite = core.call("parse_invite", JSONObject().put("uri", uri))
        val known = nasRegistry.findNAS(invite.getString("nas_id"))
        val entry = known ?: if (!status.optBoolean("paired") && nasRegistry.active().nasId.isEmpty()) nasRegistry.active() else nasRegistry.add()
        selectNas(entry.id)
        if (status.optBoolean("paired") && !status.optBoolean("revoked")) {
            publishStatus(status)
            return
        }
        core.call("pair", JSONObject().put("uri", uri).put("name", name))
    }

    fun removeNas(id: String) {
        if (nasRegistry.active().id == id) {
            core.call("forget", timeoutMillis = 20_000)
            val next = nasRegistry.list().firstOrNull { it.id != id } ?: nasRegistry.add()
            selectNas(next.id)
        }
        val directory = nasRegistry.directory(id)
        nasRegistry.remove(id)
        if (id == "legacy") {
            java.io.File(directory, "core").deleteRecursively()
            java.io.File(directory, "secrets.bin").delete()
        } else { directory.deleteRecursively() }
        publishStatus(status)
    }

    fun addListener(listener: Listener) = listeners.add(listener)
    fun removeListener(listener: Listener) = listeners.remove(listener)

    /** Stops a stuck VPN core; serialize with initialization/restart. */
    fun stopCore() {
        synchronized(initLock) {
            deliberateStop = true
            try {
                core.stop()
                initialized = false
                publishUnavailable("连接已断开，正在恢复核心")
            } finally {
                deliberateStop = false
            }
        }
    }

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
            publishStatus(core.call("status", timeoutMillis = 5_000))
            return info
        }
    }

    /** Asks the core for its status and publishes it. Blocking. */
    fun refreshStatus(): JSONObject {
        synchronized(initLock) {
        val current = try {
            if (!core.isRunning || !initialized) ensureCore()
            core.call("status", timeoutMillis = 5_000)
        } catch (error: CoreException) {
            StatusRecovery.unavailable(status, error.message ?: "核心暂时无法响应")
        }
        publishStatus(current)
        return current
        }
    }

    private fun publishStatus(current: JSONObject, epoch: Long = profileEpoch) {
        synchronized(stateLock) {
            if (epoch != profileEpoch) return
            status = current
            runCatching { nasRegistry.remember(current) }
            main.post { if (epoch == profileEpoch) listeners.forEach { it.onStatus(current) } }
        }
    }

    private fun publishUnavailable(message: String) = publishStatus(StatusRecovery.unavailable(status, message))

    private fun handleEvent(name: String, data: JSONObject, currentVault: SecretVault, epoch: Long) {
        when (name) {
            // Must finish before the next line is read: the response that
            // follows may report success that depends on this secret.
            "secrets" -> currentVault.save(data.getJSONObject("values").let { values ->
                values.keys().asSequence().associateWith { values.getString(it) }
            })
            "status" -> publishStatus(data, epoch)
            "pair_status" -> {
                pairStatus = data
                main.post { if (epoch == profileEpoch) listeners.forEach { it.onPairStatus(data) } }
                if (data.optString("stage") == "approved") worker.execute { synchronized(initLock) { if (epoch == profileEpoch) runCatching { info = core.call("init", JSONObject()) } } }
            }
            "revoked" -> {
                val message = data.optString("message", "NAS 已撤销本机授权")
                main.post { if (epoch == profileEpoch) listeners.forEach { it.onRevoked(message) } }
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
            append("\ncore_process: running=${this@NkgApp.core.isRunning} generation=${this@NkgApp.core.generation}\n")
            // Only fixed lifecycle records with a numeric exit code. Do not
            // export arbitrary stderr, which could contain sensitive data.
            this@NkgApp.core.logs.snapshot().filter { it.matches(Regex("core exited with status -?[0-9]+")) }
                .takeLast(5).forEach { append(it).append('\n') }
            val crash = CrashReport.extract(this@NkgApp.core.logs.snapshot())
            if (crash.isNotEmpty()) {
                append("\nlast core crash (redacted, memory only):\n")
                crash.forEach { append(it).append('\n') }
            }
        }
    }
}
