package io.github.viperboss.nknguard.core

import android.content.Context
import org.json.JSONObject
import java.io.BufferedReader
import java.io.BufferedWriter
import java.io.File
import java.io.InputStreamReader
import java.io.OutputStreamWriter
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicLong

/** A command the core refused, or the core not answering. */
class CoreException(message: String) : Exception(message)

/**
 * Runs the Go protocol core (lib/<abi>/libnkgcore.so) as a child process and
 * talks to it with one JSON object per line: requests carry an id and get
 * exactly one response; events have no id and arrive in order.
 *
 * Standard input is the core's lifeline: when this app process dies, the pipe
 * closes, the core exits, and the VPN file descriptor it holds closes with it.
 */
class CoreProcess(
    private val context: Context,
    private val onEvent: (name: String, data: JSONObject) -> Unit,
    private val onExit: (generation: Long) -> Unit,
) {
    private class Pending {
        val latch = CountDownLatch(1)
        @Volatile var result: JSONObject? = null
        @Volatile var error: String? = null
    }

    private val lock = Any()
    private var process: Process? = null
    private var writer: BufferedWriter? = null
    private val nextId = AtomicLong(0)
    private val pending = ConcurrentHashMap<Long, Pending>()
    private val generationCounter = AtomicLong(0)

    val logs = LogRing(300)

    /** Where the core listens for the VPN file descriptor. */
    val fdSocket: File get() = File(context.filesDir, "run/tun.sock")

    val isRunning: Boolean
        get() = synchronized(lock) { process?.isAlive == true }

    /** Starts the core if it is not running. Returns true if it was started. */
    fun start(): Boolean {
        synchronized(lock) {
            if (process?.isAlive == true) return false
            val executable = File(context.applicationInfo.nativeLibraryDir, "libnkgcore.so")
            if (!executable.canExecute()) {
                throw CoreException("找不到 NKNGuard 核心程序（${executable.name}），请重新安装应用")
            }
            val stateDir = File(context.filesDir, "core").apply { mkdirs() }
            fdSocket.parentFile?.mkdirs()
            val builder = ProcessBuilder(
                executable.absolutePath,
                "--state-dir", stateDir.absolutePath,
                "--fd-socket", fdSocket.absolutePath,
            )
            builder.environment().apply {
                put("HOME", context.filesDir.absolutePath)
                put("TMPDIR", context.cacheDir.absolutePath)
                // The 32-bit ARM and x86_64 cores are static Linux builds and
                // need to be told where Android keeps its CA certificates.
                put("SSL_CERT_DIR", "/system/etc/security/cacerts")
            }
            val started = builder.start()
            val generation = generationCounter.incrementAndGet()
            process = started
            writer = BufferedWriter(OutputStreamWriter(started.outputStream, Charsets.UTF_8))
            thread("nkg-core-out") { readOutput(started) }
            thread("nkg-core-err") { readLog(started) }
            thread("nkg-core-wait") {
                val code = try { started.waitFor() } catch (_: InterruptedException) { -1 }
                logs.add("core exited with status $code")
                synchronized(lock) {
                    if (process === started) {
                        process = null
                        writer = null
                    }
                }
                failAll("NKNGuard 核心已退出（状态 $code）")
                onExit(generation)
            }
            return true
        }
    }

    private fun thread(name: String, body: () -> Unit) {
        Thread(body, name).apply { isDaemon = true }.start()
    }

    private fun readOutput(source: Process) {
        BufferedReader(InputStreamReader(source.inputStream, Charsets.UTF_8)).useLines { lines ->
            for (line in lines) {
                val message = try { JSONObject(line) } catch (_: Exception) { continue }
                if (message.has("event")) {
                    try {
                        onEvent(message.getString("event"), message.optJSONObject("data") ?: JSONObject())
                    } catch (error: Exception) {
                        logs.add("event handler failed: ${error.message}")
                    }
                    continue
                }
                val waiter = pending.remove(message.optLong("id", -1)) ?: continue
                if (message.optBoolean("ok")) {
                    waiter.result = message.optJSONObject("result") ?: JSONObject()
                } else {
                    waiter.error = message.optString("error", "未知错误")
                }
                waiter.latch.countDown()
            }
        }
    }

    private fun readLog(source: Process) {
        BufferedReader(InputStreamReader(source.errorStream, Charsets.UTF_8)).useLines { lines ->
            lines.forEach { logs.add(it) }
        }
    }

    private fun failAll(reason: String) {
        for (id in pending.keys.toList()) {
            pending.remove(id)?.let {
                it.error = reason
                it.latch.countDown()
            }
        }
    }

    /**
     * Sends one command and waits for its response. Never call this on the
     * main thread.
     */
    fun call(cmd: String, args: JSONObject? = null, timeoutMillis: Long = 30_000): JSONObject {
        val id = nextId.incrementAndGet()
        val waiter = Pending()
        pending[id] = waiter
        val line = JSONObject().put("id", id).put("cmd", cmd).apply { if (args != null) put("args", args) }.toString()
        synchronized(lock) {
            val out = writer
            if (out == null) {
                pending.remove(id)
                throw CoreException("NKNGuard 核心未运行")
            }
            try {
                out.write(line)
                out.write("\n")
                out.flush()
            } catch (error: Exception) {
                pending.remove(id)
                throw CoreException("无法联系 NKNGuard 核心：${error.message}")
            }
        }
        if (!waiter.latch.await(timeoutMillis, TimeUnit.MILLISECONDS)) {
            pending.remove(id)
            throw CoreException("NKNGuard 核心没有响应（$cmd）")
        }
        waiter.error?.let { throw CoreException(it) }
        return waiter.result ?: JSONObject()
    }

    /** Asks the core to exit and makes sure it does. */
    fun stop() {
        val current = synchronized(lock) { process } ?: return
        try {
            call("shutdown", timeoutMillis = 3_000)
        } catch (_: Exception) {
        }
        synchronized(lock) {
            try { writer?.close() } catch (_: Exception) {}
        }
        if (!current.waitFor(3, TimeUnit.SECONDS)) {
            current.destroy()
        }
    }
}

/** A bounded in-memory log of the core's standard error. */
class LogRing(private val capacity: Int) {
    private val lines = ArrayDeque<String>()

    @Synchronized
    fun add(line: String) {
        if (lines.size == capacity) lines.removeFirst()
        lines.addLast(line)
    }

    @Synchronized
    fun snapshot(): List<String> = lines.toList()
}
