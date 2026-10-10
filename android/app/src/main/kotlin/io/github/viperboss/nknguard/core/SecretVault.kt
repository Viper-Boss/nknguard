package io.github.viperboss.nknguard.core

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import org.json.JSONObject
import java.io.File
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * The only persistent copy of the device's key material: root identity seed,
 * WireGuard private key, NKN seed and the network join secret.
 *
 * The file is AES-256-GCM encrypted with a key generated inside the Android
 * Keystore. That key never leaves the Keystore (and its secure hardware where
 * the phone has one), so copying the app's files to another device yields
 * nothing usable. Consequence, stated to the user: backups are disabled and a
 * new phone must be paired again.
 */
class SecretVault(context: Context, directory: File = context.filesDir) {
    private val file = File(directory, "secrets.bin")

    class VaultException(message: String, cause: Throwable? = null) : Exception(message, cause)

    private fun key(): SecretKey {
        val store = KeyStore.getInstance(KEYSTORE).apply { load(null) }
        (store.getKey(ALIAS, null) as? SecretKey)?.let { return it }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE)
        generator.init(
            KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build(),
        )
        return generator.generateKey()
    }

    val exists: Boolean get() = file.exists()

    /** Returns the stored secrets (base64 values, as the core sends them). */
    @Synchronized
    fun load(): Map<String, String> {
        if (!file.exists()) return emptyMap()
        try {
            val raw = file.readBytes()
            require(raw.size > MAGIC.size + 1 && raw.copyOfRange(0, MAGIC.size).contentEquals(MAGIC)) { "bad header" }
            val ivLength = raw[MAGIC.size].toInt()
            val ivStart = MAGIC.size + 1
            val iv = raw.copyOfRange(ivStart, ivStart + ivLength)
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, iv))
            cipher.updateAAD(AAD)
            val plain = cipher.doFinal(raw, ivStart + ivLength, raw.size - ivStart - ivLength)
            val json = JSONObject(String(plain, Charsets.UTF_8))
            plain.fill(0)
            return json.keys().asSequence().associateWith { json.getString(it) }
        } catch (error: Exception) {
            throw VaultException("本机密钥无法解密", error)
        }
    }

    @Synchronized
    fun save(values: Map<String, String>) {
		file.parentFile?.mkdirs()
        val plain = JSONObject(values).toString().toByteArray(Charsets.UTF_8)
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, key())
        cipher.updateAAD(AAD)
        val sealed = cipher.doFinal(plain)
        plain.fill(0)
        val iv = cipher.iv
        val temporary = File(file.parentFile, file.name + ".tmp")
        temporary.outputStream().use { out ->
            out.write(MAGIC)
            out.write(iv.size)
            out.write(iv)
            out.write(sealed)
            out.fd.sync()
        }
        if (!temporary.renameTo(file)) {
            temporary.delete()
            throw VaultException("无法保存本机密钥")
        }
    }

    /** Moves an unreadable vault aside so the user can start over. */
    @Synchronized
    fun quarantine() {
        if (file.exists()) file.renameTo(File(file.parentFile, "secrets.unreadable.${System.currentTimeMillis()}"))
    }

    companion object {
        private const val KEYSTORE = "AndroidKeyStore"
        private const val ALIAS = "nknguard.secrets.v1"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private val MAGIC = "NKG1".toByteArray(Charsets.US_ASCII)
        private val AAD = "nknguard-secrets-v1".toByteArray(Charsets.US_ASCII)
    }
}
