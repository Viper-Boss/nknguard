package io.github.viperboss.nknguard.core

import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.util.UUID

/** Public metadata only. Each NAS has its own core state and encrypted vault.
 * The legacy slot keeps the original paths, so upgrades require no re-pairing. */
class NasRegistry(private val root: File) {
    data class Entry(val id: String, val name: String, val nasId: String = "", val address: String = "", val virtualIP: String = "")
    private val file = File(root, "nas-registry.json")
    private var entries = mutableListOf<Entry>()
    private var selected = "legacy"

    init {
        if (file.exists()) {
            val json = JSONObject(file.readText())
            selected = json.getString("selected")
            val rows = json.getJSONArray("entries")
            for (i in 0 until rows.length()) {
                val row = rows.getJSONObject(i)
                val id = row.getString("id")
                require(validID(id)) { "NAS 配置目录无效" }
                entries.add(Entry(id, row.getString("name"), row.optString("nas_id"), row.optString("address"), row.optString("virtual_ip")))
            }
            require(entries.isNotEmpty() && entries.size <= 32 && entries.map { it.id }.distinct().size == entries.size && entries.any { it.id == selected }) { "NAS 列表损坏" }
        } else {
            entries.add(Entry("legacy", "我的 NAS"))
            save()
        }
    }

    @Synchronized fun list(): List<Entry> = entries.toList()
    @Synchronized fun active(): Entry = entries.first { it.id == selected }
    @Synchronized fun findNAS(id: String): Entry? = entries.firstOrNull { id.isNotEmpty() && it.nasId == id }
    @Synchronized fun directory(id: String = selected): File {
        require(validID(id) && entries.any { it.id == id })
        return if (id == "legacy") root else File(root, "nas/$id")
    }
    @Synchronized fun add(name: String = "新 NAS"): Entry {
        require(entries.size < 32) { "最多保存 32 台 NAS" }
        val entry = Entry(UUID.randomUUID().toString(), cleanName(name))
        entries.add(entry)
        try { save() } catch (e: Exception) { entries.remove(entry); throw e }
        return entry
    }
    @Synchronized fun select(id: String) {
        require(entries.any { it.id == id }) { "NAS 不存在" }
        if (selected == id) return
        val previous = selected
        selected = id
        try { save() } catch (e: Exception) { selected = previous; throw e }
    }
    @Synchronized fun rename(id: String, name: String) = update(id) { it.copy(name = cleanName(name)) }
    @Synchronized fun remember(status: JSONObject) {
        if (!status.optBoolean("paired")) return
        val id = status.optString("nas_id")
        if (id.isBlank()) return
        update(selected) { it.copy(nasId = id, address = status.optString("nas_address").ifBlank { it.address }, virtualIP = status.optString("nas_virtual_ip").ifBlank { it.virtualIP }) }
    }
    @Synchronized fun remove(id: String) {
        require(id != selected) { "不能删除当前使用的 NAS，请先切换" }
        val previous = entries.toMutableList()
        entries.removeAll { it.id == id }
        try { save() } catch (e: Exception) { entries = previous; throw e }
    }
    private fun update(id: String, transform: (Entry) -> Entry) {
        val index = entries.indexOfFirst { it.id == id }
        require(index >= 0)
        val previous = entries[index]
        val next = transform(previous)
        if (previous == next) return
        entries[index] = next
        try { save() } catch (e: Exception) { entries[index] = previous; throw e }
    }
    private fun save() {
        root.mkdirs()
        val json = JSONObject().put("selected", selected).put("entries", JSONArray(entries.map {
            JSONObject().put("id", it.id).put("name", it.name).put("nas_id", it.nasId).put("address", it.address).put("virtual_ip", it.virtualIP)
        }))
        val tmp = File(root, "nas-registry.json.tmp")
        tmp.outputStream().use { out -> out.write(json.toString().toByteArray(Charsets.UTF_8)); out.fd.sync() }
        check(tmp.renameTo(file)) { "无法保存 NAS 列表" }
    }
    companion object {
        private fun validID(id: String) = id == "legacy" || id.matches(Regex("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"))
        private fun cleanName(name: String) = name.trim().take(40).ifEmpty { "我的 NAS" }
    }
}
