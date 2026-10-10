package io.github.viperboss.nknguard.core

import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import java.nio.file.Files

class NasRegistryTest {
    @Test fun upgradeKeepsLegacyPathsAndSwitchDoesNotOverwriteOtherNAS() {
        val root = Files.createTempDirectory("nkg-profiles").toFile()
        try {
            val registry = NasRegistry(root)
            assertEquals(root, registry.directory())
            registry.remember(JSONObject().put("paired", true).put("nas_id", "home").put("nas_virtual_ip", "10.88.1.1"))
            val work = registry.add("办公室")
            registry.select(work.id)
            assertNotEquals(root, registry.directory())
            registry.remember(JSONObject().put("paired", true).put("nas_id", "work").put("nas_virtual_ip", "10.88.2.1"))
            val restored = NasRegistry(root)
            assertEquals(work.id, restored.active().id)
            assertEquals("10.88.1.1", restored.findNAS("home")!!.virtualIP)
            restored.select("legacy")
            assertEquals(root, restored.directory())
            assertEquals("10.88.2.1", restored.findNAS("work")!!.virtualIP)
            restored.remove(work.id)
            assertEquals("home", restored.active().nasId)
        } finally { root.deleteRecursively() }
    }
    @Test fun pathTraversalAndActiveDeletionAreRejected() {
        val root = Files.createTempDirectory("nkg-profiles").toFile()
        try {
            val registry = NasRegistry(root)
            for (operation in listOf<() -> Unit>({ registry.directory("../core") }, { registry.remove("legacy") })) {
                try { operation(); fail("unsafe operation accepted") } catch (_: IllegalArgumentException) { }
            }
        } finally { root.deleteRecursively() }
    }
}
