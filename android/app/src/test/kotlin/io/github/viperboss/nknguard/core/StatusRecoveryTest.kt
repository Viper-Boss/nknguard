package io.github.viperboss.nknguard.core

import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

class StatusRecoveryTest {
    @Test fun stoppedCoreRetainsPairingButDropsLiveTransport() {
        val previous = JSONObject().put("paired", true).put("revoked", false)
            .put("nas_id", "nas").put("nas_virtual_ip", "10.88.1.1")
            .put("connected", true).put("path", "direct-wg")
            .put("endpoint", "192.168.1.1:1234").put("handshake_fresh", true)
            .put("relay_ready", true).put("last_handshake_unix", 123)
        val stopped = StatusRecovery.unavailable(previous, "stopped")
        assertTrue(stopped.getBoolean("paired"))
        assertEquals("nas", stopped.getString("nas_id"))
        assertEquals("10.88.1.1", stopped.getString("nas_virtual_ip"))
        assertFalse(stopped.getBoolean("connected"))
        assertFalse(stopped.getBoolean("handshake_fresh"))
        assertEquals("none", stopped.getString("path"))
        assertFalse(stopped.has("endpoint"))
        assertFalse(stopped.has("last_handshake_unix"))
        assertFalse(stopped.has("relay_ready"))
        assertFalse(StatusRecovery.canPair(stopped))
        assertTrue(previous.getBoolean("connected"))
    }

    @Test fun startupFailureDoesNotInventPairingOrOfferScan() {
        val stopped = StatusRecovery.unavailable(JSONObject(), "failed")
        assertFalse(stopped.has("paired"))
        assertFalse(StatusRecovery.canPair(stopped))
        assertFalse(StatusRecovery.canPair(JSONObject()))
    }

    @Test fun authoritativeUnpairedOrRevokedStateOffersPairing() {
        assertTrue(StatusRecovery.canPair(JSONObject().put("paired", false).put("phase", "not_paired")))
        assertTrue(StatusRecovery.canPair(JSONObject().put("paired", true).put("revoked", true).put("phase", "revoked")))
        assertFalse(StatusRecovery.canPair(JSONObject().put("paired", true).put("revoked", false)))
    }
}
