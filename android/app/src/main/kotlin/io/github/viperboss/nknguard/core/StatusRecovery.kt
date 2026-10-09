package io.github.viperboss.nknguard.core

import org.json.JSONObject

/** A stopped transport does not remove the previously verified pairing. */
object StatusRecovery {
    fun unavailable(previous: JSONObject, message: String): JSONObject {
        val current = JSONObject().put("phase", "core_unavailable")
            .put("connected", false).put("nkn_connected", false)
            .put("path", "none").put("handshake_fresh", false)
            .put("last_error", message)
        // Retain identity only. Endpoint, handshake and relay readiness from
        // the old process must never be presented as a live connection.
        for (key in listOf("paired", "revoked", "nas_id", "nas_name", "nas_address",
            "nas_virtual_ip", "virtual_ip", "route_cidr", "allowed_cidr")) {
            if (previous.has(key)) current.put(key, previous.get(key))
        }
        return current
    }

    fun canPair(status: JSONObject): Boolean = status.has("paired") &&
        (!status.optBoolean("paired") || status.optBoolean("revoked")) &&
        status.optString("phase") != "core_unavailable"
}
