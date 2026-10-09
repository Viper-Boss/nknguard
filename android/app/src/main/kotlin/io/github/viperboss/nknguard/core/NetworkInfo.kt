package io.github.viperboss.nknguard.core

import android.content.Context
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import org.json.JSONArray
import org.json.JSONObject
import java.net.Inet6Address

/**
 * The phone's current underlying network, as the core needs it. Go cannot
 * enumerate interfaces on Android 11 and later, and has no resolv.conf to
 * read, so the app reports local addresses and DNS servers itself.
 *
 * The app excludes itself from its own VPN, so its default network is always
 * the real Wi-Fi or mobile network, never the tunnel.
 */
object NetworkInfo {
    fun underlying(context: Context): Network? {
        val manager = context.getSystemService(ConnectivityManager::class.java) ?: return null
        val active = manager.activeNetwork
        val caps = active?.let { manager.getNetworkCapabilities(it) }
        if (active != null && caps?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) != true) return active
        @Suppress("DEPRECATION")
        return manager.allNetworks.firstOrNull { network ->
            val candidate = manager.getNetworkCapabilities(network) ?: return@firstOrNull false
            !candidate.hasTransport(NetworkCapabilities.TRANSPORT_VPN) &&
                candidate.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
        }
    }

    fun describe(context: Context, network: Network? = underlying(context)): JSONObject {
        val out = JSONObject().put("network_handle", network?.networkHandle?.toString() ?: "")
        val manager = context.getSystemService(ConnectivityManager::class.java) ?: return out
        val properties: LinkProperties = network?.let { manager.getLinkProperties(it) } ?: return out
        val addresses = JSONArray()
        for (link in properties.linkAddresses) {
            val address = link.address
            if (address.isLoopbackAddress || address.isLinkLocalAddress || address.isAnyLocalAddress) continue
            addresses.put(hostAddress(address))
        }
        val dns = JSONArray()
        properties.dnsServers.forEach { dns.put(hostAddress(it)) }
        out.put("local_addresses", addresses)
        out.put("dns_servers", dns)
        return out
    }

    private fun hostAddress(address: java.net.InetAddress): String {
        val text = address.hostAddress ?: ""
        return if (address is Inet6Address) text.substringBefore('%') else text
    }
}
