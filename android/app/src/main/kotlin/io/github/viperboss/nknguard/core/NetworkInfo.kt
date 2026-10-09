package io.github.viperboss.nknguard.core

import android.content.Context
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import org.json.JSONArray
import org.json.JSONObject
import java.net.Inet6Address
import java.net.DatagramSocket
import java.net.InetAddress

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
        return manager.allNetworks.filter { network ->
            val candidate = manager.getNetworkCapabilities(network) ?: return@filter false
            !candidate.hasTransport(NetworkCapabilities.TRANSPORT_VPN) &&
                candidate.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
        }.maxByOrNull { network ->
            val candidate = manager.getNetworkCapabilities(network)
            (if (candidate?.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED) == true) 4 else 0) +
                (if (candidate?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true) 2 else 0)
        }
    }

    fun describe(context: Context, network: Network? = underlying(context)): JSONObject {
        val manager = context.getSystemService(ConnectivityManager::class.java)
        // Default callbacks may report the VPN. Never report its address as
        // the physical network, even if the app itself is excluded from it.
        val physical = if (network != null && manager?.getNetworkCapabilities(network)
                ?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true) underlying(context) else network
        val out = JSONObject().put("network_handle", physical?.networkHandle?.toString() ?: "")
        val properties: LinkProperties? = physical?.let { manager?.getLinkProperties(it) }
        val hosts = linkedSetOf<String>()
        for (link in properties?.linkAddresses.orEmpty()) {
            val address = link.address
            if (address.isLoopbackAddress || address.isLinkLocalAddress || address.isAnyLocalAddress) continue
            hosts.add(hostAddress(address))
        }
        if (physical != null) {
            // Some ROMs omit usable addresses from LinkProperties. Binding
            // a UDP socket to the chosen network and connecting it selects
            // a source address without sending a packet or requiring DNS.
            for (target in listOf("1.1.1.1", "2606:4700:4700::1111")) {
                runCatching {
                    DatagramSocket().use { socket ->
                        physical.bindSocket(socket)
                        socket.connect(InetAddress.getByName(target), 9)
                        val source = socket.localAddress
                        if (!source.isLoopbackAddress && !source.isLinkLocalAddress && !source.isAnyLocalAddress) {
                            hosts.add(hostAddress(source))
                        }
                    }
                }
            }
        }
        val dns = JSONArray()
        properties?.dnsServers.orEmpty().forEach { dns.put(hostAddress(it)) }
        out.put("local_addresses", JSONArray(hosts.toList()))
        out.put("dns_servers", dns)
        return out
    }

    private fun hostAddress(address: java.net.InetAddress): String {
        val text = address.hostAddress ?: ""
        return if (address is Inet6Address) text.substringBefore('%') else text
    }
}
