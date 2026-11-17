package com.themastersahib.vpnmaster

import android.app.Application
import android.content.Context
import com.wireguard.android.backend.GoBackend
import com.wireguard.android.backend.Tunnel
import com.wireguard.config.Config
import com.wireguard.crypto.KeyPair
import org.json.JSONObject
import java.io.ByteArrayInputStream
import java.net.HttpURLConnection
import java.net.URL
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone

/**
 * VPN Master (Android) — free Cloudflare WARP over the official WireGuard engine.
 * Holds the single WireGuard backend + tunnel for the whole app process.
 */
class App : Application() {

    lateinit var backend: GoBackend
    @Volatile var state: Tunnel.State = Tunnel.State.DOWN
    @Volatile var endpoint: String = ""
    var listener: ((Tunnel.State) -> Unit)? = null

    val tunnel = object : Tunnel {
        override fun getName() = "vpnmaster"
        override fun onStateChange(newState: Tunnel.State) {
            state = newState
            listener?.invoke(newState)
        }
    }

    override fun onCreate() {
        super.onCreate()
        instance = this
        backend = GoBackend(this)
    }

    // ---------- Cloudflare WARP free registration (done once, saved on the phone) ----------

    private val prefs get() = getSharedPreferences("warp", Context.MODE_PRIVATE)

    data class Account(val privateKey: String, val peerKey: String, val v4: String, val v6: String, val host: String)

    fun account(forceNew: Boolean = false): Account {
        val p = prefs
        if (!forceNew && p.contains("priv")) {
            return Account(p.getString("priv", "")!!, p.getString("peer", "")!!,
                p.getString("v4", "")!!, p.getString("v6", "")!!, p.getString("host", "")!!)
        }
        val kp = KeyPair()
        val tos = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", Locale.US)
            .apply { timeZone = TimeZone.getTimeZone("UTC") }.format(Date())
        val body = JSONObject()
            .put("key", kp.publicKey.toBase64())
            .put("install_id", "").put("fcm_token", "")
            .put("tos", tos).put("model", "Android").put("type", "Android").put("locale", "en_US")
            .toString()

        var lastErr: Exception? = null
        for (ver in listOf("v0a2158", "v0a1922", "v0i1909051800")) {
            try {
                val c = (URL("https://api.cloudflareclient.com/$ver/reg").openConnection() as HttpURLConnection).apply {
                    requestMethod = "POST"; doOutput = true; connectTimeout = 15000; readTimeout = 15000
                    setRequestProperty("Content-Type", "application/json; charset=UTF-8")
                    setRequestProperty("User-Agent", "okhttp/3.12.1")
                    setRequestProperty("CF-Client-Version", "a-6.10-2158")
                }
                c.outputStream.use { it.write(body.toByteArray()) }
                if (c.responseCode !in 200..299) throw Exception("HTTP ${c.responseCode}")
                val json = JSONObject(c.inputStream.bufferedReader().readText())
                val cfg = if (json.has("config")) json.getJSONObject("config") else json.getJSONObject("result").getJSONObject("config")
                val peer = cfg.getJSONArray("peers").getJSONObject(0)
                val addr = cfg.getJSONObject("interface").getJSONObject("addresses")
                val ep = peer.getJSONObject("endpoint")
                val host = ep.optString("v4", "162.159.192.1:0").substringBeforeLast(":")
                val acc = Account(kp.privateKey.toBase64(), peer.getString("public_key"),
                    addr.getString("v4"), addr.optString("v6", ""), host.ifBlank { "162.159.192.1" })
                prefs.edit().putString("priv", acc.privateKey).putString("peer", acc.peerKey)
                    .putString("v4", acc.v4).putString("v6", acc.v6).putString("host", acc.host).apply()
                return acc
            } catch (e: Exception) { lastErr = e }
        }
        throw Exception("Could not reach Cloudflare: ${lastErr?.message}")
    }

    fun buildConfig(a: Account, endpoint: String): Config {
        val addrs = listOf("${a.v4}/32", if (a.v6.isNotBlank()) "${a.v6}/128" else "").filter { it.isNotBlank() }.joinToString(", ")
        val text = """
            [Interface]
            PrivateKey = ${a.privateKey}
            Address = $addrs
            DNS = 1.1.1.1, 1.0.0.1, 2606:4700:4700::1111
            MTU = 1280

            [Peer]
            PublicKey = ${a.peerKey}
            AllowedIPs = 0.0.0.0/0, ::/0
            Endpoint = $endpoint
            PersistentKeepalive = 25
        """.trimIndent()
        return Config.parse(ByteArrayInputStream(text.toByteArray()))
    }

    /** Ports WARP listens on — tried in order until a WireGuard handshake succeeds. */
    fun endpoints(a: Account) = listOf(2408, 500, 1701, 4500, 854, 894).map { "${a.host}:$it" } +
        listOf("engage.cloudflareclient.com:2408")

    fun handshakeAt(): Long = try {
        val s = backend.getStatistics(tunnel)
        s.peers().maxOfOrNull { s.peer(it)?.latestHandshakeEpochMillis() ?: 0L } ?: 0L
    } catch (_: Exception) { 0L }

    fun traffic(): Pair<Long, Long> = try {
        val s = backend.getStatistics(tunnel); s.totalRx() to s.totalTx()
    } catch (_: Exception) { 0L to 0L }

    companion object { lateinit var instance: App }
}
