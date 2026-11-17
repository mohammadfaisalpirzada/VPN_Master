package com.themastersahib.vpnmaster

import android.annotation.SuppressLint
import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.net.VpnService
import android.os.Bundle
import android.provider.OpenableColumns
import com.wireguard.config.Config
import java.io.ByteArrayInputStream
import android.webkit.JavascriptInterface
import android.webkit.WebView
import android.webkit.WebViewClient
import com.wireguard.android.backend.Tunnel
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL
import kotlin.concurrent.thread

class MainActivity : Activity() {

    private lateinit var web: WebView
    private val app get() = App.instance
    private val reqVpn = 42
    private val reqFile = 43
    private var pendingConf: String? = null
    @Volatile private var connecting = false
    @Volatile private var cancelled = false

    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        web = WebView(this).apply {
            settings.javaScriptEnabled = true
            settings.domStorageEnabled = true
            setBackgroundColor(0xFF0B1020.toInt())
            webViewClient = WebViewClient()
            addJavascriptInterface(Bridge(this@MainActivity), "Android")
            loadUrl("file:///android_asset/index.html")
        }
        setContentView(web)
        app.listener = { s -> if (s == Tunnel.State.DOWN && !connecting) emit("disconnected", null) }
    }

    override fun onDestroy() {
        app.listener = null
        super.onDestroy()
    }

    fun emit(event: String, data: Any?) {
        val payload = JSONObject().put("event", event).put("data", data ?: JSONObject.NULL).toString()
        web.post { web.evaluateJavascript("window.onVpnEvent && window.onVpnEvent($payload)", null) }
    }

    // ---------------- connect / disconnect ----------------

    fun requestConnect(conf: String? = null) {
        pendingConf = conf
        val intent = VpnService.prepare(this)
        if (intent != null) startActivityForResult(intent, reqVpn) else startTunnel()
    }

    @Deprecated("Activity result API kept simple on purpose (no AndroidX).")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == reqVpn) {
            if (resultCode == RESULT_OK) startTunnel()
            else emit("error", "VPN permission was not granted.")
        }
        if (requestCode == reqFile && resultCode == RESULT_OK) {
            val uri = data?.data ?: return
            try {
                var name = "USA"
                contentResolver.query(uri, null, null, null, null)?.use { c ->
                    val i = c.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                    if (i >= 0 && c.moveToFirst()) name = c.getString(i)
                }
                name = name.removeSuffix(".conf").replace(Regex("[^A-Za-z0-9 _#.-]"), "").ifBlank { "USA" }
                val text = contentResolver.openInputStream(uri)!!.bufferedReader().readText()
                Config.parse(ByteArrayInputStream(text.toByteArray())) // validate
                confs().edit().putString(name, text).apply()
                emit("imported", name)
            } catch (e: Exception) {
                emit("error", "Not a valid WireGuard config: ${e.message}")
            }
        }
    }

    fun confs() = getSharedPreferences("confs", MODE_PRIVATE)

    fun pickConf() {
        startActivityForResult(Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE); type = "*/*"
        }, reqFile)
    }

    private fun startTunnel() = thread {
        connecting = true
        cancelled = false
        val confName = pendingConf
        try {
            if (confName != null) {
                val text = confs().getString(confName, null) ?: throw Exception("Config not found")
                emit("status", "Connecting to $confName…")
                app.backend.setState(app.tunnel, Tunnel.State.UP, Config.parse(ByteArrayInputStream(text.toByteArray())))
                app.endpoint = confName
                poke()
                val t0 = System.currentTimeMillis()
                while (System.currentTimeMillis() - t0 < 12000) {
                    if (cancelled) return@thread
                    if (app.handshakeAt() > 0) {
                        emit("connected", JSONObject().put("label", "$confName · WireGuard"))
                        return@thread
                    }
                    Thread.sleep(400)
                }
                if (cancelled) return@thread
                app.backend.setState(app.tunnel, Tunnel.State.DOWN, null)
                emit("error", "Server did not answer. Config may be expired, or your free account is connected on another device (Proton Free = 1 device).")
                return@thread
            }
            emit("status", "Getting free WARP key…")
            var acc = app.account()
            for ((i, ep) in app.endpoints(acc).withIndex()) {
                if (cancelled) return@thread
                emit("status", "Connecting… (route ${i + 1})")
                app.backend.setState(app.tunnel, Tunnel.State.UP, app.buildConfig(acc, ep))
                app.endpoint = ep
                poke()
                val t0 = System.currentTimeMillis()
                while (System.currentTimeMillis() - t0 < 6000) {
                    if (cancelled) return@thread
                    if (app.handshakeAt() > 0) {
                        emit("connected", JSONObject().put("label", "WARP · WireGuard"))
                        return@thread
                    }
                    Thread.sleep(400)
                }
                // Key may have been revoked by Cloudflare — re-register once and keep going.
                if (i == 1) acc = app.account(forceNew = true)
            }
            if (cancelled) return@thread
            app.backend.setState(app.tunnel, Tunnel.State.DOWN, null)
            emit("error", "Your network is blocking WARP right now. Try Wi-Fi / mobile data and tap again.")
        } catch (e: Exception) {
            try { app.backend.setState(app.tunnel, Tunnel.State.DOWN, null) } catch (_: Exception) {}
            if (!cancelled) emit("error", e.message ?: "Connection failed")
        } finally { connecting = false }
    }

    /** Send a tiny request so WireGuard starts its handshake immediately. */
    private fun poke() = thread {
        try { (URL("http://1.1.1.1/cdn-cgi/trace").openConnection() as HttpURLConnection).apply {
            connectTimeout = 3000; readTimeout = 3000 }.inputStream.close() } catch (_: Exception) {}
    }

    fun stopTunnel() = thread {
        cancelled = true
        try { app.backend.setState(app.tunnel, Tunnel.State.DOWN, null) } catch (_: Exception) {}
        emit("disconnected", null)
    }

    fun ipInfo() = thread {
        try {
            val c = URL("http://ip-api.com/json/?fields=query,country,countryCode,city").openConnection() as HttpURLConnection
            c.connectTimeout = 8000; c.readTimeout = 8000
            emit("ip", JSONObject(c.inputStream.bufferedReader().readText()))
        } catch (_: Exception) {}
    }
}

/** Methods callable from the HTML UI as window.Android.xxx() */
class Bridge(private val a: MainActivity) {
    @JavascriptInterface fun connect() = a.runOnUiThread { a.requestConnect() }
    @JavascriptInterface fun connectConf(name: String) = a.runOnUiThread { a.requestConnect(name) }
    @JavascriptInterface fun importConf() = a.runOnUiThread { a.pickConf() }
    @JavascriptInterface fun confList(): String = org.json.JSONArray(a.confs().all.keys.sorted()).toString()
    @JavascriptInterface fun confDelete(name: String) { a.confs().edit().remove(name).apply() }
    @JavascriptInterface fun disconnect() { a.stopTunnel() }
    @JavascriptInterface fun isConnected(): Boolean = App.instance.state == Tunnel.State.UP
    @JavascriptInterface fun ip() { a.ipInfo() }
    @JavascriptInterface fun stats(): String {
        val (rx, tx) = App.instance.traffic()
        return JSONObject().put("rx", rx).put("tx", tx).put("endpoint", App.instance.endpoint).toString()
    }
    @JavascriptInterface fun open(url: String) {
        if (url.startsWith("https://")) a.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url)))
    }
}
