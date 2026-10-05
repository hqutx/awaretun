package dev.awaretun

import android.app.Activity
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.view.Gravity
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView

class MainActivity : Activity() {
    private lateinit var status: TextView
    private lateinit var address: TextView
    private val vpnConsent = 41
    private val permissionRequest = 42

    private val statusReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            if (intent.action == TunnelService.ACTION_STATUS) {
                status.text = intent.getStringExtra(TunnelService.EXTRA_STATUS) ?: "Waiting for peer status"
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        status = TextView(this).apply {
            textSize = 16f
            text = "Ready. Start discovery on both devices."
        }
        address = TextView(this).apply {
            textSize = 18f
            setTextIsSelectable(true)
            text = "This device: ${NodeIdentity.overlayAddress(NodeIdentity.get(this@MainActivity))}"
        }
        val start = Button(this).apply {
            text = "Start peer discovery"
            setOnClickListener { requestAccessPermissions() }
        }
        val stop = Button(this).apply {
            text = "Stop"
            setOnClickListener {
                startService(
                    Intent(this@MainActivity, TunnelService::class.java)
                        .setAction(TunnelService.ACTION_STOP)
                )
                status.text = "Stopping…"
            }
        }
        setContentView(LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER
            setPadding(32, 32, 32, 32)
            addView(status)
            addView(address)
            addView(TextView(this@MainActivity).apply {
                text = "Nearby peers can relay traffic through the mesh to a phone with Internet access. Test by opening an HTTP or HTTPS site on a phone without its own Internet connection."
            })
            addView(start)
            addView(stop)
        })
    }

    override fun onStart() {
        super.onStart()
        val filter = IntentFilter(TunnelService.ACTION_STATUS)
        if (Build.VERSION.SDK_INT >= 33) {
            registerReceiver(statusReceiver, filter, RECEIVER_NOT_EXPORTED)
        } else {
            @Suppress("DEPRECATION")
            registerReceiver(statusReceiver, filter)
        }
    }

    override fun onStop() {
        unregisterReceiver(statusReceiver)
        super.onStop()
    }

    private fun requestVpnConsent() {
        val intent = VpnService.prepare(this)
        if (intent == null) startDiscoveryService() else startActivityForResult(intent, vpnConsent)
    }

    private fun requestAccessPermissions() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) {
            status.text = "Wi-Fi Aware data links require Android 12 or later on this device."
            return
        }
        val required = buildList {
            if (Build.VERSION.SDK_INT >= 33) {
                add(android.Manifest.permission.NEARBY_WIFI_DEVICES)
                add(android.Manifest.permission.POST_NOTIFICATIONS)
            } else {
                add(android.Manifest.permission.ACCESS_FINE_LOCATION)
            }
        }.filter { checkSelfPermission(it) != android.content.pm.PackageManager.PERMISSION_GRANTED }
        if (required.isEmpty()) requestVpnConsent() else requestPermissions(required.toTypedArray(), permissionRequest)
    }

    @Deprecated("Prototype uses platform permission callbacks")
    override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<out String>, grantResults: IntArray) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode == permissionRequest && grantResults.all { it == android.content.pm.PackageManager.PERMISSION_GRANTED }) {
            requestVpnConsent()
        } else if (requestCode == permissionRequest) {
            status.text = "Nearby Wi-Fi permission is required to discover peers."
        }
    }

    @Deprecated("Prototype uses the platform VPN consent activity")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == vpnConsent && resultCode == RESULT_OK) startDiscoveryService()
    }

    private fun startDiscoveryService() {
        val intent = Intent(this, TunnelService::class.java).setAction(TunnelService.ACTION_START)
        startForegroundService(intent)
        status.text = "Starting Wi-Fi Aware discovery…"
    }
}
