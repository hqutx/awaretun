package dev.awaretun

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Intent
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.net.wifi.aware.AttachCallback
import android.net.wifi.aware.DiscoverySessionCallback
import android.net.wifi.aware.PublishConfig
import android.net.wifi.aware.PublishDiscoverySession
import android.net.wifi.aware.SubscribeConfig
import android.net.wifi.aware.SubscribeDiscoverySession
import android.net.wifi.aware.WifiAwareManager
import android.net.wifi.aware.WifiAwareNetworkInfo
import android.net.wifi.aware.WifiAwareNetworkSpecifier
import android.net.wifi.aware.PeerHandle
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.os.PowerManager
import android.system.Os
import android.system.OsConstants
import android.util.Log
import java.net.Inet6Address
import java.net.InetSocketAddress

class TunnelService : VpnService() {
    private val mainHandler = Handler(Looper.getMainLooper())
    private lateinit var connectivity: ConnectivityManager
    private var awareSession: android.net.wifi.aware.WifiAwareSession? = null
    private var publisher: PublishDiscoverySession? = null
    private var subscriber: SubscribeDiscoverySession? = null
    private var tunnel: ParcelFileDescriptor? = null
    private val networkCallbacks = mutableListOf<ConnectivityManager.NetworkCallback>()
    private val runningPeers = mutableSetOf<String>()
    private val pendingPeers = mutableSetOf<PeerHandle>()
    private lateinit var localNodeId: ByteArray
    private var localHasInternet = false
    private var internetRouteEnabled = false
    private var discoveryStarted = false
    private var wakeLock: PowerManager.WakeLock? = null
    private var internetEgressNetwork: Network? = null

    override fun onCreate() {
        super.onCreate()
        localNodeId = NodeIdentity.get(this)
        connectivity = getSystemService(ConnectivityManager::class.java)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopDiscovery()
        } else {
            startDiscovery()
        }
        return START_STICKY
    }

    private fun startDiscovery() {
        if (discoveryStarted) return
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) {
            val status = "Wi-Fi Aware data links require Android 12 or later on this device"
            discoveryStarted = true
            startForeground(NOTIFICATION_ID, notification(status))
            updateNotification(status)
            return
        }
        discoveryStarted = true
        startForeground(NOTIFICATION_ID, notification("Looking for nearby peers"))
        wakeLock = getSystemService(PowerManager::class.java)
            .newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "$packageName:aware-tunnel")
            .apply {
                setReferenceCounted(false)
                acquire()
            }
        localHasInternet = hasValidatedInternet()
        establishOverlayInterface()
        attachAware()
    }

    private fun stopDiscovery() {
        if (!discoveryStarted) {
            stopSelf()
            return
        }
        discoveryStarted = false
        NativeCore.stop()
        networkCallbacks.forEach { callback ->
            try {
                connectivity.unregisterNetworkCallback(callback)
            } catch (e: IllegalArgumentException) {
                Log.w(TAG, "Network callback was already unregistered", e)
            }
        }
        networkCallbacks.clear()
        pendingPeers.clear()
        runningPeers.clear()
        publisher = null
        subscriber = null
        awareSession?.close()
        awareSession = null
        tunnel?.close()
        tunnel = null
        connectivity.bindProcessToNetwork(null)
        internetEgressNetwork = null
        wakeLock?.let { if (it.isHeld) it.release() }
        wakeLock = null
        internetRouteEnabled = false
        stopForeground(STOP_FOREGROUND_REMOVE)
        sendBroadcast(Intent(ACTION_STATUS).setPackage(packageName).putExtra(EXTRA_STATUS, "Stopped"))
        stopSelf()
    }

    private fun establishOverlayInterface(usePeerInternet: Boolean = false) {
        // Keep the phone's normal route during discovery; a mesh node captures IPv4
        // only after an Aware neighbor is available for Babel to find an exit through.
        val builder = Builder()
            .setSession("AwareTun prototype")
            .addAddress(overlayAddress(), 128)
            .addAddress(tunnelIpv4Address(), 32)
            .addRoute("fd71:6177::", 48)
            .allowBypass()
            .setMtu(1280)
        if (usePeerInternet) {
            builder.addDnsServer("1.1.1.1")
                .addRoute("0.0.0.0", 0)
        }
        val replacement = builder.establish() ?: run {
            Log.e(TAG, "Could not establish VPN interface; routeViaPeer=$usePeerInternet")
            return
        }
        Log.i(TAG, "VPN interface established; routeViaPeer=$usePeerInternet")
        val previous = tunnel
        tunnel = replacement
        internetRouteEnabled = usePeerInternet
        previous?.close()
    }

    private fun attachAware() {
        val manager = getSystemService(WifiAwareManager::class.java)
        if (manager == null || !manager.isAvailable) {
            updateNotification("Wi-Fi Aware is unavailable on this device")
            return
        }
        manager.attach(object : AttachCallback() {
            override fun onAttached(session: android.net.wifi.aware.WifiAwareSession) {
                awareSession = session
                session.publish(
                    PublishConfig.Builder()
                        .setServiceName(SERVICE_NAME)
                        .setServiceSpecificInfo(advertisement(localNodeId))
                        .build(),
                    publisherCallback,
                    mainHandler
                )
                session.subscribe(
                    SubscribeConfig.Builder().setServiceName(SERVICE_NAME).build(),
                    subscriberCallback,
                    mainHandler
                )
                updateNotification("Discovering AwareTun peers")
            }

            override fun onAttachFailed() {
                updateNotification("Wi-Fi Aware attach failed")
            }
        }, mainHandler)
    }

    private val publisherCallback = object : DiscoverySessionCallback() {
        override fun onPublishStarted(session: PublishDiscoverySession) {
            publisher = session
            updateNotification("Advertising tunnel service")
        }

        override fun onMessageReceived(peerHandle: android.net.wifi.aware.PeerHandle, message: ByteArray) {
            val handshake = parseHandshake(message) ?: return
            if (handshake.kind != HANDSHAKE_CONNECT) return
            val remote = handshake.peer
            val remoteId = remote.nodeId
            // The lower node ID owns the publisher/server role for this pair.
            if (compareAddresses(remoteId, localNodeId) <= 0) return
            val current = publisher ?: return
            if (!pendingPeers.add(peerHandle)) return
            updateNotification("Peer found; accepting Aware link")
            requestAwareNetwork(
                WifiAwareNetworkSpecifier.Builder(current, peerHandle).build(),
                peerHandle,
                remote.offersInternet,
                remoteId
            )
            // Register the responder request before telling the initiator to start NDP.
            current.sendMessage(peerHandle, MESSAGE_ID, handshakeMessage(HANDSHAKE_READY, advertisement(localNodeId)))
        }
    }

    private val subscriberCallback = object : DiscoverySessionCallback() {
        override fun onSubscribeStarted(session: SubscribeDiscoverySession) {
            subscriber = session
            updateNotification("Subscribed; waiting for peers")
        }

        override fun onServiceDiscovered(
            peerHandle: android.net.wifi.aware.PeerHandle,
            serviceSpecificInfo: ByteArray,
            matchFilter: List<ByteArray>
        ) {
            val remote = parseAdvertisement(serviceSpecificInfo) ?: return
            val remoteId = remote.nodeId
            // Only the higher ID subscribes as the client, avoiding duplicate Aware links.
            if (compareAddresses(remoteId, localNodeId) >= 0) return
            val current = subscriber ?: return
            if (!pendingPeers.add(peerHandle)) return
            current.sendMessage(peerHandle, MESSAGE_ID, handshakeMessage(HANDSHAKE_CONNECT, advertisement(localNodeId)))
            updateNotification("Peer found; requesting Aware link")
        }

        override fun onMessageReceived(peerHandle: PeerHandle, message: ByteArray) {
            val handshake = parseHandshake(message) ?: return
            if (handshake.kind != HANDSHAKE_READY) return
            val remoteId = handshake.peer.nodeId
            // Only the higher ID receives READY and opens the initiator-side request.
            if (compareAddresses(remoteId, localNodeId) >= 0) return
            val current = subscriber ?: return
            updateNotification("Peer found; requesting Aware link")
            requestAwareNetwork(
                WifiAwareNetworkSpecifier.Builder(current, peerHandle).build(),
                peerHandle,
                handshake.peer.offersInternet,
                remoteId
            )
        }
    }

    private fun requestAwareNetwork(
        specifier: WifiAwareNetworkSpecifier,
        peerHandle: android.net.wifi.aware.PeerHandle?,
        peerHasInternet: Boolean,
        peerNodeId: ByteArray
    ) {
        // Android 11 can crash inside WifiAwareNetworkInfo parcel decoding when a
        // virtual interface has no parent, before an app callback can catch it.
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) {
            updateNotification("Wi-Fi Aware data links require Android 12 or later on this device")
            return
        }
        val request = NetworkRequest.Builder()
            .addTransportType(NetworkCapabilities.TRANSPORT_WIFI_AWARE)
            .setNetworkSpecifier(specifier)
            .build()
        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                Log.i(TAG, "Wi-Fi Aware network is available: $network")
                connectivity.getNetworkCapabilities(network)?.let {
                    connectPeer(network, it, peerHandle, peerHasInternet, peerNodeId)
                }
            }

            override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) {
                connectPeer(network, caps, peerHandle, peerHasInternet, peerNodeId)
            }

            override fun onUnavailable() {
                peerHandle?.let { pendingPeers.remove(it) }
                runningPeers.remove(peerNodeId.toHex())
                Log.w(TAG, "Wi-Fi Aware link request timed out for $peerHandle")
                updateNotification("Peer found, but Wi-Fi Aware link timed out")
            }

            override fun onLost(network: Network) {
                Log.w(TAG, "Wi-Fi Aware network was lost: $network")
                peerHandle?.let { pendingPeers.remove(it) }
                runningPeers.remove(peerNodeId.toHex())
                NativeCore.removePeer(peerNodeId)
                if (runningPeers.isEmpty() && internetRouteEnabled && !localHasInternet) establishOverlayInterface()
                updateNotification("Peer link lost")
            }
        }
        networkCallbacks += callback
        connectivity.requestNetwork(request, callback, 30_000)
    }

    private fun connectPeer(
        network: Network,
        caps: NetworkCapabilities,
        peerHandle: android.net.wifi.aware.PeerHandle?,
        peerHasInternet: Boolean,
        peerNodeId: ByteArray
    ) {
        val info = caps.transportInfo as? WifiAwareNetworkInfo ?: return
        val address = info.peerIpv6Addr ?: return
        val key = peerNodeId.toHex()
        if (!runningPeers.add(key)) return

        try {
            localHasInternet = hasValidatedInternet()
            internetEgressNetwork = if (localHasInternet) {
                findValidatedInternetNetwork()?.also { network ->
                    if (connectivity.bindProcessToNetwork(network)) {
                        Log.i(TAG, "Gateway egress bound to network $network")
                    } else {
                        Log.e(TAG, "Could not bind gateway egress to network $network")
                    }
                }
            } else {
                connectivity.bindProcessToNetwork(null)
                null
            }
            // Babel can learn an Internet default through a relay several links away.
            val usePeerInternet = !localHasInternet
            Log.i(
                TAG,
                "Starting peer transport: localInternet=$localHasInternet peerInternet=$peerHasInternet routeViaPeer=$usePeerInternet"
            )
            if (internetRouteEnabled != usePeerInternet) {
                establishOverlayInterface(usePeerInternet)
            }
            // Binding through Android's Network API gives this IPv6 socket the Aware interface
            // scope. The duplicate handed to native code refers to the same bound socket.
            val socketFd = Os.socket(OsConstants.AF_INET6, OsConstants.SOCK_DGRAM, OsConstants.IPPROTO_UDP)
            Os.setsockoptInt(socketFd, OsConstants.SOL_SOCKET, OsConstants.SO_REUSEADDR, 1)
            Os.bind(socketFd, InetSocketAddress(Inet6Address.getByAddress(null, ByteArray(16), 0), QUIC_PORT))
            val socketPfd = ParcelFileDescriptor.dup(socketFd)
            if (!protect(socketPfd.fd)) {
                Os.close(socketFd)
                socketPfd.close()
                throw IllegalStateException("Could not protect QUIC socket from the VPN")
            }
            network.bindSocket(socketFd)
            Log.i(TAG, "QUIC UDP socket bound: ${Os.getsockname(socketFd)}")
            Os.close(socketFd)

            val linkProperties = connectivity.getLinkProperties(network)
            val localAddress = linkProperties?.linkAddresses
                ?.mapNotNull { it.address as? Inet6Address }
                ?.firstOrNull { it.isLinkLocalAddress }
            Log.i(
                TAG,
                "Aware IPv6 path: interface=${linkProperties?.interfaceName} " +
                    "local=${linkProperties?.linkAddresses?.joinToString()} peer=$address"
            )
            // Exactly one side initiates QUIC; both sides keep a listener active.
            val shouldDial = localAddress?.let { compareAddresses(it.address, address.address) > 0 } ?: true
            val tunPfd = tunnel?.let { ParcelFileDescriptor.dup(it.fileDescriptor) }
                ?: throw IllegalStateException("VPN interface was not created")

            Thread {
                NativeCore.start(
                    tunPfd.detachFd(),
                    socketPfd.detachFd(),
                    address.address,
                    localNodeId,
                    peerNodeId,
                    address.scopeId,
                    QUIC_PORT,
                    shouldDial,
                    localHasInternet
                )
            }.apply {
                name = "awaretun-quic"
                isDaemon = true
                start()
            }
            val status = when {
                localHasInternet -> "Connected; offering this phone as an Internet exit"
                usePeerInternet -> "Connected; routing Internet through peer exit"
                else -> "Peer link connected; no Internet exit available"
            }
            updateNotification(status)
        } catch (e: Exception) {
            runningPeers.remove(key)
            Log.e(TAG, "Could not start peer transport", e)
            updateNotification("Peer link setup failed: " + e.message)
        }
    }

    override fun onDestroy() {
        Log.i(TAG, "Tunnel service is being destroyed")
        if (discoveryStarted) stopDiscovery()
        super.onDestroy()
    }

    private fun notification(text: String): Notification {
        val manager = getSystemService(NotificationManager::class.java)
        if (Build.VERSION.SDK_INT >= 26) {
            manager.createNotificationChannel(NotificationChannel(CHANNEL, "AwareTun", NotificationManager.IMPORTANCE_LOW))
        }
        return Notification.Builder(this, CHANNEL)
            .setContentTitle("AwareTun")
            .setContentText(text)
            .setSmallIcon(android.R.drawable.stat_sys_upload_done)
            .setOngoing(true)
            .build()
    }

    private fun updateNotification(text: String) {
        getSystemService(NotificationManager::class.java).notify(NOTIFICATION_ID, notification(text))
        sendBroadcast(Intent(ACTION_STATUS).setPackage(packageName).putExtra(EXTRA_STATUS, text))
    }

    private fun overlayAddress(): String = NodeIdentity.overlayAddress(localNodeId)

    private fun tunnelIpv4Address(): String {
        val third = (localNodeId[6].toInt() and 0xff) % 254 + 1
        val fourth = (localNodeId[7].toInt() and 0xff) % 252 + 2
        return "10.71.$third.$fourth"
    }

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

    private fun findValidatedInternetNetwork(): Network? = connectivity.allNetworks.firstOrNull { network ->
        val caps = connectivity.getNetworkCapabilities(network) ?: return@firstOrNull false
        caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
            caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED) &&
            !caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI_AWARE) &&
            !caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
    }

    private fun hasValidatedInternet(): Boolean = findValidatedInternetNetwork() != null

    private fun advertisement(nodeId: ByteArray): ByteArray =
        HELLO_PREFIX + nodeId + byteArrayOf(if (hasValidatedInternet()) 1 else 0)

    private data class PeerAdvertisement(val nodeId: ByteArray, val offersInternet: Boolean)

    companion object {
        const val ACTION_STATUS = "dev.awaretun.STATUS"
        const val ACTION_START = "dev.awaretun.START"
        const val ACTION_STOP = "dev.awaretun.STOP"
        const val EXTRA_STATUS = "status"
        private const val TAG = "AwareTun"
        private const val CHANNEL = "awaretun"
        private const val NOTIFICATION_ID = 7
        private const val SERVICE_NAME = "dev.awaretun.mesh.v1"
        private const val MESSAGE_ID = 1
        private const val HANDSHAKE_CONNECT: Byte = 1
        private const val HANDSHAKE_READY: Byte = 2
        private const val QUIC_PORT = 4242
        private const val NODE_ID_SIZE = 8
        private val HELLO_PREFIX = byteArrayOf(0x41, 0x57, 0x54, 0x01, 0x10)

        private fun parseAdvertisement(message: ByteArray): PeerAdvertisement? {
            if (message.size != HELLO_PREFIX.size + NODE_ID_SIZE + 1) return null
            if (!message.copyOfRange(0, HELLO_PREFIX.size).contentEquals(HELLO_PREFIX)) return null
            val nodeId = message.copyOfRange(HELLO_PREFIX.size, HELLO_PREFIX.size + NODE_ID_SIZE)
            return PeerAdvertisement(nodeId, message.last().toInt() != 0)
        }

        private data class HandshakeMessage(val kind: Byte, val peer: PeerAdvertisement)

        private fun handshakeMessage(kind: Byte, advertisement: ByteArray): ByteArray =
            byteArrayOf(kind) + advertisement

        private fun parseHandshake(message: ByteArray): HandshakeMessage? {
            if (message.isEmpty()) return null
            val kind = message[0]
            if (kind != HANDSHAKE_CONNECT && kind != HANDSHAKE_READY) return null
            val peer = parseAdvertisement(message.copyOfRange(1, message.size)) ?: return null
            return HandshakeMessage(kind, peer)
        }

        private fun compareAddresses(left: ByteArray, right: ByteArray): Int {
            for (index in left.indices) {
                val difference = (left[index].toInt() and 0xff) - (right[index].toInt() and 0xff)
                if (difference != 0) return difference
            }
            return 0
        }
    }
}

private object NativeCore {
    init { System.loadLibrary("awaretun") }

    external fun start(
        tunFd: Int,
        udpFd: Int,
        peerAddress: ByteArray,
        localNodeId: ByteArray,
        remoteNodeId: ByteArray,
        scopeId: Int,
        port: Int,
        shouldDial: Boolean,
        isGateway: Boolean
    )

    external fun removePeer(remoteNodeId: ByteArray)

    external fun stop()
}
