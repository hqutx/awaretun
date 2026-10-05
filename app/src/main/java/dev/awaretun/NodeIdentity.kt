package dev.awaretun

import android.content.Context
import java.security.SecureRandom

/** Keeps the address shown by the UI identical to the address installed on the TUN. */
internal object NodeIdentity {
    private const val PREFS = "awaretun"
    private const val NODE_ID = "node_id"

    fun get(context: Context): ByteArray {
        val preferences = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val stored = preferences.getString(NODE_ID, null)
        if (stored != null) return stored.chunked(2).map { it.toInt(16).toByte() }.toByteArray()

        val generated = ByteArray(8).also { SecureRandom().nextBytes(it) }
        preferences.edit().putString(NODE_ID, generated.joinToString("") { "%02x".format(it.toInt() and 0xff) })
            .apply()
        return generated
    }

    fun overlayAddress(nodeId: ByteArray): String {
        val groups = nodeId.toList().chunked(2).map { pair ->
            "%02x%02x".format(pair[0].toInt() and 0xff, pair[1].toInt() and 0xff)
        }
        return "fd71:6177:0:0:" + groups.joinToString(":")
    }
}
