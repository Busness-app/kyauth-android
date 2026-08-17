package org.kysecurity.authenticator.pairing

import android.content.Context
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import java.util.UUID

data class PairedAccount(
    val serverUrl: String,
    val deviceId: String,
    val deviceName: String,
    val username: String? = null,
    val userId: String? = null,
)

class PairingStore(context: Context) {
    private val preferences = EncryptedSharedPreferences.create(
        context,
        "pairing",
        MasterKey.Builder(context).setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build(),
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
    )

    fun deviceIdentifier(): String = preferences.getString("installation_id", null) ?: UUID.randomUUID().toString().also {
        preferences.edit().putString("installation_id", it).apply()
    }

    fun account(): PairedAccount? {
        val serverUrl = preferences.getString("server_url", null) ?: return null
        val deviceId = preferences.getString("device_id", null) ?: return null
        val deviceName = preferences.getString("device_name", null) ?: return null
        val username = preferences.getString("username", null)
        val userId = preferences.getString("user_id", null)
        return PairedAccount(serverUrl, deviceId, deviceName, username, userId)
    }

    fun save(account: PairedAccount) {
        preferences.edit()
            .putString("server_url", account.serverUrl)
            .putString("device_id", account.deviceId)
            .putString("device_name", account.deviceName)
            .putString("username", account.username)
            .putString("user_id", account.userId)
            .apply()
    }

    fun clear() {
        preferences.edit()
            .remove("server_url")
            .remove("device_id")
            .remove("device_name")
            .remove("username")
            .remove("user_id")
            .apply()
    }
}

