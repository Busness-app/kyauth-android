package org.kysecurity.authenticator.passwords.kypasswords

import android.content.Context
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

data class KyPasswordServerAccount(
    val serverUrl: String,
    val deviceId: String,
    val sessionToken: String,
    val userId: String,
    val vaultVersion: Long = 0L,
    val lastSyncedEpoch: Long = 0L,
    val lastSyncError: String? = null,
)

class KyPasswordStore(context: Context) {
    private val preferences = EncryptedSharedPreferences.create(
        context,
        "kypasswords_pairing",
        MasterKey.Builder(context).setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build(),
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
    )

    fun account(): KyPasswordServerAccount? {
        val serverUrl = preferences.getString("server_url", null) ?: return null
        val deviceId = preferences.getString("device_id", null) ?: return null
        val sessionToken = preferences.getString("session_token", null) ?: return null
        val userId = preferences.getString("user_id", null) ?: return null
        val vaultVersion = preferences.getLong("vault_version", 0L)
        val lastSyncedEpoch = preferences.getLong("last_synced_epoch", 0L)
        val lastSyncError = preferences.getString("last_sync_error", null)
        return KyPasswordServerAccount(serverUrl, deviceId, sessionToken, userId, vaultVersion, lastSyncedEpoch, lastSyncError)
    }

    fun save(account: KyPasswordServerAccount) {
        preferences.edit()
            .putString("server_url", account.serverUrl)
            .putString("device_id", account.deviceId)
            .putString("session_token", account.sessionToken)
            .putString("user_id", account.userId)
            .putLong("vault_version", account.vaultVersion)
            .putLong("last_synced_epoch", account.lastSyncedEpoch)
            .putString("last_sync_error", account.lastSyncError)
            .apply()
    }

    fun updateSync(vaultVersion: Long, lastSyncedEpoch: Long = System.currentTimeMillis() / 1000) {
        preferences.edit()
            .putLong("vault_version", vaultVersion)
            .putLong("last_synced_epoch", lastSyncedEpoch)
            .remove("last_sync_error")
            .apply()
    }

    fun setSyncError(error: String) {
        preferences.edit()
            .putString("last_sync_error", error)
            .apply()
    }

    fun clear() {
        preferences.edit()
            .remove("server_url")
            .remove("device_id")
            .remove("session_token")
            .remove("user_id")
            .remove("vault_version")
            .remove("last_synced_epoch")
            .remove("last_sync_error")
            .apply()
    }
}
