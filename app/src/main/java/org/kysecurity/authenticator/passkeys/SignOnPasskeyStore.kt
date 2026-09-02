package org.kysecurity.authenticator.passkeys

import android.content.Context
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

/**
 * Persists the non-secret half of the KySignOn passkey. The private key is non-exportable and
 * never passes through here — only rpId, credential id, user handle, sign count, the Keystore
 * alias and which hardware backed it.
 *
 * Modelled on [org.kysecurity.authenticator.pairing.PairingStore]: same dependency, same pattern,
 * no new crypto and deliberately not a third KDBX vault.
 */
class SignOnPasskeyStore(context: Context) {

    private val preferences = EncryptedSharedPreferences.create(
        context,
        "signon_passkey",
        MasterKey.Builder(context).setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build(),
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
    )

    fun record(): SignOnPasskeyRecord? =
        SignOnPasskeyRecord.fromJson(preferences.getString(KEY_RECORD, null))

    fun save(record: SignOnPasskeyRecord) {
        preferences.edit().putString(KEY_RECORD, record.toJson()).apply()
    }

    fun clear() {
        preferences.edit().remove(KEY_RECORD).apply()
    }

    private companion object {
        const val KEY_RECORD = "record"
    }
}
