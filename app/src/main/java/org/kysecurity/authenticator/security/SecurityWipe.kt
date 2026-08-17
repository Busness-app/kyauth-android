package org.kysecurity.authenticator.security

import android.content.Context
import org.kysecurity.authenticator.pairing.DeviceSigningKey
import org.kysecurity.authenticator.pairing.PairingStore
import java.io.File
import java.security.KeyStore

object SecurityWipe {
    fun wipe(context: Context) {
        // 1. Wipe PairingStore
        runCatching { PairingStore(context).clear() }

        // 2. Wipe AppLock SharedPreferences
        runCatching {
            context.getSharedPreferences("app_lock", Context.MODE_PRIVATE)
                .edit()
                .clear()
                .commit()
        }

        // 3. Wipe all app files (including KDBX vaults)
        runCatching {
            context.filesDir.listFiles()?.forEach { file ->
                file.deleteRecursively()
            }
        }

        // 4. Wipe cached files
        runCatching {
            context.cacheDir.listFiles()?.forEach { file ->
                file.deleteRecursively()
            }
        }

        // 5. Delete Keystore signing key and peppers
        runCatching { DeviceSigningKey.deleteKey() }
        runCatching {
            val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            val aliases = keyStore.aliases()
            while (aliases.hasMoreElements()) {
                val alias = aliases.nextElement()
                if (alias.startsWith("kyauth_") || alias.startsWith("kysignon_")) {
                    keyStore.deleteEntry(alias)
                }
            }
        }

        // 6. Reset in-memory state
        AppLockManager.onWipe()
    }
}
