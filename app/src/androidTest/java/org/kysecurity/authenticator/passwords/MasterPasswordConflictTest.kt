package org.kysecurity.authenticator.passwords

import android.content.Context
import android.os.SystemClock
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.kysecurity.authenticator.MainActivity
import org.kysecurity.authenticator.pairing.PairedAccount
import org.kysecurity.authenticator.pairing.PairingStore
import org.kysecurity.authenticator.passwords.kypasswords.*
import org.kysecurity.authenticator.security.AppLockManager
import java.io.File
import java.net.InetAddress
import java.net.ServerSocket

@RunWith(AndroidJUnit4::class)
class MasterPasswordConflictTest {
    private fun contains(view: View, text: String): Boolean =
        (view is TextView && view.text.toString() == text) ||
            (view is ViewGroup && (0 until view.childCount).any { contains(view.getChildAt(it), text) })

    @Test fun masterPasswordConflictKeepsTheKeyAndOffersResolution() {
        val policy = android.security.NetworkSecurityPolicy.getInstance()
        assertTrue(policy.isCleartextTrafficPermitted("127.0.0.1"))
        assertFalse(policy.isCleartextTrafficPermitted("example.test"))
        val context = ApplicationProvider.getApplicationContext<Context>()
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val file = File(context.filesDir, "passwords_vault.kdbx")
        val remoteFile = File(context.cacheDir, "fixture-remote.kdbx")
        val key = ByteArray(32) { 12 }
        file.delete(); remoteFile.delete()
        KyPasswordVaultSync.clearConflicts(context.filesDir)
        KdbxPasswordVault.saveEntries(file, key, listOf(PasswordEntry("Local", "", "local fixture secret")))
        KdbxPasswordVault.saveEntries(remoteFile, key, listOf(PasswordEntry("Remote", "", "remote fixture secret")))
        val remote = remoteFile.readBytes()
        val envelope = KyPasswordEnvelopeCrypto.wrapVaultKey(key, "fixture password")
        val meta = KyPasswordMetadata("fixture", 1L, null, envelope, null)
        val metadataBytes = org.json.JSONObject().put("version", 1).put("passwordEnvelope", envelope).toString().toByteArray()
        val server = ServerSocket(0, 0, InetAddress.getByName("127.0.0.1"))
        val worker = Thread {
            try {
                while (!server.isClosed) server.accept().use { socket ->
                    val reader = socket.getInputStream().bufferedReader()
                    val request = reader.readLine().orEmpty()
                    while (!reader.readLine().isNullOrEmpty()) { /* consume headers */ }
                    val body = if (request.contains("/metadata ")) metadataBytes else remote
                    socket.getOutputStream().apply {
                        write("HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: ${body.size}\r\nX-Vault-Version: 1\r\n\r\n".toByteArray())
                        write(body); flush()
                    }
                }
            } catch (_: java.io.IOException) { /* closed by teardown */ }
        }.apply { isDaemon = true; start() }
        val account = KyPasswordServerAccount("http://127.0.0.1:${server.localPort}", "fixture-device", "fixture-token", "fixture", vaultVersion = 1)
        val store = KyPasswordStore(context)
        store.save(account)
        PairingStore(context).save(PairedAccount("https://example.test", "fixture-device", "Fixture"))
        if (android.os.Build.VERSION.SDK_INT >= 33) {
            instrumentation.uiAutomation.grantRuntimePermission(context.packageName, android.Manifest.permission.POST_NOTIFICATIONS)
        }
        instrumentation.runOnMainSync {
            for ((field, value) in mapOf("activeVaultKey" to key.copyOf(), "activePasswordVaultKey" to null, "isUnlocked" to true)) {
                AppLockManager::class.java.getDeclaredField(field).apply { isAccessible = true }.set(AppLockManager, value)
            }
        }
        try {
            ActivityScenario.launch(MainActivity::class.java).use { scenario ->
                scenario.onActivity { activity ->
                    MainActivity::class.java.getDeclaredField("activeTab").apply { isAccessible = true }.set(activity, MainActivity.Tab.PASSWORDS)
                    MainActivity::class.java.getDeclaredMethod("unlockKyPasswords", KyPasswordServerAccount::class.java,
                        String::class.java, KyPasswordMetadata::class.java).apply { isAccessible = true }
                        .invoke(activity, account, "fixture password", meta)
                }
                val deadline = SystemClock.elapsedRealtime() + 60_000
                var offered = false
                while (!offered && SystemClock.elapsedRealtime() < deadline) {
                    scenario.onActivity { offered = contains(it.window.decorView, "Resolve vault conflict") }
                    if (!offered) Thread.sleep(25)
                }
                assertTrue("Conflict resolution must remain reachable: unlocked=${AppLockManager.isUnlocked()}, key=${AppLockManager.getPasswordVaultKey() != null}, error=${store.account()?.lastSyncError}", offered)
                assertNotNull(AppLockManager.getPasswordVaultKey())
                assertNotNull(store.account()?.lastSyncError)
                assertEquals("Local", KdbxPasswordVault.loadEntries(file, key).single().title)
            }
        } finally {
            server.close(); worker.join(1000)
            AppLockManager.lock()
            store.clear(); PairingStore(context).clear()
            context.getSharedPreferences("app_lock", Context.MODE_PRIVATE).edit().clear().commit()
            file.delete(); remoteFile.delete()
            KyPasswordVaultSync.clearConflicts(context.filesDir)
        }
    }
}
