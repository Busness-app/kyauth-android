package org.kysecurity.authenticator.passwords

import android.content.Context
import android.os.Looper
import android.os.StrictMode
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.kysecurity.authenticator.MainActivity
import org.kysecurity.authenticator.security.AppLockManager
import java.io.File
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

@RunWith(AndroidJUnit4::class)
class VaultThreadingTest {
    @Test fun UITransactionsAndRecyclingReadsStayOffTheMainThread() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val file = File(context.filesDir, "passwords_vault.kdbx")
        val key = ByteArray(32) { 7 }
        file.delete()
        KdbxPasswordVault.saveEntries(file, key, emptyList())
        instrumentation.runOnMainSync {
            for ((field, value) in mapOf("activePasswordVaultKey" to key.copyOf(), "activeVaultKey" to key.copyOf(), "isUnlocked" to true)) {
                AppLockManager::class.java.getDeclaredField(field).apply { isAccessible = true }.set(AppLockManager, value)
            }
        }
        val violations = ConcurrentLinkedQueue<Throwable>()
        try {
            ActivityScenario.launch(MainActivity::class.java).use { scenario ->
                lateinit var policy: StrictMode.ThreadPolicy
                val saved = CountDownLatch(1)
                val entry = PasswordEntry("Thread fixture", "", "fixture secret")
                scenario.onActivity { activity ->
                    policy = StrictMode.getThreadPolicy()
                    StrictMode.setThreadPolicy(StrictMode.ThreadPolicy.Builder().detectDiskReads().detectDiskWrites()
                        .penaltyListener({ it.run() }) { violations.add(it) }.build())
                    val mutation: () -> Unit = {
                        assertNotEquals(Looper.getMainLooper(), Looper.myLooper())
                        KdbxPasswordVault.update(file, key) { it.add(entry); true }
                    }
                    val afterSave: () -> Unit = {
                        assertEquals(Looper.getMainLooper(), Looper.myLooper())
                        saved.countDown()
                    }
                    MainActivity::class.java.getDeclaredMethod("mutatePasswords", Function0::class.java, Function0::class.java)
                        .apply { isAccessible = true }.invoke(activity, afterSave, mutation)
                }
                try {
                    assertTrue("save callback", saved.await(30, TimeUnit.SECONDS))
                    val deleted = CountDownLatch(1)
                    scenario.onActivity { activity ->
                        val operation: (ByteArray) -> Boolean = { currentKey ->
                            assertNotEquals(Looper.getMainLooper(), Looper.myLooper())
                            assertTrue(KdbxPasswordVault.recyclingEnabled(file, currentKey))
                            KdbxPasswordVault.delete(file, currentKey, entry.id)
                            KdbxPasswordVault.loadEntries(file, currentKey).isEmpty()
                        }
                        val onSuccess: (Boolean) -> Unit = { empty ->
                            assertTrue(empty)
                            assertEquals(Looper.getMainLooper(), Looper.myLooper())
                            deleted.countDown()
                        }
                        MainActivity::class.java.getDeclaredMethod("readPasswordVault", Function1::class.java, Function1::class.java)
                            .apply { isAccessible = true }.invoke(activity, operation, onSuccess)
                    }
                    assertTrue("delete callback", deleted.await(30, TimeUnit.SECONDS))
                    assertTrue("KDBX I/O violated StrictMode", violations.none { violation ->
                        violation.stackTrace.any { it.className.contains("passwords.KdbxPasswordVault") }
                    })
                } finally { instrumentation.runOnMainSync { StrictMode.setThreadPolicy(policy) } }
            }
        } finally {
            AppLockManager.lock()
            file.delete()
        }
    }
}
