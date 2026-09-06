package org.kysecurity.authenticator.passwords

import android.content.Context
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.appcompat.app.AlertDialog
import androidx.lifecycle.Lifecycle
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.kysecurity.authenticator.MainActivity
import org.kysecurity.authenticator.pairing.PairedAccount
import org.kysecurity.authenticator.pairing.PairingStore
import org.kysecurity.authenticator.security.AppLockManager
import java.io.File

/** UI/lifecycle checks with fake unlocked state; these do not simulate biometric authentication. */
@RunWith(AndroidJUnit4::class)
class VaultUiTest {
    private val context = ApplicationProvider.getApplicationContext<Context>()
    private val key = ByteArray(32) { 9 }
    private val file get() = File(context.filesDir, "passwords_vault.kdbx")
    private val entry = PasswordEntry("Restore me", "fixture user", "fixture secret")

    @Before fun setup() {
        file.delete()
        KdbxPasswordVault.saveEntries(file, key, listOf(entry))
        PairingStore(context).save(PairedAccount("https://example.test", "fixture-device", "Fixture"))
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        if (android.os.Build.VERSION.SDK_INT >= 33) {
            instrumentation.uiAutomation.grantRuntimePermission(context.packageName, android.Manifest.permission.POST_NOTIFICATIONS)
        }
        // Test-only state injection keeps this test independent of biometric hardware.
        instrumentation.runOnMainSync {
            for ((field, value) in mapOf("activeVaultKey" to key.copyOf(), "activePasswordVaultKey" to key.copyOf(), "isUnlocked" to true)) {
                AppLockManager::class.java.getDeclaredField(field).apply { isAccessible = true }.set(AppLockManager, value)
            }
        }
    }

    @After fun cleanup() {
        AppLockManager.lock()
        PairingStore(context).clear()
        file.delete()
    }

    private fun invoke(activity: MainActivity, name: String) = MainActivity::class.java
        .getDeclaredMethod(name).apply { isAccessible = true }.invoke(activity)

    @Suppress("UNCHECKED_CAST")
    private fun dialogs(activity: MainActivity) = MainActivity::class.java.getDeclaredField("openDialogs")
        .apply { isAccessible = true }.get(activity) as Set<AlertDialog>

    private fun texts(view: View): List<TextView> = buildList {
        if (view is TextView) add(view)
        if (view is ViewGroup) for (i in 0 until view.childCount) addAll(texts(view.getChildAt(i)))
    }

    private fun awaitDialog(scenario: ActivityScenario<MainActivity>, text: String) {
        val deadline = android.os.SystemClock.elapsedRealtime() + 30_000
        do {
            var found = false
            scenario.onActivity { activity ->
                found = dialogs(activity).any { dialog -> texts(checkNotNull(dialog.window).decorView).any { it.text.toString() == text } }
            }
            if (found) return
            Thread.sleep(25)
        } while (android.os.SystemClock.elapsedRealtime() < deadline)
        fail("Dialog did not show: $text")
    }

    @Test fun recycleViewRestoresTheOriginalEntry() {
        KdbxPasswordVault.delete(file, key, entry.id)
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            scenario.onActivity { activity ->
                assertTrue("Fixture activity must be unlocked", AppLockManager.isUnlocked())
                invoke(activity, "showRecycleBin")
            }
            awaitDialog(scenario, "Restore to vault")
            scenario.onActivity { activity ->
                val dialog = dialogs(activity).single()
                val text = texts(checkNotNull(dialog.window).decorView)
                assertTrue(text.any { it.text.toString() == "Restore me" })
                assertFalse(text.any { it.text.toString() == "fixture secret" })
                text.single { it.text.toString() == "Restore to vault" }.performClick()
            }
            awaitDialog(scenario, "Recycle Bin is empty.")
            assertEquals(entry, KdbxPasswordVault.loadEntries(file, key).single())
            assertTrue(KdbxPasswordVault.recycledEntries(file, key).isEmpty())
        }
    }

    @Test fun backgroundClearsAndDismissesRevealedText() {
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            lateinit var secretView: TextView
            lateinit var dialog: AlertDialog
            scenario.onActivity { activity ->
                assertTrue("Fixture activity must be unlocked", AppLockManager.isUnlocked())
                MainActivity::class.java.getDeclaredMethod("showPasswordDetails", PasswordEntry::class.java)
                    .apply { isAccessible = true }.invoke(activity, entry)
                dialog = dialogs(activity).single()
                secretView = texts(checkNotNull(dialog.window).decorView).single { it.text.toString() == "fixture secret" }
            }
            scenario.moveToState(Lifecycle.State.CREATED)
            // ActivityScenario observes super.onStop before our override finishes clearing views.
            InstrumentationRegistry.getInstrumentation().runOnMainSync {
                assertFalse(AppLockManager.isUnlocked())
                assertFalse(dialog.isShowing)
                assertEquals("", secretView.text.toString())
            }
        }
    }
}
