package org.kysecurity.authenticator.security

import android.app.KeyguardManager
import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class DeviceSecurityTest {
    @Test
    fun vaultKekRequiresASecureDeviceAndCreatesRsaOaepCipher() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        assumeTrue(context.getSystemService(KeyguardManager::class.java).isDeviceSecure)

        val cipher = VaultKek.unwrapCipher()

        assertEquals("RSA/ECB/OAEPWithSHA-256AndMGF1Padding", cipher.algorithm)
    }

    @Test
    fun productionBackupFlagsRemainDisabled() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val info = context.packageManager.getApplicationInfo(context.packageName, 0)

        assertTrue(info.flags and android.content.pm.ApplicationInfo.FLAG_ALLOW_BACKUP == 0)
    }
}
