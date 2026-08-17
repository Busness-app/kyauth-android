package org.kysecurity.authenticator.totp

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

class KdbxTotpVaultTest {
    @get:Rule
    val tempFolder = TemporaryFolder()

    @Test
    fun createsAndReadsKdbxV4Vault() {
        val vaultFile = File(tempFolder.root, "totp_vault.kdbx")
        val vaultKey = ByteArray(32) { (it + 1).toByte() }

        val initial = listOf(
            TotpEntry(
                title = "Google (test@gmail.com)",
                secretBase32 = "JBSWY3DPEHPK3PXP",
                digits = 6,
                periodSeconds = 30,
                algorithm = TotpEntry.Algorithm.SHA1,
                issuer = "Google",
            ),
            TotpEntry(
                title = "GitHub (user)",
                secretBase32 = "NBSWY3DPEHPK3PXP",
                digits = 8,
                periodSeconds = 60,
                algorithm = TotpEntry.Algorithm.SHA256,
                issuer = "GitHub",
            ),
        )

        KdbxTotpVault.saveEntries(vaultFile, vaultKey, initial)
        assertTrue(vaultFile.exists())
        assertTrue(vaultFile.length() > 0)

        val loaded = KdbxTotpVault.loadEntries(vaultFile, vaultKey)
        assertEquals(2, loaded.size)

        val google = loaded.find { it.title == "Google (test@gmail.com)" }
        assertNotNull(google)
        assertEquals("JBSWY3DPEHPK3PXP", google!!.secretBase32)
        assertEquals(6, google.digits)
        assertEquals(30L, google.periodSeconds)
        assertEquals("Google", google.issuer)

        val github = loaded.find { it.title == "GitHub (user)" }
        assertNotNull(github)
        assertEquals("NBSWY3DPEHPK3PXP", github!!.secretBase32)
        assertEquals(8, github.digits)
        assertEquals(60L, github.periodSeconds)
        assertEquals(TotpEntry.Algorithm.SHA256, github.algorithm)
    }

    @Test
    fun replacesVaultAtomicallyWhenEntriesChange() {
        val vaultFile = File(tempFolder.root, "totp_vault.kdbx")
        val vaultKey = ByteArray(32) { (it + 1).toByte() }
        KdbxTotpVault.saveEntries(vaultFile, vaultKey, listOf(TotpEntry("First", "JBSWY3DPEHPK3PXP")))
        KdbxTotpVault.saveEntries(vaultFile, vaultKey, listOf(TotpEntry("Second", "NBSWY3DPEHPK3PXP")))

        assertEquals(listOf("Second"), KdbxTotpVault.loadEntries(vaultFile, vaultKey).map { it.title })
        assertTrue(!File(tempFolder.root, ".totp_vault.kdbx.tmp").exists())
    }
}
