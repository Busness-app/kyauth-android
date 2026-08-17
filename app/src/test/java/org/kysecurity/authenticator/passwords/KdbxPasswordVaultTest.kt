package org.kysecurity.authenticator.passwords

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class KdbxPasswordVaultTest {
    @get:Rule
    val tempFolder = TemporaryFolder()

    @Test
    fun writesAndReadsPasswordEntriesWithoutATotpVault() {
        val vaultFile = File(tempFolder.root, "passwords_vault.kdbx")
        val vaultKey = ByteArray(32) { (it + 7).toByte() }
        val entries = listOf(
            PasswordEntry(
                title = "KySignOn",
                username = "alice@example.test",
                password = "correct-horse-battery-staple",
                url = "https://auth.example.test",
                notes = "Test account",
            ),
        )

        KdbxPasswordVault.saveEntries(vaultFile, vaultKey, entries)

        assertTrue(vaultFile.exists())
        assertTrue(vaultFile.length() > 0)
        assertEquals(entries, KdbxPasswordVault.loadEntries(vaultFile, vaultKey))
        assertTrue(!File(tempFolder.root, ".passwords_vault.kdbx.tmp").exists())
    }
}
