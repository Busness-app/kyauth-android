package org.kysecurity.authenticator.passwords

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import org.kysecurity.authenticator.security.CredentialCipher

class KdbxPasswordVaultTest {
    @get:Rule
    val tempFolder = TemporaryFolder()

    @Test
    fun writesAndReadsPasswordEntriesWithoutATotpVault() {
        val vaultFile = File(tempFolder.root, "passwords_vault.kdbx")
        val vaultKey = CredentialCipher.generateVaultKey()
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

    @Test
    fun writesAndReadsPasskeyEntries() {
        val vaultFile = File(tempFolder.root, "passwords_vault_passkey.kdbx")
        val vaultKey = ByteArray(32) { (it + 13).toByte() }
        val passkey = PasskeyData(
            rpId = "github.com",
            username = "alice",
            userHandle = byteArrayOf(0x01, 0x02, 0x03),
            credentialId = byteArrayOf(0x04, 0x05, 0x06, 0x07),
            privateKeyPkcs8 = byteArrayOf(0x08, 0x09, 0x0A, 0x0B),
            signCount = 5,
        )
        val entries = listOf(
            PasswordEntry(
                title = "GitHub",
                username = "alice",
                passkey = passkey,
                url = "https://github.com",
                notes = "Personal passkey",
            ),
        )

        KdbxPasswordVault.saveEntries(vaultFile, vaultKey, entries)

        assertTrue(vaultFile.exists())
        assertTrue(vaultFile.length() > 0)
        val loaded = KdbxPasswordVault.loadEntries(vaultFile, vaultKey)
        assertEquals(1, loaded.size)
        assertEquals(entries[0].title, loaded[0].title)
        assertEquals(entries[0].username, loaded[0].username)
        assertEquals(entries[0].passkey, loaded[0].passkey)
        assertEquals(entries[0].url, loaded[0].url)
        assertEquals(entries[0].notes, loaded[0].notes)
    }
}
