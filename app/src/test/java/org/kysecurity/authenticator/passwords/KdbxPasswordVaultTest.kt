package org.kysecurity.authenticator.passwords

import app.keemobile.kotpass.cryptography.EncryptedValue
import app.keemobile.kotpass.database.Credentials
import app.keemobile.kotpass.database.KeePassDatabase
import app.keemobile.kotpass.database.decode
import app.keemobile.kotpass.database.encode
import app.keemobile.kotpass.database.modifiers.modifyParentGroup
import app.keemobile.kotpass.models.Entry
import app.keemobile.kotpass.models.EntryFields
import app.keemobile.kotpass.models.EntryValue
import app.keemobile.kotpass.models.Meta
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.util.UUID
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import org.kysecurity.authenticator.passwords.kypasswords.KyPasswordEnvelopeCrypto
import org.kysecurity.authenticator.security.CredentialCipher

class KdbxPasswordVaultTest {
    @get:Rule
    val tempFolder = TemporaryFolder()

    /**
     * The direction that was never tested: a vault written by kdbxweb, the library the KyPasswords
     * web client uses, opened by kotpass. Regenerate with tools/gen_kdbx_interop_fixture.js.
     *
     * Three things have to line up and all three were assumptions. The credential is the vault key
     * as lowercase hex *text*, not the raw bytes - keying on the bytes is why cross-client opening
     * never worked, and why a downloaded .kdbx had no password a human could type. The KDF is
     * Argon2d at m=32 MiB / t=8 / p=2, matching kotpass's default; kdbxweb's own defaults are far
     * weaker. And kdbxweb writes KDBX 4.0 where kotpass writes 4.1, because its setVersion takes
     * only a major version.
     */
    @Test
    fun opensVaultWrittenByTheKyPasswordsWebClient() {
        val vaultFile = File(tempFolder.root, "kypasswords-web-vault.kdbx")
        vaultFile.writeBytes(
            checkNotNull(javaClass.getResourceAsStream("/kypasswords-web-vault.kdbx")) {
                "kdbxweb interop fixture is missing from test resources"
            }.use { it.readBytes() },
        )
        val vaultKey = KyPasswordEnvelopeCrypto.hexToBytes(
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
        )

        val entries = KdbxPasswordVault.loadEntries(vaultFile, vaultKey)

        assertEquals(
            listOf(
                PasswordEntry(
                    title = "Interop fixture",
                    username = "alice@example.test",
                    password = "web-written-secret",
                    url = "https://passwords.example.test",
                    notes = "Written by kdbxweb",
                    id = entries.single().id,
                ),
            ),
            entries,
        )
    }

    @Test
    fun writesTheUrlUnderTheStandardKeePassFieldKey() {
        // The standard key is "URL". kotpass's BasicField.Url.name is "Url" - only its `key` is
        // the wire name - so writing the enum name puts the URL somewhere KeePassXC, KeePassDX and
        // the KyPasswords web client do not look.
        val vaultFile = File(tempFolder.root, "url-key.kdbx")
        val vaultKey = CredentialCipher.generateVaultKey()
        KdbxPasswordVault.saveEntries(
            vaultFile,
            vaultKey,
            listOf(PasswordEntry(title = "Site", username = "u", password = "p", url = "https://example.test")),
        )

        val credentials = Credentials.from(EncryptedValue.fromString(KyPasswordEnvelopeCrypto.bytesToHex(vaultKey)))
        val entry = KeePassDatabase
            .decode(ByteArrayInputStream(vaultFile.readBytes()), credentials)
            .content.group.entries.single()

        assertEquals("https://example.test", entry.fields["URL"]?.content)
        assertEquals(null, entry.fields["Url"])
    }

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
