package org.kysecurity.authenticator.passwords

import app.keemobile.kotpass.cryptography.EncryptedValue
import app.keemobile.kotpass.database.Credentials
import app.keemobile.kotpass.database.KeePassDatabase
import app.keemobile.kotpass.database.decode
import app.keemobile.kotpass.database.encode
import java.io.File
import org.junit.Assert.*
import org.junit.Test
import org.junit.Rule
import org.junit.rules.TemporaryFolder

class KdbxPreservationTest {
    @get:Rule val folder = TemporaryFolder()
    private val hex = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
    private val key = hex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    private fun fixture(resourceName: String = "vault-preservation.kdbx") = folder.newFile().apply {
        writeBytes(checkNotNull(this@KdbxPreservationTest.javaClass.getResourceAsStream("/$resourceName")).use { it.readBytes() })
    }

    @Test fun deletesReuseTheMetadataBinAndNeverPromoteItsDescendants() {
        val file = fixture()
        val before = KdbxPasswordVault.decode(file.readBytes(), key)
        val live = KdbxPasswordVault.loadEntries(file, key)
        val ids = live.take(2).map { it.id }
        ids.forEach { id ->
            KdbxPasswordVault.delete(file, key, id)
            assertFalse(KdbxPasswordVault.loadEntries(file, key).any { it.id == id })
            assertEquals(before.content.meta.recycleBinUuid, KdbxPasswordVault.decode(file.readBytes(), key).content.meta.recycleBinUuid)
        }
        val after = KdbxPasswordVault.decode(file.readBytes(), key)
        val bin = after.content.group.findChildGroup { it.uuid == after.content.meta.recycleBinUuid }!!.second
        assertTrue(bin.entries.map { it.uuid.toString() }.containsAll(ids))
        assertTrue(bin.groups.single().entries.any { it.fields["Title"]?.content == "Deleted child" })
        val bytes = file.readBytes()
        KdbxPasswordVault.delete(file, key, ids.first())
        assertArrayEquals(bytes, file.readBytes())
    }

    @Test fun disabledRecyclingRequiresConfirmationAndKeepsItsPolicy() {
        val file = fixture("vault-recycling-disabled.kdbx")
        val before = file.readBytes()
        val id = KdbxPasswordVault.loadEntries(file, key).first().id
        assertThrows(IllegalStateException::class.java) { KdbxPasswordVault.delete(file, key, id) }
        assertArrayEquals(before, file.readBytes())
        KdbxPasswordVault.delete(file, key, id, allowPermanent = true)
        val after = KdbxPasswordVault.decode(file.readBytes(), key)
        assertFalse(after.content.meta.recycleBinEnabled)
        assertTrue(after.content.deletedObjects.any { it.id.toString() == id })
    }

    @Test fun invalidInputAndCreationOverExistingFilesLeaveOriginalBytesAlone() {
        val file = fixture()
        val before = file.readBytes()
        assertThrows(IllegalStateException::class.java) { KdbxPasswordVault.saveEntries(file, key, emptyList()) }
        assertThrows(IllegalArgumentException::class.java) {
            KdbxPasswordVault.update(file, key) { it.add(it.first()); true }
        }
        assertArrayEquals(before, file.readBytes())
        file.writeBytes(byteArrayOf())
        assertThrows(IllegalArgumentException::class.java) { KdbxPasswordVault.update(file, key) { it.clear(); true } }
        assertEquals(0L, file.length())
    }

    @Test fun webFixtureSurvivesAndroidMutation() {
        val output = File("build/interop").apply { mkdirs() }
        val original = checkNotNull(this@KdbxPreservationTest.javaClass.getResourceAsStream("/vault-preservation.kdbx")).use { it.readBytes() }
        val database = KeePassDatabase.decode(original.inputStream(), Credentials.from(EncryptedValue.fromString(hex)))
        File(output, "noop.kdbx").outputStream().use { database.encode(it) }
        val edited = File(output, "edited.kdbx").apply { writeBytes(original) }
        KdbxPasswordVault.update(edited, key) { entries ->
            val index = entries.indexOfFirst { it.title == "Edit me" }
            entries[index] = entries[index].copy(password = "new secret")
            true
        }
        val reloaded = KeePassDatabase.decode(edited.inputStream(), Credentials.from(EncryptedValue.fromString(hex)))
        assertEquals(database.content.group.groups.map { it.uuid }, reloaded.content.group.groups.map { it.uuid })
        assertFalse(KdbxPasswordVault.loadEntries(edited, key).any { it.title.startsWith("Recycled") || it.title == "Deleted child" })
    }
}
