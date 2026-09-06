package org.kysecurity.authenticator.passwords

import app.keemobile.kotpass.cryptography.EncryptedValue
import app.keemobile.kotpass.database.Credentials
import app.keemobile.kotpass.database.KeePassDatabase
import app.keemobile.kotpass.database.decode
import app.keemobile.kotpass.database.encode
import app.keemobile.kotpass.database.modifiers.modifyContent
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

    @Test fun restoreKeepsContentsAndUuidIncludingEntriesOutsideThePasswordProjection() {
        val file = fixture()
        val original = KdbxPasswordVault.decode(file.readBytes(), key)
        val bin = original.content.group.findChildGroup { it.uuid == original.content.meta.recycleBinUuid }!!.second
        val child = bin.groups.single().entries.first { it.fields["Title"]?.content == "Deleted child" }
        val deleted = KdbxPasswordVault.recycledEntries(file, key)
        assertTrue(deleted.any { it.title == "Untitled entry" })
        KdbxPasswordVault.restore(file, key, child.uuid.toString())
        val restored = KdbxPasswordVault.decode(file.readBytes(), key).content.group.entries.single { it.uuid == child.uuid }
        assertEquals(child.fields.entries.associate { it.key to it.value.content }, restored.fields.entries.associate { it.key to it.value.content })
        assertEquals(child.history, restored.history)
        assertEquals(child.binaries, restored.binaries)
        assertTrue(KdbxPasswordVault.loadEntries(file, key).any { it.id == child.uuid.toString() })
        assertEquals(deleted.size - 1, KdbxPasswordVault.recycledEntries(file, key).size)
        assertThrows(IllegalArgumentException::class.java) { KdbxPasswordVault.restore(file, key, child.uuid.toString()) }
        val hidden = KdbxPasswordVault.recycledEntries(file, key).first { it.title == "Untitled entry" }
        KdbxPasswordVault.restore(file, key, hidden.id)
        assertTrue(KdbxPasswordVault.decode(file.readBytes(), key).content.group.entries.any { it.uuid.toString() == hidden.id })
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

    @Test fun countersDoNotCreateHistoryAndUserEditsHonorConfiguredLimits() {
        val file = fixture()
        val passkey = PasswordEntry("Counter", "", passkey = PasskeyData("example.test", "", byteArrayOf(1), byteArrayOf(2), byteArrayOf(3)))
        KdbxPasswordVault.update(file, key) { it.add(passkey); true }
        val sizeBefore = file.length()
        repeat(200) {
            KdbxPasswordVault.update(file, key) { entries ->
                val index = entries.indexOfFirst { it.id == passkey.id }
                val entry = entries[index]
                entries[index] = entry.copy(passkey = entry.passkey!!.copy(signCount = it + 1)); true
            }
        }
        var db = KdbxPasswordVault.decode(file.readBytes(), key)
        assertTrue(db.content.group.entries.single { it.uuid.toString() == passkey.id }.history.isEmpty())
        assertTrue(file.length() < sizeBefore + 1024)
        db = db.modifyContent { copy(meta = meta.copy(historyMaxItems = 2, historyMaxSize = 1024)) }
        file.outputStream().use { db.encode(it) }
        repeat(5) { iteration ->
            KdbxPasswordVault.update(file, key) { entries ->
                val index = entries.indexOfFirst { it.id == passkey.id }
                entries[index] = entries[index].copy(username = "name-$iteration"); true
            }
        }
        db = KdbxPasswordVault.decode(file.readBytes(), key)
        assertTrue(db.content.group.entries.single { it.uuid.toString() == passkey.id }.history.size <= 2)
        db = db.modifyContent { copy(meta = meta.copy(historyMaxSize = 0)) }
        file.outputStream().use { db.encode(it) }
        KdbxPasswordVault.update(file, key) { entries ->
            val index = entries.indexOfFirst { it.id == passkey.id }
            entries[index] = entries[index].copy(username = "last name"); true
        }
        assertTrue(KdbxPasswordVault.decode(file.readBytes(), key).content.group.entries.single { it.uuid.toString() == passkey.id }.history.isEmpty())
    }

    @Test fun reuseIsExactAndIncludesWhitespaceButExcludesAllRecycledRecords() {
        val file = fixture()
        val matches = KdbxPasswordVault.reusedPasswords(file, key)
        assertEquals(setOf("Edit me", "Live namesake", "Spaces one", "Spaces two"), matches.map { it.entry.title }.toSet())
        assertTrue(matches.all { it.count == 2 })
        val id = matches.first { it.entry.title == "Spaces one" }.entry.id
        KdbxPasswordVault.delete(file, key, id)
        assertFalse(KdbxPasswordVault.reusedPasswords(file, key).any { it.entry.title.startsWith("Spaces") })
        KdbxPasswordVault.restore(file, key, id)
        assertEquals(2, KdbxPasswordVault.reusedPasswords(file, key).count { it.entry.title.startsWith("Spaces") })
        // The report also includes valid nonempty passwords on untitled records.
        KdbxPasswordVault.update(file, key) { entries ->
            entries.add(PasswordEntry("Hidden match", "", "hidden password")); true
        }
        assertTrue(KdbxPasswordVault.reusedPasswords(file, key).any { it.entry.title == "Untitled entry" && it.count == 2 })
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
        val recovered = File(output, "recovered.kdbx").apply { writeBytes(original) }
        listOf("Edit me", "Live namesake").forEach { title ->
            val id = KdbxPasswordVault.loadEntries(recovered, key).single { it.title == title }.id
            KdbxPasswordVault.delete(recovered, key, id)
        }
        val child = KdbxPasswordVault.recycledEntries(recovered, key).single { it.title == "Deleted child" }
        KdbxPasswordVault.restore(recovered, key, child.id)
    }
}
