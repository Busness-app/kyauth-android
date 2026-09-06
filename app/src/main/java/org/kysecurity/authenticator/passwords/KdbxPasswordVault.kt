package org.kysecurity.authenticator.passwords

import app.keemobile.kotpass.constants.BasicField
import app.keemobile.kotpass.cryptography.EncryptedValue
import app.keemobile.kotpass.database.Credentials
import app.keemobile.kotpass.database.KeePassDatabase
import app.keemobile.kotpass.database.decode
import app.keemobile.kotpass.database.encode
import app.keemobile.kotpass.database.modifiers.modifyContent
import app.keemobile.kotpass.database.modifiers.binaries
import app.keemobile.kotpass.database.modifiers.moveEntry
import app.keemobile.kotpass.database.modifiers.removeEntry
import app.keemobile.kotpass.database.modifiers.withHistory
import app.keemobile.kotpass.models.Entry
import app.keemobile.kotpass.models.EntryFields
import app.keemobile.kotpass.models.EntryValue
import app.keemobile.kotpass.models.Group
import app.keemobile.kotpass.models.Meta
import app.keemobile.kotpass.models.TimeData
import java.io.ByteArrayOutputStream
import java.io.File
import java.time.Instant
import java.util.UUID
import org.kysecurity.authenticator.security.writeAtomically

/** All local readers, writers and sync installations share this transaction boundary. */
object KdbxPasswordVault {
    private const val MAX_VAULT_BYTES = 25L * 1024 * 1024

    /** Metadata only: even records without a title or password can be recovered. */
    data class EntrySummary(val id: String, val title: String, val username: String, val isPasskey: Boolean)

    private fun summarize(entry: Entry) = EntrySummary(
        entry.uuid.toString(), entry.fields[BasicField.Title.key]?.content.orEmpty().ifBlank { "Untitled entry" },
        entry.fields[BasicField.UserName.key]?.content.orEmpty(), entry.fields[PasskeyData.FIELD_RP_ID] != null,
    )

    @Synchronized
    fun recycledEntries(file: File, key: ByteArray): List<EntrySummary> =
        records(read(file, key), recycled = true).map(::summarize)

    @Synchronized
    fun restore(file: File, key: ByteArray, id: String) {
        val database = read(file, key)
        val uuid = UUID.fromString(id)
        require(records(database, recycled = true).any { it.uuid == uuid }) { "Entry is not in the recycle bin" }
        write(file, database.moveEntry(uuid, database.content.group.uuid))
    }

    internal fun decode(bytes: ByteArray, key: ByteArray): KeePassDatabase {
        require(bytes.isNotEmpty() && bytes.size <= MAX_VAULT_BYTES) { "Invalid password vault size" }
        val credentials = Credentials.from(EncryptedValue.fromString(key.joinToString("") { "%02x".format(it) }))
        return KeePassDatabase.decode(bytes.inputStream(), credentials).also { database ->
            val ids = mutableSetOf<UUID>()
            database.content.group.traverse { require(ids.add(it.uuid)) { "Duplicate vault UUID" } }
            require(database.content.meta.recycleBinUuid != database.content.group.uuid) { "Vault root cannot be the recycle bin" }
        }
    }

    private fun read(file: File, key: ByteArray): KeePassDatabase {
        require(file.length() <= MAX_VAULT_BYTES) { "Password vault file is too large to decode" }
        return decode(file.readBytes(), key)
    }

    private fun write(file: File, database: KeePassDatabase) {
        val output = ByteArrayOutputStream()
        database.encode(output)
        require(output.size() <= MAX_VAULT_BYTES) { "Password vault file is too large" }
        writeAtomically(file, output.toByteArray())
    }

    private fun newDatabase(key: ByteArray) = KeePassDatabase.Ver4x.create(
        rootName = "KyAuth Passwords",
        meta = Meta(generator = "KyAuth", recycleBinEnabled = true),
        credentials = Credentials.from(EncryptedValue.fromString(key.joinToString("") { "%02x".format(it) })),
    )

    private fun records(database: KeePassDatabase, recycled: Boolean = false): List<Entry> = buildList {
        fun visit(group: Group, inBin: Boolean) {
            val deleted = inBin || group.uuid == database.content.meta.recycleBinUuid
            if (deleted == recycled) addAll(group.entries)
            group.groups.forEach { visit(it, deleted) }
        }
        visit(database.content.group, false)
    }

    private fun project(entry: Entry): PasswordEntry? {
        val title = entry.fields[BasicField.Title.key]?.content.orEmpty()
        val password = entry.fields[BasicField.Password.key]?.content.orEmpty()
        val passkey = PasskeyData.fromKeepassCustomFields(entry.fields.entries.associate { it.key to it.value.content })
        if (title.isBlank() || (password.isEmpty() && passkey == null)) return null
        return PasswordEntry(title, entry.fields[BasicField.UserName.key]?.content.orEmpty(), password,
            entry.fields[BasicField.Url.key]?.content?.ifBlank { null },
            entry.fields[BasicField.Notes.key]?.content?.ifBlank { null }, passkey, entry.uuid.toString())
    }

    @Synchronized
    fun loadEntries(vaultFile: File, vaultKey: ByteArray): List<PasswordEntry> =
        if (!vaultFile.exists()) emptyList() else records(read(vaultFile, vaultKey)).mapNotNull(::project)

    /** UI projections are diffed by UUID; unrepresented records and fields are never rewritten. */
    @Synchronized
    fun update(vaultFile: File, vaultKey: ByteArray, mutate: (MutableList<PasswordEntry>) -> Boolean): List<PasswordEntry> {
        var database: KeePassDatabase = if (vaultFile.exists()) read(vaultFile, vaultKey) else newDatabase(vaultKey)
        val before = records(database).mapNotNull(::project).associateBy { it.id }
        val entries = before.values.toMutableList()
        if (!mutate(entries)) return before.values.toList()
        val after = entries.associateBy { it.id }
        require(after.size == entries.size) { "Duplicate entry UUID" }
        entries.forEach { require(UUID.fromString(it.id).toString() == it.id) { "Invalid entry UUID" } }
        val existingIds = mutableSetOf<UUID>()
        database.content.group.traverse { existingIds.add(it.uuid) }
        val additions = entries.filter { it.id !in before }.map {
            require(UUID.fromString(it.id) !in existingIds) { "Entry UUID already exists outside the live password list" }
            patch(Entry(uuid = UUID.fromString(it.id)), null, it, database)
        }
        val removed = before.keys - after.keys
        removed.forEach { database = deleteRecord(database, UUID.fromString(it), allowPermanent = false) }
        fun patchGroup(group: Group): Group = group.copy(
            entries = group.entries.map { original ->
                val old = before[original.uuid.toString()]
                val changed = after[original.uuid.toString()]
                if (old != null && changed != null && old != changed) patch(original, old, changed, database) else original
            },
            groups = group.groups.map(::patchGroup),
        )
        if (before == after) return entries
        database = database.modifyContent {
            val patched = patchGroup(group)
            copy(group = patched.copy(entries = patched.entries + additions))
        }
        write(vaultFile, database)
        return records(database).mapNotNull(::project)
    }

    /** Creation only. Existing vaults must go through update, never a cached list replacement. */
    @Synchronized
    fun saveEntries(vaultFile: File, vaultKey: ByteArray, entries: List<PasswordEntry>) {
        check(!vaultFile.exists()) { "Password vault already exists; use a vault transaction" }
        if (entries.isEmpty()) write(vaultFile, newDatabase(vaultKey))
        else update(vaultFile, vaultKey) { it.addAll(entries); true }
    }

    private fun patch(original: Entry, old: PasswordEntry?, changed: PasswordEntry, database: KeePassDatabase): Entry {
        val fields = original.fields.toMutableMap()
        fun set(name: String, before: String?, after: String?, secret: Boolean = false) {
            if (old != null && before == after) return
            if (after == null) fields.remove(name)
            else fields[name] = if (secret || fields[name] is EntryValue.Encrypted) {
                EntryValue.Encrypted(EncryptedValue.fromString(after))
            } else EntryValue.Plain(after)
        }
        set(BasicField.Title.key, old?.title, changed.title)
        set(BasicField.UserName.key, old?.username, changed.username)
        set(BasicField.Password.key, old?.password, changed.password, true)
        set(BasicField.Url.key, old?.url, changed.url)
        set(BasicField.Notes.key, old?.notes, changed.notes)
        val oldPasskey = old?.passkey?.toKeepassCustomFields().orEmpty()
        val newPasskey = changed.passkey?.toKeepassCustomFields().orEmpty()
        (oldPasskey.keys + newPasskey.keys).forEach { name ->
            set(name, oldPasskey[name], newPasskey[name], name == PasskeyData.FIELD_PRIVATE_KEY)
        }
        val result = original.copy(fields = EntryFields(fields), times = original.times?.copy(
            lastModificationTime = Instant.now(), lastAccessTime = Instant.now(),
        ) ?: TimeData.create())
        if (old == null) return result
        val counterOnly = old.passkey != null && changed.passkey != null &&
            old.copy(passkey = old.passkey.copy(signCount = changed.passkey.signCount)) == changed
        if (counterOnly) return result
        val meta = database.content.meta
        val history = original.withHistory { result }.history.let {
            if (meta.historyMaxItems >= 0) it.takeLast(meta.historyMaxItems) else it
        }
        var totalBytes = 0L
        val retained = history.asReversed().takeWhile { entry ->
            // Approximate uncompressed entry content plus referenced attachment bytes. This is a
            // history budget, not the encrypted file ceiling; -1 explicitly requests no limit.
            totalBytes += 256L + entry.fields.entries.sumOf { (name, value) ->
                name.toByteArray().size.toLong() + value.content.toByteArray().size
            } + entry.tags.sumOf { it.toByteArray().size.toLong() } +
                entry.customData.toString().toByteArray().size + entry.autoType.toString().toByteArray().size +
                entry.overrideUrl.toByteArray().size + entry.binaries.sumOf {
                    (database.binaries[it.hash]?.getContent()?.size ?: 0).toLong() + it.name.toByteArray().size
                }
            meta.historyMaxSize < 0 || totalBytes <= meta.historyMaxSize
        }.asReversed()
        return result.copy(history = retained)
    }

    @Synchronized
    fun recyclingEnabled(file: File, key: ByteArray): Boolean = read(file, key).content.meta.recycleBinEnabled

    @Synchronized
    fun delete(file: File, key: ByteArray, id: String, allowPermanent: Boolean = false) {
        val original = read(file, key)
        val updated = deleteRecord(original, UUID.fromString(id), allowPermanent)
        if (updated !== original) write(file, updated)
    }

    private fun deleteRecord(original: KeePassDatabase, id: UUID, allowPermanent: Boolean): KeePassDatabase {
        if (records(original).none { it.uuid == id }) return original
        if (!original.content.meta.recycleBinEnabled) {
            check(allowPermanent) { "Recycling is disabled; confirm permanent deletion" }
            return original.removeEntry(id)
        }
        var database = original
        val binId = original.content.meta.recycleBinUuid
        val binExists = binId != null && original.content.group.findChildGroup { it.uuid == binId } != null
        val destination = if (binExists) checkNotNull(binId) else {
            val bin = Group.createRecycleBin("Recycle Bin")
            database = database.modifyContent { copy(
                group = group.copy(groups = group.groups + bin),
                meta = meta.copy(recycleBinUuid = bin.uuid, recycleBinChanged = Instant.now()),
            ) }
            bin.uuid
        }
        return database.moveEntry(id, destination)
    }
}
