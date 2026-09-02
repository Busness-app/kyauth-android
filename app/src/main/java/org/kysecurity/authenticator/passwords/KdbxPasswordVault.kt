package org.kysecurity.authenticator.passwords

import app.keemobile.kotpass.constants.BasicField
import app.keemobile.kotpass.cryptography.EncryptedValue
import app.keemobile.kotpass.database.Credentials
import app.keemobile.kotpass.database.KeePassDatabase
import app.keemobile.kotpass.database.decode
import app.keemobile.kotpass.database.encode
import app.keemobile.kotpass.database.modifiers.modifyParentGroup
import app.keemobile.kotpass.models.Entry
import app.keemobile.kotpass.models.EntryFields
import app.keemobile.kotpass.models.EntryValue
import app.keemobile.kotpass.models.Group
import app.keemobile.kotpass.models.Meta
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.util.UUID
import org.kysecurity.authenticator.security.writeAtomically

/**
 * All access is serialized on this object: the UI, Autofill, the Credential Provider and vault
 * sync all read-modify-write the same file, and an unsynchronized pair of those loses an update.
 *
 * [loadEntries] throws on a vault it cannot decode. Callers must not turn that into an empty list
 * and save over it — an unreadable vault is not an empty vault.
 */
object KdbxPasswordVault {
    private const val VAULT_GROUP_NAME = "KyAuth Passwords"

    /** The vault is read into memory whole, so a synced file is bounded before it is decoded. */
    private const val MAX_VAULT_BYTES = 25L * 1024 * 1024

    @Synchronized
    fun loadEntries(vaultFile: File, vaultKey: ByteArray): List<PasswordEntry> {
        if (!vaultFile.exists() || vaultFile.length() == 0L) return emptyList()
        require(vaultFile.length() <= MAX_VAULT_BYTES) { "Password vault file is too large to decode" }

        val credentials = Credentials.from(EncryptedValue.fromString(bytesToHex(vaultKey)))
        val database = KeePassDatabase.decode(ByteArrayInputStream(vaultFile.readBytes()), credentials)
        val entries = mutableListOf<PasswordEntry>()
        fun extract(group: Group) {
            group.entries.forEach { entry ->
                val title = entry.fields[BasicField.Title.key]?.content.orEmpty()
                val password = entry.fields[BasicField.Password.key]?.content.orEmpty()
                val customMap = entry.fields.entries.associate { (k, v) -> k to v.content }
                val passkey = PasskeyData.fromKeepassCustomFields(customMap)
                if (title.isNotBlank() && (password.isNotBlank() || passkey != null)) {
                    entries.add(
                        PasswordEntry(
                            title = title,
                            username = entry.fields[BasicField.UserName.key]?.content.orEmpty(),
                            password = password,
                            url = entry.fields.url?.content?.ifBlank { null },
                            notes = entry.fields[BasicField.Notes.key]?.content?.ifBlank { null },
                            passkey = passkey,
                            id = entry.uuid.toString(),
                        ),
                    )
                }
            }
            group.groups.forEach(::extract)
        }
        extract(database.content.group)
        return entries
    }

    /**
     * Atomic read-modify-write, returning the resulting entries.
     *
     * Serializing [loadEntries] and [saveEntries] individually is not enough: two writers that
     * each load, mutate and save will still lose one another's changes. Every incremental
     * mutation must go through here. [mutate] returns true when it changed anything; returning
     * false skips the write so a read-only or failed operation does not rewrite the vault.
     */
    @Synchronized
    fun update(
        vaultFile: File,
        vaultKey: ByteArray,
        mutate: (MutableList<PasswordEntry>) -> Boolean,
    ): List<PasswordEntry> {
        val entries = loadEntries(vaultFile, vaultKey).toMutableList()
        if (mutate(entries)) saveEntries(vaultFile, vaultKey, entries)
        return entries
    }

    @Synchronized
    fun saveEntries(vaultFile: File, vaultKey: ByteArray, entries: List<PasswordEntry>) {
        val credentials = Credentials.from(EncryptedValue.fromString(bytesToHex(vaultKey)))
        val kdbxEntries = entries.map { password ->
            val fields = mutableMapOf<String, EntryValue>(
                BasicField.Title.key to EntryValue.Plain(password.title),
                BasicField.UserName.key to EntryValue.Plain(password.username),
                BasicField.Password.key to EntryValue.Plain(password.password),
            )
            password.url?.let { fields[BasicField.Url.key] = EntryValue.Plain(it) }
            password.notes?.let { fields[BasicField.Notes.key] = EntryValue.Plain(it) }
            password.passkey?.toKeepassCustomFields()?.forEach { (k, v) ->
                fields[k] = EntryValue.Plain(v)
            }
            Entry(
                uuid = runCatching { UUID.fromString(password.id) }.getOrDefault(UUID.randomUUID()),
                fields = EntryFields(fields),
            )
        }
        val database = KeePassDatabase.Ver4x.create(
            rootName = VAULT_GROUP_NAME,
            meta = Meta(generator = "KyAuth"),
            credentials = credentials,
        ).modifyParentGroup { copy(entries = kdbxEntries) }

        val output = ByteArrayOutputStream()
        database.encode(output)
        writeAtomically(vaultFile, output.toByteArray())
    }

    private fun bytesToHex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it) }
}
