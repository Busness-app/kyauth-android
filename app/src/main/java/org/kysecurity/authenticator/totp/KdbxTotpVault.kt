package org.kysecurity.authenticator.totp

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

/** Serialized like [org.kysecurity.authenticator.passwords.KdbxPasswordVault]; load throws on a corrupt vault. */
object KdbxTotpVault {
    private const val VAULT_GROUP_NAME = "KyAuth TOTP"

    @Synchronized
    fun loadEntries(vaultFile: File, vaultKey: ByteArray): List<TotpEntry> {
        if (!vaultFile.exists() || vaultFile.length() == 0L) {
            return emptyList()
        }

        val credentials = Credentials.from(EncryptedValue.fromString(bytesToHex(vaultKey)))
        val bytes = vaultFile.readBytes()
        val database = KeePassDatabase.decode(ByteArrayInputStream(bytes), credentials)

        val entries = mutableListOf<TotpEntry>()
        fun extractEntries(group: Group) {
            for (entry in group.entries) {
                val title = entry.fields[BasicField.Title.name]?.content ?: "Unnamed"
                val url = entry.fields[BasicField.Url.name]?.content?.ifBlank { null }
                val notes = entry.fields[BasicField.Notes.name]?.content?.ifBlank { null }
                val customMap = mutableMapOf<String, String>()
                for ((key, value) in entry.fields) {
                    if (key.startsWith("TimeOtp-")) {
                        customMap[key] = value.content
                    }
                }
                TotpEntry.fromKeepassFields(title, customMap, entry.uuid.toString(), url = url, notes = notes)?.let {
                    entries.add(it)
                }
            }
            for (subGroup in group.groups) {
                extractEntries(subGroup)
            }
        }

        extractEntries(database.content.group)
        return entries
    }

    @Synchronized
    fun saveEntries(vaultFile: File, vaultKey: ByteArray, entries: List<TotpEntry>) {
        val credentials = Credentials.from(EncryptedValue.fromString(bytesToHex(vaultKey)))

        val kdbxEntries = entries.map { totp ->
            val fieldsMap = mutableMapOf<String, EntryValue>(
                BasicField.Title.name to EntryValue.Plain(totp.title),
            )
            totp.url?.let { fieldsMap[BasicField.Url.name] = EntryValue.Plain(it) }
            totp.notes?.let { fieldsMap[BasicField.Notes.name] = EntryValue.Plain(it) }
            for ((k, v) in totp.keepassFields()) {
                fieldsMap[k] = EntryValue.Plain(v)
            }
            Entry(
                uuid = runCatching { UUID.fromString(totp.id) }.getOrDefault(UUID.randomUUID()),
                fields = EntryFields(fieldsMap),
            )
        }

        val initialDb = KeePassDatabase.Ver4x.create(
            rootName = VAULT_GROUP_NAME,
            meta = Meta(generator = "KyAuth"),
            credentials = credentials,
        )

        val updatedDb = initialDb.modifyParentGroup {
            copy(entries = kdbxEntries)
        }

        val out = ByteArrayOutputStream()
        updatedDb.encode(out)
        writeAtomically(vaultFile, out.toByteArray())
    }

    private fun bytesToHex(bytes: ByteArray): String =
        bytes.joinToString("") { "%02x".format(it) }
}
