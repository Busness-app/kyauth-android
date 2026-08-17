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
import java.io.FileOutputStream
import java.nio.file.AtomicMoveNotSupportedException
import java.nio.file.Files
import java.nio.file.StandardCopyOption.ATOMIC_MOVE
import java.nio.file.StandardCopyOption.REPLACE_EXISTING
import java.util.UUID

object KdbxPasswordVault {
    private const val VAULT_GROUP_NAME = "KyAuth Passwords"

    fun loadEntries(vaultFile: File, vaultKey: ByteArray): List<PasswordEntry> {
        if (!vaultFile.exists() || vaultFile.length() == 0L) return emptyList()

        val credentials = Credentials.from(EncryptedValue.fromString(bytesToHex(vaultKey)))
        val database = KeePassDatabase.decode(ByteArrayInputStream(vaultFile.readBytes()), credentials)
        val entries = mutableListOf<PasswordEntry>()
        fun extract(group: Group) {
            group.entries.forEach { entry ->
                val title = entry.fields[BasicField.Title.name]?.content.orEmpty()
                val password = entry.fields[BasicField.Password.name]?.content.orEmpty()
                val customMap = entry.fields.entries.associate { (k, v) -> k to v.content }
                val passkey = PasskeyData.fromKeepassCustomFields(customMap)
                if (title.isNotBlank() && (password.isNotBlank() || passkey != null)) {
                    entries.add(
                        PasswordEntry(
                            title = title,
                            username = entry.fields[BasicField.UserName.name]?.content.orEmpty(),
                            password = password,
                            url = entry.fields[BasicField.Url.name]?.content?.ifBlank { null },
                            notes = entry.fields[BasicField.Notes.name]?.content?.ifBlank { null },
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

    fun saveEntries(vaultFile: File, vaultKey: ByteArray, entries: List<PasswordEntry>) {
        val credentials = Credentials.from(EncryptedValue.fromString(bytesToHex(vaultKey)))
        val kdbxEntries = entries.map { password ->
            val fields = mutableMapOf<String, EntryValue>(
                BasicField.Title.name to EntryValue.Plain(password.title),
                BasicField.UserName.name to EntryValue.Plain(password.username),
                BasicField.Password.name to EntryValue.Plain(password.password),
            )
            password.url?.let { fields[BasicField.Url.name] = EntryValue.Plain(it) }
            password.notes?.let { fields[BasicField.Notes.name] = EntryValue.Plain(it) }
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
        vaultFile.parentFile?.mkdirs()
        val temporaryFile = File(vaultFile.parentFile, ".${vaultFile.name}.tmp")
        FileOutputStream(temporaryFile).use {
            it.write(output.toByteArray())
            it.fd.sync()
        }
        try {
            Files.move(temporaryFile.toPath(), vaultFile.toPath(), ATOMIC_MOVE, REPLACE_EXISTING)
        } catch (_: AtomicMoveNotSupportedException) {
            Files.move(temporaryFile.toPath(), vaultFile.toPath(), REPLACE_EXISTING)
        }
    }

    private fun bytesToHex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it) }
}
