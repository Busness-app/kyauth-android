package org.kysecurity.authenticator.passwords.kypasswords

import java.io.File
import java.security.MessageDigest
import org.kysecurity.authenticator.passwords.KdbxPasswordVault
import org.kysecurity.authenticator.security.writeAtomically

/** Serializes network sync sessions, without holding the local vault lock during I/O. */
object KyPasswordVaultSync {
    data class Result(val version: Long, val fingerprint: String)

    fun fingerprint(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256")
        .digest(bytes).joinToString("") { "%02x".format(it) }

    // The caller holds this object's monitor through account lookup and acknowledgment too.
    fun sync(
        file: File,
        key: ByteArray,
        account: KyPasswordServerAccount,
        client: KyPasswordClient,
        isCurrent: () -> Boolean,
        passwordEnvelope: String? = null,
    ): Result {
        check(Thread.holdsLock(this))
        val original = synchronized(KdbxPasswordVault) {
            check(isCurrent()) { "Vault session ended" }
            if (file.exists()) {
                KdbxPasswordVault.loadEntries(file, key) // Fail before touching the server on corrupt local data.
                file.readBytes()
            } else null
        }
        val snapshot = File.createTempFile(".vault-upload-", ".kdbx", file.parentFile)
        val candidate = File.createTempFile(".vault-download-", ".kdbx", file.parentFile)
        try {
            if (original != null) writeAtomically(snapshot, original)
            val metadata = client.fetchMetadata(account.serverUrl, account.sessionToken)
            if (metadata.version > account.vaultVersion ||
                (metadata.version > 0 && (original == null || account.lastSyncedFingerprint == null))) {
                val version = client.downloadVault(account.serverUrl, account.sessionToken, candidate)
                return installOrPreserve(file, key, original, candidate, version, account.lastSyncedFingerprint, isCurrent)
            }
            check(metadata.version == account.vaultVersion) { "Server vault version moved backwards; local vault retained" }
            check(original != null) { "Create a local vault before uploading" }
            check(isCurrent()) { "Vault session ended" }
            if (account.lastSyncedFingerprint == fingerprint(original)) return Result(account.vaultVersion, fingerprint(original))
            try {
                val version = client.uploadVault(account.serverUrl, account.sessionToken, snapshot,
                    account.vaultVersion, account.deviceId, passwordEnvelope)
                return Result(version, fingerprint(original))
            } catch (_: KyPasswordConflictException) {
                val version = client.downloadVault(account.serverUrl, account.sessionToken, candidate)
                return installOrPreserve(file, key, original, candidate, version, null, isCurrent)
            }
        } finally {
            snapshot.delete()
            candidate.delete()
        }
    }

    internal fun installOrPreserve(
        file: File, key: ByteArray, original: ByteArray?, candidate: File, version: Long,
        baseline: String?, isCurrent: () -> Boolean,
    ): Result {
        val remote = candidate.readBytes()
        KdbxPasswordVault.decode(remote, key) // Never install an unreadable download.
        return synchronized(KdbxPasswordVault) {
            check(isCurrent()) { "Vault session ended" }
            val current = if (file.exists()) file.readBytes() else null
            val unchanged = if (original == null) current == null else current?.contentEquals(original) == true
            val clean = original == null || (baseline != null && fingerprint(original) == baseline)
            if (!unchanged || !clean) {
                val conflicts = File(file.parentFile, "password-vault-conflicts").apply { mkdirs() }
                // Content hashes deduplicate retries, while preserving distinct versions.
                (listOfNotNull(original, current) + remote).forEach { bytes ->
                    writeAtomically(File(conflicts, "${fingerprint(bytes)}.kdbx"), bytes)
                }
                throw KyPasswordException("Vault conflict: both encrypted versions were kept on this device. Export them from Passwords to reconcile in KeePass before syncing again.")
            }
            writeAtomically(file, remote)
            Result(version, fingerprint(remote))
        }
    }
}
