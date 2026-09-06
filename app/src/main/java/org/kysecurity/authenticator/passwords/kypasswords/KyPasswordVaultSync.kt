package org.kysecurity.authenticator.passwords.kypasswords

import java.io.File
import java.security.MessageDigest
import org.kysecurity.authenticator.passwords.KdbxPasswordVault
import org.kysecurity.authenticator.security.writeAtomically

/** Serializes network sync sessions, without holding the local vault lock during I/O. */
object KyPasswordVaultSync {
    data class Result(val version: Long, val fingerprint: String)
    enum class Resolution { KEEP_DEVICE, KEEP_SERVER }

    fun fingerprint(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256")
        .digest(bytes).joinToString("") { "%02x".format(it) }

    /** Called on startup and before sync, under the sync monitor; no active snapshot can be swept. */
    @Synchronized
    fun clearInterruptedSnapshots(directory: File) {
        directory.listFiles()?.filter {
            val name = it.name.trimStart('.')
            name.startsWith("vault-upload-") || name.startsWith("vault-download-")
        }?.forEach { it.delete() }
        File(directory, "password-vault-conflicts").listFiles()?.filter { it.name.endsWith(".tmp") }?.forEach { it.delete() }
    }

    fun clearConflicts(directory: File) = synchronized(KdbxPasswordVault) {
        File(directory, "password-vault-conflicts").deleteRecursively()
    }

    // The caller holds this object's monitor through account lookup and acknowledgment too.
    fun sync(
        file: File,
        key: ByteArray,
        account: KyPasswordServerAccount,
        client: KyPasswordClient,
        isCurrent: () -> Boolean,
        passwordEnvelope: String? = null,
        resolution: Resolution? = null,
    ): Result {
        check(Thread.holdsLock(this))
        clearInterruptedSnapshots(checkNotNull(file.parentFile))
        val original = synchronized(KdbxPasswordVault) {
            check(isCurrent()) { "Vault session ended" }
            if (file.exists()) {
                KdbxPasswordVault.loadEntries(file, key)
                file.readBytes()
            } else null
        }
        fun finished(result: Result): Result {
            synchronized(KdbxPasswordVault) {
                if (isCurrent() && file.exists() && fingerprint(file.readBytes()) == result.fingerprint) {
                    clearConflicts(checkNotNull(file.parentFile))
                }
            }
            return result
        }
        val snapshot = File.createTempFile(".vault-upload-", ".kdbx", file.parentFile)
        val candidate = File.createTempFile(".vault-download-", ".kdbx", file.parentFile)
        try {
            if (original != null) writeAtomically(snapshot, original)
            val metadata = client.fetchMetadata(account.serverUrl, account.sessionToken)
            var expectedVersion = account.vaultVersion
            if (resolution != null || metadata.version > account.vaultVersion ||
                (metadata.version > 0 && (original == null || account.lastSyncedFingerprint == null))) {
                val version = client.downloadVault(account.serverUrl, account.sessionToken, candidate)
                if (resolution == Resolution.KEEP_DEVICE) {
                    KdbxPasswordVault.decode(candidate.readBytes(), key) // Retain the different-key guard.
                    expectedVersion = version
                } else {
                    return finished(installOrPreserve(file, key, original, candidate, version,
                        account.lastSyncedFingerprint, isCurrent, resolution == Resolution.KEEP_SERVER))
                }
            }
            check(metadata.version >= account.vaultVersion) { "Server vault version moved backwards; local vault retained" }
            check(original != null) { "Create a local vault before uploading" }
            check(isCurrent()) { "Vault session ended" }
            if (resolution == null && account.lastSyncedFingerprint == fingerprint(original)) {
                return finished(Result(account.vaultVersion, fingerprint(original)))
            }
            try {
                val version = client.uploadVault(account.serverUrl, account.sessionToken, snapshot,
                    expectedVersion, account.deviceId, passwordEnvelope)
                return finished(Result(version, fingerprint(original)))
            } catch (_: KyPasswordConflictException) {
                val version = client.downloadVault(account.serverUrl, account.sessionToken, candidate)
                return finished(installOrPreserve(file, key, original, candidate, version, null, isCurrent))
            }
        } finally {
            snapshot.delete()
            candidate.delete()
        }
    }

    internal fun installOrPreserve(
        file: File, key: ByteArray, original: ByteArray?, candidate: File, version: Long,
        baseline: String?, isCurrent: () -> Boolean, keepServer: Boolean = false,
    ): Result {
        val remote = candidate.readBytes()
        KdbxPasswordVault.decode(remote, key)
        return synchronized(KdbxPasswordVault) {
            check(isCurrent()) { "Vault session ended" }
            val current = if (file.exists()) file.readBytes() else null
            // Migration: byte-identical copies prove a baseline without trusting an old preference.
            if (current?.contentEquals(remote) == true) return@synchronized Result(version, fingerprint(remote))
            val unchanged = if (original == null) current == null else current?.contentEquals(original) == true
            val clean = keepServer || original == null || (baseline != null && fingerprint(original) == baseline)
            if (!unchanged || !clean) {
                val conflicts = File(file.parentFile, "password-vault-conflicts").apply { mkdirs() }
                (listOfNotNull(original, current) + remote).forEach { bytes ->
                    writeAtomically(File(conflicts, "${fingerprint(bytes)}.kdbx"), bytes)
                }
                throw KyPasswordException("Vault conflict: both encrypted versions were kept on this device. Resolve the conflict in Passwords, or export the versions before choosing one.")
            }
            writeAtomically(file, remote)
            Result(version, fingerprint(remote))
        }
    }
}
