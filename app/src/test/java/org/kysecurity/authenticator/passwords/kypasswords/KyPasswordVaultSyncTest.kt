package org.kysecurity.authenticator.passwords.kypasswords

import com.sun.net.httpserver.HttpServer
import java.io.File
import java.net.InetSocketAddress
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import org.kysecurity.authenticator.passwords.KdbxPasswordVault

class KyPasswordVaultSyncTest {
    @get:Rule val folder = TemporaryFolder()
    private val key = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
        .chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    private fun fixture() = checkNotNull(javaClass.getResourceAsStream("/vault-preservation.kdbx")).use { it.readBytes() }

    @Test fun cleanDownloadInstallsButDirtyOrConcurrentChangesKeepBothVersions() {
        for (dirty in listOf(false, true)) for (race in listOf(false, true)) {
            val dir = folder.newFolder()
            val file = File(dir, "vault.kdbx").apply { writeBytes(fixture()) }
            val before = file.readBytes()
            val remote = File(dir, "remote.kdbx").apply { writeBytes(before) }
            KdbxPasswordVault.update(remote, key) { list ->
                list[0] = list[0].copy(username = "remote edit"); true
            }
            if (race) KdbxPasswordVault.update(file, key) { list ->
                list[0] = list[0].copy(username = "concurrent local edit"); true
            }
            val current = file.readBytes()
            val result = runCatching { KyPasswordVaultSync.installOrPreserve(file, key, before, remote, 2,
                if (dirty) null else KyPasswordVaultSync.fingerprint(before), { true }) }
            if (dirty || race) {
                assertTrue(result.exceptionOrNull() is KyPasswordException)
                assertArrayEquals(current, file.readBytes())
                val preserved = File(dir, "password-vault-conflicts").listFiles()!!.map { it.readBytes() }
                for (bytes in listOf(before, current, remote.readBytes())) assertTrue(preserved.any { it.contentEquals(bytes) })
            } else {
                assertEquals(2L, result.getOrThrow().version)
                assertArrayEquals(remote.readBytes(), file.readBytes())
            }
        }
    }

    @Test fun invalidDownloadOrEndedSessionNeverReplacesLocalVault() {
        val file = folder.newFile().apply { writeBytes(fixture()) }
        val before = file.readBytes()
        val candidate = folder.newFile().apply { writeText("invalid") }
        assertTrue(runCatching { KyPasswordVaultSync.installOrPreserve(file, key, before, candidate, 2,
            KyPasswordVaultSync.fingerprint(before), { true }) }.isFailure)
        candidate.writeBytes(before)
        assertTrue(runCatching { KyPasswordVaultSync.installOrPreserve(file, key, before, candidate, 2,
            KyPasswordVaultSync.fingerprint(before), { false }) }.isFailure)
        assertArrayEquals(before, file.readBytes())
    }

    @Test fun upload409PreservesFullLocalAndRemoteFilesAndDoesNotRetryUpload() {
        val file = folder.newFile("vault.kdbx").apply { writeBytes(fixture()) }
        val before = file.readBytes()
        val remoteFile = folder.newFile("server.kdbx").apply { writeBytes(before) }
        KdbxPasswordVault.update(remoteFile, key) { it[0] = it[0].copy(username = "server change"); true }
        val remote = remoteFile.readBytes()
        val server = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        var uploads = 0
        server.createContext("/api/vault/metadata") { e ->
            val response = """{"version":1}""".toByteArray()
            e.sendResponseHeaders(200, response.size.toLong()); e.responseBody.use { it.write(response) }
        }
        server.createContext("/api/vault/upload") { e ->
            uploads++
            assertEquals("\"1\"", e.requestHeaders.getFirst("If-Match"))
            assertArrayEquals(before, e.requestBody.use { it.readBytes() })
            val response = """{"currentVersion":2}""".toByteArray()
            e.sendResponseHeaders(409, response.size.toLong()); e.responseBody.use { it.write(response) }
        }
        server.createContext("/api/vault/kdbx") { e ->
            e.responseHeaders.add("X-Vault-Version", "2")
            e.sendResponseHeaders(200, remote.size.toLong()); e.responseBody.use { it.write(remote) }
        }
        server.start()
        try {
            val account = KyPasswordServerAccount("http://127.0.0.1:${server.address.port}", "device", "token", "user",
                vaultVersion = 1, lastSyncedFingerprint = "different-encrypted-snapshot")
            val result = runCatching { synchronized(KyPasswordVaultSync) {
                KyPasswordVaultSync.sync(file, key, account, KyPasswordClient(), { true })
            } }
            assertTrue(result.exceptionOrNull() is KyPasswordException)
            assertEquals(1, uploads)
            assertArrayEquals(before, file.readBytes())
            assertTrue(File(folder.root, "password-vault-conflicts").listFiles()!!.isNotEmpty())
            assertFalse(folder.root.listFiles()!!.any { it.name.startsWith(".vault-") })
            KyPasswordVaultSync.clearConflicts(folder.root)
            assertFalse(File(folder.root, "password-vault-conflicts").exists())
        } finally { server.stop(0) }
    }

    @Test fun migrationAdoptsIdenticalBytesAndExplicitChoicesResolveDifferentCopies() {
        val file = folder.newFile("vault.kdbx").apply { writeBytes(fixture()) }
        var remote = file.readBytes()
        var version = 1L
        val server = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        server.createContext("/api/vault/metadata") { e ->
            val response = """{"version":$version}""".toByteArray()
            e.sendResponseHeaders(200, response.size.toLong()); e.responseBody.use { it.write(response) }
        }
        server.createContext("/api/vault/kdbx") { e ->
            e.responseHeaders.add("X-Vault-Version", "$version")
            e.sendResponseHeaders(200, remote.size.toLong()); e.responseBody.use { it.write(remote) }
        }
        server.createContext("/api/vault/upload") { e ->
            assertEquals("\"$version\"", e.requestHeaders.getFirst("If-Match"))
            remote = e.requestBody.use { it.readBytes() }; version++
            val response = """{"metadata":{"version":$version}}""".toByteArray()
            e.sendResponseHeaders(200, response.size.toLong()); e.responseBody.use { it.write(response) }
        }
        server.start()
        try {
            val account = KyPasswordServerAccount("http://127.0.0.1:${server.address.port}", "device", "token", "user", vaultVersion = 1)
            val conflicts = File(folder.root, "password-vault-conflicts")
            val stale = folder.newFile(".vault-upload-interrupted.kdbx")
            fun sync(resolution: KyPasswordVaultSync.Resolution? = null) = synchronized(KyPasswordVaultSync) {
                KyPasswordVaultSync.sync(file, key, account, KyPasswordClient(), { true }, resolution = resolution)
            }
            val migrated = sync()
            assertEquals(KyPasswordVaultSync.fingerprint(remote), migrated.fingerprint)
            assertFalse(conflicts.exists())
            assertFalse(stale.exists())
            KdbxPasswordVault.update(file, key) { it[0] = it[0].copy(username = "device edit"); true }
            assertTrue(runCatching { sync() }.isFailure)
            assertTrue(conflicts.exists())
            sync(KyPasswordVaultSync.Resolution.KEEP_DEVICE)
            assertArrayEquals(file.readBytes(), remote)
            assertFalse(conflicts.exists())
            KdbxPasswordVault.update(file, key) { it[0] = it[0].copy(username = "another edit"); true }
            assertTrue(runCatching { sync() }.isFailure)
            sync(KyPasswordVaultSync.Resolution.KEEP_SERVER)
            assertArrayEquals(remote, file.readBytes())
            assertFalse(conflicts.exists())
            assertFalse(folder.root.listFiles()!!.any { it.name.startsWith(".vault-") })
        } finally { server.stop(0) }
    }
}
