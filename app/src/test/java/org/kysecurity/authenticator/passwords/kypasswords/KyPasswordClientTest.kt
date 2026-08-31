package org.kysecurity.authenticator.passwords.kypasswords

import com.sun.net.httpserver.HttpServer
import java.net.InetSocketAddress
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.rules.TemporaryFolder

class KyPasswordClientTest {
    @Test
    fun initialUploadSendsPasswordEnvelope() {
        val server = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        var envelope: String? = null
        server.createContext("/api/vault/upload") { exchange ->
            envelope = exchange.requestHeaders.getFirst("X-Password-Envelope")
            exchange.requestBody.use { it.readBytes() }
            val response = """{"ok":true,"metadata":{"version":1}}""".toByteArray()
            exchange.sendResponseHeaders(200, response.size.toLong())
            exchange.responseBody.use { it.write(response) }
        }
        server.start()

        val folder = TemporaryFolder().apply { create() }
        try {
            val vault = folder.newFile("passwords_vault.kdbx").apply { writeText("encrypted") }
            val version = KyPasswordClient().uploadVault(
                serverUrl = "http://127.0.0.1:${server.address.port}",
                sessionToken = "session",
                vaultFile = vault,
                expectedVersion = 0,
                passwordEnvelope = "wrapped-local-key",
            )

            assertEquals(1L, version)
            assertEquals("wrapped-local-key", envelope)
        } finally {
            server.stop(0)
            folder.delete()
        }
    }
}
