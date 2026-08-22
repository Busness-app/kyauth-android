package org.kysecurity.authenticator.passkeys

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class DigitalAssetLinksTest {

    private val fingerprint = "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99"

    @Test
    fun readsPackageAndFingerprintFromALoginStatement() {
        val json = """
            [{
              "relation": ["delegate_permission/common.get_login_creds"],
              "target": {
                "namespace": "android_app",
                "package_name": "com.example.app",
                "sha256_cert_fingerprints": ["$fingerprint"]
              }
            }]
        """.trimIndent()

        val parsed = DigitalAssetLinks.parse(json)
        assertEquals(setOf(fingerprint), parsed["com.example.app"])
    }

    @Test
    fun ignoresStatementsThatDoNotGrantLoginCredentials() {
        val json = """
            [{
              "relation": ["delegate_permission/common.handle_all_urls"],
              "target": {
                "namespace": "android_app",
                "package_name": "com.example.app",
                "sha256_cert_fingerprints": ["$fingerprint"]
              }
            }]
        """.trimIndent()

        assertTrue(DigitalAssetLinks.parse(json).isEmpty())
    }

    @Test
    fun ignoresWebTargets() {
        val json = """
            [{
              "relation": ["delegate_permission/common.get_login_creds"],
              "target": { "namespace": "web", "site": "https://example.com" }
            }]
        """.trimIndent()

        assertTrue(DigitalAssetLinks.parse(json).isEmpty())
    }

    @Test
    fun normalisesFingerprintCase() {
        val json = """
            [{
              "relation": ["delegate_permission/common.get_login_creds"],
              "target": {
                "namespace": "android_app",
                "package_name": "com.example.app",
                "sha256_cert_fingerprints": ["${fingerprint.lowercase()}"]
              }
            }]
        """.trimIndent()

        assertEquals(setOf(fingerprint), DigitalAssetLinks.parse(json)["com.example.app"])
    }
}
