package org.kysecurity.authenticator.pairing

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertThrows
import org.junit.Test
import java.net.URLEncoder

class QrPairingParserTest {
    @Test
    fun parse_kySignOnJsonPayload_parsesAllFields() {
        val json = """
            {
                "type": "kysignon_device_pairing",
                "serverUrl": "https://auth.example.com",
                "pairingToken": "abc123token",
                "pinCode": "123456",
                "userId": "user-uuid-1",
                "username": "alice",
                "expiresAt": 4102444800
            }
        """.trimIndent()

        val pairing = QrPairingParser.parse(json)
        assertEquals("https://auth.example.com", pairing.serverUrl)
        assertEquals("abc123token", pairing.pairingToken)
        assertEquals("123456", pairing.pinCode)
        assertEquals("user-uuid-1", pairing.userId)
        assertEquals("alice", pairing.username)
        assertEquals(4102444800L, pairing.expiresAtEpochSeconds)
    }

    @Test
    fun parse_kyPostStyleDeepLink_keepsCredentialInMemory() {
        val server = URLEncoder.encode("https://signin.example.com", "UTF-8")
        val registration = URLEncoder.encode(
            "https://signin.example.com/api/notifications/native/register",
            "UTF-8",
        )

        val pairing = QrPairingParser.parse("kysignon://native-pair?srv=$server&reg=$registration&pt=one-time-token&sub=user-123&user=bob")

        assertEquals("https://signin.example.com", pairing.serverUrl)
        assertEquals("https://signin.example.com/api/notifications/native/register", pairing.registrationUrl)
        assertEquals("one-time-token", pairing.pairingToken)
        assertEquals("user-123", pairing.userId)
        assertEquals("bob", pairing.username)
    }

    @Test
    fun parse_kypostSchemeDeepLink_supported() {
        val server = URLEncoder.encode("https://auth.example.com", "UTF-8")
        val pairing = QrPairingParser.parse("kypost://native-pair?srv=$server&pt=token-999")
        assertEquals("https://auth.example.com", pairing.serverUrl)
        assertEquals("token-999", pairing.pairingToken)
    }

    @Test
    fun parse_rejectsRegistrationEndpointOnAnotherOrigin() {
        assertThrows(IllegalArgumentException::class.java) {
            QrPairingParser.parse(
                "kysignon://native-pair?srv=https%3A%2F%2Fsignin.example.com" +
                    "&reg=https%3A%2F%2Fevil.example%2Fregister&pt=one-time-token",
            )
        }
    }

    @Test
    fun parse_rejectsEmptyOrInvalidPayload() {
        assertThrows(IllegalArgumentException::class.java) {
            QrPairingParser.parse("")
        }
        assertThrows(IllegalArgumentException::class.java) {
            QrPairingParser.parse("""{"type":"unknown_pairing"}""")
        }
    }

    @Test
    fun parse_rejectsExpiredPayload() {
        assertThrows(IllegalArgumentException::class.java) {
            QrPairingParser.parse(
                """{"type":"kysignon_device_pairing","serverUrl":"https://auth.example.com","pairingToken":"token","expiresAt":1}""",
            )
        }
    }
}
