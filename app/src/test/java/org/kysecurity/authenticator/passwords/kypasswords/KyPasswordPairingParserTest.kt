package org.kysecurity.authenticator.passwords.kypasswords

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Test

class KyPasswordPairingParserTest {

    @Test
    fun parsesPairingJson() {
        val json = """
            {
                "server": "https://passwords.example.com",
                "secret": "pair-secret-12345",
                "pin": "123456"
            }
        """.trimIndent()

        val pairing = KyPasswordPairingParser.parse(json)
        assertEquals("https://passwords.example.com", pairing.serverUrl)
        assertEquals("pair-secret-12345", pairing.secret)
        assertEquals("123456", pairing.pin)
    }

    @Test
    fun parsesDeepLink() {
        val link = "kypasswords://native-pair?srv=https%3A%2F%2Fpasswords.example.com&secret=sec123&pin=654321"
        val pairing = KyPasswordPairingParser.parse(link)
        assertEquals("https://passwords.example.com", pairing.serverUrl)
        assertEquals("sec123", pairing.secret)
        assertEquals("654321", pairing.pin)
    }
}
