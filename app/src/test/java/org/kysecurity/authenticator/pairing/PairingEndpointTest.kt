package org.kysecurity.authenticator.pairing

import org.junit.Assert.assertEquals
import org.junit.Test

class PairingEndpointTest {
    @Test fun `builds the KySignOn registration endpoint`() {
        assertEquals(
            "https://signin.example.com/api/notifications/native/register",
            PairingEndpoint.registrationUrl("https://signin.example.com/").toString(),
        )
    }

    @Test(expected = IllegalArgumentException::class)
    fun `rejects cleartext public server`() {
        PairingEndpoint.registrationUrl("http://signin.example.com")
    }
}
