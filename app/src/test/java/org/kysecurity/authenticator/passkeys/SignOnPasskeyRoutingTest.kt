package org.kysecurity.authenticator.passkeys

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class SignOnPasskeyRoutingTest {

    @Test
    fun `derives the rp id from the paired server url`() {
        assertEquals("signon.example.com", SignOnPasskey.signOnRpId("https://signon.example.com"))
        assertEquals("signon.example.com", SignOnPasskey.signOnRpId("https://signon.example.com:8443/pair"))
    }

    @Test
    fun `unpaired device has no signon rp id`() {
        assertNull(SignOnPasskey.signOnRpId(null))
        assertNull(SignOnPasskey.signOnRpId(""))
    }

    @Test
    fun `matches only the paired host exactly`() {
        val server = "https://signon.example.com"
        assertTrue(SignOnPasskey.isSignOnRpId("signon.example.com", server))
        // Subdomain and parent must not match: WebAuthn scopes a credential to exactly one RP ID.
        assertFalse(SignOnPasskey.isSignOnRpId("login.signon.example.com", server))
        assertFalse(SignOnPasskey.isSignOnRpId("example.com", server))
        assertFalse(SignOnPasskey.isSignOnRpId("signon.example.com.evil.test", server))
    }

    @Test
    fun `an unpaired device routes nothing to the local store`() {
        assertFalse(SignOnPasskey.isSignOnRpId("signon.example.com", null))
    }
}
