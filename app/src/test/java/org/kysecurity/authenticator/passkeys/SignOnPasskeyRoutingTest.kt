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

    @Test
    fun `keeps a www host instead of widening to its parent`() {
        // DomainMatcher.normalizeHost would strip "www." here; that would let any sibling
        // subdomain authorized for the parent route itself into the device-local store.
        assertEquals("www.signon.example.com", SignOnPasskey.signOnRpId("https://www.signon.example.com"))
    }

    @Test
    fun `a www pairing url does not match its parent domain`() {
        val server = "https://www.signon.example.com"
        assertTrue(SignOnPasskey.isSignOnRpId("www.signon.example.com", server))
        assertFalse(SignOnPasskey.isSignOnRpId("signon.example.com", server))
        assertFalse(SignOnPasskey.isSignOnRpId("blog.signon.example.com", server))
    }

    // suppressesVaultPasskeys is the deny-side test in CredentialEntryBuilder.kt that decides
    // whether a synced-vault passkey is offered. Unlike isSignOnRpId it must be www-insensitive on
    // BOTH sides: DomainMatcher.matchesPasskey (which selects the vault entries this guards) itself
    // normalizes away a leading "www.", so an exact compare here would let a stranded KySignOn
    // passkey through whenever the stored rpId or the incoming request differs from the paired host
    // only by that prefix.

    @Test
    fun `suppresses vault passkeys when the stored passkey has a leading www the request lacks`() {
        // The direction round 1 already fixed: request matches the paired host exactly, the vault
        // holds a "www." variant. Caught because matchesPasskey would still offer it.
        assertTrue(suppressesVaultPasskeys("signon.example.com", "https://signon.example.com"))
    }

    @Test
    fun `suppresses vault passkeys when the request has a leading www the paired host lacks`() {
        // The direction round 1 missed: paired host is bare, the request itself carries "www.".
        // isSignOnRpId would say false here (exact compare), but matchesPasskey would still match
        // a bare-host stored passkey against this request, so it must still be suppressed.
        assertTrue(suppressesVaultPasskeys("www.signon.example.com", "https://signon.example.com"))
    }

    @Test
    fun `an unpaired device never suppresses vault passkeys`() {
        assertFalse(suppressesVaultPasskeys("signon.example.com", null))
        assertFalse(suppressesVaultPasskeys("www.signon.example.com", null))
    }

    @Test
    fun `an unrelated rp is never suppressed`() {
        val server = "https://signon.example.com"
        assertFalse(suppressesVaultPasskeys("example.com", server))
        assertFalse(suppressesVaultPasskeys("attacker.test", server))
        assertFalse(suppressesVaultPasskeys("login.signon.example.com", server))
    }
}
