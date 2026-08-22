package org.kysecurity.authenticator.passkeys

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class RpIdTest {

    @Test
    fun acceptsAnOrdinaryRegistrableDomain() {
        assertEquals("example.com", RpId.normalize("example.com"))
        assertEquals("login.example.com", RpId.normalize("LOGIN.Example.Com"))
        assertEquals("example.co.uk", RpId.normalize("example.co.uk"))
    }

    @Test
    fun rejectsPublicSuffixes() {
        assertNull(RpId.normalize("com"))
        assertNull(RpId.normalize("co.uk"))
        assertNull(RpId.normalize("github.io"))
    }

    @Test
    fun rejectsMalformedIdentifiers() {
        assertNull(RpId.normalize(null))
        assertNull(RpId.normalize(""))
        assertNull(RpId.normalize("   "))
        assertNull(RpId.normalize("https://example.com"))
        assertNull(RpId.normalize("example.com:443"))
        assertNull(RpId.normalize("example.com/login"))
        assertNull(RpId.normalize("user@example.com"))
        assertNull(RpId.normalize("exa mple.com"))
        assertNull(RpId.normalize("example..com"))
        assertNull(RpId.normalize("-example.com"))
        assertNull(RpId.normalize("localhost"))
    }

    @Test
    fun aWebCallerMayOnlyClaimItsOwnDomainOrARegistrableParent() {
        assertEquals("example.com", RpId.validate("example.com", "example.com"))
        assertEquals("example.com", RpId.validate("example.com", "login.example.com"))
        assertNull(RpId.validate("login.example.com", "example.com"))
        assertNull(RpId.validate("bank.example", "attacker.example"))
        assertNull(RpId.validate("example.com", "notexample.com"))
    }

    @Test
    fun aNativeCallerIsNotOriginChecked() {
        // Offline we can only validate the shape; asset-link verification is still outstanding.
        assertEquals("example.com", RpId.validate("example.com", null))
        assertNull(RpId.validate("co.uk", null))
    }
}
