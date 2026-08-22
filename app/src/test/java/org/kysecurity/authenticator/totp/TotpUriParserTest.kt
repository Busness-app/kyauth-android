package org.kysecurity.authenticator.totp

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertThrows
import org.junit.Test

class TotpUriParserTest {
    @Test
    fun parsesStandardOtpAuthUri() {
        val uri = "otpauth://totp/KySecurity:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=KySecurity&algorithm=SHA256&digits=8&period=60"
        val entry = TotpUriParser.parse(uri)

        assertEquals("KySecurity (alice@example.com)", entry.title)
        assertEquals("JBSWY3DPEHPK3PXP", entry.secretBase32)
        assertEquals("KySecurity", entry.issuer)
        assertEquals(8, entry.digits)
        assertEquals(60L, entry.periodSeconds)
        assertEquals(TotpEntry.Algorithm.SHA256, entry.algorithm)
    }

    @Test
    fun parsesMinimalOtpAuthUri() {
        val uri = "otpauth://totp/GitHub:user?secret=NBSWY3DPEHPK3PXP"
        val entry = TotpUriParser.parse(uri)

        assertEquals("GitHub (user)", entry.title)
        assertEquals("NBSWY3DPEHPK3PXP", entry.secretBase32)
        assertEquals(6, entry.digits)
        assertEquals(30L, entry.periodSeconds)
        assertEquals(TotpEntry.Algorithm.SHA1, entry.algorithm)
    }

    @Test
    fun rejectsInvalidSchemeOrHost() {
        assertThrows(IllegalArgumentException::class.java) {
            TotpUriParser.parse("https://example.com")
        }
        assertThrows(IllegalArgumentException::class.java) {
            TotpUriParser.parse("otpauth://hotp/account?secret=ABC")
        }
    }

    @Test
    fun rejectsSecretThatDecodesToNothing() {
        // A single Base32 character carries five bits and decodes to an empty HMAC key. Accepting
        // it used to persist an entry that crashed the TOTP list on every launch.
        assertThrows(IllegalArgumentException::class.java) {
            TotpUriParser.parse("otpauth://totp/Acme?secret=A")
        }
        assertThrows(IllegalArgumentException::class.java) {
            TotpUriParser.parse("otpauth://totp/Acme?secret=%3D")
        }
    }

    @Test
    fun acceptsShortButUsableSecret() {
        val entry = TotpUriParser.parse("otpauth://totp/Acme?secret=AA")
        assertEquals("AA", entry.secretBase32)
    }
}
