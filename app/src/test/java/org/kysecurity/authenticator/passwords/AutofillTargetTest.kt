package org.kysecurity.authenticator.passwords

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class AutofillTargetTest {

    @Test
    fun aBrowserSpeaksForThePageItLoaded() {
        assertEquals(
            "bank.com",
            AutofillParser.resolveTargetDomain("bank.com", "com.android.chrome", trustWebDomain = true),
        )
    }

    @Test
    fun anOrdinaryAppCannotClaimAWebDomain() {
        // The whole point: setWebDomain is public API, so a spoofed domain from a non-browser must
        // never select another site's credential.
        assertEquals(
            "com.evil.app",
            AutofillParser.resolveTargetDomain("bank.com", "com.evil.app", trustWebDomain = false),
        )
    }

    @Test
    fun aBrowserWithoutAPageFallsBackToItsPackage() {
        assertEquals(
            "com.android.chrome",
            AutofillParser.resolveTargetDomain(null, "com.android.chrome", trustWebDomain = true),
        )
    }

    @Test
    fun anUnidentifiableCallerHasNoTarget() {
        assertNull(AutofillParser.resolveTargetDomain("bank.com", null, trustWebDomain = false))
    }

    @Test
    fun onlyKnownBrowsersAreTrusted() {
        assertTrue(TrustedBrowsers.isKnownPackage("com.android.chrome"))
        assertTrue(TrustedBrowsers.isKnownPackage("org.mozilla.firefox"))
        assertFalse(TrustedBrowsers.isKnownPackage("com.evil.app"))
        assertFalse(TrustedBrowsers.isKnownPackage("com.android.chrome.evil"))
        assertFalse(TrustedBrowsers.isKnownPackage(null))
    }

    @Test
    fun aSpoofedDomainDoesNotMatchAStoredCredential() {
        // End to end: the resolved target for a hostile app must not match a bank.com entry.
        val entry = PasswordEntry(title = "Bank", username = "u", password = "p", url = "https://bank.com")
        val target = AutofillParser.resolveTargetDomain("bank.com", "com.evil.app", trustWebDomain = false)
        assertFalse(DomainMatcher.matchesPassword(entry, target!!))
    }
}
