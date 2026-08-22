package org.kysecurity.authenticator.passwords

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class DomainMatcherTest {

    private fun passkeyEntry(rpId: String) = PasswordEntry(
        title = "GitHub",
        username = "alice",
        passkey = PasskeyData(
            rpId = rpId,
            username = "alice",
            userHandle = byteArrayOf(1, 2, 3),
            credentialId = byteArrayOf(4, 5, 6),
            privateKeyPkcs8 = byteArrayOf(7, 8, 9),
        ),
        url = "https://$rpId",
    )

    private fun passwordEntry(url: String) = PasswordEntry(
        title = "Account",
        username = "alice@example.com",
        password = "secret-password",
        url = url,
    )

    @Test
    fun extractsDomainFromVariousUrls() {
        assertEquals("github.com", DomainMatcher.extractDomain("https://github.com/login"))
        assertEquals("github.com", DomainMatcher.extractDomain("http://www.github.com/"))
        assertEquals("auth.example.test", DomainMatcher.extractDomain("https://auth.example.test:8080/path"))
        assertEquals("example.com", DomainMatcher.extractDomain("android-app://com.example.app/example.com"))
        assertEquals("com.example.app", DomainMatcher.extractDomain("android-app://com.example.app"))
    }

    @Test
    fun passwordFillsOnSubdomainsOfTheDomainItWasSavedFor() {
        val entry = passwordEntry("https://example.com")

        assertTrue(DomainMatcher.matchesPassword(entry, "example.com"))
        assertTrue(DomainMatcher.matchesPassword(entry, "accounts.example.com"))
        assertFalse(DomainMatcher.matchesPassword(entry, "github.com"))
    }

    @Test
    fun passwordSavedForSubdomainDoesNotLeakToParentOrSiblings() {
        val entry = passwordEntry("https://accounts.example.com")

        assertTrue(DomainMatcher.matchesPassword(entry, "accounts.example.com"))
        assertFalse(DomainMatcher.matchesPassword(entry, "example.com"))
        assertFalse(DomainMatcher.matchesPassword(entry, "billing.example.com"))
    }

    @Test
    fun passwordNeverCrossesAPublicSuffixBoundary() {
        assertFalse(DomainMatcher.matchesPassword(passwordEntry("https://co.uk"), "victim.co.uk"))
        assertFalse(DomainMatcher.matchesPassword(passwordEntry("https://github.io"), "victim.github.io"))
    }

    @Test
    fun passkeyMatchingIsExactOnRpId() {
        val entry = passkeyEntry("github.com")

        assertTrue(DomainMatcher.matchesPasskey(entry, "github.com"))
        assertFalse(DomainMatcher.matchesPasskey(entry, "auth.github.com"))
        assertFalse(DomainMatcher.matchesPasskey(entry, "google.com"))
    }

    @Test
    fun passkeyEntryIsNotOfferedAsAPassword() {
        assertFalse(DomainMatcher.matchesPasskey(passwordEntry("https://example.com"), "example.com"))
    }
}
