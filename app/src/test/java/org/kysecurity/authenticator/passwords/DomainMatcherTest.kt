package org.kysecurity.authenticator.passwords

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class DomainMatcherTest {

    @Test
    fun extractsDomainFromVariousUrls() {
        assertEquals("github.com", DomainMatcher.extractDomain("https://github.com/login"))
        assertEquals("github.com", DomainMatcher.extractDomain("http://www.github.com/"))
        assertEquals("auth.example.test", DomainMatcher.extractDomain("https://auth.example.test:8080/path"))
        assertEquals("example.com", DomainMatcher.extractDomain("android-app://com.example.app/example.com"))
        assertEquals("com.example.app", DomainMatcher.extractDomain("android-app://com.example.app"))
    }

    @Test
    fun matchesEntriesCorrectly() {
        val passkey = PasskeyData(
            rpId = "github.com",
            username = "alice",
            userHandle = byteArrayOf(1, 2, 3),
            credentialId = byteArrayOf(4, 5, 6),
            privateKeyPkcs8 = byteArrayOf(7, 8, 9),
        )

        val passkeyEntry = PasswordEntry(
            title = "GitHub",
            username = "alice",
            passkey = passkey,
            url = "https://github.com",
        )

        assertTrue(DomainMatcher.matches(passkeyEntry, "github.com"))
        assertTrue(DomainMatcher.matches(passkeyEntry, "auth.github.com"))
        assertFalse(DomainMatcher.matches(passkeyEntry, "google.com"))

        val regularEntry = PasswordEntry(
            title = "Google Account",
            username = "alice@gmail.com",
            password = "secret-password",
            url = "https://accounts.google.com",
        )

        assertTrue(DomainMatcher.matches(regularEntry, "google.com"))
        assertTrue(DomainMatcher.matches(regularEntry, "accounts.google.com"))
        assertFalse(DomainMatcher.matches(regularEntry, "github.com"))
    }
}
