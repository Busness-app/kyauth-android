package org.kysecurity.authenticator.mfa

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class MfaPushChallengeParserTest {
    @Test
    fun parsesKySignOnPushChallengeDataPayload() {
        val before = System.currentTimeMillis()
        val challenge = MfaPushChallengeParser.parse(
            mapOf(
                "challengeId" to "ch-123",
                "matchDigits" to "42",
                "decoyDigits" to """["12","55","88"]""",
                "serverUrl" to "https://signin.example.com",
                "username" to "alice",
            ),
            fallbackServerUrl = null,
        )
        val after = System.currentTimeMillis()

        assertEquals("ch-123", challenge.challengeId)
        assertEquals("42", challenge.matchDigits)
        assertEquals(listOf("12", "55", "88"), challenge.decoyDigits)
        assertEquals("https://signin.example.com", challenge.serverUrl)
        assertEquals("alice", challenge.username)
        assertTrue(
            challenge.timestampEpochMs in before + MfaPushChallengeParser.DEFAULT_EXPIRES_AFTER_MS..after + MfaPushChallengeParser.DEFAULT_EXPIRES_AFTER_MS,
        )
    }

    @Test
    fun acceptsRelayAliasesAndFallbackServerUrl() {
        val challenge = MfaPushChallengeParser.parse(
            mapOf(
                "id" to "ch-456",
                "match" to "19",
                "decoys" to "22,33,44",
            ),
            fallbackServerUrl = "https://signin.example.com",
        )

        assertEquals("ch-456", challenge.challengeId)
        assertEquals("19", challenge.matchDigits)
        assertEquals(listOf("22", "33", "44"), challenge.decoyDigits)
        assertEquals("https://signin.example.com", challenge.serverUrl)
    }

    @Test
    fun parsesExplicitExpirySeconds() {
        val challenge = MfaPushChallengeParser.parse(
            mapOf(
                "challengeId" to "ch-789",
                "matchDigits" to "77",
                "expiresAt" to "2000",
            ),
            fallbackServerUrl = "https://signin.example.com",
        )

        assertEquals(2_000_000L, challenge.timestampEpochMs)
    }
}
