package org.kysecurity.authenticator.mfa

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class MfaPushChallengeParserTest {
    private val paired = "https://signin.example.com"

    @Test
    fun parsesKySignOnPushChallengeDataPayload() {
        val now = 1_000_000L
        val challenge = MfaPushChallengeParser.parse(
            mapOf(
                "challengeId" to "ch-123",
                "matchDigits" to "42",
                "decoyDigits" to """["12","55","88"]""",
                "username" to "alice",
            ),
            pairedServerUrl = paired,
            nowMs = now,
        )

        assertEquals("ch-123", challenge.challengeId)
        assertEquals("42", challenge.matchDigits)
        assertEquals(listOf("12", "55", "88"), challenge.decoyDigits)
        assertEquals(paired, challenge.serverUrl)
        assertEquals("alice", challenge.username)
        assertEquals(now + MfaPushChallengeParser.DEFAULT_EXPIRES_AFTER_MS, challenge.expiresAtEpochMs)
    }

    @Test
    fun acceptsRelayAliases() {
        val challenge = MfaPushChallengeParser.parse(
            mapOf("id" to "ch-456", "match" to "19", "decoys" to "22,33,44"),
            pairedServerUrl = paired,
        )

        assertEquals("ch-456", challenge.challengeId)
        assertEquals("19", challenge.matchDigits)
        assertEquals(listOf("22", "33", "44"), challenge.decoyDigits)
    }

    @Test
    fun ignoresAServerUrlSuppliedByThePushPayload() {
        val challenge = MfaPushChallengeParser.parse(
            mapOf(
                "challengeId" to "ch-1",
                "matchDigits" to "42",
                "serverUrl" to "https://attacker.example",
                "server_url" to "https://attacker.example",
            ),
            pairedServerUrl = paired,
        )

        assertEquals(paired, challenge.serverUrl)
    }

    @Test
    fun refusesToBuildAChallengeWithoutAPairedServer() {
        assertThrows(IllegalArgumentException::class.java) {
            MfaPushChallengeParser.parse(mapOf("challengeId" to "ch-1"), pairedServerUrl = null)
        }
    }

    @Test
    fun parsesExplicitExpirySeconds() {
        val challenge = MfaPushChallengeParser.parse(
            mapOf("challengeId" to "ch-789", "matchDigits" to "77", "expiresAt" to "2000"),
            pairedServerUrl = paired,
            nowMs = 1_500_000L,
        )

        assertEquals(2_000_000L, challenge.expiresAtEpochMs)
    }

    @Test
    fun clampsAnOverlongExpiry() {
        val now = 1_000_000L
        val challenge = MfaPushChallengeParser.parse(
            mapOf("challengeId" to "ch-1", "matchDigits" to "42", "expiresAtEpochMs" to "999999999999"),
            pairedServerUrl = paired,
            nowMs = now,
        )

        assertEquals(now + MfaPushChallengeParser.MAX_EXPIRES_AFTER_MS, challenge.expiresAtEpochMs)
    }

    @Test
    fun rejectsAnAlreadyExpiredChallenge() {
        assertThrows(IllegalArgumentException::class.java) {
            MfaPushChallengeParser.parse(
                mapOf("challengeId" to "ch-1", "matchDigits" to "42", "expiresAtEpochMs" to "500"),
                pairedServerUrl = paired,
                nowMs = 1_000_000L,
            )
        }
    }

    @Test
    fun rejectsMalformedMatchDigits() {
        assertThrows(IllegalArgumentException::class.java) {
            MfaPushChallengeParser.parse(
                mapOf("challengeId" to "ch-1", "matchDigits" to "42x"),
                pairedServerUrl = paired,
            )
        }
    }

    @Test
    fun dropsMalformedDuplicateAndExcessDecoys() {
        val challenge = MfaPushChallengeParser.parse(
            mapOf(
                "challengeId" to "ch-1",
                "matchDigits" to "42",
                "decoyDigits" to "11,11,notdigits,42,22,33,44,55",
            ),
            pairedServerUrl = paired,
        )

        assertEquals(listOf("11", "22", "33"), challenge.decoyDigits)
        assertTrue(challenge.decoyDigits.size <= MfaPushChallengeParser.MAX_DECOYS)
    }
}
