package org.kysecurity.authenticator.mfa

import org.junit.Assert.assertEquals
import org.junit.Test

class MfaMessageTest {
    @Test
    fun formatsApprovedChallengeMessage() {
        val payload = MfaMessage.formatPayload("ch-1234", true, "42")
        assertEquals(
            "kysignon-push-v1|ch-1234|approve|42",
            String(payload, Charsets.UTF_8),
        )
    }

    @Test
    fun formatsDeniedChallengeMessage() {
        val payload = MfaMessage.formatPayload("ch-5678", false, "99")
        assertEquals(
            "kysignon-push-v1|ch-5678|deny|99",
            String(payload, Charsets.UTF_8),
        )
    }

    @Test
    fun challengeOptionsIncludeMatchAndDecoysSorted() {
        val challenge = MfaChallenge(
            challengeId = "ch-1",
            matchDigits = "42",
            decoyDigits = listOf("88", "12", "55"),
            serverUrl = "https://auth.example.com",
        )
        assertEquals(listOf("12", "42", "55", "88"), challenge.options())
    }
}
