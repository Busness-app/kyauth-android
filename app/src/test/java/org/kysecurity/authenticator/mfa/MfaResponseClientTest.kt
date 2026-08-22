package org.kysecurity.authenticator.mfa

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class MfaResponseClientTest {
    private val client = MfaResponseClient()

    @Test
    fun parseResponse_acceptsKySignOnSuccessField() {
        val result = client.parseResponse(200, JSONObject("""{"success":true}"""), "ch-1")

        assertTrue((result as MfaResponseResult.Success).approved)
    }

    @Test
    fun parseResponse_acceptsKySignOnDeniedFieldAsHandledResponse() {
        val result = client.parseResponse(200, JSONObject("""{"success":false}"""), "ch-1")

        assertEquals(false, (result as MfaResponseResult.Success).approved)
    }

    @Test
    fun parseResponse_keepsServerErrorMessage() {
        val result = client.parseResponse(
            400,
            JSONObject("""{"error_description":"Challenge could not be answered"}"""),
            "ch-1",
        )

        assertEquals("Challenge could not be answered", (result as MfaResponseResult.Error).message)
    }

    @Test
    fun parseResponse_treatsA2xxWithoutADecisionAsAProtocolError() {
        val result = client.parseResponse(200, JSONObject("{}"), "ch-1")

        assertEquals("Server did not report a decision", (result as MfaResponseResult.Error).message)
    }

    @Test
    fun parseResponse_rejectsAnAnswerForADifferentChallenge() {
        val result = client.parseResponse(
            200,
            JSONObject("""{"challengeId":"ch-other","approved":true}"""),
            "ch-1",
        )

        assertEquals("Server answered a different challenge", (result as MfaResponseResult.Error).message)
    }

    @Test
    fun parseResponse_acceptsAMatchingChallengeId() {
        val result = client.parseResponse(
            200,
            JSONObject("""{"challengeId":"ch-1","approved":true,"deviceId":"dev-9"}"""),
            "ch-1",
        )

        assertEquals("dev-9", (result as MfaResponseResult.Success).deviceId)
        assertTrue(result.approved)
    }
}
