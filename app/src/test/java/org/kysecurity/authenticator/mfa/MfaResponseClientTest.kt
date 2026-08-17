package org.kysecurity.authenticator.mfa

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class MfaResponseClientTest {
    @Test
    fun parseResponse_acceptsKySignOnSuccessField() {
        val result = MfaResponseClient().parseResponse(200, JSONObject("""{"success":true}"""), true)

        assertTrue((result as MfaResponseResult.Success).approved)
    }

    @Test
    fun parseResponse_acceptsKySignOnDeniedFieldAsHandledResponse() {
        val result = MfaResponseClient().parseResponse(200, JSONObject("""{"success":false}"""), false)

        assertEquals(false, (result as MfaResponseResult.Success).approved)
    }

    @Test
    fun parseResponse_keepsServerErrorMessage() {
        val result = MfaResponseClient().parseResponse(
            400,
            JSONObject("""{"error_description":"Challenge could not be answered"}"""),
            true,
        )

        assertEquals("Challenge could not be answered", (result as MfaResponseResult.Error).message)
    }
}
