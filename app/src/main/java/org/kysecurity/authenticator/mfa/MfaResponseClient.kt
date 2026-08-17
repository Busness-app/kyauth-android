package org.kysecurity.authenticator.mfa

import org.json.JSONObject
import org.kysecurity.authenticator.pairing.PairingEndpoint
import java.net.HttpURLConnection

sealed class MfaResponseResult {
    data class Success(val approved: Boolean, val deviceId: String) : MfaResponseResult()
    data class Error(val message: String) : MfaResponseResult()
}

class MfaResponseClient {
    fun respond(
        serverUrl: String,
        challengeId: String,
        selectedDigits: String,
        approve: Boolean,
        signature: String,
    ): MfaResponseResult {
        require(challengeId.isNotBlank()) { "Challenge ID is required" }
        require(signature.isNotBlank()) { "Device signature is required" }

        val server = PairingEndpoint.registrationUrl(serverUrl)
        val basePath = server.path.removeSuffix("/api/notifications/native/register")
        val respondUrl = "${server.scheme}://${server.host}${if (server.port != -1) ":${server.port}" else ""}$basePath/api/mfa/push/respond"

        val request = JSONObject()
            .put("challengeId", challengeId.trim())
            .put("selectedDigits", selectedDigits.trim())
            .put("approve", approve)
            .put("signature", signature.trim())
            .toString()

        val connection = (java.net.URI(respondUrl).toURL().openConnection() as HttpURLConnection).apply {
            requestMethod = "POST"
            connectTimeout = 10_000
            readTimeout = 10_000
            doOutput = true
            instanceFollowRedirects = false
            setRequestProperty("Content-Type", "application/json")
            setRequestProperty("Accept", "application/json")
        }

        return try {
            connection.outputStream.bufferedWriter(Charsets.UTF_8).use { it.write(request) }
            val body = (if (connection.responseCode in 200..299) connection.inputStream else connection.errorStream)
                ?.bufferedReader(Charsets.UTF_8)?.use { it.readText() }.orEmpty()
            val response = JSONObject(body.ifBlank { "{}" })

            parseResponse(connection.responseCode, response, approve)
        } catch (e: Exception) {
            MfaResponseResult.Error(e.message ?: "Network error during MFA response")
        } finally {
            connection.disconnect()
        }
    }

    internal fun parseResponse(responseCode: Int, response: JSONObject, requestedApprove: Boolean): MfaResponseResult {
        if (responseCode !in 200..299) {
            val errorMsg = response.optString(
                "error_description",
                response.optString("error", "Push response failed ($responseCode)"),
            )
            return MfaResponseResult.Error(errorMsg)
        }
        return MfaResponseResult.Success(
            approved = response.optBoolean("success", response.optBoolean("approved", requestedApprove)),
            deviceId = response.optString("deviceId"),
        )
    }
}
