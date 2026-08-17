package org.kysecurity.authenticator.pairing

import org.json.JSONObject
import java.net.HttpURLConnection

class PairingClient {
    fun register(
        pairing: QrPairing,
        deviceName: String,
        deviceIdentifier: String,
        pushToken: String? = null,
        publicKeyBase64: String = DeviceSigningKey.publicKeyBase64(),
    ): PairedAccount {
        require(deviceName.isNotBlank()) { "Device name is required" }
        require(deviceIdentifier.isNotBlank()) { "Device identifier is required" }
        require(publicKeyBase64.isNotBlank()) { "Device public key is required" }

        val endpoint = PairingEndpoint.validatedRegistrationUrl(pairing.serverUrl, pairing.registrationUrl)
        val request = registrationRequestJson(pairing, deviceName, deviceIdentifier, pushToken, publicKeyBase64)

        val connection = (endpoint.toURL().openConnection() as HttpURLConnection).apply {
            requestMethod = "POST"
            connectTimeout = 10_000
            readTimeout = 10_000
            doOutput = true
            instanceFollowRedirects = false
            setRequestProperty("Content-Type", "application/json")
            setRequestProperty("Accept", "application/json")
        }

        try {
            connection.outputStream.bufferedWriter(Charsets.UTF_8).use { it.write(request) }
            val body = (if (connection.responseCode in 200..299) connection.inputStream else connection.errorStream)
                ?.bufferedReader(Charsets.UTF_8)?.use { it.readText() }.orEmpty()
            val response = JSONObject(body.ifBlank { "{}" })
            if (connection.responseCode !in 200..299 || !response.optBoolean("success")) {
                val errorMsg = response.optString(
                    "error_description",
                    response.optString("error", "Pairing failed (${connection.responseCode})"),
                )
                throw IllegalStateException(errorMsg)
            }
            val deviceId = response.optString("deviceId")
            require(deviceId.isNotBlank()) { "KySignOn did not return a device ID" }
            val respDevice = response.optJSONObject("device")
            val userId = respDevice?.optString("userId")?.takeIf { it.isNotBlank() } ?: pairing.userId

            return PairedAccount(
                serverUrl = pairing.serverUrl.trimEnd('/'),
                deviceId = deviceId,
                deviceName = deviceName.trim(),
                username = pairing.username,
                userId = userId,
            )
        } finally {
            connection.disconnect()
        }
    }

    internal fun registrationRequestJson(
        pairing: QrPairing,
        deviceName: String,
        deviceIdentifier: String,
        pushToken: String?,
        publicKeyBase64: String,
    ): String = JSONObject().apply {
        if (!pairing.pairingToken.isNullOrBlank()) {
            put("pairingToken", pairing.pairingToken)
        }
        if (!pairing.pinCode.isNullOrBlank()) {
            put("pinCode", pairing.pinCode)
        }
        if (!pairing.userId.isNullOrBlank()) {
            put("userId", pairing.userId)
        }
        put("deviceName", deviceName.trim())
        put("deviceIdentifier", deviceIdentifier.trim())
        put("platform", "android")
        put("publicKey", publicKeyBase64)
        if (!pushToken.isNullOrBlank()) {
            put("pushToken", pushToken.trim())
        }
    }.toString()
}
