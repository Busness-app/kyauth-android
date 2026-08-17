package org.kysecurity.authenticator.pairing

import org.json.JSONObject
import java.net.URI
import java.net.URLDecoder
import java.nio.charset.StandardCharsets

/**
 * The ephemeral pairing credentials parsed from a KySignOn QR code or deep link.
 * Kept in memory only and never saved to persistent storage.
 */
data class QrPairing(
    val serverUrl: String,
    val registrationUrl: String? = null,
    val pairingToken: String? = null,
    val pinCode: String? = null,
    val userId: String? = null,
    val username: String? = null,
    val expiresAtEpochSeconds: Long? = null,
) {
    init {
        require(serverUrl.isNotBlank()) { "Server URL is required" }
        require(!pairingToken.isNullOrBlank() || (!pinCode.isNullOrBlank() && !userId.isNullOrBlank())) {
            "Pairing token or (PIN code and user ID) is required"
        }
    }
}

/**
 * Accepts KySignOn's current QR JSON plus the KyPost/KySignOn-style deep-link envelopes.
 * Both forms must identify the same HTTPS origin before a credential can be sent.
 */
object QrPairingParser {
    fun parse(raw: String): QrPairing {
        val value = raw.trim()
        require(value.isNotBlank()) { "QR code is empty" }
        val pairing = if (value.startsWith("{")) parseJson(value) else parseDeepLink(value)
        require(pairing.expiresAtEpochSeconds == null || pairing.expiresAtEpochSeconds > System.currentTimeMillis() / 1_000) {
            "Pairing credential has expired"
        }
        PairingEndpoint.validatedRegistrationUrl(pairing.serverUrl, pairing.registrationUrl)
        return pairing
    }

    private fun parseJson(value: String): QrPairing {
        val json = JSONObject(value)
        val type = json.optString("type")
        require(type == "kysignon_device_pairing" || type == "kypost_device_pairing") {
            "Unsupported QR code type: $type"
        }
        val serverUrl = json.optString("serverUrl").trim()
        val registrationUrl = json.optString("registrationUrl").trim().ifBlank { null }
        val pairingToken = json.optString("pairingToken").trim().ifBlank { null }
        val pinCode = json.optString("pinCode").trim().ifBlank { null }
        val userId = json.optString("userId").trim().ifBlank { null }
        val username = json.optString("username").trim().ifBlank { null }
        val expiresAt = if (json.has("expiresAt")) json.optLong("expiresAt") else null

        return QrPairing(
            serverUrl = serverUrl,
            registrationUrl = registrationUrl,
            pairingToken = pairingToken,
            pinCode = pinCode,
            userId = userId,
            username = username,
            expiresAtEpochSeconds = expiresAt,
        )
    }

    private fun parseDeepLink(value: String): QrPairing {
        val uri = URI(value)
        require(
            (uri.scheme.equals("kysignon", ignoreCase = true) || uri.scheme.equals("kypost", ignoreCase = true)) &&
                uri.host.equals("native-pair", ignoreCase = true),
        ) {
            "Unsupported pairing deep link"
        }
        val params = uri.rawQuery.orEmpty().split('&').mapNotNull { part ->
            val index = part.indexOf('=')
            if (index < 0) null else decode(part.substring(0, index)) to decode(part.substring(index + 1))
        }.toMap()

        val serverUrl = params["srv"].orEmpty().trim()
        val registrationUrl = params["reg"]?.trim()?.ifBlank { null }
        val pairingToken = params["pt"]?.trim()?.ifBlank { null }
        val pinCode = params["pin"]?.trim()?.ifBlank { null }
        val userId = (params["sub"] ?: params["uid"])?.trim()?.ifBlank { null }
        val username = (params["user"] ?: params["username"])?.trim()?.ifBlank { null }
        val expiresAt = params["exp"]?.toLongOrNull()

        return QrPairing(
            serverUrl = serverUrl,
            registrationUrl = registrationUrl,
            pairingToken = pairingToken,
            pinCode = pinCode,
            userId = userId,
            username = username,
            expiresAtEpochSeconds = expiresAt,
        )
    }

    private fun decode(value: String): String = URLDecoder.decode(value, StandardCharsets.UTF_8.name())
}
