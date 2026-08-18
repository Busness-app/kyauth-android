package org.kysecurity.authenticator.passwords.kypasswords

import org.json.JSONObject
import org.kysecurity.authenticator.pairing.PairingEndpoint
import java.net.URI
import java.net.URLDecoder
import java.nio.charset.StandardCharsets

data class KyPasswordPairing(
    val serverUrl: String,
    val secret: String? = null,
    val pin: String? = null,
) {
    init {
        require(serverUrl.isNotBlank()) { "Server URL is required" }
        require(!secret.isNullOrBlank() || !pin.isNullOrBlank()) {
            "Pairing secret or PIN is required"
        }
    }
}

object KyPasswordPairingParser {
    fun parse(raw: String): KyPasswordPairing {
        val value = raw.trim()
        require(value.isNotBlank()) { "QR code is empty" }
        val pairing = if (value.startsWith("{")) parseJson(value) else parseDeepLink(value)
        val validatedUrl = PairingEndpoint.validateServerUrl(pairing.serverUrl)
        return pairing.copy(serverUrl = validatedUrl)
    }

    private fun parseJson(value: String): KyPasswordPairing {
        val json = JSONObject(value)
        val serverUrl = when {
            json.has("server") -> json.optString("server")
            json.has("serverUrl") -> json.optString("serverUrl")
            else -> ""
        }.trim()
        val secret = json.optString("secret").trim().ifBlank { null }
        val pin = when {
            json.has("pin") -> json.optString("pin")
            json.has("pinCode") -> json.optString("pinCode")
            else -> null
        }?.trim()?.ifBlank { null }

        return KyPasswordPairing(
            serverUrl = serverUrl,
            secret = secret,
            pin = pin,
        )
    }

    private fun parseDeepLink(value: String): KyPasswordPairing {
        val uri = URI(value)
        require(
            (uri.scheme.equals("kypasswords", ignoreCase = true) || uri.scheme.equals("kypassword", ignoreCase = true)) &&
                uri.host.equals("native-pair", ignoreCase = true),
        ) {
            "Unsupported KyPasswords pairing deep link"
        }
        val params = uri.rawQuery.orEmpty().split('&').mapNotNull { part ->
            val index = part.indexOf('=')
            if (index < 0) null else decode(part.substring(0, index)) to decode(part.substring(index + 1))
        }.toMap()

        val serverUrl = (params["srv"] ?: params["server"]).orEmpty().trim()
        val secret = params["secret"]?.trim()?.ifBlank { null }
        val pin = params["pin"]?.trim()?.ifBlank { null }

        return KyPasswordPairing(
            serverUrl = serverUrl,
            secret = secret,
            pin = pin,
        )
    }

    private fun decode(value: String): String = URLDecoder.decode(value, StandardCharsets.UTF_8.name())
}
