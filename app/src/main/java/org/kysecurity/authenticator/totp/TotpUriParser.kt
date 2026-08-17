package org.kysecurity.authenticator.totp

import java.net.URI
import java.net.URLDecoder
import java.nio.charset.StandardCharsets

object TotpUriParser {
    fun parse(uriString: String): TotpEntry {
        val raw = uriString.trim()
        require(raw.isNotBlank()) { "URI is empty" }
        val uri = URI(raw)
        require(uri.scheme.equals("otpauth", ignoreCase = true)) {
            "Invalid OTP URI scheme: ${uri.scheme}"
        }
        require(uri.host.equals("totp", ignoreCase = true)) {
            "Only TOTP is currently supported (got ${uri.host})"
        }

        // Label: path after host
        val rawPath = uri.path.orEmpty().trimStart('/')
        val label = if (rawPath.isNotBlank()) decode(rawPath) else "Account"

        val queryParams = uri.rawQuery.orEmpty().split('&').mapNotNull { part ->
            val idx = part.indexOf('=')
            if (idx < 0) null else decode(part.substring(0, idx)) to decode(part.substring(idx + 1))
        }.toMap()

        val secret = queryParams["secret"].orEmpty().trim()
        require(secret.isNotBlank()) { "Missing OTP secret parameter" }

        val issuer = queryParams["issuer"]?.trim()?.ifBlank { null }
        val digits = queryParams["digits"]?.toIntOrNull() ?: 6
        val period = queryParams["period"]?.toLongOrNull() ?: 30L
        val algorithm = when (queryParams["algorithm"]?.uppercase()) {
            null, "SHA1" -> TotpEntry.Algorithm.SHA1
            "SHA256" -> TotpEntry.Algorithm.SHA256
            "SHA512" -> TotpEntry.Algorithm.SHA512
            else -> TotpEntry.Algorithm.SHA1
        }

        val title = when {
            label.contains(':') -> {
                val prefix = label.substringBefore(':').trim()
                val suffix = label.substringAfter(':').trim()
                if (suffix.isNotBlank()) "$prefix ($suffix)" else prefix
            }
            !issuer.isNullOrBlank() && !label.equals(issuer, ignoreCase = true) -> "$issuer ($label)"
            else -> label
        }

        return TotpEntry(
            title = title,
            secretBase32 = secret,
            digits = digits,
            periodSeconds = period,
            algorithm = algorithm,
            issuer = issuer,
        )
    }

    private fun decode(value: String): String = URLDecoder.decode(value, StandardCharsets.UTF_8.name())
}
