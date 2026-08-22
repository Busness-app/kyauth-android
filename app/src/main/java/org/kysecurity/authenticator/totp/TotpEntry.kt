package org.kysecurity.authenticator.totp

import java.util.UUID

/**
 * KeePass-compatible fields for the dedicated TOTP KDBX v4 vault.
 */
data class TotpEntry(
    val title: String,
    val secretBase32: String,
    val digits: Int = 6,
    val periodSeconds: Long = 30,
    val algorithm: Algorithm = Algorithm.SHA1,
    val issuer: String? = null,
    val url: String? = null,
    val notes: String? = null,
    val id: String = UUID.randomUUID().toString(),
) {
    init {
        require(title.isNotBlank())
        require(digits in 6..8)
        require(periodSeconds > 0)
        require(secretBase32.isNotBlank())
        require(TotpGenerator.isUsableSecret(secretBase32)) { "TOTP secret is not usable Base32" }
    }

    enum class Algorithm { SHA1, SHA256, SHA512 }

    fun keepassFields(): Map<String, String> = buildMap {
        put("TimeOtp-Secret-Base32", secretBase32)
        if (digits != 6) put("TimeOtp-Length", digits.toString())
        if (periodSeconds != 30L) put("TimeOtp-Period", periodSeconds.toString())
        if (algorithm != Algorithm.SHA1) put("TimeOtp-Algorithm", "HMAC-${algorithm.name.replace("SHA", "SHA-")}")
        if (!issuer.isNullOrBlank()) put("TimeOtp-Issuer", issuer)
    }

    companion object {
        fun fromKeepassFields(
            title: String,
            fields: Map<String, String>,
            id: String = UUID.randomUUID().toString(),
            url: String? = null,
            notes: String? = null,
        ): TotpEntry? {
            val secret = fields["TimeOtp-Secret-Base32"] ?: return null
            // An entry stored before this was validated must be skipped, not thrown out of the
            // whole vault load.
            return runCatching {
                TotpEntry(
                    title = title,
                    secretBase32 = secret,
                    digits = fields["TimeOtp-Length"]?.toIntOrNull() ?: 6,
                    periodSeconds = fields["TimeOtp-Period"]?.toLongOrNull() ?: 30,
                    algorithm = when (fields["TimeOtp-Algorithm"]?.uppercase()) {
                        null, "HMAC-SHA-1", "HMAC-SHA1", "SHA1" -> Algorithm.SHA1
                        "HMAC-SHA-256", "HMAC-SHA256", "SHA256" -> Algorithm.SHA256
                        "HMAC-SHA-512", "HMAC-SHA512", "SHA512" -> Algorithm.SHA512
                        else -> Algorithm.SHA1
                    },
                    issuer = fields["TimeOtp-Issuer"],
                    url = url ?: fields["URL"] ?: fields["Url"],
                    notes = notes ?: fields["Notes"],
                    id = id,
                )
            }.getOrNull()
        }
    }
}

