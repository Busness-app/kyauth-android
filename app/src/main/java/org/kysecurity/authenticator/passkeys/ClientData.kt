package org.kysecurity.authenticator.passkeys

import android.content.pm.SigningInfo
import android.util.Base64
import java.security.MessageDigest
import org.json.JSONObject

/**
 * WebAuthn `CollectedClientData`.
 *
 * An assertion signs `authenticatorData || SHA-256(clientDataJSON)`, so the bytes that are hashed
 * and the bytes returned to the relying party must be the same serialization — [serialize]
 * produces it once and callers use it for both.
 */
object ClientData {
    const val TYPE_GET = "webauthn.get"
    const val TYPE_CREATE = "webauthn.create"

    private const val B64 = Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP

    /**
     * The exact UTF-8 serialization to hash and return. [challengeB64Url] is passed through
     * verbatim from the request so the relying party sees the challenge it issued.
     */
    fun serialize(
        type: String,
        challengeB64Url: String,
        origin: String,
        androidPackageName: String?,
    ): ByteArray {
        val json = JSONObject()
            .put("type", type)
            .put("challenge", challengeB64Url)
            .put("origin", origin)
            .put("crossOrigin", false)
        if (androidPackageName != null) json.put("androidPackageName", androidPackageName)
        return json.toString().toByteArray(Charsets.UTF_8)
    }

    /**
     * The origin for a native caller: `android:apk-key-hash:<base64url(sha256(signing cert))>`.
     * Returns null when the caller cannot be identified, which must fail the request rather than
     * fall back to an unauthenticated origin string.
     */
    fun apkKeyHashOrigin(signingInfo: SigningInfo?): String? {
        val info = signingInfo ?: return null
        val signatures = if (info.hasMultipleSigners()) info.apkContentsSigners else info.signingCertificateHistory
        val certificate = signatures?.firstOrNull() ?: return null
        val digest = MessageDigest.getInstance("SHA-256").digest(certificate.toByteArray())
        return "android:apk-key-hash:" + Base64.encodeToString(digest, B64)
    }

    /** The host of a web origin such as `https://example.com`, or null if it is not one. */
    fun webOriginHost(origin: String?): String? {
        if (origin.isNullOrBlank() || !origin.startsWith("https://", ignoreCase = true)) return null
        return runCatching { java.net.URI(origin).host }.getOrNull()?.lowercase()?.ifBlank { null }
    }
}
