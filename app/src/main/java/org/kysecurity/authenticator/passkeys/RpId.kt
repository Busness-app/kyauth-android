package org.kysecurity.authenticator.passkeys

import org.kysecurity.authenticator.passwords.PublicSuffix

/**
 * Validation of the relying-party identifier a caller asks KyAuth to act for.
 *
 * What is enforced here is what can be decided offline: the RP ID must be a syntactically valid
 * domain, must not be a registry boundary, and — when the caller is a browser passing a web
 * origin — must be that origin's domain or a registrable parent of it.
 *
 * A native app is NOT verified against the RP it claims. Doing that requires fetching
 * `https://<rpId>/.well-known/assetlinks.json` and matching the caller's signing certificate;
 * until that exists, any installed app can request a credential for any RP ID. Tracked in
 * AGENTS.md.
 */
object RpId {
    private val LABEL = Regex("[a-z0-9]([a-z0-9-]*[a-z0-9])?")

    /** Returns the normalized RP ID, or null when it is not a usable domain. */
    fun normalize(raw: String?): String? {
        val candidate = raw?.trim()?.lowercase()?.trim('.').orEmpty()
        if (candidate.isBlank() || candidate.length > 253) return null
        if (candidate.any { it == '/' || it == ':' || it == '@' || it == '?' || it == '#' }) return null
        val labels = candidate.split('.')
        if (labels.size < 2) return null
        if (!labels.all { it.isNotEmpty() && it.length <= 63 && LABEL.matches(it) }) return null
        if (PublicSuffix.isPublicSuffix(candidate)) return null
        return candidate
    }

    /**
     * Validates [raw] for a caller. [webOriginHost] is the host of the caller's web origin when
     * one was supplied, and null for a native app caller.
     */
    fun validate(raw: String?, webOriginHost: String?): String? {
        val rpId = normalize(raw) ?: return null
        if (webOriginHost == null) return rpId
        val host = webOriginHost.trim().lowercase().trim('.')
        return if (host == rpId || host.endsWith(".$rpId")) rpId else null
    }
}
