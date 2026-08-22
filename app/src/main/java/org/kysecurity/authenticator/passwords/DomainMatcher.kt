package org.kysecurity.authenticator.passwords

import java.net.URI

object DomainMatcher {

    fun extractDomain(urlOrHost: String?): String? {
        if (urlOrHost.isNullOrBlank()) return null
        val trimmed = urlOrHost.trim()

        // Handle android-app:// schemes
        if (trimmed.startsWith("android-app://", ignoreCase = true)) {
            val rest = trimmed.substring(14)
            if (rest.contains("/")) {
                val pathPart = rest.substringAfterLast('/')
                if (pathPart.contains(".")) {
                    return normalizeHost(pathPart)
                }
            }
            val packagePart = rest.substringBefore('/')
            return packagePart.lowercase().ifBlank { null }
        }

        val withScheme = if (!trimmed.contains("://")) "https://$trimmed" else trimmed
        return runCatching {
            val uri = URI(withScheme)
            val host = uri.host ?: return null
            normalizeHost(host)
        }.getOrNull()
    }

    fun normalizeHost(host: String): String {
        var normalized = host.trim().lowercase().trim('.')
        if (normalized.startsWith("www.")) {
            normalized = normalized.removePrefix("www.")
        }
        return normalized
    }

    /**
     * Password fill matching. A credential saved for a parent domain may fill on its subdomains,
     * never the reverse, and never across a registry boundary — otherwise a credential stored for
     * `example.com` would be offered on `attacker.example.com`, and one stored for a shared host
     * such as `github.io` would be offered to every tenant on it.
     */
    fun matchesPassword(entry: PasswordEntry, targetDomain: String): Boolean {
        val target = normalizeHost(targetDomain)
        if (target.isBlank()) return false
        val candidates = listOfNotNull(entry.url?.let(::extractDomain), extractDomain(entry.title))
        return candidates.any { domainsMatch(it, target) }
    }

    /**
     * Passkey matching. WebAuthn scopes a credential to exactly one RP ID, so this is an exact
     * comparison: a passkey for `example.com` is not a passkey for `login.example.com`.
     */
    fun matchesPasskey(entry: PasswordEntry, rpId: String): Boolean {
        val passkey = entry.passkey ?: return false
        return normalizeHost(passkey.rpId) == normalizeHost(rpId)
    }

    /** True when a credential scoped to [entryDomain] may be used on [target]. */
    fun domainsMatch(entryDomain: String, target: String): Boolean {
        if (entryDomain.isBlank() || target.isBlank()) return false
        if (entryDomain == target) return true
        if (!target.endsWith(".$entryDomain")) return false
        return !PublicSuffix.isPublicSuffix(entryDomain)
    }
}
