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
        var normalized = host.trim().lowercase()
        if (normalized.startsWith("www.")) {
            normalized = normalized.removePrefix("www.")
        }
        return normalized
    }

    fun matches(entry: PasswordEntry, targetDomainOrRpId: String): Boolean {
        val target = normalizeHost(targetDomainOrRpId)
        if (target.isBlank()) return false

        // Check explicit passkey RP ID
        entry.passkey?.let {
            val passkeyRp = normalizeHost(it.rpId)
            if (domainsMatch(passkeyRp, target)) return true
        }

        // Check entry URL
        entry.url?.let {
            val entryDomain = extractDomain(it)
            if (entryDomain != null && domainsMatch(entryDomain, target)) return true
        }

        // Check entry title if it looks like a domain
        val titleDomain = extractDomain(entry.title)
        if (titleDomain != null && domainsMatch(titleDomain, target)) {
            return true
        }

        return false
    }

    fun domainsMatch(candidate: String, target: String): Boolean {
        if (candidate == target) return true
        // Allow subdomain matches, e.g. auth.example.com matches example.com
        if (candidate.endsWith(".$target") || target.endsWith(".$candidate")) return true
        return false
    }
}
