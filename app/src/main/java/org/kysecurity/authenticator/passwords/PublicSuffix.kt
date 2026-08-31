package org.kysecurity.authenticator.passwords

import com.google.common.net.InternetDomainName

/** Registry-boundary checks backed by Guava's complete Mozilla Public Suffix List snapshot. */
object PublicSuffix {
    fun isPublicSuffix(host: String): Boolean = runCatching {
        InternetDomainName.from(host.trim().lowercase().trim('.')).isPublicSuffix
    }.getOrDefault(true)
}
