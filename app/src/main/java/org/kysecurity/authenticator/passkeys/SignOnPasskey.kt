package org.kysecurity.authenticator.passkeys

import org.kysecurity.authenticator.passwords.DomainMatcher

/**
 * Decides whether a relying party is the paired KySignOn server.
 *
 * A KySignOn login passkey must not live in `passwords_vault.kdbx`, because that vault syncs to
 * KyPasswords: a KyPasswords compromise plus the master password would otherwise yield a KySignOn
 * authentication factor. This predicate is the single place that decision is made.
 *
 * The paired server URL is a locally held fact, never a caller assertion, so a hostile relying
 * party cannot route itself into the local store by naming an RP ID.
 */
object SignOnPasskey {

    /** The RP ID of the paired KySignOn server, or null when unpaired or unusable as an RP ID. */
    fun signOnRpId(serverUrl: String?): String? =
        RpId.normalize(DomainMatcher.extractDomain(serverUrl))

    /** Exact match only; a passkey for `example.com` is not a passkey for `login.example.com`. */
    fun isSignOnRpId(rpId: String?, serverUrl: String?): Boolean {
        val paired = signOnRpId(serverUrl) ?: return false
        return RpId.normalize(rpId) == paired
    }
}
