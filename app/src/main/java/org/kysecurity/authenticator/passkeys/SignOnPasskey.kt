package org.kysecurity.authenticator.passkeys

import java.util.Base64
import org.json.JSONObject
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

/**
 * Everything about a KySignOn passkey except the private key, which is non-exportable and lives in
 * AndroidKeyStore under [alias]. None of these fields is key material, so this record is what gets
 * persisted; there is no secret left to put in a vault.
 */
data class SignOnPasskeyRecord(
    val rpId: String,
    val username: String,
    val userHandle: ByteArray,
    val credentialId: ByteArray,
    val signCount: Int,
    val alias: String,
    val strongBoxBacked: Boolean,
) {
    fun toJson(): String = JSONObject()
        .put(F_RP_ID, rpId)
        .put(F_USERNAME, username)
        .put(F_USER_HANDLE, b64(userHandle))
        .put(F_CREDENTIAL_ID, b64(credentialId))
        .put(F_SIGN_COUNT, signCount)
        .put(F_ALIAS, alias)
        .put(F_STRONGBOX, strongBoxBacked)
        .toString()

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is SignOnPasskeyRecord) return false
        return rpId == other.rpId &&
            username == other.username &&
            userHandle.contentEquals(other.userHandle) &&
            credentialId.contentEquals(other.credentialId) &&
            signCount == other.signCount &&
            alias == other.alias &&
            strongBoxBacked == other.strongBoxBacked
    }

    override fun hashCode(): Int {
        var result = rpId.hashCode()
        result = 31 * result + username.hashCode()
        result = 31 * result + userHandle.contentHashCode()
        result = 31 * result + credentialId.contentHashCode()
        result = 31 * result + signCount
        result = 31 * result + alias.hashCode()
        result = 31 * result + strongBoxBacked.hashCode()
        return result
    }

    companion object {
        private const val F_RP_ID = "rpId"
        private const val F_USERNAME = "username"
        private const val F_USER_HANDLE = "userHandle"
        private const val F_CREDENTIAL_ID = "credentialId"
        private const val F_SIGN_COUNT = "signCount"
        private const val F_ALIAS = "alias"
        private const val F_STRONGBOX = "strongBox"

        fun fromJson(serialized: String?): SignOnPasskeyRecord? {
            if (serialized.isNullOrBlank()) return null
            return runCatching {
                val json = JSONObject(serialized)
                SignOnPasskeyRecord(
                    rpId = json.getString(F_RP_ID),
                    username = json.getString(F_USERNAME),
                    userHandle = unb64(json.getString(F_USER_HANDLE)),
                    credentialId = unb64(json.getString(F_CREDENTIAL_ID)),
                    signCount = json.getInt(F_SIGN_COUNT),
                    alias = json.getString(F_ALIAS),
                    strongBoxBacked = json.getBoolean(F_STRONGBOX),
                )
            }.getOrNull()
        }

        private fun b64(bytes: ByteArray): String = Base64.getEncoder().encodeToString(bytes)

        private fun unb64(value: String): ByteArray = Base64.getDecoder().decode(value)
    }
}
