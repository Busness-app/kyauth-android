package org.kysecurity.authenticator.passwords

import java.util.Base64
import java.util.UUID

data class PasskeyData(
    val rpId: String,
    val username: String,
    val userHandle: ByteArray,
    val credentialId: ByteArray,
    val privateKeyPkcs8: ByteArray,
    val signCount: Int = 0,
) {
    init {
        require(rpId.isNotBlank()) { "rpId must not be blank" }
        require(credentialId.isNotEmpty()) { "credentialId must not be empty" }
        require(privateKeyPkcs8.isNotEmpty()) { "privateKeyPkcs8 must not be empty" }
    }

    fun toKeepassCustomFields(): Map<String, String> = mapOf(
        FIELD_RP_ID to rpId,
        FIELD_USER_NAME to username,
        FIELD_USER_HANDLE to Base64.getEncoder().encodeToString(userHandle),
        FIELD_CREDENTIAL_ID to Base64.getEncoder().encodeToString(credentialId),
        FIELD_PRIVATE_KEY to Base64.getEncoder().encodeToString(privateKeyPkcs8),
        FIELD_SIGN_COUNT to signCount.toString(),
    )

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is PasskeyData) return false
        return rpId == other.rpId &&
            username == other.username &&
            userHandle.contentEquals(other.userHandle) &&
            credentialId.contentEquals(other.credentialId) &&
            privateKeyPkcs8.contentEquals(other.privateKeyPkcs8) &&
            signCount == other.signCount
    }

    override fun hashCode(): Int {
        var result = rpId.hashCode()
        result = 31 * result + username.hashCode()
        result = 31 * result + userHandle.contentHashCode()
        result = 31 * result + credentialId.contentHashCode()
        result = 31 * result + privateKeyPkcs8.contentHashCode()
        result = 31 * result + signCount
        return result
    }

    companion object {
        const val FIELD_RP_ID = "Passkey-RpId"
        const val FIELD_USER_NAME = "Passkey-UserName"
        const val FIELD_USER_HANDLE = "Passkey-UserHandle"
        const val FIELD_CREDENTIAL_ID = "Passkey-CredentialId"
        const val FIELD_PRIVATE_KEY = "Passkey-PrivateKey"
        const val FIELD_SIGN_COUNT = "Passkey-SignCount"

        fun fromKeepassCustomFields(fields: Map<String, String>): PasskeyData? {
            val rpId = fields[FIELD_RP_ID] ?: return null
            val credIdB64 = fields[FIELD_CREDENTIAL_ID] ?: return null
            val privKeyB64 = fields[FIELD_PRIVATE_KEY] ?: return null
            val userHandleB64 = fields[FIELD_USER_HANDLE]
            val username = fields[FIELD_USER_NAME].orEmpty()
            val signCount = fields[FIELD_SIGN_COUNT]?.toIntOrNull() ?: 0

            return runCatching {
                val credId = Base64.getDecoder().decode(credIdB64)
                val privKey = Base64.getDecoder().decode(privKeyB64)
                val userHandle = if (userHandleB64 != null) Base64.getDecoder().decode(userHandleB64) else ByteArray(0)
                PasskeyData(
                    rpId = rpId,
                    username = username,
                    userHandle = userHandle,
                    credentialId = credId,
                    privateKeyPkcs8 = privKey,
                    signCount = signCount,
                )
            }.getOrNull()
        }
    }
}

data class PasswordEntry(
    val title: String,
    val username: String,
    val password: String = "",
    val url: String? = null,
    val notes: String? = null,
    val passkey: PasskeyData? = null,
    val id: String = UUID.randomUUID().toString(),
) {
    init {
        require(title.isNotBlank()) { "title must not be blank" }
        require(password.isNotBlank() || passkey != null) { "entry must have a password or a passkey" }
    }

    val isPasskey: Boolean get() = passkey != null
}
