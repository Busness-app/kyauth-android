package org.kysecurity.authenticator.mfa

data class MfaChallenge(
    val challengeId: String,
    val matchDigits: String = "",
    val decoyDigits: List<String>,
    val serverUrl: String,
    val username: String? = null,
    val purpose: String = "session",
    val expiresAtEpochMs: Long = System.currentTimeMillis(),
) {
    init {
        require(challengeId.isNotBlank()) { "Challenge ID is required" }
        require(serverUrl.isNotBlank()) { "Server URL is required" }
    }

    /**
     * Returns the 4 distinct 2-digit candidate numbers (the match and 3 decoys)
     * in a deterministic shuffled order for display in the grid.
     */
    fun options(): List<String> {
        val all = (listOf(matchDigits) + decoyDigits).filter { it.isNotBlank() }.distinct()
        return all.sorted()
    }
}

object MfaMessage {
    private const val PREFIX = "kysignon-push-v1"

    /**
     * Builds the exact domain-separated byte array that the device must sign with its
     * hardware-backed ECDSA P-256 key to answer a challenge.
     *
     * The payload does not yet bind the server origin, account or expiry. Doing so is the right
     * fix for a compromised push sender, but changes the wire format and needs a matching
     * KySignOn change; until then the client refuses to answer any server but the paired one.
     * Tracked in AGENTS.md.
     */
    fun formatPayload(challengeId: String, approve: Boolean, selectedDigits: String): ByteArray {
        val verb = if (approve) "approve" else "deny"
        val payload = "$PREFIX|$challengeId|$verb|$selectedDigits"
        return payload.toByteArray(Charsets.UTF_8)
    }
}
