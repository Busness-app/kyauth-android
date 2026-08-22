package org.kysecurity.authenticator.mfa

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject

object MfaPushChallengeParser {
    const val DEFAULT_EXPIRES_AFTER_MS = 5 * 60 * 1000L
    const val MAX_EXPIRES_AFTER_MS = 10 * 60 * 1000L
    const val MAX_DECOYS = 3

    private val DIGITS = Regex("\\d{2}")

    /**
     * Parses an FCM data message into a challenge.
     *
     * [pairedServerUrl] is the server this device is paired with and is the only server a response
     * may be sent to: a push payload that names its own server would let anyone who can reach the
     * FCM sender collect a valid device signature. Anything in the payload that would widen the
     * challenge — unbounded expiry, malformed or excess digits — is rejected or clamped.
     */
    fun parse(data: Map<String, String>, pairedServerUrl: String?, nowMs: Long = System.currentTimeMillis()): MfaChallenge {
        val serverUrl = pairedServerUrl?.trim().orEmpty()
        require(serverUrl.isNotBlank()) { "KyAuth is not paired with a server" }

        val challengeId = first(data, "challengeId", "challenge_id", "id")
        val matchDigits = firstOrNull(data, "matchDigits", "match_digits", "match").orEmpty()
        require(matchDigits.isBlank() || DIGITS.matches(matchDigits)) { "Malformed match digits" }

        val decoys = parseDecoys(firstOrNull(data, "decoyDigits", "decoy_digits", "decoys"))
            .filter { DIGITS.matches(it) }
            .distinct()
            .filter { it != matchDigits }
            .take(MAX_DECOYS)

        val claimedExpiry = firstOrNull(data, "expiresAtEpochMs", "expires_at_ms", "expiresAtMs")?.toLongOrNull()
            ?: firstOrNull(data, "expiresAt", "expires_at")?.toLongOrNull()?.times(1_000)
            ?: (nowMs + DEFAULT_EXPIRES_AFTER_MS)
        val expiresAt = claimedExpiry.coerceAtMost(nowMs + MAX_EXPIRES_AFTER_MS)
        require(expiresAt > nowMs) { "Challenge has already expired" }

        return MfaChallenge(
            challengeId = challengeId,
            matchDigits = matchDigits,
            decoyDigits = decoys,
            serverUrl = serverUrl,
            username = firstOrNull(data, "username", "user"),
            purpose = firstOrNull(data, "purpose") ?: "session",
            expiresAtEpochMs = expiresAt,
        )
    }

    private fun first(data: Map<String, String>, vararg keys: String): String =
        firstOrNull(data, *keys) ?: error("MFA push payload missing ${keys.first()}")

    private fun firstOrNull(data: Map<String, String>, vararg keys: String): String? =
        keys.firstNotNullOfOrNull { key -> data[key]?.trim()?.takeIf { it.isNotBlank() } }

    private fun parseDecoys(raw: String?): List<String> {
        if (raw.isNullOrBlank()) return emptyList()
        return if (raw.trim().startsWith("[")) {
            val array = JSONArray(raw)
            (0 until array.length()).mapNotNull { array.optString(it).trim().takeIf { value -> value.isNotBlank() } }
        } else {
            raw.split(',', '|', ' ').mapNotNull { it.trim().takeIf { value -> value.isNotBlank() } }
        }
    }
}

class MfaPushChallengeStore(context: Context) {
    private val preferences = context.getSharedPreferences("mfa_push_challenge", Context.MODE_PRIVATE)

    fun save(challenge: MfaChallenge) {
        preferences.edit().putString("challenge", encode(challenge)).apply()
    }

    fun load(): MfaChallenge? {
        val value = preferences.getString("challenge", null) ?: return null
        val challenge = runCatching { decode(value) }.getOrNull() ?: return null
        if (isExpired(challenge)) {
            clear()
            return null
        }
        return challenge
    }

    fun isExpired(challenge: MfaChallenge, nowMs: Long = System.currentTimeMillis()): Boolean =
        nowMs >= challenge.expiresAtEpochMs

    fun secondsRemaining(challenge: MfaChallenge, nowMs: Long = System.currentTimeMillis()): Long =
        maxOf(0, (challenge.expiresAtEpochMs - nowMs + 999) / 1_000)

    fun clear() {
        preferences.edit().clear().apply()
    }

    private fun encode(challenge: MfaChallenge): String = JSONObject()
        .put("challengeId", challenge.challengeId)
        .put("matchDigits", challenge.matchDigits)
        .put("decoyDigits", JSONArray(challenge.decoyDigits))
        .put("serverUrl", challenge.serverUrl)
        .put("username", challenge.username)
        .put("purpose", challenge.purpose)
        .put("expiresAtEpochMs", challenge.expiresAtEpochMs)
        .toString()

    private fun decode(value: String): MfaChallenge {
        val json = JSONObject(value)
        val decoys = json.optJSONArray("decoyDigits")
        return MfaChallenge(
            challengeId = json.getString("challengeId"),
            matchDigits = json.optString("matchDigits"),
            decoyDigits = if (decoys == null) emptyList() else (0 until decoys.length()).map { decoys.getString(it) },
            serverUrl = json.getString("serverUrl"),
            username = json.optString("username").takeIf { it.isNotBlank() },
            purpose = json.optString("purpose", "session"),
            expiresAtEpochMs = json.getLong("expiresAtEpochMs"),
        )
    }
}
