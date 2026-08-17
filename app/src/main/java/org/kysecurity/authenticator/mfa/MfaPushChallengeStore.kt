package org.kysecurity.authenticator.mfa

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject

object MfaPushChallengeParser {
    const val DEFAULT_EXPIRES_AFTER_MS = 5 * 60 * 1000L

    fun parse(data: Map<String, String>, fallbackServerUrl: String?): MfaChallenge {
        val challengeId = first(data, "challengeId", "challenge_id", "id")
        val matchDigits = firstOrNull(data, "matchDigits", "match_digits", "match").orEmpty()
        val serverUrl = firstOrNull(data, "serverUrl", "server_url") ?: fallbackServerUrl.orEmpty()
        val decoys = parseDecoys(firstOrNull(data, "decoyDigits", "decoy_digits", "decoys"))
        val receivedAt = System.currentTimeMillis()
        val expiresAt = firstOrNull(data, "expiresAtEpochMs", "expires_at_ms", "expiresAtMs")?.toLongOrNull()
            ?: firstOrNull(data, "expiresAt", "expires_at")?.toLongOrNull()?.times(1_000)
            ?: (receivedAt + DEFAULT_EXPIRES_AFTER_MS)
        return MfaChallenge(
            challengeId = challengeId,
            matchDigits = matchDigits,
            decoyDigits = decoys,
            serverUrl = serverUrl,
            username = firstOrNull(data, "username", "user"),
            purpose = firstOrNull(data, "purpose") ?: "session",
            timestampEpochMs = expiresAt,
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
        nowMs >= challenge.timestampEpochMs

    fun secondsRemaining(challenge: MfaChallenge, nowMs: Long = System.currentTimeMillis()): Long =
        maxOf(0, (challenge.timestampEpochMs - nowMs + 999) / 1_000)

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
        .put("timestampEpochMs", challenge.timestampEpochMs)
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
            timestampEpochMs = json.optLong("timestampEpochMs", System.currentTimeMillis()),
        )
    }
}
