package org.kysecurity.authenticator.passkeys

import android.content.pm.SigningInfo
import java.io.ByteArrayOutputStream
import java.net.HttpURLConnection
import java.net.URI
import java.security.MessageDigest
import java.util.Locale
import java.util.concurrent.ConcurrentHashMap
import org.json.JSONArray

/**
 * Binds a native caller to the relying party it claims.
 *
 * A browser proves which site it speaks for through the privileged origin the platform attaches to
 * the request. A native app proves nothing by itself — without this check any installed app can
 * name any RP ID and have the user's passkeys for it listed. The relying party settles it: an app
 * may act for an RP only if that RP's `assetlinks.json` names the app's package and the SHA-256
 * fingerprint of the certificate it was signed with.
 *
 * Verification fails closed. An RP that publishes no statement, or a device that is offline with a
 * cold cache, yields no passkeys for native callers rather than an unverified assertion.
 *
 * The fetch blocks, so callers must be off the main thread.
 */
object DigitalAssetLinks {
    private const val RELATION = "delegate_permission/common.get_login_creds"
    private const val NAMESPACE = "android_app"
    private const val MAX_BYTES = 512L * 1024
    private const val SUCCESS_TTL_MS = 24L * 60 * 60 * 1000
    private const val FAILURE_TTL_MS = 5L * 60 * 1000

    private data class Cached(val fingerprints: Map<String, Set<String>>, val expiresAtMs: Long)

    private val cache = ConcurrentHashMap<String, Cached>()

    /** True when [rpId] has published a statement naming this caller's package and signing key. */
    fun isCallerAuthorized(rpId: String, packageName: String?, signingInfo: SigningInfo?): Boolean {
        if (packageName.isNullOrBlank()) return false
        val callerFingerprints = certFingerprints(signingInfo)
        if (callerFingerprints.isEmpty()) return false
        val declared = statementsFor(rpId)[packageName].orEmpty()
        return declared.any { it in callerFingerprints }
    }

    /** SHA-256 fingerprints of the caller's signing certificates, as uppercase colon-separated hex. */
    fun certFingerprints(signingInfo: SigningInfo?): Set<String> {
        val info = signingInfo ?: return emptySet()
        val signatures = if (info.hasMultipleSigners()) info.apkContentsSigners else info.signingCertificateHistory
        return signatures.orEmpty().mapNotNull { signature ->
            runCatching {
                val digest = MessageDigest.getInstance("SHA-256").digest(signature.toByteArray())
                digest.joinToString(":") { "%02X".format(it) }
            }.getOrNull()
        }.toSet()
    }

    private fun statementsFor(rpId: String): Map<String, Set<String>> {
        val now = System.currentTimeMillis()
        cache[rpId]?.let { if (it.expiresAtMs > now) return it.fingerprints }

        val body = runCatching { fetch(rpId) }.getOrNull()
        val parsed = if (body == null) emptyMap() else runCatching { parse(body) }.getOrDefault(emptyMap())
        val ttl = if (parsed.isEmpty()) FAILURE_TTL_MS else SUCCESS_TTL_MS
        cache[rpId] = Cached(parsed, now + ttl)
        return parsed
    }

    private fun fetch(rpId: String): String {
        val url = URI("https://$rpId/.well-known/assetlinks.json").toURL()
        val connection = (url.openConnection() as HttpURLConnection).apply {
            requestMethod = "GET"
            connectTimeout = 10_000
            readTimeout = 10_000
            // A statement must be served by the relying party itself, not by wherever it points.
            instanceFollowRedirects = false
            setRequestProperty("Accept", "application/json")
        }
        try {
            if (connection.responseCode !in 200..299) return ""
            val out = ByteArrayOutputStream()
            connection.inputStream.use { input ->
                val buffer = ByteArray(8192)
                var total = 0L
                while (true) {
                    val read = input.read(buffer)
                    if (read < 0) break
                    total += read
                    if (total > MAX_BYTES) return ""
                    out.write(buffer, 0, read)
                }
            }
            return out.toString(Charsets.UTF_8.name())
        } finally {
            connection.disconnect()
        }
    }

    /** Package name to the certificate fingerprints it is allowed to present, from a statement list. */
    internal fun parse(json: String): Map<String, Set<String>> {
        val statements = JSONArray(json)
        val result = mutableMapOf<String, MutableSet<String>>()
        for (i in 0 until statements.length()) {
            val statement = statements.optJSONObject(i) ?: continue
            val relations = statement.optJSONArray("relation") ?: continue
            val grantsLogin = (0 until relations.length()).any { relations.optString(it) == RELATION }
            if (!grantsLogin) continue

            val target = statement.optJSONObject("target") ?: continue
            if (target.optString("namespace") != NAMESPACE) continue
            val packageName = target.optString("package_name").ifBlank { null } ?: continue
            val fingerprints = target.optJSONArray("sha256_cert_fingerprints") ?: continue

            val bucket = result.getOrPut(packageName) { mutableSetOf() }
            for (f in 0 until fingerprints.length()) {
                val fingerprint = fingerprints.optString(f).trim().uppercase(Locale.ROOT)
                if (fingerprint.isNotBlank()) bucket.add(fingerprint)
            }
        }
        return result
    }
}
