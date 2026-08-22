package org.kysecurity.authenticator.passwords.kypasswords

import org.json.JSONObject
import org.kysecurity.authenticator.pairing.PairingEndpoint
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.net.HttpURLConnection
import java.net.URI

open class KyPasswordException(message: String, cause: Throwable? = null) : Exception(message, cause)
class KyPasswordAuthException(message: String) : KyPasswordException(message)
class KyPasswordNotFoundException(message: String) : KyPasswordException(message)
class KyPasswordConflictException(
    val currentVersion: Long,
    val expectedVersion: Long,
    val conflictId: String?,
    message: String,
) : KyPasswordException(message)

data class KyPasswordSession(
    val deviceId: String,
    val sessionToken: String,
    val userId: String,
)

data class KyPasswordMetadata(
    val userId: String,
    val version: Long,
    val checksum: String? = null,
    val passwordEnvelope: String? = null,
    val recoveryEnvelope: String? = null,
)

/**
 * A paired server is not trusted to be well behaved: every response it sends is read through a
 * ceiling so a hostile or broken server cannot exhaust the device's heap or storage.
 */
private const val MAX_JSON_BYTES = 1L * 1024 * 1024
private const val MAX_VAULT_BYTES = 25L * 1024 * 1024

/** Reads at most [max] bytes, failing rather than truncating so a clipped vault is never stored. */
private fun InputStream.copyCapped(out: OutputStream, max: Long): Long {
    val buffer = ByteArray(8192)
    var total = 0L
    while (true) {
        val read = read(buffer)
        if (read < 0) break
        total += read
        if (total > max) throw KyPasswordException("Server response exceeds $max bytes")
        out.write(buffer, 0, read)
    }
    return total
}

private fun InputStream?.readCapped(max: Long): String {
    if (this == null) return ""
    val out = ByteArrayOutputStream()
    copyCapped(out, max)
    return out.toString(Charsets.UTF_8.name())
}

class KyPasswordClient {
    fun redeemPairing(
        serverUrl: String,
        codeOrPin: String,
        deviceName: String,
        platform: String = "android",
    ): KyPasswordSession {
        require(serverUrl.isNotBlank()) { "Server URL is required" }
        require(codeOrPin.isNotBlank()) { "Pairing code or PIN is required" }
        require(deviceName.isNotBlank()) { "Device name is required" }

        val validatedUrl = PairingEndpoint.validateServerUrl(serverUrl).trimEnd('/')
        val endpoint = URI("$validatedUrl/api/devices/pairing/redeem")

        val payload = JSONObject().apply {
            put("codeOrPin", codeOrPin.trim())
            put("deviceName", deviceName.trim())
            put("platform", platform)
        }.toString()

        val connection = (endpoint.toURL().openConnection() as HttpURLConnection).apply {
            requestMethod = "POST"
            connectTimeout = 10_000
            readTimeout = 10_000
            doOutput = true
            instanceFollowRedirects = false
            setRequestProperty("Content-Type", "application/json")
            setRequestProperty("Accept", "application/json")
        }

        try {
            connection.outputStream.bufferedWriter(Charsets.UTF_8).use { it.write(payload) }
            val body = (if (connection.responseCode in 200..299) connection.inputStream else connection.errorStream)
                .readCapped(MAX_JSON_BYTES)
            val response = runCatching { JSONObject(body) }.getOrElse { JSONObject() }

            if (connection.responseCode == 401) {
                throw KyPasswordAuthException("Pairing failed (401): code or PIN is invalid or has expired")
            }
            if (connection.responseCode !in 200..299 || !response.optBoolean("ok", false)) {
                val errorMsg = response.optString("error", "Pairing failed (${connection.responseCode}): $body")
                throw KyPasswordException(errorMsg)
            }

            val deviceId = response.getString("deviceId")
            val sessionToken = response.getString("sessionToken")
            val userObj = response.optJSONObject("user")
            val userId = userObj?.optString("id") ?: ""

            return KyPasswordSession(
                deviceId = deviceId,
                sessionToken = sessionToken,
                userId = userId,
            )
        } finally {
            connection.disconnect()
        }
    }

    fun fetchMetadata(serverUrl: String, sessionToken: String): KyPasswordMetadata {
        val validatedUrl = PairingEndpoint.validateServerUrl(serverUrl).trimEnd('/')
        val endpoint = URI("$validatedUrl/api/vault/metadata")

        val connection = (endpoint.toURL().openConnection() as HttpURLConnection).apply {
            requestMethod = "GET"
            connectTimeout = 10_000
            readTimeout = 10_000
            instanceFollowRedirects = false
            setRequestProperty("Authorization", "Bearer $sessionToken")
            setRequestProperty("Accept", "application/json")
        }

        try {
            val body = (if (connection.responseCode in 200..299) connection.inputStream else connection.errorStream)
                .readCapped(MAX_JSON_BYTES)

            if (connection.responseCode == 401) {
                throw KyPasswordAuthException("Unauthorized (401): KyPasswords session token is expired or device was revoked")
            }
            if (connection.responseCode == 404) {
                throw KyPasswordNotFoundException("Vault not found on server (404)")
            }
            if (connection.responseCode !in 200..299) {
                throw KyPasswordException("Failed to fetch vault metadata (${connection.responseCode}): $body")
            }

            val json = JSONObject(body)
            return KyPasswordMetadata(
                userId = json.optString("userId"),
                version = json.optLong("version", 0L),
                checksum = json.optString("checksum").ifBlank { null },
                passwordEnvelope = json.optString("passwordEnvelope").ifBlank { null },
                recoveryEnvelope = json.optString("recoveryEnvelope").ifBlank { null },
            )
        } finally {
            connection.disconnect()
        }
    }

    fun downloadVault(serverUrl: String, sessionToken: String, targetFile: File): Long {
        val validatedUrl = PairingEndpoint.validateServerUrl(serverUrl).trimEnd('/')
        val endpoint = URI("$validatedUrl/api/vault/kdbx")

        val connection = (endpoint.toURL().openConnection() as HttpURLConnection).apply {
            requestMethod = "GET"
            connectTimeout = 15_000
            readTimeout = 15_000
            instanceFollowRedirects = false
            setRequestProperty("Authorization", "Bearer $sessionToken")
        }

        try {
            if (connection.responseCode == 401) {
                throw KyPasswordAuthException("Unauthorized (401): KyPasswords session expired or device revoked")
            }
            if (connection.responseCode == 404) {
                throw KyPasswordNotFoundException("Vault file does not exist on server (404)")
            }
            if (connection.responseCode !in 200..299) {
                val error = connection.errorStream.readCapped(MAX_JSON_BYTES)
                throw KyPasswordException("Failed to download vault (${connection.responseCode}): $error")
            }

            val versionHeader = connection.getHeaderField("X-Vault-Version")
                ?: connection.getHeaderField("ETag")?.trim('"', ' ')
            val version = versionHeader?.toLongOrNull() ?: 1L

            val tempFile = File(targetFile.parentFile, ".${targetFile.name}.download")
            tempFile.parentFile?.mkdirs()
            try {
                connection.inputStream.use { input ->
                    FileOutputStream(tempFile).use { output ->
                        input.copyCapped(output, MAX_VAULT_BYTES)
                    }
                }
            } catch (e: Exception) {
                tempFile.delete()
                throw e
            }

            if (!tempFile.renameTo(targetFile)) {
                targetFile.delete()
                if (!tempFile.renameTo(targetFile)) {
                    tempFile.copyTo(targetFile, overwrite = true)
                    tempFile.delete()
                }
            }

            return version
        } finally {
            connection.disconnect()
        }
    }

    fun uploadVault(
        serverUrl: String,
        sessionToken: String,
        vaultFile: File,
        expectedVersion: Long,
        deviceId: String? = null,
    ): Long {
        require(vaultFile.exists() && vaultFile.length() > 0) {
            "Cannot upload empty or nonexistent vault file (${vaultFile.name})"
        }

        val validatedUrl = PairingEndpoint.validateServerUrl(serverUrl).trimEnd('/')
        val endpoint = URI("$validatedUrl/api/vault/upload")

        val connection = (endpoint.toURL().openConnection() as HttpURLConnection).apply {
            requestMethod = "POST"
            connectTimeout = 15_000
            readTimeout = 15_000
            doOutput = true
            instanceFollowRedirects = false
            setRequestProperty("Authorization", "Bearer $sessionToken")
            setRequestProperty("Content-Type", "application/octet-stream")
            setRequestProperty("If-Match", "\"$expectedVersion\"")
            if (!deviceId.isNullOrBlank()) {
                setRequestProperty("X-Device-ID", deviceId)
            }
        }

        try {
            connection.outputStream.use { output ->
                vaultFile.inputStream().use { input ->
                    input.copyTo(output)
                }
            }

            val body = (if (connection.responseCode in 200..299) connection.inputStream else connection.errorStream)
                .readCapped(MAX_JSON_BYTES)

            if (connection.responseCode == 401) {
                throw KyPasswordAuthException("Unauthorized (401): KyPasswords session expired or device revoked")
            }
            if (connection.responseCode == 409) {
                val json = runCatching { JSONObject(body) }.getOrElse { JSONObject() }
                val curVer = json.optLong("currentVersion", expectedVersion + 1)
                val conflictId = json.optString("conflictId").ifBlank { null }
                throw KyPasswordConflictException(
                    currentVersion = curVer,
                    expectedVersion = expectedVersion,
                    conflictId = conflictId,
                    message = "Conflict (409): Server has newer vault version ($curVer vs local $expectedVersion)",
                )
            }
            if (connection.responseCode !in 200..299) {
                throw KyPasswordException("Failed to upload vault (${connection.responseCode}): $body")
            }

            val json = JSONObject(body)
            val meta = json.optJSONObject("metadata")
            return meta?.optLong("version", expectedVersion + 1) ?: (expectedVersion + 1)
        } finally {
            connection.disconnect()
        }
    }
}
