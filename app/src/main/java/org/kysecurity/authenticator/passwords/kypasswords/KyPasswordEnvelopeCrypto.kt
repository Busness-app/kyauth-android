package org.kysecurity.authenticator.passwords.kypasswords

import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.params.Argon2Parameters
import org.json.JSONObject
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Implements Argon2id key wrapping with AES-GCM, compatible with KyPasswords Server.
 *
 * `kdf` must say `argon2id`; anything else, including its absence, is an envelope this app cannot
 * identify and refuses rather than guesses at. Every cost parameter is read from the envelope
 * rather than assumed, because a server may legitimately have written different ones.
 */
object KyPasswordEnvelopeCrypto {
    private const val KDF_ARGON2ID = "argon2id"

    /** OWASP baseline, matching what the KyPasswords web client writes. */
    private const val ARGON2ID_MEMORY_KIB = 65_536
    private const val ARGON2ID_ITERATIONS = 3
    private const val ARGON2ID_PARALLELISM = 1

    /**
     * Argon2id costs arrive from the server and are an allocation size and a CPU budget. They are
     * checked before anything is allocated: an envelope claiming 4 GiB is an out-of-memory kill on
     * a phone, not a slow unlock. Out-of-range values are rejected rather than clamped — a clamped
     * parameter derives the wrong key and surfaces as a GCM tag failure, which reads like a wrong
     * password.
     */
    private const val MAX_MEMORY_KIB = 256 * 1024
    private const val MAX_ARGON2_ITERATIONS = 16
    private const val MAX_PARALLELISM = 4

    private const val KEY_LENGTH_BITS = 256
    private const val GCM_TAG_LENGTH_BITS = 128

    fun unwrapVaultKey(envelopeJson: String, secret: String): ByteArray {
        val json = JSONObject(envelopeJson)
        val salt = hexToBytes(json.getString("salt"))
        val iv = hexToBytes(json.getString("iv"))
        val ciphertext = hexToBytes(json.getString("ciphertext"))

        // An envelope we cannot identify is one we refuse, not one we guess at.
        require(json.optString("kdf") == KDF_ARGON2ID) { "Unsupported envelope KDF: ${json.optString("kdf")}" }
        val derivedKey = deriveArgon2id(secret, salt, json)

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(derivedKey, "AES"), GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv))
        return cipher.doFinal(ciphertext)
    }

    private fun deriveArgon2id(secret: String, salt: ByteArray, json: JSONObject): ByteArray {
        val memoryKiB = requiredCost(json, "memoryKiB", 8..MAX_MEMORY_KIB)
        val iterations = requiredCost(json, "iterations", 1..MAX_ARGON2_ITERATIONS)
        val parallelism = requiredCost(json, "parallelism", 1..MAX_PARALLELISM)
        require(memoryKiB >= 8 * parallelism) { "Argon2id memoryKiB is too small for parallelism" }

        return argon2id(secret, salt, memoryKiB, iterations, parallelism)
    }

    private fun argon2id(
        secret: String,
        salt: ByteArray,
        memoryKiB: Int,
        iterations: Int,
        parallelism: Int,
    ): ByteArray {
        val parameters = Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
            .withVersion(Argon2Parameters.ARGON2_VERSION_13)
            .withSalt(salt)
            .withMemoryAsKB(memoryKiB)
            .withIterations(iterations)
            .withParallelism(parallelism)
            .build()

        val generator = Argon2BytesGenerator().apply { init(parameters) }
        val derivedKey = ByteArray(KEY_LENGTH_BITS / 8)
        // The byte[] overload, not the char[] one: the encoding of the password is part of the
        // wire format, and the web client hashes UTF-8.
        generator.generateBytes(secret.toByteArray(Charsets.UTF_8), derivedKey)
        return derivedKey
    }

    /** Argon2id costs are never defaulted: one we cannot reproduce exactly is one we cannot open. */
    private fun requiredCost(json: JSONObject, name: String, allowed: IntRange): Int {
        require(json.has(name)) { "Argon2id envelope is missing $name" }
        val value = json.optInt(name, Int.MIN_VALUE)
        require(value in allowed) { "Argon2id envelope $name is out of range" }
        return value
    }

    fun wrapVaultKey(vaultKey: ByteArray, secret: String): String {
        val salt = ByteArray(16).apply { SecureRandom().nextBytes(this) }
        val iv = ByteArray(12).apply { SecureRandom().nextBytes(this) }

        val derivedKey = argon2id(secret, salt, ARGON2ID_MEMORY_KIB, ARGON2ID_ITERATIONS, ARGON2ID_PARALLELISM)

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(derivedKey, "AES"), GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv))
        val ciphertext = cipher.doFinal(vaultKey)

        return JSONObject().apply {
            put("kdf", KDF_ARGON2ID)
            put("salt", bytesToHex(salt))
            put("iv", bytesToHex(iv))
            put("ciphertext", bytesToHex(ciphertext))
            put("memoryKiB", ARGON2ID_MEMORY_KIB)
            put("iterations", ARGON2ID_ITERATIONS)
            put("parallelism", ARGON2ID_PARALLELISM)
        }.toString()
    }

    fun bytesToHex(bytes: ByteArray): String =
        bytes.joinToString("") { "%02x".format(it) }

    fun hexToBytes(hex: String): ByteArray {
        val clean = hex.trim()
        val len = clean.length
        require(len % 2 == 0) { "Hex string must have an even length" }
        val data = ByteArray(len / 2)
        var i = 0
        while (i < len) {
            val high = Character.digit(clean[i], 16)
            val low = Character.digit(clean[i + 1], 16)
            require(high != -1 && low != -1) { "Invalid hex character at $i" }
            data[i / 2] = ((high shl 4) + low).toByte()
            i += 2
        }
        return data
    }
}
