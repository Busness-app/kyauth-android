package org.kysecurity.authenticator.passwords.kypasswords

import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.params.Argon2Parameters
import org.json.JSONObject
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

/**
 * Implements Argon2id and PBKDF2-HMAC-SHA256 key wrapping with AES-GCM, compatible with
 * KyPasswords Server.
 *
 * The envelope's `kdf` field selects the derivation. **Its absence is the definition of
 * PBKDF2-HMAC-SHA256** — that is how existing envelopes are marked, so it is never inferred from
 * the other fields. Every Argon2id cost parameter is read from the envelope rather than assumed,
 * because a server may legitimately have written different ones.
 */
object KyPasswordEnvelopeCrypto {
    private const val KDF_ARGON2ID = "argon2id"

    private const val DEFAULT_ITERATIONS = 600_000

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

    /**
     * A paired server supplies the iteration count, so it also decides how much work unwrapping
     * costs. Without a ceiling a hostile server pins a core for minutes on every unlock. There is
     * deliberately no floor: a low count only produces a wrong key (the GCM tag then fails), and
     * rejecting it would lock users out of envelopes a server legitimately wrote with fewer
     * rounds.
     */
    private const val MAX_ITERATIONS = 5_000_000
    private const val KEY_LENGTH_BITS = 256
    private const val GCM_TAG_LENGTH_BITS = 128

    fun unwrapVaultKey(envelopeJson: String, secret: String): ByteArray {
        val json = JSONObject(envelopeJson)
        val salt = hexToBytes(json.getString("salt"))
        val iv = hexToBytes(json.getString("iv"))
        val ciphertext = hexToBytes(json.getString("ciphertext"))

        val derivedKey = when {
            !json.has("kdf") -> derivePbkdf2(secret, salt, envelopeIterations(json))
            json.getString("kdf") == KDF_ARGON2ID -> deriveArgon2id(secret, salt, json)
            // Falling through to PBKDF2 would derive a wrong key from an envelope we do not
            // understand, instead of saying we cannot open it.
            else -> throw IllegalArgumentException("Unsupported envelope KDF: ${json.getString("kdf")}")
        }

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(derivedKey, "AES"), GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv))
        return cipher.doFinal(ciphertext)
    }

    private fun envelopeIterations(json: JSONObject): Int {
        val iterations = if (json.has("iterations")) json.getInt("iterations") else DEFAULT_ITERATIONS
        require(iterations in 1..MAX_ITERATIONS) { "Envelope iteration count is out of range" }
        return iterations
    }

    private fun derivePbkdf2(secret: String, salt: ByteArray, iterations: Int): ByteArray {
        val spec = PBEKeySpec(secret.toCharArray(), salt, iterations, KEY_LENGTH_BITS)
        return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).encoded
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

    /** Writes the Argon2id shape. Envelopes KyAuth wrote earlier stay readable; see [unwrapVaultKey]. */
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
