package org.kysecurity.authenticator.passwords.kypasswords

import org.json.JSONObject
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

/**
 * Implements PBKDF2-HMAC-SHA256 and AES-GCM envelope crypto compatible with KyPasswords Server.
 */
object KyPasswordEnvelopeCrypto {
    private const val DEFAULT_ITERATIONS = 600_000
    private const val KEY_LENGTH_BITS = 256
    private const val GCM_TAG_LENGTH_BITS = 128

    fun unwrapVaultKey(envelopeJson: String, secret: String): ByteArray {
        val json = JSONObject(envelopeJson)
        val saltHex = json.getString("salt")
        val ivHex = json.getString("iv")
        val ciphertextHex = json.getString("ciphertext")
        val iterations = if (json.has("iterations")) json.getInt("iterations") else DEFAULT_ITERATIONS

        val salt = hexToBytes(saltHex)
        val iv = hexToBytes(ivHex)
        val ciphertext = hexToBytes(ciphertextHex)

        val spec = PBEKeySpec(secret.toCharArray(), salt, iterations, KEY_LENGTH_BITS)
        val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        val derivedKey = factory.generateSecret(spec).encoded
        val keySpec = SecretKeySpec(derivedKey, "AES")

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, keySpec, GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv))
        return cipher.doFinal(ciphertext)
    }

    fun wrapVaultKey(vaultKey: ByteArray, secret: String, iterations: Int = DEFAULT_ITERATIONS): String {
        val salt = ByteArray(16).apply { SecureRandom().nextBytes(this) }
        val iv = ByteArray(12).apply { SecureRandom().nextBytes(this) }

        val spec = PBEKeySpec(secret.toCharArray(), salt, iterations, KEY_LENGTH_BITS)
        val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        val derivedKey = factory.generateSecret(spec).encoded
        val keySpec = SecretKeySpec(derivedKey, "AES")

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv))
        val ciphertext = cipher.doFinal(vaultKey)

        return JSONObject().apply {
            put("salt", bytesToHex(salt))
            put("iv", bytesToHex(iv))
            put("ciphertext", bytesToHex(ciphertext))
            put("iterations", iterations)
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
