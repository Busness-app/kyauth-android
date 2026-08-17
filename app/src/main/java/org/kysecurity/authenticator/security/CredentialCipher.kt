package org.kysecurity.authenticator.security

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyStore
import java.security.SecureRandom
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.Mac
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

private const val PBKDF2_ITERATIONS = 150_000
private const val KEY_LENGTH_BITS = 256
private const val SALT_LENGTH_BYTES = 16
private const val GCM_IV_LENGTH_BYTES = 12
private const val GCM_TAG_LENGTH_BITS = 128
private const val ANDROID_KEYSTORE = "AndroidKeyStore"
private const val PEPPER_KEY_ALIAS = "kyauth_credential_pepper"
private const val PIN_PEPPER_KEY_ALIAS = "kyauth_pin_pepper"

data class WrappedSecret(val iv: ByteArray, val ciphertext: ByteArray) {
    fun serialize(): String =
        Base64.getEncoder().encodeToString(iv) + ":" + Base64.getEncoder().encodeToString(ciphertext)

    companion object {
        fun deserialize(serialized: String): WrappedSecret? {
            val parts = serialized.split(":")
            if (parts.size != 2) return null
            val iv = Base64.getDecoder().decode(parts[0])
            val ciphertext = Base64.getDecoder().decode(parts[1])
            return WrappedSecret(iv, ciphertext)
        }
    }
}

interface CredentialPepper {
    fun mix(derived: ByteArray): ByteArray
}

object KeystoreCredentialPepper : CredentialPepper {
    private var testSecret: SecretKey? = null

    fun setTestSecret(secret: SecretKey?) {
        testSecret = secret
    }

    override fun mix(derived: ByteArray): ByteArray {
        testSecret?.let { return hmac(it, derived) }
        return keystoreHmac(PEPPER_KEY_ALIAS, derived)
    }

    fun ensureExists() {
        if (testSecret == null) {
            createPepperKeyIfAbsent(PEPPER_KEY_ALIAS)
        }
    }
}

object KeystorePinPepper : CredentialPepper {
    private var testSecret: SecretKey? = null

    fun setTestSecret(secret: SecretKey?) {
        testSecret = secret
    }

    override fun mix(derived: ByteArray): ByteArray {
        testSecret?.let { return hmac(it, derived) }
        return keystoreHmac(PIN_PEPPER_KEY_ALIAS, derived)
    }

    fun ensureExists() {
        if (testSecret == null) {
            createPepperKeyIfAbsent(PIN_PEPPER_KEY_ALIAS)
        }
    }
}

object CredentialCipher {
    fun generateRandomSalt(): ByteArray {
        val salt = ByteArray(SALT_LENGTH_BYTES)
        SecureRandom().nextBytes(salt)
        return salt
    }

    fun generateVaultKey(): ByteArray {
        val key = ByteArray(32)
        SecureRandom().nextBytes(key)
        return key
    }

    fun deriveKey(pin: String, salt: ByteArray, pepper: CredentialPepper = KeystoreCredentialPepper): SecretKeySpec {
        val spec = PBEKeySpec(pin.toCharArray(), salt, PBKDF2_ITERATIONS, KEY_LENGTH_BITS)
        val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        val derived = factory.generateSecret(spec).encoded
        val peppered = pepper.mix(derived)
        return SecretKeySpec(peppered, "AES")
    }

    fun deriveBiometricKey(salt: ByteArray, pepper: CredentialPepper = KeystoreCredentialPepper): SecretKeySpec =
        SecretKeySpec(pepper.mix(salt), "AES")

    fun hashPinForStorage(pin: String, salt: ByteArray, pepper: CredentialPepper = KeystorePinPepper): String {
        val spec = PBEKeySpec(pin.toCharArray(), salt, PBKDF2_ITERATIONS, KEY_LENGTH_BITS)
        val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        val derived = factory.generateSecret(spec).encoded
        val peppered = pepper.mix(derived)
        return Base64.getEncoder().encodeToString(peppered)
    }

    fun wrap(secret: ByteArray, key: SecretKeySpec, aad: ByteArray = "kyauth_aad".toByteArray(Charsets.UTF_8)): WrappedSecret {
        val iv = ByteArray(GCM_IV_LENGTH_BYTES).apply { SecureRandom().nextBytes(this) }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding").apply {
            init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv))
            updateAAD(aad)
        }
        val ciphertext = cipher.doFinal(secret)
        return WrappedSecret(iv, ciphertext)
    }

    fun unwrap(wrapped: WrappedSecret, key: SecretKeySpec, aad: ByteArray = "kyauth_aad".toByteArray(Charsets.UTF_8)): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding").apply {
            init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_LENGTH_BITS, wrapped.iv))
            updateAAD(aad)
        }
        return cipher.doFinal(wrapped.ciphertext)
    }
}

private fun hmac(key: SecretKey, data: ByteArray): ByteArray {
    val mac = Mac.getInstance("HmacSHA256")
    mac.init(key)
    return mac.doFinal(data)
}

private fun keystoreHmac(alias: String, data: ByteArray): ByteArray {
    val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
    val secretKey = keyStore.getKey(alias, null) as? SecretKey
        ?: throw IllegalStateException("Keystore pepper key '$alias' not found")
    return hmac(secretKey, data)
}

private fun createPepperKeyIfAbsent(alias: String) {
    runCatching {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        if (!keyStore.containsAlias(alias)) {
            val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_HMAC_SHA256, ANDROID_KEYSTORE)
            keyGenerator.init(
                KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                    .build(),
            )
            keyGenerator.generateKey()
        }
    }
}
