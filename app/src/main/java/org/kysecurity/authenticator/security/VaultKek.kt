package org.kysecurity.authenticator.security

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.spec.MGF1ParameterSpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource

/**
 * Authentication-bound key-encryption key for the vault keys.
 *
 * RSA-OAEP is used so that wrapping needs no prompt (public-key operation) while unwrapping
 * requires a fresh biometric or device-credential authentication carried by a
 * `BiometricPrompt.CryptoObject`. There is deliberately no "decrypt whenever asked" entry point:
 * [unwrap] only accepts a cipher the framework has already authenticated.
 */
object VaultKek {
    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    private const val ALIAS = "kyauth_vault_kek"
    private const val TRANSFORMATION = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding"

    /** Raised when the device has no secure lock screen, so no key can be authentication-bound. */
    class NoSecureLockScreen(cause: Throwable?) :
        IllegalStateException("KyAuth needs a device screen lock to protect the vault key.", cause)

    fun hasWrappingKey(): Boolean = runCatching { keyStore().containsAlias(ALIAS) }.getOrDefault(false)

    /** Wraps [plaintext] (at most 190 bytes). Never prompts: this is a public-key operation. */
    fun wrap(plaintext: ByteArray): ByteArray {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, softwarePublicKey(), oaepSpec())
        return cipher.doFinal(plaintext)
    }

    /**
     * Returns a cipher for `BiometricPrompt.CryptoObject`. The key is bound to per-use
     * authentication, so [unwrap] fails until the prompt succeeds, and the cipher is
     * single-use: one authentication unwraps one blob.
     */
    fun unwrapCipher(): Cipher = Cipher.getInstance(TRANSFORMATION).apply {
        init(Cipher.DECRYPT_MODE, entryOrCreate().privateKey, oaepSpec())
    }

    fun unwrap(authenticatedCipher: Cipher, ciphertext: ByteArray): ByteArray =
        authenticatedCipher.doFinal(ciphertext)

    fun delete() {
        runCatching { keyStore().deleteEntry(ALIAS) }
    }

    private fun keyStore(): KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    private fun entryOrCreate(): KeyStore.PrivateKeyEntry =
        keyStore().getEntry(ALIAS, null) as? KeyStore.PrivateKeyEntry ?: create()

    private fun create(): KeyStore.PrivateKeyEntry {
        try {
            KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, ANDROID_KEYSTORE).apply {
                initialize(
                    KeyGenParameterSpec.Builder(
                        ALIAS,
                        KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
                    )
                        .setKeySize(2048)
                        .setDigests(KeyProperties.DIGEST_SHA256)
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
                        .setUserAuthenticationRequired(true)
                        .setUserAuthenticationParameters(
                            0,
                            KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL,
                        )
                        // Enrolling a new fingerprint must not destroy the vault, and device
                        // credential is an accepted factor here anyway, so invalidation would
                        // cost data without closing an attack path.
                        .setInvalidatedByBiometricEnrollment(false)
                        .build(),
                )
            }.generateKeyPair()
        } catch (e: Exception) {
            throw NoSecureLockScreen(e)
        }
        return keyStore().getEntry(ALIAS, null) as? KeyStore.PrivateKeyEntry ?: throw NoSecureLockScreen(null)
    }

    /**
     * Re-imports the public key through the default provider. A Keystore-backed public key would
     * route encryption through AndroidKeyStore, which would demand authentication for wrapping too.
     */
    private fun softwarePublicKey() = entryOrCreate().certificate.publicKey.let {
        KeyFactory.getInstance(it.algorithm).generatePublic(X509EncodedKeySpec(it.encoded))
    }

    /** AndroidKeyStore always uses MGF1-SHA1, whatever digest the transformation names. */
    private fun oaepSpec() =
        OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT)
}
