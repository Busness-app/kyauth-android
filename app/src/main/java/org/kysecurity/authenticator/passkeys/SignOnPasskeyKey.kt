package org.kysecurity.authenticator.passkeys

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec

/**
 * The KySignOn login passkey's private key: generated in, and never leaving, the device's secure
 * hardware. StrongBox where the device has a discrete secure element, the TEE otherwise.
 *
 * There is deliberately no software fallback. A software-backed key would be exportable, which is
 * the property this whole design exists to remove, so generation fails closed instead.
 *
 * Two alternating aliases exist because enrolment must be atomic: generating over the live alias
 * would destroy a working passkey if the user then cancelled the prompt, stranding the credential
 * the server has already registered. A new key goes into the spare and the caller flips the
 * pointer only once the response is built.
 */
object SignOnPasskeyKey {

    const val ALIAS_A = "kyauth_signon_passkey_a"
    const val ALIAS_B = "kyauth_signon_passkey_b"

    private const val ANDROID_KEYSTORE = "AndroidKeyStore"

    /** Raised when the device cannot hold the key in hardware. Enrolment must not proceed. */
    class NoHardwareKeystore :
        IllegalStateException("KyAuth needs hardware-backed key storage for a KySignOn passkey.")

    class Generated(val publicKey: ECPublicKey, val alias: String, val strongBoxBacked: Boolean)

    /** The alias not currently in use, so generating never overwrites a live key. */
    fun spareAlias(liveAlias: String?): String = if (liveAlias == ALIAS_A) ALIAS_B else ALIAS_A

    /**
     * Generates a fresh P-256 key at [alias], replacing anything already there. Tries StrongBox
     * first and falls back to the TEE, then verifies the result really is hardware-backed.
     */
    fun generate(alias: String): Generated {
        delete(alias)
        val strongBox = runCatching { generateKey(alias, strongBox = true) }
            .fold(onSuccess = { true }, onFailure = {
                // Any failure of the StrongBox attempt falls back to the TEE, not only
                // StrongBoxUnavailableException: setUnlockedDeviceRequired plus StrongBox throws
                // assorted ProviderExceptions on real devices whose TEE is perfectly capable, and
                // no emulator can reproduce that. The fail-closed guarantee comes from the
                // isHardwareBacked() check below, not from the exception type, so widening here
                // cannot admit a software key.
                generateKey(alias, strongBox = false)
                false
            })

        val publicKey = keyStore().getCertificate(alias)?.publicKey as? ECPublicKey
        // Every failure exit deletes the alias: a rejected key must not outlive the call that
        // rejected it.
        if (publicKey == null || !isHardwareBacked(alias)) {
            delete(alias)
            throw NoHardwareKeystore()
        }
        return Generated(publicKey, alias, strongBox)
    }

    /**
     * A [Signature] for `BiometricPrompt.CryptoObject`. The key requires per-use authentication, so
     * signing fails until the prompt succeeds. Null when no key exists at [alias].
     */
    fun signatureFor(alias: String): Signature? = runCatching {
        val privateKey = keyStore().getKey(alias, null) as? PrivateKey ?: return null
        Signature.getInstance("SHA256withECDSA").apply { initSign(privateKey) }
    }.getOrNull()

    fun delete(alias: String) {
        runCatching { keyStore().takeIf { it.containsAlias(alias) }?.deleteEntry(alias) }
    }

    fun deleteAll() {
        delete(ALIAS_A)
        delete(ALIAS_B)
    }

    private fun generateKey(alias: String, strongBox: Boolean) {
        KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE).apply {
            initialize(
                KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                    .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setUserAuthenticationRequired(true)
                    .setUserAuthenticationParameters(
                        0,
                        KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL,
                    )
                    .setUnlockedDeviceRequired(true)
                    .setIsStrongBoxBacked(strongBox)
                    .build(),
            )
        }.generateKeyPair()
    }

    /**
     * Asks the platform what actually backs the key rather than trusting the request.
     *
     * True only for the three levels that assert secure hardware. `SECURITY_LEVEL_UNKNOWN` means
     * the platform could not determine the level at all, and "I don't know" must not pass the one
     * check standing between a KySignOn login passkey and a key that could be exportable.
     * `SECURITY_LEVEL_UNKNOWN_SECURE` is accepted: it asserts secure hardware of an unspecified
     * kind, which is what some pre-KeyMint devices report, and refusing it would fail enrolment on
     * hardware that is genuinely fine.
     */
    private fun isHardwareBacked(alias: String): Boolean = runCatching {
        val privateKey = keyStore().getKey(alias, null) as PrivateKey
        val info = KeyFactory.getInstance(privateKey.algorithm, ANDROID_KEYSTORE)
            .getKeySpec(privateKey, KeyInfo::class.java)
        info.securityLevel == KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT ||
            info.securityLevel == KeyProperties.SECURITY_LEVEL_STRONGBOX ||
            info.securityLevel == KeyProperties.SECURITY_LEVEL_UNKNOWN_SECURE
    }.getOrDefault(false)

    private fun keyStore(): KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
}
