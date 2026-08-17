package org.kysecurity.authenticator.pairing

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.Base64

object DeviceSigningKey {
    private const val ANDROID_KEY_STORE = "AndroidKeyStore"
    private const val ALIAS = "kysignon-device-signing-v1"

    @Volatile
    private var testKeyPair: KeyPair? = null

    fun setTestKeyPair(keyPair: KeyPair?) {
        testKeyPair = keyPair
    }

    fun publicKeyBase64(): String {
        testKeyPair?.let {
            return Base64.getEncoder().encodeToString(it.public.encoded)
        }
        val keyStore = KeyStore.getInstance(ANDROID_KEY_STORE).apply { load(null) }
        val publicKey = keyStore.getCertificate(ALIAS)?.publicKey ?: generate().public
        return Base64.getEncoder().encodeToString(publicKey.encoded)
    }

    fun initSignature(): Signature {
        val signature = Signature.getInstance("SHA256withECDSA")
        testKeyPair?.let {
            signature.initSign(it.private)
            return signature
        }
        val keyStore = KeyStore.getInstance(ANDROID_KEY_STORE).apply { load(null) }
        val privateKey = keyStore.getKey(ALIAS, null) as? PrivateKey
            ?: generate().private
        signature.initSign(privateKey)
        return signature
    }

    fun sign(message: ByteArray, signatureObj: Signature? = null): String {
        val sig = signatureObj ?: initSignature()
        sig.update(message)
        val signatureBytes = sig.sign()
        return Base64.getEncoder().encodeToString(signatureBytes)
    }

    fun deleteKey() {
        testKeyPair = null
        runCatching {
            val keyStore = KeyStore.getInstance(ANDROID_KEY_STORE).apply { load(null) }
            if (keyStore.containsAlias(ALIAS)) {
                keyStore.deleteEntry(ALIAS)
            }
        }
    }

    private fun generate(): KeyPair = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEY_STORE).apply {
        initialize(
            KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY)
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setUserAuthenticationRequired(true)
                .setUserAuthenticationParameters(0, authenticationTypes())
                .build(),
        )
    }.generateKeyPair()

    private fun authenticationTypes(): Int =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL
        } else {
            KeyProperties.AUTH_BIOMETRIC_STRONG
        }
}
