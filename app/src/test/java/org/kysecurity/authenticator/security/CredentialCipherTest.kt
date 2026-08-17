package org.kysecurity.authenticator.security

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Before
import org.junit.Test
import javax.crypto.spec.SecretKeySpec

class CredentialCipherTest {
    private val testPepper = object : CredentialPepper {
        override fun mix(derived: ByteArray): ByteArray = derived.reversedArray()
    }

    @Before
    fun setup() {
        KeystoreCredentialPepper.setTestSecret(SecretKeySpec(ByteArray(32) { 1 }, "HmacSHA256"))
        KeystorePinPepper.setTestSecret(SecretKeySpec(ByteArray(32) { 2 }, "HmacSHA256"))
    }

    @Test
    fun derivesKeyAndWrapsUnwrapsVaultKey() {
        val pin = "849204"
        val salt = CredentialCipher.generateRandomSalt()
        val derivedKey = CredentialCipher.deriveKey(pin, salt, testPepper)

        val vaultKey = CredentialCipher.generateVaultKey()
        assertEquals(32, vaultKey.size)

        val wrapped = CredentialCipher.wrap(vaultKey, derivedKey)
        val serialized = wrapped.serialize()
        val deserialized = WrappedSecret.deserialize(serialized)
        assertNotNull(deserialized)

        val unwrapped = CredentialCipher.unwrap(deserialized!!, derivedKey)
        assertArrayEquals(vaultKey, unwrapped)
    }

    @Test
    fun generatesDeterministicPinHashForSameInputs() {
        val pin = "987654"
        val salt = CredentialCipher.generateRandomSalt()
        val hash1 = CredentialCipher.hashPinForStorage(pin, salt, testPepper)
        val hash2 = CredentialCipher.hashPinForStorage(pin, salt, testPepper)
        assertEquals(hash1, hash2)
    }

    @Test
    fun biometricDerivedKeyRecoversWrappedVaultKey() {
        val salt = CredentialCipher.generateRandomSalt()
        val vaultKey = CredentialCipher.generateVaultKey()
        val wrapped = CredentialCipher.wrap(vaultKey, CredentialCipher.deriveBiometricKey(salt, testPepper))

        assertArrayEquals(vaultKey, CredentialCipher.unwrap(wrapped, CredentialCipher.deriveBiometricKey(salt, testPepper)))
    }
}
