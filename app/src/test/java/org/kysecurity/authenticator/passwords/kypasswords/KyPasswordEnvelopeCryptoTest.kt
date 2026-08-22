package org.kysecurity.authenticator.passwords.kypasswords

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertThrows
import org.junit.Test

class KyPasswordEnvelopeCryptoTest {

    @Test
    fun wrapsAndUnwrapsVaultKey() {
        val vaultKey = ByteArray(32) { (it * 3 + 7).toByte() }
        val masterPassword = "correct-horse-battery-staple"

        val envelopeJson = KyPasswordEnvelopeCrypto.wrapVaultKey(
            vaultKey = vaultKey,
            secret = masterPassword,
            iterations = 10_000,
        )

        assertNotNull(envelopeJson)

        val unwrappedKey = KyPasswordEnvelopeCrypto.unwrapVaultKey(
            envelopeJson = envelopeJson,
            secret = masterPassword,
        )

        assertArrayEquals(vaultKey, unwrappedKey)
    }

    @Test(expected = Exception::class)
    fun failsToUnwrapWithWrongPassword() {
        val vaultKey = ByteArray(32) { it.toByte() }
        val envelopeJson = KyPasswordEnvelopeCrypto.wrapVaultKey(
            vaultKey = vaultKey,
            secret = "password123",
            iterations = 5_000,
        )

        KyPasswordEnvelopeCrypto.unwrapVaultKey(envelopeJson, "wrongpassword")
    }

    @Test
    fun hexConversionRoundtrips() {
        val bytes = byteArrayOf(0x00, 0x01, 0x0f, 0x10, 0x7f, (-1).toByte(), (-128).toByte())
        val hex = KyPasswordEnvelopeCrypto.bytesToHex(bytes)
        val result = KyPasswordEnvelopeCrypto.hexToBytes(hex)
        assertArrayEquals(bytes, result)
    }

    @Test
    fun rejectsAbsurdIterationCount() {
        // A hostile server dictating the KDF cost would pin a core for minutes on every unlock.
        val envelope = org.json.JSONObject()
            .put("salt", "00112233445566778899aabbccddeeff")
            .put("iv", "000102030405060708090a0b")
            .put("ciphertext", "00112233445566778899aabbccddeeff")
            .put("iterations", Int.MAX_VALUE)
            .toString()

        assertThrows(IllegalArgumentException::class.java) {
            KyPasswordEnvelopeCrypto.unwrapVaultKey(envelope, "secret")
        }
    }
}
