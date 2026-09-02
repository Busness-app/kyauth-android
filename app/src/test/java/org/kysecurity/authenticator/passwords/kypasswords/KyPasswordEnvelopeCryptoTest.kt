package org.kysecurity.authenticator.passwords.kypasswords

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertThrows
import org.junit.Test

class KyPasswordEnvelopeCryptoTest {

    @Test
    fun wrapsAndUnwrapsVaultKey() {
        // Unwrapping reads the costs back out of the JSON rather than reusing the constants
        // wrapping derived with, so an envelope declaring a cost it did not use fails here.
        val vaultKey = ByteArray(32) { (it * 3 + 7).toByte() }
        val masterPassword = "correct-horse-battery-staple"

        val envelopeJson = KyPasswordEnvelopeCrypto.wrapVaultKey(
            vaultKey = vaultKey,
            secret = masterPassword,
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
        )

        KyPasswordEnvelopeCrypto.unwrapVaultKey(envelopeJson, "wrongpassword")
    }

    @Test
    fun wrapVaultKeyWritesArgon2idEnvelope() {
        val envelope = org.json.JSONObject(
            KyPasswordEnvelopeCrypto.wrapVaultKey(ByteArray(32) { it.toByte() }, "a-master-password"),
        )

        // The shape KyPasswords reads, at the OWASP baseline costs its web client writes.
        assertEquals("argon2id", envelope.getString("kdf"))
        assertEquals(65536, envelope.getInt("memoryKiB"))
        assertEquals(3, envelope.getInt("iterations"))
        assertEquals(1, envelope.getInt("parallelism"))
        assertEquals(16, KyPasswordEnvelopeCrypto.hexToBytes(envelope.getString("salt")).size)
        assertEquals(12, KyPasswordEnvelopeCrypto.hexToBytes(envelope.getString("iv")).size)
    }

    @Test
    fun hexConversionRoundtrips() {
        val bytes = byteArrayOf(0x00, 0x01, 0x0f, 0x10, 0x7f, (-1).toByte(), (-128).toByte())
        val hex = KyPasswordEnvelopeCrypto.bytesToHex(bytes)
        val result = KyPasswordEnvelopeCrypto.hexToBytes(hex)
        assertArrayEquals(bytes, result)
    }

    /**
     * Built by reference implementations — libargon2 (argon2-cffi) for the KDF, pyca/cryptography
     * for AES-GCM — via tools/gen_argon2id_envelope_fixture.py. A fixture KyAuth generated itself
     * would only prove self-consistency: the parameters are written into the envelope
     * independently of what the KDF actually consumed, so a mangled memory unit round-trips
     * cleanly. On the KyPasswords side exactly that bug ran Argon2 at 32 KiB instead of 32 MiB
     * and every round-trip test still passed.
     *
     * Its derived key is the vector KyPasswords pins in frontend/src/lib/vaultCrypto.test.ts:
     * Argon2id, m=65536 KiB, t=3, p=1, 32-byte output, password "correct horse battery staple",
     * salt 16 x 0x03 -> 73eb74162616418d643f08dc0856539ea61400cb268f85ce8df01d8257795b8d
     */
    private val referenceArgon2idEnvelope = """
        {"kdf":"argon2id",
         "salt":"03030303030303030303030303030303",
         "iv":"0102030405060708090a0b0c",
         "ciphertext":"ab2e11bbc778f8cbda713aba769e714d7669118ddbd463ed9db9a94116a3023e2d84a1635b2f7f78c94169eba8f0030c",
         "memoryKiB":65536,"iterations":3,"parallelism":1}
    """.trimIndent()

    private val referenceArgon2idSecret = "correct horse battery staple"

    private val referenceArgon2idVaultKey = ByteArray(32) { it.toByte() }

    /** PBKDF2-HMAC-SHA256, 600k rounds, same generator script. Wraps ByteArray(32) { it * 5 + 1 }. */
    private val referencePbkdf2Envelope = """
        {"salt":"00112233445566778899aabbccddeeff",
         "iv":"0b0a090807060504030201ff",
         "ciphertext":"90c66f242532e23434f3604f96c2ec1dd4f1cb822e22d137ed4ce3163700a6325bd03ae884e55a2f5fba2c8b2f63fd34",
         "iterations":600000}
    """.trimIndent()

    @Test
    fun unwrapsArgon2idEnvelopeFromReferenceImplementation() {
        val vaultKey = KyPasswordEnvelopeCrypto.unwrapVaultKey(
            envelopeJson = referenceArgon2idEnvelope,
            secret = referenceArgon2idSecret,
        )

        assertArrayEquals(referenceArgon2idVaultKey, vaultKey)
    }

    @Test
    fun rejectsUnknownKdf() {
        // Falling through to PBKDF2 on an unrecognised KDF would derive a wrong key from an
        // envelope we do not understand, instead of saying so.
        val envelope = org.json.JSONObject(referenceArgon2idEnvelope)
            .put("kdf", "scrypt")
            .toString()

        assertThrows(IllegalArgumentException::class.java) {
            KyPasswordEnvelopeCrypto.unwrapVaultKey(envelope, referenceArgon2idSecret)
        }
    }

    @Test
    fun rejectsArgon2idMemoryBeyondCeiling() {
        // memoryKiB comes off the server and is an allocation size. Reject before allocating.
        val envelope = org.json.JSONObject(referenceArgon2idEnvelope)
            .put("memoryKiB", 4 * 1024 * 1024)
            .toString()

        assertThrows(IllegalArgumentException::class.java) {
            KyPasswordEnvelopeCrypto.unwrapVaultKey(envelope, referenceArgon2idSecret)
        }
    }

    @Test
    fun rejectsArgon2idEnvelopeMissingParameters() {
        // No defaults: an argon2id envelope without its cost parameters is one we cannot reproduce.
        val envelope = org.json.JSONObject(referenceArgon2idEnvelope)
            .apply { remove("parallelism") }
            .toString()

        assertThrows(IllegalArgumentException::class.java) {
            KyPasswordEnvelopeCrypto.unwrapVaultKey(envelope, referenceArgon2idSecret)
        }
    }

    @Test
    fun unwrapsLegacyEnvelopeWithoutKdfField() {
        // Absence of "kdf" is the definition of PBKDF2-HMAC-SHA256. Envelopes already on servers
        // must keep opening after Argon2id lands — so this pins a fixture rather than round-tripping
        // through wrapVaultKey, which stops writing this shape once the write path moves.
        val vaultKey = ByteArray(32) { (it * 5 + 1).toByte() }

        assertArrayEquals(
            vaultKey,
            KyPasswordEnvelopeCrypto.unwrapVaultKey(referencePbkdf2Envelope, "legacy-secret"),
        )
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
