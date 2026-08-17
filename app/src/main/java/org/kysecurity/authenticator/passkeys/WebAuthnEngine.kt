package org.kysecurity.authenticator.passkeys

import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.Signature
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.PKCS8EncodedKeySpec

object WebAuthnEngine {

    const val FLAG_USER_PRESENT: Byte = 0x01
    const val FLAG_USER_VERIFIED: Byte = 0x04
    const val FLAG_ATTESTED_CREDENTIAL_DATA: Byte = 0x40

    fun generateEcKeyPair(): KeyPair {
        val kpg = KeyPairGenerator.getInstance("EC")
        kpg.initialize(ECGenParameterSpec("secp256r1"), SecureRandom())
        return kpg.generateKeyPair()
    }

    fun generateCredentialId(): ByteArray {
        val bytes = ByteArray(32)
        SecureRandom().nextBytes(bytes)
        return bytes
    }

    fun restorePrivateKey(pkcs8Bytes: ByteArray): ECPrivateKey {
        val keyFactory = KeyFactory.getInstance("EC")
        val keySpec = PKCS8EncodedKeySpec(pkcs8Bytes)
        return keyFactory.generatePrivate(keySpec) as ECPrivateKey
    }

    fun encodeCosePublicKey(publicKey: ECPublicKey): ByteArray {
        val affineX = toUnsigned32Bytes(publicKey.w.affineX.toByteArray())
        val affineY = toUnsigned32Bytes(publicKey.w.affineY.toByteArray())

        val out = ByteArrayOutputStream()
        // Map with 5 entries: 0xA5
        out.write(0xA5)

        // 1 (kty): 2 (EC2)
        out.write(0x01)
        out.write(0x02)

        // 3 (alg): -7 (ES256) -> 0x26 in CBOR
        out.write(0x03)
        out.write(0x26)

        // -1 (crv): 1 (P-256) -> 0x20 in CBOR
        out.write(0x20)
        out.write(0x01)

        // -2 (x coordinate): 32-byte byte string -> 0x21, 0x58, 0x20
        out.write(0x21)
        out.write(0x58)
        out.write(0x20)
        out.write(affineX)

        // -3 (y coordinate): 32-byte byte string -> 0x22, 0x58, 0x20
        out.write(0x22)
        out.write(0x58)
        out.write(0x20)
        out.write(affineY)

        return out.toByteArray()
    }

    fun buildRegistrationAuthData(
        rpId: String,
        signCount: Int,
        credentialId: ByteArray,
        cosePublicKey: ByteArray,
        aaguid: ByteArray = ByteArray(16),
    ): ByteArray {
        val rpIdHash = sha256(rpId.toByteArray(Charsets.UTF_8))
        val flags = (FLAG_USER_PRESENT.toInt() or FLAG_USER_VERIFIED.toInt() or FLAG_ATTESTED_CREDENTIAL_DATA.toInt()).toByte()

        val out = ByteArrayOutputStream()
        out.write(rpIdHash)
        out.write(flags.toInt())

        val countBytes = ByteBuffer.allocate(4).putInt(signCount).array()
        out.write(countBytes)

        // Attested Credential Data
        out.write(aaguid)
        val credIdLen = ByteBuffer.allocate(2).putShort(credentialId.size.toShort()).array()
        out.write(credIdLen)
        out.write(credentialId)
        out.write(cosePublicKey)

        return out.toByteArray()
    }

    fun buildAssertionAuthData(
        rpId: String,
        signCount: Int,
    ): ByteArray {
        val rpIdHash = sha256(rpId.toByteArray(Charsets.UTF_8))
        val flags = (FLAG_USER_PRESENT.toInt() or FLAG_USER_VERIFIED.toInt()).toByte()

        val out = ByteArrayOutputStream()
        out.write(rpIdHash)
        out.write(flags.toInt())

        val countBytes = ByteBuffer.allocate(4).putInt(signCount).array()
        out.write(countBytes)

        return out.toByteArray()
    }

    fun buildAttestationObject(authData: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()
        // Map with 3 entries: 0xA3
        out.write(0xA3)

        // "fmt": "none"
        out.write(byteArrayOf(0x63, 'f'.code.toByte(), 'm'.code.toByte(), 't'.code.toByte()))
        out.write(byteArrayOf(0x64, 'n'.code.toByte(), 'o'.code.toByte(), 'n'.code.toByte(), 'e'.code.toByte()))

        // "attStmt": {}
        out.write(byteArrayOf(0x67, 'a'.code.toByte(), 't'.code.toByte(), 't'.code.toByte(), 'S'.code.toByte(), 't'.code.toByte(), 'm'.code.toByte(), 't'.code.toByte()))
        out.write(0xA0)

        // "authData": bytes
        out.write(byteArrayOf(0x68, 'a'.code.toByte(), 'u'.code.toByte(), 't'.code.toByte(), 'h'.code.toByte(), 'D'.code.toByte(), 'a'.code.toByte(), 't'.code.toByte(), 'a'.code.toByte()))
        writeCborByteStringHeader(out, authData.size)
        out.write(authData)

        return out.toByteArray()
    }

    fun signAssertion(
        privateKey: ECPrivateKey,
        authData: ByteArray,
        clientDataHash: ByteArray,
    ): ByteArray {
        val dataToSign = ByteArray(authData.size + clientDataHash.size)
        System.arraycopy(authData, 0, dataToSign, 0, authData.size)
        System.arraycopy(clientDataHash, 0, dataToSign, authData.size, clientDataHash.size)

        val signer = Signature.getInstance("SHA256withECDSA")
        signer.initSign(privateKey)
        signer.update(dataToSign)
        return signer.sign()
    }

    fun sha256(data: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(data)

    private fun writeCborByteStringHeader(out: ByteArrayOutputStream, length: Int) {
        when {
            length < 24 -> out.write(0x40 or length)
            length <= 0xFF -> {
                out.write(0x58)
                out.write(length)
            }
            length <= 0xFFFF -> {
                out.write(0x59)
                out.write(length shr 8)
                out.write(length and 0xFF)
            }
            else -> {
                out.write(0x5A)
                out.write(ByteBuffer.allocate(4).putInt(length).array())
            }
        }
    }

    private fun toUnsigned32Bytes(raw: ByteArray): ByteArray {
        val result = ByteArray(32)
        if (raw.size == 32) {
            System.arraycopy(raw, 0, result, 0, 32)
        } else if (raw.size > 32) {
            // Drop leading sign byte if 33 bytes
            val offset = raw.size - 32
            System.arraycopy(raw, offset, result, 0, 32)
        } else {
            // Pad left with zeroes
            val offset = 32 - raw.size
            System.arraycopy(raw, 0, result, offset, raw.size)
        }
        return result
    }
}
