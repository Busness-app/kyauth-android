package org.kysecurity.authenticator.passkeys

import java.nio.charset.StandardCharsets
import java.security.Signature
import java.security.interfaces.ECPublicKey
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

class WebAuthnEngineTest {

    @Test
    fun generatesValidEcKeyPairAndSignsAssertion() {
        val keyPair = WebAuthnEngine.generateEcKeyPair()
        val publicKey = keyPair.public as ECPublicKey
        val privateKey = WebAuthnEngine.restorePrivateKey(keyPair.private.encoded)

        val credentialId = WebAuthnEngine.generateCredentialId()
        assertEquals(32, credentialId.size)

        val coseKey = WebAuthnEngine.encodeCosePublicKey(publicKey)
        assertTrue("COSE key should not be empty", coseKey.isNotEmpty())

        val rpId = "auth.example.test"
        val signCount = 42

        val authData = WebAuthnEngine.buildAssertionAuthData(rpId, signCount)
        assertEquals(37, authData.size)

        val clientData = "{\"type\":\"webauthn.get\",\"challenge\":\"dGVzdA\"}".toByteArray(StandardCharsets.UTF_8)
        val clientDataHash = WebAuthnEngine.sha256(clientData)

        val signature = WebAuthnEngine.signAssertion(privateKey, authData, clientDataHash)
        assertTrue("Signature should not be empty", signature.isNotEmpty())

        // Verify signature with public key
        val dataToVerify = ByteArray(authData.size + clientDataHash.size)
        System.arraycopy(authData, 0, dataToVerify, 0, authData.size)
        System.arraycopy(clientDataHash, 0, dataToVerify, authData.size, clientDataHash.size)

        val verifier = Signature.getInstance("SHA256withECDSA")
        verifier.initVerify(publicKey)
        verifier.update(dataToVerify)
        assertTrue("Signature must verify against public key", verifier.verify(signature))
    }

    @Test
    fun buildsRegistrationAuthDataAndAttestationObject() {
        val keyPair = WebAuthnEngine.generateEcKeyPair()
        val publicKey = keyPair.public as ECPublicKey
        val credentialId = WebAuthnEngine.generateCredentialId()
        val coseKey = WebAuthnEngine.encodeCosePublicKey(publicKey)

        val authData = WebAuthnEngine.buildRegistrationAuthData(
            rpId = "example.com",
            signCount = 0,
            credentialId = credentialId,
            cosePublicKey = coseKey,
        )

        assertTrue(authData.size > 37)

        val attestationObject = WebAuthnEngine.buildAttestationObject(authData)
        assertTrue(attestationObject.isNotEmpty())
        // CBOR map starts with 0xA3
        assertEquals(0xA3.toByte(), attestationObject[0])
    }
}
