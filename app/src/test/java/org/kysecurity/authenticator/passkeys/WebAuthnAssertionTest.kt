package org.kysecurity.authenticator.passkeys

import java.security.Signature
import org.json.JSONObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The assertion contract a relying party actually verifies: it hashes the `clientDataJSON` it was
 * handed and checks the signature over `authenticatorData || that hash`.
 */
class WebAuthnAssertionTest {

    private val challenge = "Q0hBTExFTkdF"
    private val origin = "android:apk-key-hash:abc123"

    private fun clientData(type: String) =
        ClientData.serialize(type, challenge, origin, "com.example.app")

    @Test
    fun clientDataCarriesTheRequestedTypeChallengeAndOrigin() {
        val json = JSONObject(String(clientData(ClientData.TYPE_GET), Charsets.UTF_8))

        assertEquals("webauthn.get", json.getString("type"))
        assertEquals(challenge, json.getString("challenge"))
        assertEquals(origin, json.getString("origin"))
        assertEquals("com.example.app", json.getString("androidPackageName"))
        assertFalse(json.getBoolean("crossOrigin"))
    }

    @Test
    fun registrationAndAssertionAreDomainSeparatedByType() {
        assertEquals(
            "webauthn.create",
            JSONObject(String(clientData(ClientData.TYPE_CREATE), Charsets.UTF_8)).getString("type"),
        )
    }

    @Test
    fun aRelyingPartyCanVerifyTheAssertionFromTheReturnedClientDataJson() {
        val keyPair = WebAuthnEngine.generateEcKeyPair()
        val authData = WebAuthnEngine.buildAssertionAuthData("example.com", signCount = 7)

        // What KyAuth returns to the relying party.
        val returnedClientDataJson = clientData(ClientData.TYPE_GET)
        val signature = WebAuthnEngine.signAssertion(
            WebAuthnEngine.restorePrivateKey(keyPair.private.encoded),
            authData,
            WebAuthnEngine.sha256(returnedClientDataJson),
        )

        // What the relying party does with it.
        val verifier = Signature.getInstance("SHA256withECDSA").apply {
            initVerify(keyPair.public)
            update(authData)
            update(WebAuthnEngine.sha256(returnedClientDataJson))
        }
        assertTrue(verifier.verify(signature))
    }

    @Test
    fun signingTheRawChallengeInsteadOfTheClientDataHashDoesNotVerify() {
        val keyPair = WebAuthnEngine.generateEcKeyPair()
        val authData = WebAuthnEngine.buildAssertionAuthData("example.com", signCount = 1)
        val returnedClientDataJson = clientData(ClientData.TYPE_GET)

        // The pre-fix behaviour: sign the decoded challenge, hand back some other JSON.
        val signature = WebAuthnEngine.signAssertion(
            WebAuthnEngine.restorePrivateKey(keyPair.private.encoded),
            authData,
            challenge.toByteArray(Charsets.UTF_8),
        )

        val verifier = Signature.getInstance("SHA256withECDSA").apply {
            initVerify(keyPair.public)
            update(authData)
            update(WebAuthnEngine.sha256(returnedClientDataJson))
        }
        assertFalse(verifier.verify(signature))
    }

    @Test
    fun assertionAuthDataStartsWithTheRpIdHashAndCarriesTheSignCount() {
        val authData = WebAuthnEngine.buildAssertionAuthData("example.com", signCount = 258)

        assertEquals(37, authData.size)
        assertArrayEquals(
            WebAuthnEngine.sha256("example.com".toByteArray(Charsets.UTF_8)),
            authData.copyOfRange(0, 32),
        )
        assertEquals(
            WebAuthnEngine.FLAG_USER_PRESENT.toInt() or WebAuthnEngine.FLAG_USER_VERIFIED.toInt(),
            authData[32].toInt(),
        )
        assertArrayEquals(byteArrayOf(0, 0, 1, 2), authData.copyOfRange(33, 37))
    }

    @Test
    fun `signing through a Signature matches signing through a private key`() {
        val keyPair = WebAuthnEngine.generateEcKeyPair()
        val authData = WebAuthnEngine.buildAssertionAuthData("example.com", 1)
        val clientDataHash = WebAuthnEngine.sha256("client data".toByteArray())

        val viaSignature = java.security.Signature.getInstance("SHA256withECDSA").apply {
            initSign(keyPair.private)
        }
        val fromSignature = WebAuthnEngine.signAssertion(viaSignature, authData, clientDataHash)

        // ECDSA is randomised, so the bytes differ every time; both must verify against the key.
        val verifier = java.security.Signature.getInstance("SHA256withECDSA").apply {
            initVerify(keyPair.public)
            update(authData)
            update(clientDataHash)
        }
        org.junit.Assert.assertTrue(verifier.verify(fromSignature))
    }
}
