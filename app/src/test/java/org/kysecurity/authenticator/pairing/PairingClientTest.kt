package org.kysecurity.authenticator.pairing

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Test

class PairingClientTest {
    @Test
    fun registrationRequestJson_includesAndroidPushRegistrationFormat() {
        val request = JSONObject(
            PairingClient().registrationRequestJson(
                pairing = QrPairing(
                    serverUrl = "https://signin.example.com",
                    pairingToken = "pair-token",
                ),
                deviceName = " SM-F971U1 ",
                deviceIdentifier = " install-id ",
                pushToken = " fcm-token ",
                publicKeyBase64 = "public-key",
            ),
        )

        assertEquals("pair-token", request.getString("pairingToken"))
        assertEquals("SM-F971U1", request.getString("deviceName"))
        assertEquals("install-id", request.getString("deviceIdentifier"))
        assertEquals("android", request.getString("platform"))
        assertEquals("public-key", request.getString("publicKey"))
        assertEquals("fcm-token", request.getString("pushToken"))
    }
}
