package org.kysecurity.authenticator.passkeys

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class SignOnPasskeyRecordTest {

    private fun record() = SignOnPasskeyRecord(
        rpId = "signon.example.com",
        username = "yoshi",
        userHandle = byteArrayOf(1, 2, 3),
        credentialId = byteArrayOf(9, 8, 7, 6),
        signCount = 4,
        alias = "kyauth_signon_passkey_a",
        strongBoxBacked = true,
    )

    @Test
    fun `round trips through json`() {
        assertEquals(record(), SignOnPasskeyRecord.fromJson(record().toJson()))
    }

    @Test
    fun `rejects malformed or absent json instead of throwing`() {
        assertNull(SignOnPasskeyRecord.fromJson(null))
        assertNull(SignOnPasskeyRecord.fromJson(""))
        assertNull(SignOnPasskeyRecord.fromJson("not json"))
        assertNull(SignOnPasskeyRecord.fromJson("""{"rpId":"signon.example.com"}"""))
    }

    @Test
    fun `an empty user handle survives the round trip`() {
        val empty = record().copy(userHandle = ByteArray(0))
        assertEquals(empty, SignOnPasskeyRecord.fromJson(empty.toJson()))
    }
}
