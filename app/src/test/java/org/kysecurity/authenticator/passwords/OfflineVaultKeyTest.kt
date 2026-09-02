package org.kysecurity.authenticator.passwords

import org.junit.Assert.assertEquals
import org.junit.Assert.assertArrayEquals
import org.junit.Test
import org.kysecurity.authenticator.passwords.kypasswords.KyPasswordEnvelopeCrypto

class OfflineVaultKeyTest {

    @Test
    fun groupsTheKeyIntoBlocksOfFour() {
        // 64 hex characters are unreadable in one run and easy to lose your place in when typing
        // them into another password manager.
        val formatted = OfflineVaultKey.formatForDisplay(ByteArray(32) { it.toByte() })

        assertEquals(
            "0001 0203 0405 0607 0809 0a0b 0c0d 0e0f 1011 1213 1415 1617 1819 1a1b 1c1d 1e1f",
            formatted,
        )
    }

    @Test
    fun formattingDoesNotCorruptTheKey() {
        // What is displayed is the KDBX password. If grouping altered it, a user transcribing it
        // would be locked out of their own vault with no way to tell why.
        val vaultKey = ByteArray(32) { (it * 7 + 5).toByte() }

        val transcribed = OfflineVaultKey.formatForDisplay(vaultKey).filterNot { it == ' ' }

        assertArrayEquals(vaultKey, KyPasswordEnvelopeCrypto.hexToBytes(transcribed))
    }
}
