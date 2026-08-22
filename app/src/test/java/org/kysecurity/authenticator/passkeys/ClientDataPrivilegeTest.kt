package org.kysecurity.authenticator.passkeys

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertNull
import org.junit.Test

class ClientDataPrivilegeTest {

    private val hash = ByteArray(32) { it.toByte() }

    @Test
    fun honoursHashFromAPrivilegedWebOrigin() {
        assertArrayEquals(hash, ClientData.privilegedClientDataHash("https://example.com", hash))
    }

    @Test
    fun ignoresHashFromANativeCaller() {
        // Only a privileged caller can set a web origin, so an apk-key-hash origin means the hash
        // came from an app that could have chosen any bytes it liked.
        assertNull(ClientData.privilegedClientDataHash("android:apk-key-hash:AAAA", hash))
        assertNull(ClientData.privilegedClientDataHash(null, hash))
        assertNull(ClientData.privilegedClientDataHash("", hash))
        assertNull(ClientData.privilegedClientDataHash("http://example.com", hash))
    }
}
