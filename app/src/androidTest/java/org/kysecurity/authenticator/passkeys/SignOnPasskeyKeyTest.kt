package org.kysecurity.authenticator.passkeys

import androidx.test.ext.junit.runners.AndroidJUnit4
import java.security.KeyStore
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class SignOnPasskeyKeyTest {

    @After fun tearDown() = SignOnPasskeyKey.deleteAll()

    @Test
    fun generatesAHardwareBackedP256Key() {
        val generated = SignOnPasskeyKey.generate(SignOnPasskeyKey.ALIAS_A)
        assertEquals("EC", generated.publicKey.algorithm)
        assertEquals(256, generated.publicKey.params.curve.field.fieldSize)
    }

    @Test
    fun thePrivateKeyIsNotExportable() {
        SignOnPasskeyKey.generate(SignOnPasskeyKey.ALIAS_A)
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val privateKey = keyStore.getKey(SignOnPasskeyKey.ALIAS_A, null)
        assertNotNull(privateKey)
        // A Keystore key never yields its bytes; this is the property the whole design rests on.
        assertNull(privateKey.encoded)
    }

    @Test
    fun spareAliasAlternatesSoEnrolmentNeverOverwritesALiveKey() {
        assertEquals(SignOnPasskeyKey.ALIAS_A, SignOnPasskeyKey.spareAlias(null))
        assertEquals(SignOnPasskeyKey.ALIAS_B, SignOnPasskeyKey.spareAlias(SignOnPasskeyKey.ALIAS_A))
        assertEquals(SignOnPasskeyKey.ALIAS_A, SignOnPasskeyKey.spareAlias(SignOnPasskeyKey.ALIAS_B))
    }

    @Test
    fun generatingTheSpareLeavesTheLiveKeyIntact() {
        SignOnPasskeyKey.generate(SignOnPasskeyKey.ALIAS_A)
        SignOnPasskeyKey.generate(SignOnPasskeyKey.ALIAS_B)
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        assertTrue(keyStore.containsAlias(SignOnPasskeyKey.ALIAS_A))
        assertTrue(keyStore.containsAlias(SignOnPasskeyKey.ALIAS_B))
    }

    @Test
    fun deleteRemovesOnlyTheNamedAlias() {
        SignOnPasskeyKey.generate(SignOnPasskeyKey.ALIAS_A)
        SignOnPasskeyKey.generate(SignOnPasskeyKey.ALIAS_B)
        SignOnPasskeyKey.delete(SignOnPasskeyKey.ALIAS_A)
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        assertTrue(!keyStore.containsAlias(SignOnPasskeyKey.ALIAS_A))
        assertTrue(keyStore.containsAlias(SignOnPasskeyKey.ALIAS_B))
    }

    @Test
    fun signatureForAnAbsentAliasIsNull() {
        assertNull(SignOnPasskeyKey.signatureFor(SignOnPasskeyKey.ALIAS_A))
    }
}
