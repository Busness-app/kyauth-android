package org.kysecurity.authenticator.passkeys

import androidx.test.ext.junit.runners.AndroidJUnit4
import java.security.KeyStore
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class SignOnPasskeyKeyTest {

    @After fun tearDown() = SignOnPasskeyKey.deleteAll()

    /**
     * Null when this device has no hardware-backed keystore — true of every Android emulator,
     * which ships the software KeyMint reference implementation. Callers assume past it rather
     * than failing, so a skipped result is never mistaken for a verified one.
     */
    private fun generateOrNull(alias: String): SignOnPasskeyKey.Generated? =
        try {
            SignOnPasskeyKey.generate(alias)
        } catch (expected: SignOnPasskeyKey.NoHardwareKeystore) {
            null
        }

    @Test
    fun generatesAHardwareBackedP256Key() {
        val generated = generateOrNull(SignOnPasskeyKey.ALIAS_A)
        assumeTrue("no hardware-backed keystore on this device", generated != null)
        assertEquals("EC", generated!!.publicKey.algorithm)
        assertEquals(256, generated.publicKey.params.curve.field.fieldSize)
    }

    @Test
    fun thePrivateKeyIsNotExportable() {
        val generated = generateOrNull(SignOnPasskeyKey.ALIAS_A)
        assumeTrue("no hardware-backed keystore on this device", generated != null)
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
        val a = generateOrNull(SignOnPasskeyKey.ALIAS_A)
        assumeTrue("no hardware-backed keystore on this device", a != null)
        val b = generateOrNull(SignOnPasskeyKey.ALIAS_B)
        assumeTrue("no hardware-backed keystore on this device", b != null)
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        assertTrue(keyStore.containsAlias(SignOnPasskeyKey.ALIAS_A))
        assertTrue(keyStore.containsAlias(SignOnPasskeyKey.ALIAS_B))
    }

    @Test
    fun deleteRemovesOnlyTheNamedAlias() {
        val a = generateOrNull(SignOnPasskeyKey.ALIAS_A)
        assumeTrue("no hardware-backed keystore on this device", a != null)
        val b = generateOrNull(SignOnPasskeyKey.ALIAS_B)
        assumeTrue("no hardware-backed keystore on this device", b != null)
        SignOnPasskeyKey.delete(SignOnPasskeyKey.ALIAS_A)
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        assertTrue(!keyStore.containsAlias(SignOnPasskeyKey.ALIAS_A))
        assertTrue(keyStore.containsAlias(SignOnPasskeyKey.ALIAS_B))
    }

    @Test
    fun signatureForAnAbsentAliasIsNull() {
        assertNull(SignOnPasskeyKey.signatureFor(SignOnPasskeyKey.ALIAS_A))
    }

    @Test
    fun refusesASoftwareBackedKeyAndDoesNotLeaveItBehind() {
        // A software-backed key would be exportable, which is the property this class exists to
        // remove. On a device without hardware backing, generate() must throw AND must not leave
        // the rejected key sitting in the keystore for something else to pick up.
        val error = runCatching { SignOnPasskeyKey.generate(SignOnPasskeyKey.ALIAS_A) }.exceptionOrNull()
        assumeTrue("this device has hardware backing, so the fail-closed path cannot run here", error != null)
        assertTrue(
            "expected NoHardwareKeystore, got ${error!!::class.java.name}",
            error is SignOnPasskeyKey.NoHardwareKeystore,
        )
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        assertFalse(keyStore.containsAlias(SignOnPasskeyKey.ALIAS_A))
    }
}
