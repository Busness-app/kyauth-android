package org.kysecurity.authenticator.passkeys

import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class SignOnPasskeyStoreTest {

    private val store = SignOnPasskeyStore(ApplicationProvider.getApplicationContext())

    private fun record() = SignOnPasskeyRecord(
        rpId = "signon.example.com",
        username = "yoshi",
        userHandle = byteArrayOf(1, 2, 3),
        credentialId = byteArrayOf(9, 8, 7, 6),
        signCount = 0,
        alias = "kyauth_signon_passkey_a",
        strongBoxBacked = false,
    )

    @Before fun setUp() = store.clear()

    @After fun tearDown() = store.clear()

    @Test
    fun startsEmpty() {
        assertNull(store.record())
    }

    @Test
    fun savesAndReadsBack() {
        store.save(record())
        assertEquals(record(), store.record())
    }

    @Test
    fun saveReplacesRatherThanAccumulates() {
        store.save(record())
        store.save(record().copy(signCount = 7))
        assertEquals(7, store.record()?.signCount)
    }

    @Test
    fun clearRemovesTheRecord() {
        store.save(record())
        store.clear()
        assertNull(store.record())
    }

    @Test
    fun securityWipeClearsTheRecord() {
        // shared_prefs is a sibling of filesDir, so deleting filesDir does not reach this store.
        // SecurityWipe must clear it explicitly or a wipe leaves metadata pointing at a key that
        // step 5 of the same wipe has already deleted.
        store.save(record())
        org.kysecurity.authenticator.security.SecurityWipe.wipe(
            ApplicationProvider.getApplicationContext(),
        )
        assertNull(store.record())
    }
}
