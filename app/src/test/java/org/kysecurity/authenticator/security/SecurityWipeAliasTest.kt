package org.kysecurity.authenticator.security

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The wipe sweeps AndroidKeyStore by alias prefix. A KyAuth key the sweep does not match survives a
 * local wipe, so every alias the app creates is pinned here by its literal value.
 */
class SecurityWipeAliasTest {

    @Test
    fun `matches every alias KyAuth creates`() {
        val aliases = listOf(
            "kyauth_vault_kek",
            "kyauth_credential_pepper",
            "kyauth_pin_pepper",
            "kysignon-device-signing-v1",
            "kyauth_signon_passkey_v1",
        )
        for (alias in aliases) {
            assertTrue("wipe would leave $alias behind", SecurityWipe.isAppAlias(alias))
        }
    }

    @Test
    fun `leaves the androidx master key alone`() {
        // EncryptedSharedPreferences cannot re-open its files once this key is gone, so deleting it
        // turns a wipe into a crash on next launch. The prefs are cleared by content instead.
        assertFalse(SecurityWipe.isAppAlias("_androidx_security_master_key_"))
    }

    @Test
    fun `ignores keys belonging to other software`() {
        assertFalse(SecurityWipe.isAppAlias("bitwarden_key"))
        assertFalse(SecurityWipe.isAppAlias("com.example.kyauth_lookalike"))
    }
}
