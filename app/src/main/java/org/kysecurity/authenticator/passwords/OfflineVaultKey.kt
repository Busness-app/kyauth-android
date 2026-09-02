package org.kysecurity.authenticator.passwords

import org.kysecurity.authenticator.passwords.kypasswords.KyPasswordEnvelopeCrypto

/**
 * The vault key rendered for a human to read off a screen and type into KeePassXC or KeePassDX.
 *
 * Separate from the Activity that shows it only because an `Activity` cannot be unit-tested on the
 * JVM, and what is displayed here is the KDBX password itself — grouping that silently altered it
 * would lock someone out of their own vault with nothing to point at.
 */
object OfflineVaultKey {
    private const val GROUP_SIZE = 4

    fun formatForDisplay(vaultKey: ByteArray): String =
        KyPasswordEnvelopeCrypto.bytesToHex(vaultKey).chunked(GROUP_SIZE).joinToString(" ")
}
