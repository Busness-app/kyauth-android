package org.kysecurity.authenticator.passwords

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class PasswordGeneratorTest {

    @Test
    fun generatesPasswordsOfRequestedLength() {
        val p1 = PasswordGenerator.generate(12)
        assertEquals(12, p1.length)

        val p2 = PasswordGenerator.generate(32)
        assertEquals(32, p2.length)
    }

    @Test
    fun generatesPasswordWithCharacterClassConstraints() {
        val password = PasswordGenerator.generate(
            length = 24,
            includeUppercase = true,
            includeLowercase = true,
            includeDigits = true,
            includeSymbols = true,
        )

        assertTrue(password.any { it.isUpperCase() })
        assertTrue(password.any { it.isLowerCase() })
        assertTrue(password.any { it.isDigit() })
        assertTrue(password.any { "!@#%+=_-".contains(it) })
    }

    @Test
    fun generatesPassphrases() {
        val passphrase = PasswordGenerator.generatePassphrase(wordCount = 4, separator = "-")
        val words = passphrase.split("-")
        assertEquals(4, words.size)
        assertTrue(words.all { it.isNotBlank() })
    }
}
