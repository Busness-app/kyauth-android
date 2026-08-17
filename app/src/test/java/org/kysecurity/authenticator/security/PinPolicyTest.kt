package org.kysecurity.authenticator.security

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class PinPolicyTest {
    @Test
    fun rejectsShortPin() {
        val result = PinPolicy.validate("123")
        assertTrue(result is PinPolicy.ValidationResult.Error)
    }

    @Test
    fun rejectsTooLongPin() {
        val result = PinPolicy.validate("1234567890123456")
        assertTrue(result is PinPolicy.ValidationResult.Error)
    }

    @Test
    fun rejectsNonNumericPin() {
        val result = PinPolicy.validate("1234ab")
        assertTrue(result is PinPolicy.ValidationResult.Error)
    }

    @Test
    fun rejectsCommonPin() {
        val result = PinPolicy.validate("1234")
        assertTrue(result is PinPolicy.ValidationResult.Error)
        val result2 = PinPolicy.validate("111111")
        assertTrue(result2 is PinPolicy.ValidationResult.Error)
    }

    @Test
    fun acceptsStrongPin() {
        val result = PinPolicy.validate("849204")
        assertTrue(result is PinPolicy.ValidationResult.Valid)
    }
}
