package org.kysecurity.authenticator.security

object PinPolicy {
    const val MIN_LENGTH = 4
    const val MAX_LENGTH = 12

    private val WEAK_PINS = setOf(
        "0000", "1111", "2222", "3333", "4444", "5555", "6666", "7777", "8888", "9999",
        "1234", "4321", "1212", "0123", "9876", "2580", "1357", "2468",
        "000000", "111111", "222222", "333333", "444444", "555555", "666666", "777777", "888888", "999999",
        "123456", "654321", "121212", "123123", "112233", "696969",
        "12345678", "87654321", "11223344", "12341234",
    )

    sealed class ValidationResult {
        object Valid : ValidationResult()
        data class Error(val message: String) : ValidationResult()
    }

    fun validate(pin: String): ValidationResult = when {
        pin.length < MIN_LENGTH -> ValidationResult.Error("PIN must be at least $MIN_LENGTH digits")
        pin.length > MAX_LENGTH -> ValidationResult.Error("PIN cannot exceed $MAX_LENGTH digits")
        !pin.all { it.isDigit() } -> ValidationResult.Error("PIN must contain only numbers")
        pin in WEAK_PINS -> ValidationResult.Error("This PIN is too common and easily guessed")
        isRun(pin) -> ValidationResult.Error("PIN cannot be a sequence of consecutive numbers")
        else -> ValidationResult.Valid
    }

    private fun isRun(pin: String): Boolean {
        if (pin.length < 4) return false
        val deltas = pin.zipWithNext { a, b -> b - a }
        return deltas.all { it == 1 } || deltas.all { it == -1 } || deltas.all { it == 0 }
    }
}
