package org.kysecurity.authenticator.security

data class PinFailureState(val failedAttempts: Int = 0, val retryAfterEpochSeconds: Long = 0) {
    init { require(failedAttempts >= 0) }
}

object PinFailurePolicy {
    const val WIPE_AFTER_ATTEMPTS = 5

    fun registerFailure(state: PinFailureState, nowEpochSeconds: Long): PinFailureState =
        PinFailureState(
            failedAttempts = state.failedAttempts + 1,
            retryAfterEpochSeconds = nowEpochSeconds + delaySeconds(state.failedAttempts + 1),
        )

    fun mayTry(state: PinFailureState, nowEpochSeconds: Long): Boolean =
        state.failedAttempts < WIPE_AFTER_ATTEMPTS && nowEpochSeconds >= state.retryAfterEpochSeconds

    fun secondsUntilRetry(state: PinFailureState, nowEpochSeconds: Long): Long =
        (state.retryAfterEpochSeconds - nowEpochSeconds).coerceAtLeast(0)

    fun attemptsRemaining(state: PinFailureState): Int =
        (WIPE_AFTER_ATTEMPTS - state.failedAttempts).coerceAtLeast(0)

    fun mustWipe(state: PinFailureState): Boolean = state.failedAttempts >= WIPE_AFTER_ATTEMPTS

    private fun delaySeconds(attempt: Int): Long = when (attempt) {
        1 -> 0
        2 -> 5
        3 -> 30
        4 -> 300
        else -> 0
    }
}

