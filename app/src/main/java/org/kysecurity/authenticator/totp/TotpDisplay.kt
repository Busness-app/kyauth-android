package org.kysecurity.authenticator.totp

data class TotpDisplayState(val code: String?, val formattedCode: String, val remainingSeconds: Long)

object TotpDisplay {
    fun state(entry: TotpEntry, nowEpochSeconds: Long, unavailable: String): TotpDisplayState {
        val code = runCatching { TotpGenerator.generate(entry, nowEpochSeconds) }.getOrNull()
        val formatted = when {
            code == null -> unavailable
            code.length == 6 -> "${code.substring(0, 3)} ${code.substring(3)}"
            else -> code
        }
        return TotpDisplayState(code, formatted, TotpGenerator.secondsRemaining(entry, nowEpochSeconds))
    }
}
