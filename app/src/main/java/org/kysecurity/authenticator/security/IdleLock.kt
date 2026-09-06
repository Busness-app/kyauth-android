package org.kysecurity.authenticator.security

/** Uses elapsed realtime, which includes device sleep and is independent of wall-clock changes. */
class IdleLock {
    private var lastActivity: Long? = null

    @Synchronized fun expired(now: Long, timeoutMillis: Long): Boolean {
        val last = lastActivity ?: return false.also { lastActivity = now }
        return now < last || now - last >= timeoutMillis
    }

    @Synchronized fun activity(now: Long, timeoutMillis: Long): Boolean {
        if (expired(now, timeoutMillis)) return false
        lastActivity = now
        return true
    }

    @Synchronized fun reset() { lastActivity = null }

    companion object {
        val minutes = listOf(1, 5, 15, 30, 60)
        fun validatedMinutes(value: Int): Int = value.takeIf { it in minutes } ?: 5
    }
}
