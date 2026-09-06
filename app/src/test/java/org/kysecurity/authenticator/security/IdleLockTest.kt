package org.kysecurity.authenticator.security

import org.junit.Assert.*
import org.junit.Test

class IdleLockTest {
    @Test fun activityCannotReviveAnExpiredSession() {
        val clock = IdleLock()
        assertTrue(clock.activity(100, 60_000))
        assertFalse(clock.expired(60_099, 60_000))
        assertFalse(clock.activity(60_100, 60_000))
        assertTrue(clock.expired(60_101, 60_000))
        clock.reset()
        assertTrue(clock.activity(70_000, 60_000))
        assertTrue(clock.activity(80_000, 60_000))
        assertFalse(clock.expired(139_999, 60_000))
        assertTrue(clock.expired(140_000, 60_000))
        assertTrue(clock.expired(0, 60_000))
        assertEquals(5, IdleLock.validatedMinutes(0))
        assertEquals(15, IdleLock.validatedMinutes(15))
    }
}
