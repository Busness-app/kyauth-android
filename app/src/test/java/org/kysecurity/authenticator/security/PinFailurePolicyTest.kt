package org.kysecurity.authenticator.security

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class PinFailurePolicyTest {
    @Test fun `fifth failed PIN requires wipe`() {
        var state = PinFailureState()
        repeat(5) { state = PinFailurePolicy.registerFailure(state, 1_000L + it * 1_000L) }
        assertTrue(PinFailurePolicy.mustWipe(state))
        assertFalse(PinFailurePolicy.mayTry(state, 99_999L))
    }
}
