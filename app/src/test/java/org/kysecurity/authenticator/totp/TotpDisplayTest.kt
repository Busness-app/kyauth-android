package org.kysecurity.authenticator.totp

import org.junit.Assert.assertEquals
import org.junit.Test

class TotpDisplayTest {
    @Test
    fun formatsSixDigitCodesWithoutRebuildingTheScreen() {
        val state = TotpDisplay.state(
            TotpEntry(title = "Example", secretBase32 = "JBSWY3DPEHPK3PXP"),
            nowEpochSeconds = 0,
            unavailable = "Unavailable",
        )

        assertEquals("282 760", state.formattedCode)
        assertEquals(30, state.remainingSeconds)
    }
}
