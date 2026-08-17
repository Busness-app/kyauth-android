package org.kysecurity.authenticator.totp

import org.junit.Assert.assertEquals
import org.junit.Test

class TotpGeneratorTest {
    @Test fun `matches RFC 6238 SHA-1 vector`() {
        val entry = TotpEntry("RFC", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", digits = 8)
        assertEquals("94287082", TotpGenerator.generate(entry, 59))
    }

    @Test fun `writes KeePass standard fields`() {
        val fields = TotpEntry("Example", "JBSWY3DPEHPK3PXP", digits = 8, periodSeconds = 60, algorithm = TotpEntry.Algorithm.SHA256).keepassFields()
        assertEquals("JBSWY3DPEHPK3PXP", fields["TimeOtp-Secret-Base32"])
        assertEquals("HMAC-SHA-256", fields["TimeOtp-Algorithm"])
    }

    @Test fun `reads KeePass standard fields`() {
        val entry = TotpEntry.fromKeepassFields(
            "Example",
            mapOf(
                "TimeOtp-Secret-Base32" to "JBSWY3DPEHPK3PXP",
                "TimeOtp-Length" to "8",
                "TimeOtp-Period" to "60",
                "TimeOtp-Algorithm" to "HMAC-SHA-512",
            ),
        )!!
        assertEquals(TotpEntry.Algorithm.SHA512, entry.algorithm)
        assertEquals(60L, entry.periodSeconds)
    }
}
