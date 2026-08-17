package org.kysecurity.authenticator.totp

import java.nio.ByteBuffer
import java.util.Locale
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

object TotpGenerator {
    fun generate(entry: TotpEntry, epochSeconds: Long): String {
        val counter = epochSeconds / entry.periodSeconds
        val digest = Mac.getInstance("Hmac${entry.algorithm.name}").run {
            init(SecretKeySpec(base32Decode(entry.secretBase32), algorithm))
            doFinal(ByteBuffer.allocate(Long.SIZE_BYTES).putLong(counter).array())
        }
        val offset = digest.last().toInt() and 0x0f
        val value = ((digest[offset].toInt() and 0x7f) shl 24) or
            ((digest[offset + 1].toInt() and 0xff) shl 16) or
            ((digest[offset + 2].toInt() and 0xff) shl 8) or
            (digest[offset + 3].toInt() and 0xff)
        return (value % POW10[entry.digits]).toString().padStart(entry.digits, '0')
    }

    fun secondsRemaining(entry: TotpEntry, epochSeconds: Long): Long =
        entry.periodSeconds - (epochSeconds % entry.periodSeconds)

    private fun base32Decode(input: String): ByteArray {
        val normalized = input.uppercase(Locale.ROOT).filterNot { it == '=' || it.isWhitespace() }
        require(normalized.isNotEmpty()) { "TOTP secret is empty" }
        var bits = 0
        var value = 0
        val output = ArrayList<Byte>()
        for (character in normalized) {
            val digit = BASE32.indexOf(character)
            require(digit >= 0) { "TOTP secret is not Base32" }
            value = (value shl 5) or digit
            bits += 5
            if (bits >= 8) {
                output += ((value shr (bits - 8)) and 0xff).toByte()
                bits -= 8
            }
        }
        return output.toByteArray()
    }

    private const val BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    private val POW10 = intArrayOf(1, 10, 100, 1_000, 10_000, 100_000, 1_000_000, 10_000_000, 100_000_000)
}
