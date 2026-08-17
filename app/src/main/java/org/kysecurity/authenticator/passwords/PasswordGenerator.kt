package org.kysecurity.authenticator.passwords

import java.security.SecureRandom

object PasswordGenerator {

    private const val UPPERCASE = "ABCDEFGHJKLMNPQRSTUVWXYZ"
    private const val LOWERCASE = "abcdefghijkmnopqrstuvwxyz"
    private const val DIGITS = "23456789"
    private const val SYMBOLS = "!@#%+=_-"

    private const val AMBIGUOUS = "IO0l1"

    private val PASSPHRASE_WORDS = listOf(
        "anchor", "beacon", "breeze", "bridge", "canyon", "castle", "cedar", "cliff",
        "cloud", "comet", "coral", "crater", "delta", "desert", "dragon", "eagle",
        "falcon", "forest", "frost", "galaxy", "glacier", "harbor", "haven", "island",
        "jungle", "lagoon", "lantern", "meadow", "meteor", "mountain", "nebula", "oasis",
        "ocean", "orbit", "peak", "planet", "prairie", "quasar", "radius", "reef",
        "river", "shadow", "shield", "silver", "summit", "timber", "valley", "vortex",
    )

    fun generate(
        length: Int = 20,
        includeUppercase: Boolean = true,
        includeLowercase: Boolean = true,
        includeDigits: Boolean = true,
        includeSymbols: Boolean = true,
    ): String {
        require(length >= 4) { "Password length must be at least 4" }

        val pool = StringBuilder()
        val mandatory = mutableListOf<Char>()
        val random = SecureRandom()

        if (includeUppercase) {
            pool.append(UPPERCASE)
            mandatory.add(UPPERCASE[random.nextInt(UPPERCASE.length)])
        }
        if (includeLowercase) {
            pool.append(LOWERCASE)
            mandatory.add(LOWERCASE[random.nextInt(LOWERCASE.length)])
        }
        if (includeDigits) {
            pool.append(DIGITS)
            mandatory.add(DIGITS[random.nextInt(DIGITS.length)])
        }
        if (includeSymbols) {
            pool.append(SYMBOLS)
            mandatory.add(SYMBOLS[random.nextInt(SYMBOLS.length)])
        }

        if (pool.isEmpty()) {
            pool.append(LOWERCASE).append(DIGITS)
            mandatory.add(LOWERCASE[random.nextInt(LOWERCASE.length)])
            mandatory.add(DIGITS[random.nextInt(DIGITS.length)])
        }

        val poolStr = pool.toString()
        val result = mutableListOf<Char>()
        result.addAll(mandatory)

        val remaining = length - mandatory.size
        repeat(remaining) {
            result.add(poolStr[random.nextInt(poolStr.length)])
        }

        // Shuffle using Fisher-Yates
        for (i in result.size - 1 downTo 1) {
            val j = random.nextInt(i + 1)
            val temp = result[i]
            result[i] = result[j]
            result[j] = temp
        }

        return result.joinToString("")
    }

    fun generatePassphrase(wordCount: Int = 4, separator: String = "-"): String {
        require(wordCount >= 2) { "Word count must be at least 2" }
        val random = SecureRandom()
        return (1..wordCount)
            .map { PASSPHRASE_WORDS[random.nextInt(PASSPHRASE_WORDS.size)] }
            .joinToString(separator)
    }
}
