package org.kysecurity.authenticator.passwords

import java.io.File
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * The UI, Autofill, the Credential Provider and vault sync all mutate one file from one process.
 * [KdbxPasswordVault.update] is what makes that safe.
 */
class KdbxPasswordVaultConcurrencyTest {
    @get:Rule
    val tempFolder = TemporaryFolder()

    private val vaultKey = ByteArray(32) { (it + 11).toByte() }

    private fun entry(index: Int) = PasswordEntry(
        title = "site-$index.example",
        username = "user-$index",
        password = "password-$index",
        url = "https://site-$index.example",
    )

    @Test
    fun concurrentUpdatesDoNotLoseEachOther() {
        val vaultFile = File(tempFolder.root, "passwords_vault.kdbx")
        KdbxPasswordVault.saveEntries(vaultFile, vaultKey, emptyList())

        val writers = 8
        val start = CountDownLatch(1)
        val done = CountDownLatch(writers)
        val failures = mutableListOf<Throwable>()

        repeat(writers) { index ->
            Thread {
                try {
                    start.await()
                    KdbxPasswordVault.update(vaultFile, vaultKey) { entries ->
                        entries.add(entry(index))
                        true
                    }
                } catch (t: Throwable) {
                    synchronized(failures) { failures.add(t) }
                } finally {
                    done.countDown()
                }
            }.start()
        }

        start.countDown()
        assertTrue("writers did not finish", done.await(60, TimeUnit.SECONDS))
        assertEquals(emptyList<Throwable>(), failures)

        val stored = KdbxPasswordVault.loadEntries(vaultFile, vaultKey)
        assertEquals(writers, stored.size)
        assertEquals(
            (0 until writers).map { "user-$it" }.toSet(),
            stored.map { it.username }.toSet(),
        )
    }

    @Test
    fun concurrentWritesLeaveNoScratchFilesBehind() {
        val vaultFile = File(tempFolder.root, "passwords_vault.kdbx")
        KdbxPasswordVault.saveEntries(vaultFile, vaultKey, emptyList())

        val threads = (0 until 6).map { index ->
            Thread {
                repeat(3) {
                    KdbxPasswordVault.update(vaultFile, vaultKey) { entries ->
                        entries.add(entry(index * 10 + it))
                        true
                    }
                }
            }
        }
        threads.forEach { it.start() }
        threads.forEach { it.join(60_000) }

        val leftovers = tempFolder.root.listFiles()?.filter { it.name != vaultFile.name }.orEmpty()
        assertEquals(emptyList<File>(), leftovers)
        assertEquals(18, KdbxPasswordVault.loadEntries(vaultFile, vaultKey).size)
    }

    @Test
    fun aFailedUpdateDoesNotRewriteTheVault() {
        val vaultFile = File(tempFolder.root, "passwords_vault.kdbx")
        KdbxPasswordVault.saveEntries(vaultFile, vaultKey, listOf(entry(1)))
        val before = vaultFile.readBytes()

        KdbxPasswordVault.update(vaultFile, vaultKey) { entries ->
            entries.add(entry(2))
            false
        }

        assertTrue(before.contentEquals(vaultFile.readBytes()))
        assertEquals(1, KdbxPasswordVault.loadEntries(vaultFile, vaultKey).size)
    }
}
