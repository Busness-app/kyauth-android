package org.kysecurity.authenticator.security

import java.io.File
import java.io.FileOutputStream
import java.nio.file.AtomicMoveNotSupportedException
import java.nio.file.Files
import java.nio.file.StandardCopyOption.ATOMIC_MOVE
import java.nio.file.StandardCopyOption.REPLACE_EXISTING

/**
 * Replaces [target] with [bytes] via a uniquely named sibling, so two concurrent writers cannot
 * collide on a shared scratch file and leave a half-written vault behind.
 */
fun writeAtomically(target: File, bytes: ByteArray) {
    val directory = target.parentFile ?: target.absoluteFile.parentFile
    directory?.mkdirs()
    val temporary = File.createTempFile(".${target.name}", ".tmp", directory)
    try {
        FileOutputStream(temporary).use {
            it.write(bytes)
            it.fd.sync()
        }
        try {
            Files.move(temporary.toPath(), target.toPath(), ATOMIC_MOVE, REPLACE_EXISTING)
        } catch (_: AtomicMoveNotSupportedException) {
            Files.move(temporary.toPath(), target.toPath(), REPLACE_EXISTING)
        }
    } finally {
        temporary.delete()
    }
}
