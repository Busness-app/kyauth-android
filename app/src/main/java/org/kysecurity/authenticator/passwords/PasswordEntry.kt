package org.kysecurity.authenticator.passwords

import java.util.UUID

data class PasswordEntry(
    val title: String,
    val username: String,
    val password: String,
    val url: String? = null,
    val notes: String? = null,
    val id: String = UUID.randomUUID().toString(),
) {
    init {
        require(title.isNotBlank())
        require(password.isNotBlank())
    }
}
