package org.kysecurity.authenticator

import app.keemobile.kotpass.constants.BasicField
import app.keemobile.kotpass.models.EntryFields

/**
 * kotpass's [BasicField] carries the KeePass wire name in `key`; `name` is only the enum constant.
 * They are identical for every field except [BasicField.Url], where the wire name is `URL` and the
 * constant is `Url`. KyAuth read and wrote the constant, so its URLs were invisible to KeePassXC,
 * KeePassDX and the KyPasswords web client, and theirs were invisible to KyAuth.
 *
 * Reads accept the legacy key as a fallback so URLs already in a KyAuth-written vault survive;
 * writes use [BasicField.Url] only, which migrates the entry on its next save.
 */
private const val LEGACY_URL_KEY = "Url"

internal fun EntryFields.urlOrLegacy(): String? =
    (url ?: this[LEGACY_URL_KEY])?.content?.ifBlank { null }
