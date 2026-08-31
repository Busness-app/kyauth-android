package org.kysecurity.authenticator.passwords

import android.app.PendingIntent
import android.content.Intent
import android.os.CancellationSignal
import android.service.autofill.AutofillService
import android.service.autofill.FillCallback
import android.service.autofill.FillRequest
import android.service.autofill.FillResponse
import android.service.autofill.SaveCallback
import android.service.autofill.SaveRequest
import java.io.File
import org.kysecurity.authenticator.security.AppLockManager

/**
 * Autofill provider.
 *
 * While KyAuth is locked no vault material is touched: the response carries an authentication
 * [PendingIntent] instead of datasets, and the secrets are only read inside
 * [AutofillUnlockActivity] after the user authenticates.
 */
class KyAuthAutofillService : AutofillService() {

    override fun onFillRequest(
        request: FillRequest,
        cancellationSignal: CancellationSignal,
        callback: FillCallback,
    ) {
        val structure = request.fillContexts.lastOrNull()?.structure ?: run {
            callback.onSuccess(null)
            return
        }

        val fields = AutofillParser.parse(this, structure)
        if (fields.targetDomain == null || fields.autofillIds.isEmpty()) {
            callback.onSuccess(null)
            return
        }

        if (!AppLockManager.isUnlocked()) {
            callback.onSuccess(unlockResponse(fields))
            return
        }

        val vaultKey = AppLockManager.getPasswordVaultKey() ?: run {
            callback.onSuccess(unlockResponse(fields))
            return
        }
        val entries = runCatching {
            KdbxPasswordVault.loadEntries(File(filesDir, VAULT_FILE_NAME), vaultKey)
        }.getOrNull() ?: run {
            // An undecodable vault is not an empty vault: offer nothing rather than a wrong answer.
            callback.onSuccess(null)
            return
        }

        callback.onSuccess(AutofillParser.buildDatasets(this, fields, entries))
    }

    override fun onSaveRequest(request: SaveRequest, callback: SaveCallback) {
        val structure = request.fillContexts.lastOrNull()?.structure ?: run {
            callback.onFailure("No form data to save")
            return
        }

        val vaultKey = AppLockManager.getPasswordVaultKey() ?: run {
            callback.onFailure("Unlock KyAuth to save this password")
            return
        }

        val fields = AutofillParser.parse(this, structure)
        val password = fields.passwordValue.orEmpty()
        val domain = fields.targetDomain
        if (password.isBlank() || domain == null) {
            callback.onFailure("No password to save")
            return
        }

        val saved = runCatching {
            KdbxPasswordVault.update(File(filesDir, VAULT_FILE_NAME), vaultKey) { entries ->
                entries.upserted(domain, fields.usernameValue.orEmpty(), password)
                true
            }
        }.isSuccess

        if (saved) callback.onSuccess() else callback.onFailure("Could not save to the KyAuth vault")
    }

    /** A single "unlock" affordance; selecting it launches the authenticated fill. */
    private fun unlockResponse(fields: ParsedFields): FillResponse {
        val intent = Intent(this, AutofillUnlockActivity::class.java)
        val pendingIntent = PendingIntent.getActivity(
            this,
            0,
            intent,
            PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        return FillResponse.Builder()
            .setAuthentication(
                fields.autofillIds,
                pendingIntent.intentSender,
                AutofillParser.presentation(this, "Unlock KyAuth", "Authenticate to fill"),
            )
            .build()
    }

    companion object {
        const val VAULT_FILE_NAME = "passwords_vault.kdbx"
    }
}

/** Replaces the matching entry for [domain]/[username], or appends a new one. */
internal fun MutableList<PasswordEntry>.upserted(
    domain: String,
    username: String,
    password: String,
): List<PasswordEntry> {
    val index = indexOfFirst {
        DomainMatcher.matchesPassword(it, domain) && it.username.equals(username, ignoreCase = true)
    }
    val url = if (domain.contains("://")) domain else "https://$domain"
    if (index >= 0) {
        this[index] = this[index].copy(password = password, url = this[index].url ?: url)
    } else {
        add(
            PasswordEntry(
                title = if (username.isNotBlank()) "$domain ($username)" else domain,
                username = username,
                password = password,
                url = url,
            ),
        )
    }
    return this
}
