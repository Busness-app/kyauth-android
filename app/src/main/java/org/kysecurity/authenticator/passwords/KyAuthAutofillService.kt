package org.kysecurity.authenticator.passwords

import android.app.assist.AssistStructure
import android.os.CancellationSignal
import android.service.autofill.AutofillService
import android.service.autofill.Dataset
import android.service.autofill.FillCallback
import android.service.autofill.FillContext
import android.service.autofill.FillRequest
import android.service.autofill.FillResponse
import android.service.autofill.SaveCallback
import android.service.autofill.SaveRequest
import android.view.View
import android.view.autofill.AutofillId
import android.view.autofill.AutofillValue
import android.widget.RemoteViews
import java.io.File
import org.kysecurity.authenticator.security.AppLockManager

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

        val fields = ParsedFields()
        traverseStructure(structure, fields)

        val targetDomain = fields.webDomain ?: fields.packageName ?: run {
            callback.onSuccess(null)
            return
        }

        val entries = loadVaultEntries()
        val matchingEntries = entries.filter {
            !it.password.isNullOrBlank() && DomainMatcher.matches(it, targetDomain)
        }

        if (matchingEntries.isEmpty()) {
            callback.onSuccess(null)
            return
        }

        val responseBuilder = FillResponse.Builder()

        for (entry in matchingEntries) {
            val presentation = RemoteViews(packageName, android.R.layout.simple_list_item_2).apply {
                setTextViewText(android.R.id.text1, "${entry.title} (${entry.username})")
                setTextViewText(android.R.id.text2, "KyAuth Password")
            }

            val datasetBuilder = Dataset.Builder(presentation)
            var hasValue = false

            fields.usernameId?.let { id ->
                datasetBuilder.setValue(id, AutofillValue.forText(entry.username), presentation)
                hasValue = true
            }

            fields.passwordId?.let { id ->
                datasetBuilder.setValue(id, AutofillValue.forText(entry.password), presentation)
                hasValue = true
            }

            if (hasValue) {
                responseBuilder.addDataset(datasetBuilder.build())
            }
        }

        callback.onSuccess(responseBuilder.build())
    }

    override fun onSaveRequest(request: SaveRequest, callback: SaveCallback) {
        val structure = request.fillContexts.lastOrNull()?.structure ?: run {
            callback.onSuccess()
            return
        }

        val fields = ParsedFields()
        traverseStructure(structure, fields)

        val domain = fields.webDomain ?: fields.packageName ?: "Unknown"
        val username = fields.usernameValue.orEmpty()
        val password = fields.passwordValue.orEmpty()

        if (password.isNotBlank()) {
            val vaultKey = AppLockManager.getPasswordVaultKey() ?: AppLockManager.ensurePasswordVaultKeyInitialized(applicationContext)
            if (vaultKey != null) {
                val vaultFile = File(filesDir, "passwords_vault.kdbx")
                val entries = KdbxPasswordVault.loadEntries(vaultFile, vaultKey).toMutableList()

                val existingIndex = entries.indexOfFirst {
                    DomainMatcher.matches(it, domain) && it.username.equals(username, ignoreCase = true)
                }

                if (existingIndex >= 0) {
                    val existing = entries[existingIndex]
                    entries[existingIndex] = existing.copy(password = password, url = existing.url ?: "https://$domain")
                } else {
                    val title = if (username.isNotBlank()) "$domain ($username)" else domain
                    entries.add(
                        PasswordEntry(
                            title = title,
                            username = username,
                            password = password,
                            url = if (domain.contains("://")) domain else "https://$domain",
                        ),
                    )
                }
                KdbxPasswordVault.saveEntries(vaultFile, vaultKey, entries)
            }
        }

        callback.onSuccess()
    }

    private fun loadVaultEntries(): List<PasswordEntry> {
        val vaultKey = AppLockManager.getPasswordVaultKey() ?: AppLockManager.ensurePasswordVaultKeyInitialized(applicationContext)
            ?: return emptyList()
        val vaultFile = File(filesDir, "passwords_vault.kdbx")
        return runCatching { KdbxPasswordVault.loadEntries(vaultFile, vaultKey) }.getOrDefault(emptyList())
    }

    private fun traverseStructure(structure: AssistStructure, fields: ParsedFields) {
        val nodes = structure.windowNodeCount
        for (i in 0 until nodes) {
            val windowNode = structure.getWindowNodeAt(i)
            traverseViewNode(windowNode.rootViewNode, fields)
        }
    }

    private fun traverseViewNode(node: AssistStructure.ViewNode, fields: ParsedFields) {
        node.webDomain?.let { fields.webDomain = it }
        node.idPackage?.let { if (fields.packageName == null) fields.packageName = it }

        val hints = node.autofillHints?.toList().orEmpty()
        val isPasswordType = node.inputType and (android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD or android.text.InputType.TYPE_TEXT_VARIATION_WEB_PASSWORD) != 0
        val isUsernameHint = hints.any { it.contains("username", ignoreCase = true) || it.contains("email", ignoreCase = true) }
        val isPasswordHint = hints.any { it.contains("password", ignoreCase = true) }

        if (isPasswordHint || isPasswordType) {
            fields.passwordId = node.autofillId
            node.autofillValue?.textValue?.toString()?.let { fields.passwordValue = it }
        } else if (isUsernameHint) {
            fields.usernameId = node.autofillId
            node.autofillValue?.textValue?.toString()?.let { fields.usernameValue = it }
        }

        for (i in 0 until node.childCount) {
            traverseViewNode(node.getChildAt(i), fields)
        }
    }

    private class ParsedFields {
        var webDomain: String? = null
        var packageName: String? = null
        var usernameId: AutofillId? = null
        var passwordId: AutofillId? = null
        var usernameValue: String? = null
        var passwordValue: String? = null
    }
}
