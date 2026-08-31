package org.kysecurity.authenticator.passwords

import android.app.assist.AssistStructure
import android.content.Context
import android.service.autofill.Dataset
import android.service.autofill.FillResponse
import android.text.InputType
import android.view.autofill.AutofillId
import android.view.autofill.AutofillValue
import android.widget.RemoteViews

/** The autofillable fields of one request. */
class ParsedFields {
    var webDomain: String? = null
    var packageName: String? = null
    /** True only when the request came from a known browser; see [TrustedBrowsers]. */
    var trustWebDomain: Boolean = false
    var usernameId: AutofillId? = null
    var passwordId: AutofillId? = null
    var usernameValue: String? = null
    var passwordValue: String? = null

    val targetDomain: String? get() = AutofillParser.resolveTargetDomain(webDomain, packageName, trustWebDomain)
    val autofillIds: Array<AutofillId> get() = listOfNotNull(usernameId, passwordId).toTypedArray()
}

object AutofillParser {

    fun parse(context: Context, structure: AssistStructure): ParsedFields {
        val fields = ParsedFields()
        // The activity component is filled in by the system, unlike anything in the view tree.
        val callerPackage = runCatching { structure.activityComponent?.packageName }.getOrNull()
        fields.packageName = callerPackage
        fields.trustWebDomain = TrustedBrowsers.isTrusted(context, callerPackage)
        for (i in 0 until structure.windowNodeCount) {
            traverse(structure.getWindowNodeAt(i).rootViewNode, fields)
        }
        return fields
    }

    /**
     * What this request is asking for a credential *for*.
     *
     * A browser is answering for the page it has loaded, so its web domain is the target. Every
     * other app is only ever its own package: an app that names a domain is making a claim it was
     * never asked to prove, and honouring it would hand one site's password to another app.
     */
    fun resolveTargetDomain(webDomain: String?, packageName: String?, trustWebDomain: Boolean): String? =
        if (trustWebDomain) webDomain ?: packageName else packageName

    /** Builds the filled datasets. Only ever reached with vault entries the user has unlocked. */
    fun buildDatasets(
        context: Context,
        fields: ParsedFields,
        entries: List<PasswordEntry>,
    ): FillResponse? {
        val target = fields.targetDomain ?: return null
        val matching = entries.filter { it.password.isNotBlank() && DomainMatcher.matchesPassword(it, target) }
        if (matching.isEmpty()) return null

        val responseBuilder = FillResponse.Builder()
        var added = false
        for (entry in matching) {
            val presentation = presentation(context, "${entry.title} (${entry.username})", "KyAuth Password")
            val datasetBuilder = Dataset.Builder(presentation)
            var hasValue = false
            fields.usernameId?.let {
                datasetBuilder.setValue(it, AutofillValue.forText(entry.username), presentation)
                hasValue = true
            }
            fields.passwordId?.let {
                datasetBuilder.setValue(it, AutofillValue.forText(entry.password), presentation)
                hasValue = true
            }
            if (hasValue) {
                responseBuilder.addDataset(datasetBuilder.build())
                added = true
            }
        }
        return if (added) responseBuilder.build() else null
    }

    fun presentation(context: Context, line1: String, line2: String): RemoteViews =
        RemoteViews(context.packageName, android.R.layout.simple_list_item_2).apply {
            setTextViewText(android.R.id.text1, line1)
            setTextViewText(android.R.id.text2, line2)
        }

    private fun traverse(node: AssistStructure.ViewNode, fields: ParsedFields) {
        node.webDomain?.let { fields.webDomain = it }
        // The package deliberately is not taken from the tree: only the activity component read in
        // parse() comes from the system. Without it there is no caller identity, and no fill.

        val hints = node.autofillHints?.toList().orEmpty()
        val isPasswordType = node.inputType and
            (InputType.TYPE_TEXT_VARIATION_PASSWORD or InputType.TYPE_TEXT_VARIATION_WEB_PASSWORD) != 0
        val isUsernameHint = hints.any {
            it.contains("username", ignoreCase = true) || it.contains("email", ignoreCase = true)
        }
        val isPasswordHint = hints.any { it.contains("password", ignoreCase = true) }

        if (isPasswordHint || isPasswordType) {
            fields.passwordId = node.autofillId
            node.autofillValue?.takeIf { it.isText }?.textValue?.toString()?.let { fields.passwordValue = it }
        } else if (isUsernameHint) {
            fields.usernameId = node.autofillId
            node.autofillValue?.takeIf { it.isText }?.textValue?.toString()?.let { fields.usernameValue = it }
        }

        for (i in 0 until node.childCount) {
            traverse(node.getChildAt(i), fields)
        }
    }
}
