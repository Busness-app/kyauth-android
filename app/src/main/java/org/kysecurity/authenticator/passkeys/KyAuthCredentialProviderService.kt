package org.kysecurity.authenticator.passkeys

import android.content.Intent
import android.credentials.ClearCredentialStateException
import android.credentials.CreateCredentialException
import android.credentials.GetCredentialException
import android.os.Build
import android.os.CancellationSignal
import android.os.OutcomeReceiver
import androidx.annotation.RequiresApi
import android.service.credentials.BeginCreateCredentialRequest
import android.service.credentials.BeginCreateCredentialResponse
import android.service.credentials.BeginGetCredentialOption
import android.service.credentials.BeginGetCredentialRequest
import android.service.credentials.BeginGetCredentialResponse
import android.service.credentials.ClearCredentialStateRequest
import android.service.credentials.CredentialProviderService
import java.io.File
import org.json.JSONObject
import org.kysecurity.authenticator.passwords.DomainMatcher
import org.kysecurity.authenticator.passwords.KdbxPasswordVault
import org.kysecurity.authenticator.passwords.PasswordEntry
import org.kysecurity.authenticator.security.AppLockManager

@RequiresApi(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
class KyAuthCredentialProviderService : CredentialProviderService() {

    override fun onBeginGetCredential(
        request: BeginGetCredentialRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<BeginGetCredentialResponse, GetCredentialException>,
    ) {
        val responseBuilder = BeginGetCredentialResponse.Builder()
        val entries = loadVaultEntries()

        var requestCode = 1000
        for (option in request.beginGetCredentialOptions) {
            when (option.type) {
                TYPE_PUBLIC_KEY_CREDENTIAL, TYPE_PUBLIC_KEY_CREDENTIAL_ANDX -> {
                    handlePublicKeyGetOption(option, entries, responseBuilder, requestCode++)
                }
                TYPE_PASSWORD_CREDENTIAL, TYPE_PASSWORD_CREDENTIAL_ANDX -> {
                    val origin = request.callingAppInfo?.origin ?: request.callingAppInfo?.packageName
                    handlePasswordGetOption(option, origin, entries, responseBuilder, requestCode++)
                }
            }
        }

        callback.onResult(responseBuilder.build())
    }

    override fun onBeginCreateCredential(
        request: BeginCreateCredentialRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<BeginCreateCredentialResponse, CreateCredentialException>,
    ) {
        val responseBuilder = BeginCreateCredentialResponse.Builder()
        val callingOrigin = request.callingAppInfo?.origin ?: request.callingAppInfo?.packageName.orEmpty()

        when (request.type) {
            TYPE_PUBLIC_KEY_CREDENTIAL, TYPE_PUBLIC_KEY_CREDENTIAL_ANDX -> {
                val requestJson = request.data.getString(BUNDLE_KEY_REQUEST_JSON)
                    ?: request.data.getString(BUNDLE_KEY_REQUEST_JSON_LEGACY).orEmpty()
                val json = runCatching { JSONObject(requestJson) }.getOrDefault(JSONObject())
                val rpId = json.optJSONObject("rp")?.optString("id")?.ifBlank { null }
                    ?: DomainMatcher.extractDomain(callingOrigin)
                    ?: callingOrigin
                val userObj = json.optJSONObject("user")
                val username = userObj?.optString("name") ?: userObj?.optString("displayName").orEmpty()

                val title = if (username.isNotBlank()) "Create Passkey for $username" else "Create Passkey"
                val subtitle = "Save Passkey for $rpId in KyAuth"

                val intent = Intent(this, CredentialAuthActivity::class.java).apply {
                    putExtra(CredentialAuthActivity.EXTRA_ACTION, CredentialAuthActivity.ACTION_CREATE_PASSKEY)
                    putExtra(CredentialAuthActivity.EXTRA_REQUEST_JSON, requestJson)
                    putExtra(CredentialAuthActivity.EXTRA_RP_ID, rpId)
                    putExtra(CredentialAuthActivity.EXTRA_USERNAME, username)
                    putExtra(CredentialAuthActivity.EXTRA_DISPLAY_TITLE, title)
                    putExtra(CredentialAuthActivity.EXTRA_DISPLAY_SUBTITLE, subtitle)
                }

                val createEntry = CredentialSliceHelper.createCreateCredentialEntry(
                    context = this,
                    request = request,
                    title = title,
                    subtitle = subtitle,
                    createIntent = intent,
                    requestCode = 2001,
                )
                responseBuilder.setCreateEntries(listOf(createEntry))
            }
            TYPE_PASSWORD_CREDENTIAL, TYPE_PASSWORD_CREDENTIAL_ANDX -> {
                val username = request.data.getString("androidx.credentials.BUNDLE_KEY_ID")
                    ?: request.data.getString("android.credentials.CreatePasswordRequest.BUNDLE_KEY_ID").orEmpty()
                val password = request.data.getString("androidx.credentials.BUNDLE_KEY_PASSWORD")
                    ?: request.data.getString("android.credentials.CreatePasswordRequest.BUNDLE_KEY_PASSWORD").orEmpty()
                val domain = DomainMatcher.extractDomain(callingOrigin) ?: callingOrigin
                val title = if (username.isNotBlank()) "Save Password for $username" else "Save Password to KyAuth"
                val subtitle = "Save credentials for $domain"

                val intent = Intent(this, CredentialAuthActivity::class.java).apply {
                    putExtra(CredentialAuthActivity.EXTRA_ACTION, CredentialAuthActivity.ACTION_CREATE_PASSWORD)
                    putExtra(CredentialAuthActivity.EXTRA_DOMAIN, domain)
                    putExtra(CredentialAuthActivity.EXTRA_USERNAME, username)
                    putExtra(CredentialAuthActivity.EXTRA_PASSWORD, password)
                    putExtra(CredentialAuthActivity.EXTRA_DISPLAY_TITLE, title)
                    putExtra(CredentialAuthActivity.EXTRA_DISPLAY_SUBTITLE, subtitle)
                }

                val createEntry = CredentialSliceHelper.createCreateCredentialEntry(
                    context = this,
                    request = request,
                    title = title,
                    subtitle = subtitle,
                    createIntent = intent,
                    requestCode = 2002,
                )
                responseBuilder.setCreateEntries(listOf(createEntry))
            }
        }

        callback.onResult(responseBuilder.build())
    }

    override fun onClearCredentialState(
        request: ClearCredentialStateRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<Void?, ClearCredentialStateException>,
    ) {
        callback.onResult(null)
    }

    private fun handlePublicKeyGetOption(
        option: BeginGetCredentialOption,
        entries: List<PasswordEntry>,
        responseBuilder: BeginGetCredentialResponse.Builder,
        requestCode: Int,
    ) {
        val requestJson = option.candidateQueryData.getString(BUNDLE_KEY_REQUEST_JSON)
            ?: option.candidateQueryData.getString(BUNDLE_KEY_REQUEST_JSON_LEGACY).orEmpty()
        val json = runCatching { JSONObject(requestJson) }.getOrDefault(JSONObject())
        val rpId = json.optString("rpId").ifBlank { null }

        val matchingEntries = entries.filter { entry ->
            entry.isPasskey && (rpId == null || DomainMatcher.matches(entry, rpId))
        }

        for (entry in matchingEntries) {
            val passkey = entry.passkey ?: continue
            val title = if (passkey.username.isNotBlank()) passkey.username else entry.title
            val subtitle = "Passkey • ${passkey.rpId}"

            val intent = Intent(this, CredentialAuthActivity::class.java).apply {
                putExtra(CredentialAuthActivity.EXTRA_ACTION, CredentialAuthActivity.ACTION_GET_PASSKEY)
                putExtra(CredentialAuthActivity.EXTRA_ENTRY_ID, entry.id)
                putExtra(CredentialAuthActivity.EXTRA_REQUEST_JSON, requestJson)
                putExtra(CredentialAuthActivity.EXTRA_DISPLAY_TITLE, "Sign in with Passkey")
                putExtra(CredentialAuthActivity.EXTRA_DISPLAY_SUBTITLE, "$title ($subtitle)")
            }

            val credentialEntry = CredentialSliceHelper.createGetCredentialEntry(
                context = this,
                option = option,
                title = title,
                subtitle = subtitle,
                fillIntent = intent,
                requestCode = requestCode,
            )
            responseBuilder.addCredentialEntry(credentialEntry)
        }
    }

    private fun handlePasswordGetOption(
        option: BeginGetCredentialOption,
        origin: String?,
        entries: List<PasswordEntry>,
        responseBuilder: BeginGetCredentialResponse.Builder,
        requestCode: Int,
    ) {
        val domain = DomainMatcher.extractDomain(origin)
        val matchingEntries = entries.filter { entry ->
            entry.password.isNotBlank() && (domain == null || DomainMatcher.matches(entry, domain))
        }

        for (entry in matchingEntries) {
            val title = entry.username.ifBlank { entry.title }
            val subtitle = "Password • ${entry.title}"

            val intent = Intent(this, CredentialAuthActivity::class.java).apply {
                putExtra(CredentialAuthActivity.EXTRA_ACTION, CredentialAuthActivity.ACTION_GET_PASSWORD)
                putExtra(CredentialAuthActivity.EXTRA_ENTRY_ID, entry.id)
                putExtra(CredentialAuthActivity.EXTRA_DISPLAY_TITLE, "Autofill Password")
                putExtra(CredentialAuthActivity.EXTRA_DISPLAY_SUBTITLE, "$title ($subtitle)")
            }

            val credentialEntry = CredentialSliceHelper.createGetCredentialEntry(
                context = this,
                option = option,
                title = title,
                subtitle = subtitle,
                fillIntent = intent,
                requestCode = requestCode,
            )
            responseBuilder.addCredentialEntry(credentialEntry)
        }
    }

    private fun loadVaultEntries(): List<PasswordEntry> {
        val vaultKey = AppLockManager.getPasswordVaultKey() ?: AppLockManager.ensurePasswordVaultKeyInitialized(applicationContext)
            ?: return emptyList()
        val vaultFile = File(filesDir, "passwords_vault.kdbx")
        return runCatching { KdbxPasswordVault.loadEntries(vaultFile, vaultKey) }.getOrDefault(emptyList())
    }

    companion object {
        const val TYPE_PUBLIC_KEY_CREDENTIAL = "android.credentials.TYPE_PUBLIC_KEY_CREDENTIAL"
        const val TYPE_PUBLIC_KEY_CREDENTIAL_ANDX = "androidx.credentials.TYPE_PUBLIC_KEY_CREDENTIAL"
        const val TYPE_PASSWORD_CREDENTIAL = "android.credentials.TYPE_PASSWORD_CREDENTIAL"
        const val TYPE_PASSWORD_CREDENTIAL_ANDX = "androidx.credentials.TYPE_PASSWORD_CREDENTIAL"

        const val BUNDLE_KEY_REQUEST_JSON = "androidx.credentials.BUNDLE_KEY_REQUEST_JSON"
        const val BUNDLE_KEY_REQUEST_JSON_LEGACY = "android.credentials.GetPublicKeyCredentialOption.BUNDLE_KEY_REQUEST_JSON"
    }
}
