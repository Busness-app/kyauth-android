package org.kysecurity.authenticator.passkeys

import android.app.PendingIntent
import android.app.slice.Slice
import android.app.slice.SliceSpec
import android.content.Intent
import android.credentials.ClearCredentialStateException
import android.credentials.CreateCredentialException
import android.credentials.GetCredentialException
import android.net.Uri
import android.os.Build
import android.os.CancellationSignal
import android.os.OutcomeReceiver
import android.service.credentials.Action
import android.service.credentials.BeginCreateCredentialRequest
import android.service.credentials.BeginCreateCredentialResponse
import android.service.credentials.BeginGetCredentialRequest
import android.service.credentials.BeginGetCredentialResponse
import android.service.credentials.ClearCredentialStateRequest
import android.service.credentials.CredentialProviderService
import androidx.annotation.RequiresApi
import java.io.File
import org.json.JSONObject
import org.kysecurity.authenticator.pairing.PairingStore
import org.kysecurity.authenticator.passwords.DomainMatcher
import org.kysecurity.authenticator.passwords.KdbxPasswordVault
import org.kysecurity.authenticator.passwords.KyAuthAutofillService
import org.kysecurity.authenticator.security.AppLockManager

/**
 * System Credential Provider.
 *
 * Enumerating credentials must not decrypt the vault. While KyAuth is locked this returns a single
 * authentication action; [CredentialUnlockActivity] produces the real entries once the user has
 * authenticated.
 */
@RequiresApi(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
class KyAuthCredentialProviderService : CredentialProviderService() {

    override fun onBeginGetCredential(
        request: BeginGetCredentialRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<BeginGetCredentialResponse, GetCredentialException>,
    ) {
        // Verifying a native caller against the relying party fetches over the network, so this
        // must not run on the binder thread.
        Thread { callback.onResult(buildGetResponse(request)) }.start()
    }

    private fun buildGetResponse(request: BeginGetCredentialRequest): BeginGetCredentialResponse {
        // EncryptedSharedPreferences can throw (GeneralSecurityException/IOException, e.g. after a
        // device restore or Keystore keyset invalidation); this runs before the vault check below,
        // so it must fail closed the same way rather than crashing the process.
        val signOnPasskey = runCatching { SignOnPasskeyStore(this).record() }.getOrNull()
        val serverUrl = runCatching { PairingStore(this).account()?.serverUrl }.getOrNull()
        val vaultKey = AppLockManager.getPasswordVaultKey()
        val entries = vaultKey?.let {
            runCatching {
                KdbxPasswordVault.loadEntries(File(filesDir, KyAuthAutofillService.VAULT_FILE_NAME), it)
            }.getOrNull()
        }
        // Nothing local to offer and no vault: short-circuit before the builder runs. The builder
        // can trigger a DigitalAssetLinks HTTPS fetch to a caller-named host, and a locked device
        // with no enrolled KySignOn passkey must not let an arbitrary native app cause that with no
        // user interaction.
        if (signOnPasskey == null && entries == null) {
            return BeginGetCredentialResponse.Builder()
                .addAuthenticationAction(unlockAction())
                .build()
        }
        // While the vault is unavailable the KySignOn passkey is still offered: it needs no vault
        // key, and routing it through "Unlock KyAuth" would make KySignOn MFA depend on the
        // password vault, which is exactly what this design removes.
        return CredentialEntryBuilder.build(
            context = this,
            request = request,
            entries = entries.orEmpty(),
            signOnPasskey = signOnPasskey,
            signOnServerUrl = serverUrl,
            authenticationAction = if (entries == null) unlockAction() else null,
        )
    }

    /** An invitation to authenticate; touches no vault material. */
    private fun unlockAction(): Action {
        val pendingIntent = PendingIntent.getActivity(
            this,
            3001,
            Intent(this, CredentialUnlockActivity::class.java),
            PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val spec = SliceSpec("kyauth", 1)
        val slice = Slice.Builder(Uri.parse("kyauth://unlock"), spec)
            .addAction(
                pendingIntent,
                Slice.Builder(Uri.parse("kyauth://unlock/action"), spec).build(),
                null,
            )
            .addText("Unlock KyAuth", null, listOf(Slice.HINT_TITLE))
            .addText("Authenticate to see your credentials", null, listOf(Slice.HINT_SUMMARY))
            .build()
        return Action(slice)
    }

    override fun onBeginCreateCredential(
        request: BeginCreateCredentialRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<BeginCreateCredentialResponse, CreateCredentialException>,
    ) {
        Thread { callback.onResult(buildCreateResponse(request)) }.start()
    }

    private fun buildCreateResponse(request: BeginCreateCredentialRequest): BeginCreateCredentialResponse {
        val callingAppInfo = request.callingAppInfo
        val origin = callingAppInfo?.origin
        val webOriginHost = ClientData.webOriginHost(origin)
        val callerPackage = callingAppInfo?.packageName
        val callerOrigin = origin ?: ClientData.apkKeyHashOrigin(callingAppInfo?.signingInfo)
        val responseBuilder = BeginCreateCredentialResponse.Builder()

        when (request.type) {
            CredentialEntryBuilder.TYPE_PUBLIC_KEY, CredentialEntryBuilder.TYPE_PUBLIC_KEY_ANDX -> {
                val requestJson = request.data.getString(CredentialEntryBuilder.BUNDLE_KEY_REQUEST_JSON)
                    ?: request.data.getString(CredentialEntryBuilder.BUNDLE_KEY_REQUEST_JSON_LEGACY).orEmpty()
                val json = runCatching { JSONObject(requestJson) }.getOrNull() ?: run {
                    return responseBuilder.build()
                }
                val rpId = RpId.validate(json.optJSONObject("rp")?.optString("id"), webOriginHost) ?: run {
                    // Refuse to mint a credential for an RP ID the caller has no claim to.
                    return responseBuilder.build()
                }
                if (webOriginHost == null &&
                    !DigitalAssetLinks.isCallerAuthorized(rpId, callerPackage, callingAppInfo?.signingInfo)
                ) {
                    return responseBuilder.build()
                }
                val isSignOn = SignOnPasskey.isSignOnRpId(rpId, PairingStore(this).account()?.serverUrl)
                val userObj = json.optJSONObject("user")
                val username = userObj?.optString("name")?.ifBlank { null }
                    ?: userObj?.optString("displayName").orEmpty()

                val title = if (isSignOn) {
                    "Create KySignOn Passkey"
                } else if (username.isNotBlank()) {
                    "Create Passkey for $username"
                } else {
                    "Create Passkey"
                }
                val subtitle = if (isSignOn) {
                    "Stays on this device, in secure hardware"
                } else {
                    "Save Passkey for $rpId in KyAuth"
                }

                val intent = Intent(this, CredentialAuthActivity::class.java).apply {
                    putExtra(
                        CredentialAuthActivity.EXTRA_ACTION,
                        if (isSignOn) {
                            CredentialAuthActivity.ACTION_CREATE_SIGNON_PASSKEY
                        } else {
                            CredentialAuthActivity.ACTION_CREATE_PASSKEY
                        },
                    )
                    putExtra(CredentialAuthActivity.EXTRA_REQUEST_JSON, requestJson)
                    putExtra(CredentialAuthActivity.EXTRA_RP_ID, rpId)
                    putExtra(CredentialAuthActivity.EXTRA_ORIGIN, callerOrigin)
                    putExtra(CredentialAuthActivity.EXTRA_CALLER_PACKAGE, callerPackage)
                    putExtra(
                        CredentialAuthActivity.EXTRA_CLIENT_DATA_HASH,
                        // Only a privileged browser may dictate the signed client data.
                        ClientData.privilegedClientDataHash(
                            origin,
                            request.data.getByteArray(CredentialEntryBuilder.BUNDLE_KEY_CLIENT_DATA_HASH),
                        ),
                    )
                    putExtra(CredentialAuthActivity.EXTRA_USERNAME, username)
                    putExtra(CredentialAuthActivity.EXTRA_DISPLAY_TITLE, title)
                    putExtra(CredentialAuthActivity.EXTRA_DISPLAY_SUBTITLE, subtitle)
                }

                responseBuilder.setCreateEntries(
                    listOf(
                        CredentialSliceHelper.createCreateCredentialEntry(
                            context = this,
                            request = request,
                            title = title,
                            subtitle = subtitle,
                            createIntent = intent,
                            requestCode = 2001,
                        ),
                    ),
                )
            }
            CredentialEntryBuilder.TYPE_PASSWORD, CredentialEntryBuilder.TYPE_PASSWORD_ANDX -> {
                val username = request.data.getString("androidx.credentials.BUNDLE_KEY_ID")
                    ?: request.data.getString("android.credentials.CreatePasswordRequest.BUNDLE_KEY_ID").orEmpty()
                val password = request.data.getString("androidx.credentials.BUNDLE_KEY_PASSWORD")
                    ?: request.data.getString("android.credentials.CreatePasswordRequest.BUNDLE_KEY_PASSWORD").orEmpty()
                val domain = webOriginHost ?: DomainMatcher.extractDomain(callerPackage) ?: run {
                    return responseBuilder.build()
                }
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

                responseBuilder.setCreateEntries(
                    listOf(
                        CredentialSliceHelper.createCreateCredentialEntry(
                            context = this,
                            request = request,
                            title = title,
                            subtitle = subtitle,
                            createIntent = intent,
                            requestCode = 2002,
                        ),
                    ),
                )
            }
        }

        return responseBuilder.build()
    }

    override fun onClearCredentialState(
        request: ClearCredentialStateRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<Void?, ClearCredentialStateException>,
    ) {
        callback.onResult(null)
    }
}
