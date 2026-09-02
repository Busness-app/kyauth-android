package org.kysecurity.authenticator.passkeys

import android.content.Context
import android.content.Intent
import android.content.pm.SigningInfo
import android.os.Build
import android.service.credentials.Action
import android.service.credentials.BeginGetCredentialOption
import android.service.credentials.BeginGetCredentialRequest
import android.service.credentials.BeginGetCredentialResponse
import androidx.annotation.RequiresApi
import org.json.JSONObject
import org.kysecurity.authenticator.passwords.DomainMatcher
import org.kysecurity.authenticator.passwords.PasswordEntry

/**
 * Deny-side test for whether vault passkeys should be suppressed for [rpId] because the request
 * is, www-insensitively, the paired KySignOn host.
 *
 * Deliberately more lenient than [SignOnPasskey.isSignOnRpId]: [DomainMatcher.matchesPasskey]
 * normalizes away a leading "www.", but [RpId.normalize] (which backs [SignOnPasskey.isSignOnRpId])
 * does not. An exact compare here would let a stranded vault passkey through whenever the request
 * and the paired host differ only by that prefix, in either direction. [SignOnPasskey.isSignOnRpId]
 * itself stays exact, because it also gates enrolment and routing to hardware, where this leniency
 * would widen the security boundary instead of only narrowing what the vault offers.
 *
 * A top-level internal function, not a method on [CredentialEntryBuilder]: kept pure and free of
 * this file's `@RequiresApi` framework surface so it stays trivially testable from a plain JVM
 * unit test (verified empirically to work fine even inside this file, but this is clearer intent).
 */
internal fun suppressesVaultPasskeys(rpId: String, signOnServerUrl: String?): Boolean {
    val paired = SignOnPasskey.signOnRpId(signOnServerUrl) ?: return false
    return DomainMatcher.normalizeHost(paired) == DomainMatcher.normalizeHost(rpId)
}

/**
 * Create-path guard: the request is the paired KySignOn host by the lenient test above, but is not
 * exactly routable to hardware by [SignOnPasskey.isSignOnRpId], so nothing may be minted for it.
 *
 * The two predicates disagree whenever the request and the paired host differ only by a leading
 * "www." — a real configuration, since the pairing URL and the server's `rp.id` are set
 * independently. Minting into `passwords_vault.kdbx` there would put a KySignOn login private key
 * into an exportable, KyPasswords-synced artifact, which is the exact outcome this design removes;
 * and the get path, which uses the lenient test, would then hide the entry anyway, leaving a
 * credential the server believes in and the device can never use. Refusing to create is the only
 * correct failure mode.
 */
internal fun refusesVaultPasskeyCreate(rpId: String, signOnServerUrl: String?): Boolean =
    suppressesVaultPasskeys(rpId, signOnServerUrl) && !SignOnPasskey.isSignOnRpId(rpId, signOnServerUrl)

/**
 * Turns a credential query into the entries offered to the user.
 *
 * The hardware-backed KySignOn passkey needs no vault key, so [KyAuthCredentialProviderService]
 * reaches this even while locked; the password-vault entries are added only when a vault is
 * supplied. [CredentialUnlockActivity] reaches this after authenticating, to add the vault
 * entries the service could not.
 */
@RequiresApi(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
object CredentialEntryBuilder {

    fun build(
        context: Context,
        request: BeginGetCredentialRequest,
        entries: List<PasswordEntry>,
        signOnPasskey: SignOnPasskeyRecord?,
        signOnServerUrl: String?,
        authenticationAction: Action? = null,
    ): BeginGetCredentialResponse {
        val callingAppInfo = request.callingAppInfo
        val origin = callingAppInfo?.origin
        val webOriginHost = ClientData.webOriginHost(origin)
        val callerPackage = callingAppInfo?.packageName
        val callerOrigin = origin ?: ClientData.apkKeyHashOrigin(callingAppInfo?.signingInfo)

        val responseBuilder = BeginGetCredentialResponse.Builder()
        authenticationAction?.let(responseBuilder::addAuthenticationAction)
        var requestCode = 1000
        for (option in request.beginGetCredentialOptions) {
            when (option.type) {
                TYPE_PUBLIC_KEY, TYPE_PUBLIC_KEY_ANDX ->
                    addPasskeyEntries(
                        context, option, entries, signOnPasskey, signOnServerUrl, webOriginHost,
                        callerPackage, callerOrigin, origin, callingAppInfo?.signingInfo,
                        responseBuilder, requestCode++,
                    )
                TYPE_PASSWORD, TYPE_PASSWORD_ANDX ->
                    addPasswordEntries(
                        context, option, entries, webOriginHost ?: callerPackage,
                        responseBuilder, requestCode++,
                    )
            }
        }
        return responseBuilder.build()
    }

    private fun addPasskeyEntries(
        context: Context,
        option: BeginGetCredentialOption,
        entries: List<PasswordEntry>,
        signOnPasskey: SignOnPasskeyRecord?,
        signOnServerUrl: String?,
        webOriginHost: String?,
        callerPackage: String?,
        callerOrigin: String?,
        callerWebOrigin: String?,
        callerSigningInfo: SigningInfo?,
        responseBuilder: BeginGetCredentialResponse.Builder,
        requestCode: Int,
    ) {
        val requestJson = option.candidateQueryData.getString(BUNDLE_KEY_REQUEST_JSON)
            ?: option.candidateQueryData.getString(BUNDLE_KEY_REQUEST_JSON_LEGACY).orEmpty()
        val json = runCatching { JSONObject(requestJson) }.getOrNull() ?: return

        // Fail closed: an RP ID we cannot validate against the caller gets no entries at all.
        val rpId = RpId.validate(json.optString("rpId"), webOriginHost) ?: return
        // Nothing here could be offered to this caller, so stop before the DigitalAssetLinks fetch
        // below: that fetch is an HTTPS request to a host the caller names, and an rpId unrelated to
        // anything we hold must short-circuit identically whether or not a KySignOn passkey is
        // enrolled. Otherwise a locked device answers "is one enrolled?" in the attacker's own
        // server log. Costs nothing when unlocked, where entries is normally non-empty.
        if (entries.isEmpty() && signOnPasskey?.rpId != rpId) return
        // A native caller named this RP itself; only the RP can confirm the claim.
        if (webOriginHost == null &&
            !DigitalAssetLinks.isCallerAuthorized(rpId, callerPackage, callerSigningInfo)
        ) {
            return
        }
        // Only a privileged browser may dictate the signed client data; see ClientData.
        val clientDataHash = ClientData.privilegedClientDataHash(
            callerWebOrigin,
            option.candidateQueryData.getByteArray(BUNDLE_KEY_CLIENT_DATA_HASH),
        )

        // The hardware-backed KySignOn passkey. Offered without any vault key, so it survives the
        // password vault being locked, compromised, or in recovery.
        if (signOnPasskey != null && signOnPasskey.rpId == rpId) {
            val title = signOnPasskey.username.ifBlank { rpId }
            val intent = Intent(context, CredentialAuthActivity::class.java).apply {
                putExtra(CredentialAuthActivity.EXTRA_ACTION, CredentialAuthActivity.ACTION_GET_SIGNON_PASSKEY)
                putExtra(CredentialAuthActivity.EXTRA_REQUEST_JSON, requestJson)
                putExtra(CredentialAuthActivity.EXTRA_RP_ID, rpId)
                putExtra(CredentialAuthActivity.EXTRA_ORIGIN, callerOrigin)
                putExtra(CredentialAuthActivity.EXTRA_CALLER_PACKAGE, callerPackage)
                putExtra(CredentialAuthActivity.EXTRA_CLIENT_DATA_HASH, clientDataHash)
                putExtra(CredentialAuthActivity.EXTRA_DISPLAY_TITLE, "Sign in to KySignOn")
                putExtra(CredentialAuthActivity.EXTRA_DISPLAY_SUBTITLE, "$title (Passkey • this device)")
            }
            responseBuilder.addCredentialEntry(
                CredentialSliceHelper.createGetCredentialEntry(
                    context = context,
                    option = option,
                    title = title,
                    subtitle = "Passkey • this device",
                    fillIntent = intent,
                    requestCode = requestCode + 500,
                ),
            )
        }

        // A KySignOn passkey in the synced vault is never offered: it must be re-enrolled into
        // secure hardware. See suppressesVaultPasskeys for why this is www-insensitive on both
        // sides, unlike SignOnPasskey.isSignOnRpId.
        if (!suppressesVaultPasskeys(rpId, signOnServerUrl)) {
            val matches = entries.filter { DomainMatcher.matchesPasskey(it, rpId) }
            for ((index, entry) in matches.withIndex()) {
                val passkey = entry.passkey ?: continue
                val title = passkey.username.ifBlank { entry.title }
                val intent = Intent(context, CredentialAuthActivity::class.java).apply {
                    putExtra(CredentialAuthActivity.EXTRA_ACTION, CredentialAuthActivity.ACTION_GET_PASSKEY)
                    putExtra(CredentialAuthActivity.EXTRA_ENTRY_ID, entry.id)
                    putExtra(CredentialAuthActivity.EXTRA_REQUEST_JSON, requestJson)
                    putExtra(CredentialAuthActivity.EXTRA_RP_ID, rpId)
                    putExtra(CredentialAuthActivity.EXTRA_ORIGIN, callerOrigin)
                    putExtra(CredentialAuthActivity.EXTRA_CALLER_PACKAGE, callerPackage)
                    putExtra(CredentialAuthActivity.EXTRA_CLIENT_DATA_HASH, clientDataHash)
                    putExtra(CredentialAuthActivity.EXTRA_DISPLAY_TITLE, "Sign in with Passkey")
                    putExtra(CredentialAuthActivity.EXTRA_DISPLAY_SUBTITLE, "$title (Passkey • $rpId)")
                }
                responseBuilder.addCredentialEntry(
                    CredentialSliceHelper.createGetCredentialEntry(
                        context = context,
                        option = option,
                        title = title,
                        subtitle = "Passkey • $rpId",
                        fillIntent = intent,
                        // PendingIntent identity is requestCode + Intent.filterEquals; extras are not
                        // part of that identity and both intents target the same Activity. Without a
                        // distinct code per entry, FLAG_UPDATE_CURRENT collapses every row here onto
                        // one PendingIntent, so all of them would fire the last entry's extras.
                        requestCode = requestCode * 1000 + index,
                    ),
                )
            }
        }
    }

    private fun addPasswordEntries(
        context: Context,
        option: BeginGetCredentialOption,
        entries: List<PasswordEntry>,
        origin: String?,
        responseBuilder: BeginGetCredentialResponse.Builder,
        requestCode: Int,
    ) {
        val domain = DomainMatcher.extractDomain(origin) ?: return
        val matches = entries.filter { it.password.isNotBlank() && DomainMatcher.matchesPassword(it, domain) }
        for ((index, entry) in matches.withIndex()) {
            val title = entry.username.ifBlank { entry.title }
            val intent = Intent(context, CredentialAuthActivity::class.java).apply {
                putExtra(CredentialAuthActivity.EXTRA_ACTION, CredentialAuthActivity.ACTION_GET_PASSWORD)
                putExtra(CredentialAuthActivity.EXTRA_ENTRY_ID, entry.id)
                putExtra(CredentialAuthActivity.EXTRA_DISPLAY_TITLE, "Autofill Password")
                putExtra(CredentialAuthActivity.EXTRA_DISPLAY_SUBTITLE, "$title (${entry.title})")
            }
            responseBuilder.addCredentialEntry(
                CredentialSliceHelper.createGetCredentialEntry(
                    context = context,
                    option = option,
                    title = title,
                    subtitle = "Password • ${entry.title}",
                    fillIntent = intent,
                    // Same reason as the passkey loop above: without a distinct code per entry
                    // every row collapses onto one PendingIntent and they all fire the last
                    // entry's extras. Each option gets its own requestCode, so this cannot
                    // collide with the passkey codes or with the local entry's requestCode + 500.
                    requestCode = requestCode * 1000 + index,
                ),
            )
        }
    }

    const val TYPE_PUBLIC_KEY = "android.credentials.TYPE_PUBLIC_KEY_CREDENTIAL"
    const val TYPE_PUBLIC_KEY_ANDX = "androidx.credentials.TYPE_PUBLIC_KEY_CREDENTIAL"
    const val TYPE_PASSWORD = "android.credentials.TYPE_PASSWORD_CREDENTIAL"
    const val TYPE_PASSWORD_ANDX = "androidx.credentials.TYPE_PASSWORD_CREDENTIAL"

    const val BUNDLE_KEY_REQUEST_JSON = "androidx.credentials.BUNDLE_KEY_REQUEST_JSON"
    const val BUNDLE_KEY_REQUEST_JSON_LEGACY =
        "android.credentials.GetPublicKeyCredentialOption.BUNDLE_KEY_REQUEST_JSON"
    const val BUNDLE_KEY_CLIENT_DATA_HASH = "androidx.credentials.BUNDLE_KEY_CLIENT_DATA_HASH"
}
