package org.kysecurity.authenticator.passkeys

import android.app.Activity
import android.content.Intent
import android.credentials.CreateCredentialException
import android.credentials.CreateCredentialResponse
import android.credentials.Credential
import android.credentials.GetCredentialException
import android.credentials.GetCredentialResponse
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.os.Build
import android.os.Bundle
import androidx.annotation.RequiresApi
import android.service.credentials.CredentialProviderService
import android.text.InputType
import android.util.Base64
import android.util.TypedValue
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.EditText
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import java.io.File
import java.nio.charset.StandardCharsets
import java.security.interfaces.ECPublicKey
import java.util.UUID
import javax.crypto.Cipher
import org.json.JSONObject
import org.kysecurity.authenticator.R
import org.kysecurity.authenticator.ThemeManager
import org.kysecurity.authenticator.passwords.DomainMatcher
import org.kysecurity.authenticator.passwords.KdbxPasswordVault
import org.kysecurity.authenticator.passwords.KyAuthAutofillService
import org.kysecurity.authenticator.passwords.PasskeyData
import org.kysecurity.authenticator.passwords.PasswordEntry
import org.kysecurity.authenticator.passwords.PasswordGenerator
import org.kysecurity.authenticator.passwords.upserted
import org.kysecurity.authenticator.security.AppLockManager
import org.kysecurity.authenticator.security.VaultUnlockPrompt

@RequiresApi(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
class CredentialAuthActivity : AppCompatActivity() {

    private lateinit var usernameInput: EditText
    private lateinit var passwordInput: EditText

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val action = intent.getStringExtra(EXTRA_ACTION) ?: run {
            finishWithFailure("Invalid credential action")
            return
        }

        val promptTitle = intent.getStringExtra(EXTRA_DISPLAY_TITLE) ?: "KyAuth Verification"
        val promptSubtitle = intent.getStringExtra(EXTRA_DISPLAY_SUBTITLE) ?: ""
        val isCreation = action == ACTION_CREATE_PASSWORD || action == ACTION_CREATE_PASSKEY

        val rootLayout = FrameLayout(this).apply {
            layoutParams = ViewGroup.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT)
            setBackgroundColor(0x99000000.toInt())
        }

        val density = resources.displayMetrics.density
        val card = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            val pad = (24 * density).toInt()
            setPadding(pad, pad, pad, pad)
            background = GradientDrawable().apply {
                setColor(ThemeManager.color(this@CredentialAuthActivity, R.color.ky_surface))
                cornerRadius = 24 * density
                setStroke((1 * density).toInt(), ThemeManager.color(this@CredentialAuthActivity, R.color.ky_border))
            }
            layoutParams = FrameLayout.LayoutParams(
                (360 * density).toInt(),
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply {
                gravity = Gravity.CENTER
            }
        }

        val appLabel = TextView(this).apply {
            text = "KyAuth"
            setTextColor(ThemeManager.color(this@CredentialAuthActivity, R.color.ky_cyan))
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 14f)
            typeface = Typeface.DEFAULT_BOLD
            gravity = Gravity.CENTER
        }
        card.addView(appLabel)

        val titleView = TextView(this).apply {
            text = promptTitle
            setTextColor(ThemeManager.color(this@CredentialAuthActivity, R.color.ky_text))
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 18f)
            typeface = Typeface.DEFAULT_BOLD
            gravity = Gravity.CENTER
            setPadding(0, (8 * density).toInt(), 0, 0)
        }
        card.addView(titleView)

        val subtitleView = TextView(this).apply {
            text = promptSubtitle
            setTextColor(ThemeManager.color(this@CredentialAuthActivity, R.color.ky_muted))
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 14f)
            gravity = Gravity.CENTER
            setPadding(0, (4 * density).toInt(), 0, (16 * density).toInt())
        }
        card.addView(subtitleView)

        if (action == ACTION_CREATE_PASSWORD) {
            val initialUser = intent.getStringExtra(EXTRA_USERNAME).orEmpty()
            val initialPass = intent.getStringExtra(EXTRA_PASSWORD).orEmpty()

            usernameInput = EditText(this).apply {
                hint = "Username or email"
                setText(initialUser)
                styleInputField(this, density)
            }
            card.addView(usernameInput, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, (48 * density).toInt()).apply {
                bottomMargin = (10 * density).toInt()
            })

            passwordInput = EditText(this).apply {
                hint = "Password"
                setText(initialPass)
                inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
                styleInputField(this, density)
            }
            card.addView(passwordInput, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, (48 * density).toInt()).apply {
                bottomMargin = (10 * density).toInt()
            })

            val generateButton = Button(this).apply {
                text = "Generate Strong Password"
                setTextColor(ThemeManager.color(this@CredentialAuthActivity, R.color.ky_cyan))
                background = GradientDrawable().apply {
                    setColor(ThemeManager.color(this@CredentialAuthActivity, R.color.ky_surface_elevated))
                    cornerRadius = 12 * density
                }
                setOnClickListener {
                    val generated = PasswordGenerator.generate(20)
                    passwordInput.setText(generated)
                    passwordInput.inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD
                }
            }
            card.addView(generateButton, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, (42 * density).toInt()).apply {
                bottomMargin = (18 * density).toInt()
            })
        } else if (action == ACTION_CREATE_PASSKEY) {
            val initialUser = intent.getStringExtra(EXTRA_USERNAME).orEmpty()
            usernameInput = EditText(this).apply {
                hint = "Username or display name"
                setText(initialUser)
                styleInputField(this, density)
            }
            card.addView(usernameInput, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, (48 * density).toInt()).apply {
                bottomMargin = (18 * density).toInt()
            })
        }

        val buttonContainer = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER
        }

        val cancelButton = Button(this).apply {
            text = "Cancel"
            setTextColor(ThemeManager.color(this@CredentialAuthActivity, R.color.ky_muted))
            background = GradientDrawable().apply {
                setColor(ThemeManager.color(this@CredentialAuthActivity, R.color.ky_surface_elevated))
                cornerRadius = 14 * density
            }
            setOnClickListener { finishWithCancellation() }
            layoutParams = LinearLayout.LayoutParams(0, (48 * density).toInt(), 1f).apply {
                marginEnd = (8 * density).toInt()
            }
        }
        buttonContainer.addView(cancelButton)

        val confirmButton = Button(this).apply {
            text = if (isCreation) "Save" else "Verify"
            setTextColor(ThemeManager.buttonText(this@CredentialAuthActivity))
            background = GradientDrawable().apply {
                setColor(ThemeManager.color(this@CredentialAuthActivity, R.color.ky_cyan))
                cornerRadius = 14 * density
            }
            setOnClickListener { authenticateAndExecute(action) }
            layoutParams = LinearLayout.LayoutParams(0, (48 * density).toInt(), 1f).apply {
                marginStart = (8 * density).toInt()
            }
        }
        buttonContainer.addView(confirmButton)
        card.addView(buttonContainer)

        val scrollView = ScrollView(this).apply {
            layoutParams = FrameLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                gravity = Gravity.CENTER
            }
            addView(card)
        }
        rootLayout.addView(scrollView)
        setContentView(rootLayout)

        // For retrieval, automatically prompt for fast 1-tap UX
        if (!isCreation) {
            authenticateAndExecute(action)
        }
    }

    private fun styleInputField(editText: EditText, density: Float) {
        editText.setTextColor(ThemeManager.color(this, R.color.ky_text))
        editText.setHintTextColor(ThemeManager.color(this, R.color.ky_muted))
        editText.setTextSize(TypedValue.COMPLEX_UNIT_SP, 15f)
        val padH = (14 * density).toInt()
        val padV = (10 * density).toInt()
        editText.setPadding(padH, padV, padH, padV)
        editText.background = GradientDrawable().apply {
            setColor(ThemeManager.color(this@CredentialAuthActivity, R.color.ky_surface_elevated))
            cornerRadius = 12 * density
            setStroke((1 * density).toInt(), ThemeManager.color(this@CredentialAuthActivity, R.color.ky_border))
        }
    }

    private fun authenticateAndExecute(action: String) {
        val isCreation = action == ACTION_CREATE_PASSWORD || action == ACTION_CREATE_PASSKEY
        VaultUnlockPrompt.show(
            activity = this,
            subtitle = intent.getStringExtra(EXTRA_DISPLAY_TITLE) ?: "Authenticate to proceed",
            onAuthenticated = { cipher -> executeCredentialAction(action, cipher) },
            onFailed = { message ->
                if (isCreation) {
                    Toast.makeText(applicationContext, message, Toast.LENGTH_SHORT).show()
                } else {
                    finishWithCancellation()
                }
            },
        )
    }

    /**
     * Opens the vault for this one request. The keys are erased when the block returns, so the
     * process is never left holding vault material after a credential operation, and every
     * mutation runs inside one [KdbxPasswordVault.update] transaction.
     */
    private fun executeCredentialAction(action: String, cipher: Cipher) {
        val vaultFile = File(filesDir, KyAuthAutofillService.VAULT_FILE_NAME)
        val ran = AppLockManager.useVaultKeys(applicationContext, cipher) { keys ->
            val vaultKey = keys.passwords ?: return@useVaultKeys false
            runCatching {
                when (action) {
                    ACTION_GET_PASSWORD -> handleGetPassword(KdbxPasswordVault.loadEntries(vaultFile, vaultKey))
                    ACTION_GET_PASSKEY -> KdbxPasswordVault.update(vaultFile, vaultKey, ::handleGetPasskey)
                    ACTION_CREATE_PASSKEY -> KdbxPasswordVault.update(vaultFile, vaultKey, ::handleCreatePasskey)
                    ACTION_CREATE_PASSWORD -> KdbxPasswordVault.update(vaultFile, vaultKey, ::handleCreatePassword)
                    else -> finishWithFailure("Unknown credential action: $action")
                }
            }.isSuccess
        }
        if (ran != true) finishWithFailure("The KyAuth vault is locked or unreadable")
    }

    private fun handleGetPasskey(entries: MutableList<PasswordEntry>): Boolean {
        val index = entries.indexOfFirst { it.id == intent.getStringExtra(EXTRA_ENTRY_ID) }
        if (index < 0) return failed("Passkey entry not found")
        val entry = entries[index]
        val passkey = entry.passkey ?: return failed("Entry is missing passkey data")

        val requestJson = intent.getStringExtra(EXTRA_REQUEST_JSON).orEmpty()
        val json = runCatching { JSONObject(requestJson) }.getOrNull()
            ?: return failed("Malformed passkey request")

        val rpId = intent.getStringExtra(EXTRA_RP_ID)?.takeIf { it.isNotBlank() }
            ?: return failed("Request has no relying party")
        if (RpId.normalize(json.optString("rpId")) != rpId) {
            return failed("Relying party does not match the request")
        }
        if (!DomainMatcher.matchesPasskey(entry, rpId)) {
            return failed("This passkey does not belong to $rpId")
        }

        val challenge = json.optString("challenge").takeIf { it.isNotBlank() }
            ?: return failed("Request has no challenge")

        // A privileged caller supplies the hash it already committed to; otherwise KyAuth builds
        // the CollectedClientData itself and returns the exact bytes it hashed.
        val callerHash = intent.privilegedClientDataHash()
        val clientDataJson = if (callerHash != null) {
            null
        } else {
            val origin = intent.getStringExtra(EXTRA_ORIGIN)?.takeIf { it.isNotBlank() }
                ?: return failed("Caller origin is unavailable")
            ClientData.serialize(
                ClientData.TYPE_GET,
                challenge,
                origin,
                intent.getStringExtra(EXTRA_CALLER_PACKAGE),
            )
        }
        val clientDataHash = callerHash ?: WebAuthnEngine.sha256(requireNotNull(clientDataJson))

        val privateKey = runCatching { WebAuthnEngine.restorePrivateKey(passkey.privateKeyPkcs8) }.getOrNull()
            ?: return failed("Corrupted private key")

        val newSignCount = passkey.signCount + 1
        val authData = WebAuthnEngine.buildAssertionAuthData(passkey.rpId, newSignCount)
        val signature = WebAuthnEngine.signAssertion(privateKey, authData, clientDataHash)

        entries[index] = entry.copy(passkey = passkey.copy(signCount = newSignCount))

        val responseJson = JSONObject().apply {
            put("id", b64(passkey.credentialId))
            put("rawId", b64(passkey.credentialId))
            put("type", "public-key")
            put(
                "response",
                JSONObject().apply {
                    put("authenticatorData", b64(authData))
                    put("signature", b64(signature))
                    if (passkey.userHandle.isNotEmpty()) put("userHandle", b64(passkey.userHandle))
                    if (clientDataJson != null) put("clientDataJSON", b64(clientDataJson))
                },
            )
        }

        val data = Bundle().apply {
            putString("androidx.credentials.BUNDLE_KEY_AUTHENTICATION_RESPONSE_JSON", responseJson.toString())
        }
        setResult(
            Activity.RESULT_OK,
            Intent().putExtra(
                CredentialProviderService.EXTRA_GET_CREDENTIAL_RESPONSE,
                GetCredentialResponse(Credential(TYPE_PUBLIC_KEY_CREDENTIAL, data)),
            ),
        )
        finish()
        return true
    }

    private fun handleGetPassword(entries: List<PasswordEntry>) {
        val entry = entries.find { it.id == intent.getStringExtra(EXTRA_ENTRY_ID) }
            ?: return finishWithFailure("Password entry not found")

        val data = Bundle().apply {
            putString("androidx.credentials.BUNDLE_KEY_ID", entry.username)
            putString("androidx.credentials.BUNDLE_KEY_PASSWORD", entry.password)
        }
        setResult(
            Activity.RESULT_OK,
            Intent().putExtra(
                CredentialProviderService.EXTRA_GET_CREDENTIAL_RESPONSE,
                GetCredentialResponse(Credential(TYPE_PASSWORD_CREDENTIAL, data)),
            ),
        )
        finish()
    }

    private fun handleCreatePasskey(entries: MutableList<PasswordEntry>): Boolean {
        val requestJson = intent.getStringExtra(EXTRA_REQUEST_JSON).orEmpty()
        val json = runCatching { JSONObject(requestJson) }.getOrNull()
            ?: return failed("Malformed passkey request")

        val rpId = intent.getStringExtra(EXTRA_RP_ID)?.takeIf { it.isNotBlank() }
            ?: return failed("Request has no relying party")
        if (RpId.normalize(json.optJSONObject("rp")?.optString("id")) != rpId) {
            return failed("Relying party does not match the request")
        }

        val challenge = json.optString("challenge").takeIf { it.isNotBlank() }
            ?: return failed("Request has no challenge")

        val clientDataJson = if (intent.privilegedClientDataHash() != null) {
            null
        } else {
            val origin = intent.getStringExtra(EXTRA_ORIGIN)?.takeIf { it.isNotBlank() }
                ?: return failed("Caller origin is unavailable")
            ClientData.serialize(
                ClientData.TYPE_CREATE,
                challenge,
                origin,
                intent.getStringExtra(EXTRA_CALLER_PACKAGE),
            )
        }

        val userObj = json.optJSONObject("user")
        val fallbackUsername = userObj?.optString("name")?.ifBlank { null }
            ?: userObj?.optString("displayName")?.ifBlank { null }
            ?: intent.getStringExtra(EXTRA_USERNAME).orEmpty()
        val username = if (::usernameInput.isInitialized) usernameInput.text.toString().trim() else fallbackUsername

        val userHandleStr = userObj?.optString("id")
        val userHandle = if (!userHandleStr.isNullOrBlank()) {
            runCatching { Base64.decode(userHandleStr, B64_FLAGS) }
                .getOrDefault(userHandleStr.toByteArray(StandardCharsets.UTF_8))
        } else {
            ByteArray(0)
        }

        val keyPair = WebAuthnEngine.generateEcKeyPair()
        val credentialId = WebAuthnEngine.generateCredentialId()
        val authData = WebAuthnEngine.buildRegistrationAuthData(
            rpId = rpId,
            signCount = 0,
            credentialId = credentialId,
            cosePublicKey = WebAuthnEngine.encodeCosePublicKey(keyPair.public as ECPublicKey),
        )
        val attestationObject = WebAuthnEngine.buildAttestationObject(authData)

        val passkeyData = PasskeyData(
            rpId = rpId,
            username = username,
            userHandle = userHandle,
            credentialId = credentialId,
            privateKeyPkcs8 = keyPair.private.encoded,
            signCount = 0,
        )

        val existingIndex = entries.indexOfFirst {
            DomainMatcher.matchesPasskey(it, rpId) && it.username.equals(username, ignoreCase = true)
        }
        if (existingIndex >= 0) {
            val existing = entries[existingIndex]
            entries[existingIndex] = existing.copy(passkey = passkeyData, url = existing.url ?: "https://$rpId")
        } else {
            entries.add(
                PasswordEntry(
                    title = if (username.isNotBlank()) "$rpId ($username)" else rpId,
                    username = username,
                    passkey = passkeyData,
                    url = "https://$rpId",
                    id = UUID.randomUUID().toString(),
                ),
            )
        }
        val responseJson = JSONObject().apply {
            put("id", b64(credentialId))
            put("rawId", b64(credentialId))
            put("type", "public-key")
            put(
                "response",
                JSONObject().apply {
                    put("attestationObject", b64(attestationObject))
                    if (clientDataJson != null) put("clientDataJSON", b64(clientDataJson))
                },
            )
        }

        val data = Bundle().apply {
            putString("androidx.credentials.BUNDLE_KEY_REGISTRATION_RESPONSE_JSON", responseJson.toString())
        }
        setResult(
            Activity.RESULT_OK,
            Intent().putExtra(
                CredentialProviderService.EXTRA_CREATE_CREDENTIAL_RESPONSE,
                CreateCredentialResponse(data),
            ),
        )
        finish()
        return true
    }

    private fun handleCreatePassword(entries: MutableList<PasswordEntry>): Boolean {
        val username = if (::usernameInput.isInitialized) {
            usernameInput.text.toString().trim()
        } else {
            intent.getStringExtra(EXTRA_USERNAME).orEmpty()
        }
        val password = if (::passwordInput.isInitialized) {
            passwordInput.text.toString()
        } else {
            intent.getStringExtra(EXTRA_PASSWORD).orEmpty()
        }
        val domain = intent.getStringExtra(EXTRA_DOMAIN)?.takeIf { it.isNotBlank() }
            ?: return failed("Request has no domain")

        if (password.isBlank()) return failed("Password cannot be blank")

        entries.upserted(domain, username, password)

        setResult(
            Activity.RESULT_OK,
            Intent().putExtra(
                CredentialProviderService.EXTRA_CREATE_CREDENTIAL_RESPONSE,
                CreateCredentialResponse(Bundle()),
            ),
        )
        finish()
        return true
    }

    /** Reports the failure to the caller and tells [KdbxPasswordVault.update] not to write. */
    private fun failed(message: String): Boolean {
        finishWithFailure(message)
        return false
    }

    /**
     * The hash is honoured only alongside a privileged web origin. The service already refuses to
     * forward an unprivileged caller's hash; re-checking here keeps the rule with the code that
     * signs, so a future caller of this activity cannot reintroduce the bypass.
     */
    private fun Intent.privilegedClientDataHash(): ByteArray? =
        ClientData.privilegedClientDataHash(
            getStringExtra(EXTRA_ORIGIN),
            getByteArrayExtra(EXTRA_CLIENT_DATA_HASH),
        )

    private fun b64(bytes: ByteArray): String = Base64.encodeToString(bytes, B64_FLAGS)

    private fun finishWithFailure(message: String) {
        val result = Intent().apply {
            putExtra(CredentialProviderService.EXTRA_GET_CREDENTIAL_EXCEPTION, GetCredentialException("android.credentials.GetCredentialException.TYPE_UNKNOWN", message))
            putExtra(CredentialProviderService.EXTRA_CREATE_CREDENTIAL_EXCEPTION, CreateCredentialException("android.credentials.CreateCredentialException.TYPE_UNKNOWN", message))
        }
        setResult(Activity.RESULT_CANCELED, result)
        finish()
    }

    private fun finishWithCancellation() {
        val result = Intent().apply {
            putExtra(CredentialProviderService.EXTRA_GET_CREDENTIAL_EXCEPTION, GetCredentialException("android.credentials.GetCredentialException.TYPE_USER_CANCELED", "User cancelled authentication"))
            putExtra(CredentialProviderService.EXTRA_CREATE_CREDENTIAL_EXCEPTION, CreateCredentialException("android.credentials.CreateCredentialException.TYPE_USER_CANCELED", "User cancelled creation"))
        }
        setResult(Activity.RESULT_CANCELED, result)
        finish()
    }

    companion object {
        const val ACTION_GET_PASSKEY = "org.kysecurity.authenticator.action.GET_PASSKEY"
        const val ACTION_GET_PASSWORD = "org.kysecurity.authenticator.action.GET_PASSWORD"
        const val ACTION_CREATE_PASSKEY = "org.kysecurity.authenticator.action.CREATE_PASSKEY"
        const val ACTION_CREATE_PASSWORD = "org.kysecurity.authenticator.action.CREATE_PASSWORD"

        const val EXTRA_ACTION = "extra_action"
        const val EXTRA_ENTRY_ID = "extra_entry_id"
        const val EXTRA_REQUEST_JSON = "extra_request_json"
        const val EXTRA_RP_ID = "extra_rp_id"
        const val EXTRA_USERNAME = "extra_username"
        const val EXTRA_PASSWORD = "extra_password"
        const val EXTRA_DOMAIN = "extra_domain"
        const val EXTRA_DISPLAY_TITLE = "extra_display_title"
        const val EXTRA_DISPLAY_SUBTITLE = "extra_display_subtitle"
        const val EXTRA_ORIGIN = "extra_origin"
        const val EXTRA_CALLER_PACKAGE = "extra_caller_package"
        const val EXTRA_CLIENT_DATA_HASH = "extra_client_data_hash"

        private const val B64_FLAGS = Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP

        const val TYPE_PUBLIC_KEY_CREDENTIAL = "android.credentials.TYPE_PUBLIC_KEY_CREDENTIAL"
        const val TYPE_PASSWORD_CREDENTIAL = "android.credentials.TYPE_PASSWORD_CREDENTIAL"
    }
}
