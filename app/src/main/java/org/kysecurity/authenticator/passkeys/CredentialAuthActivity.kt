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
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import java.io.File
import java.nio.charset.StandardCharsets
import java.util.UUID
import org.json.JSONObject
import org.kysecurity.authenticator.R
import org.kysecurity.authenticator.ThemeManager
import org.kysecurity.authenticator.passwords.DomainMatcher
import org.kysecurity.authenticator.passwords.KdbxPasswordVault
import org.kysecurity.authenticator.passwords.PasskeyData
import org.kysecurity.authenticator.passwords.PasswordEntry
import org.kysecurity.authenticator.passwords.PasswordGenerator
import org.kysecurity.authenticator.security.AppLockManager

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
        val executor = ContextCompat.getMainExecutor(this)
        val prompt = BiometricPrompt(
            this,
            executor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    AppLockManager.unlockWithBiometrics(applicationContext)
                    executeCredentialAction(action)
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    if (errorCode != BiometricPrompt.ERROR_USER_CANCELED && errorCode != BiometricPrompt.ERROR_NEGATIVE_BUTTON) {
                        Toast.makeText(applicationContext, errString, Toast.LENGTH_SHORT).show()
                    }
                }
            },
        )

        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("KyAuth")
            .setSubtitle(intent.getStringExtra(EXTRA_DISPLAY_TITLE) ?: "Authenticate to proceed")
            .setNegativeButtonText(getString(android.R.string.cancel))
            .build()

        prompt.authenticate(promptInfo)
    }

    private fun executeCredentialAction(action: String) {
        val vaultKey = AppLockManager.ensurePasswordVaultKeyInitialized(applicationContext)
        if (vaultKey == null) {
            finishWithFailure("Password vault is locked")
            return
        }

        val vaultFile = File(filesDir, "passwords_vault.kdbx")
        val entries = KdbxPasswordVault.loadEntries(vaultFile, vaultKey).toMutableList()

        when (action) {
            ACTION_GET_PASSKEY -> handleGetPasskey(entries, vaultFile, vaultKey)
            ACTION_GET_PASSWORD -> handleGetPassword(entries)
            ACTION_CREATE_PASSKEY -> handleCreatePasskey(entries, vaultFile, vaultKey)
            ACTION_CREATE_PASSWORD -> handleCreatePassword(entries, vaultFile, vaultKey)
            else -> finishWithFailure("Unknown credential action: $action")
        }
    }

    private fun handleGetPasskey(entries: MutableList<PasswordEntry>, vaultFile: File, vaultKey: ByteArray) {
        val entryId = intent.getStringExtra(EXTRA_ENTRY_ID)
        val entry = entries.find { it.id == entryId } ?: run {
            finishWithFailure("Passkey entry not found")
            return
        }
        val passkey = entry.passkey ?: run {
            finishWithFailure("Entry is missing passkey data")
            return
        }

        val requestJson = intent.getStringExtra(EXTRA_REQUEST_JSON).orEmpty()
        val json = runCatching { JSONObject(requestJson) }.getOrDefault(JSONObject())
        val challengeB64 = json.optString("challenge")
        val clientDataHash = if (challengeB64.isNotBlank()) {
            runCatching { Base64.decode(challengeB64, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP) }
                .getOrDefault(WebAuthnEngine.sha256(requestJson.toByteArray(StandardCharsets.UTF_8)))
        } else {
            WebAuthnEngine.sha256(requestJson.toByteArray(StandardCharsets.UTF_8))
        }

        val newSignCount = passkey.signCount + 1
        val privateKey = runCatching { WebAuthnEngine.restorePrivateKey(passkey.privateKeyPkcs8) }.getOrNull()
        if (privateKey == null) {
            finishWithFailure("Corrupted private key")
            return
        }

        val authData = WebAuthnEngine.buildAssertionAuthData(passkey.rpId, newSignCount)
        val signature = WebAuthnEngine.signAssertion(privateKey, authData, clientDataHash)

        // Update sign count in vault
        val updatedPasskey = passkey.copy(signCount = newSignCount)
        val updatedEntries = entries.map { if (it.id == entry.id) it.copy(passkey = updatedPasskey) else it }
        KdbxPasswordVault.saveEntries(vaultFile, vaultKey, updatedEntries)

        val responseJson = JSONObject().apply {
            put("id", Base64.encodeToString(passkey.credentialId, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP))
            put("rawId", Base64.encodeToString(passkey.credentialId, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP))
            put("type", "public-key")
            val responseObj = JSONObject().apply {
                put("authenticatorData", Base64.encodeToString(authData, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP))
                put("signature", Base64.encodeToString(signature, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP))
                if (passkey.userHandle.isNotEmpty()) {
                    put("userHandle", Base64.encodeToString(passkey.userHandle, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP))
                }
                put("clientDataJSON", Base64.encodeToString(requestJson.toByteArray(StandardCharsets.UTF_8), Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP))
            }
            put("response", responseObj)
        }

        val data = Bundle().apply {
            putString("androidx.credentials.BUNDLE_KEY_AUTHENTICATION_RESPONSE_JSON", responseJson.toString())
        }
        val credential = Credential(TYPE_PUBLIC_KEY_CREDENTIAL, data)
        val result = Intent().apply {
            putExtra(CredentialProviderService.EXTRA_GET_CREDENTIAL_RESPONSE, GetCredentialResponse(credential))
        }
        setResult(Activity.RESULT_OK, result)
        finish()
    }

    private fun handleGetPassword(entries: List<PasswordEntry>) {
        val entryId = intent.getStringExtra(EXTRA_ENTRY_ID)
        val entry = entries.find { it.id == entryId } ?: run {
            finishWithFailure("Password entry not found")
            return
        }

        val data = Bundle().apply {
            putString("androidx.credentials.BUNDLE_KEY_ID", entry.username)
            putString("androidx.credentials.BUNDLE_KEY_PASSWORD", entry.password)
        }
        val credential = Credential(TYPE_PASSWORD_CREDENTIAL, data)
        val result = Intent().apply {
            putExtra(CredentialProviderService.EXTRA_GET_CREDENTIAL_RESPONSE, GetCredentialResponse(credential))
        }
        setResult(Activity.RESULT_OK, result)
        finish()
    }

    private fun handleCreatePasskey(entries: MutableList<PasswordEntry>, vaultFile: File, vaultKey: ByteArray) {
        val requestJson = intent.getStringExtra(EXTRA_REQUEST_JSON).orEmpty()
        val json = runCatching { JSONObject(requestJson) }.getOrDefault(JSONObject())

        val rpObj = json.optJSONObject("rp")
        val rpId = rpObj?.optString("id")?.ifBlank { null } ?: intent.getStringExtra(EXTRA_RP_ID) ?: "unknown"
        val userObj = json.optJSONObject("user")
        val fallbackUsername = userObj?.optString("name") ?: userObj?.optString("displayName") ?: intent.getStringExtra(EXTRA_USERNAME) ?: ""
        val username = if (::usernameInput.isInitialized) usernameInput.text.toString().trim() else fallbackUsername

        val userHandleStr = userObj?.optString("id")
        val userHandle = if (!userHandleStr.isNullOrBlank()) {
            runCatching { Base64.decode(userHandleStr, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP) }.getOrDefault(userHandleStr.toByteArray(StandardCharsets.UTF_8))
        } else {
            ByteArray(0)
        }

        val keyPair = WebAuthnEngine.generateEcKeyPair()
        val credentialId = WebAuthnEngine.generateCredentialId()
        val coseKey = WebAuthnEngine.encodeCosePublicKey(keyPair.public as java.security.interfaces.ECPublicKey)
        val authData = WebAuthnEngine.buildRegistrationAuthData(
            rpId = rpId,
            signCount = 0,
            credentialId = credentialId,
            cosePublicKey = coseKey,
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

        val title = if (username.isNotBlank()) "$rpId ($username)" else rpId

        // Deduplication: if an entry for this rpId and username already exists, update its passkey
        val existingIndex = entries.indexOfFirst {
            DomainMatcher.matches(it, rpId) && it.username.equals(username, ignoreCase = true)
        }

        if (existingIndex >= 0) {
            val existing = entries[existingIndex]
            entries[existingIndex] = existing.copy(passkey = passkeyData, url = existing.url ?: "https://$rpId")
        } else {
            val newEntry = PasswordEntry(
                title = title,
                username = username,
                passkey = passkeyData,
                url = "https://$rpId",
                id = UUID.randomUUID().toString(),
            )
            entries.add(newEntry)
        }

        KdbxPasswordVault.saveEntries(vaultFile, vaultKey, entries)

        val responseJson = JSONObject().apply {
            put("id", Base64.encodeToString(credentialId, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP))
            put("rawId", Base64.encodeToString(credentialId, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP))
            put("type", "public-key")
            val responseObj = JSONObject().apply {
                put("attestationObject", Base64.encodeToString(attestationObject, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP))
                put("clientDataJSON", Base64.encodeToString(requestJson.toByteArray(StandardCharsets.UTF_8), Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP))
            }
            put("response", responseObj)
        }

        val data = Bundle().apply {
            putString("androidx.credentials.BUNDLE_KEY_REGISTRATION_RESPONSE_JSON", responseJson.toString())
        }
        val result = Intent().apply {
            putExtra(CredentialProviderService.EXTRA_CREATE_CREDENTIAL_RESPONSE, CreateCredentialResponse(data))
        }
        setResult(Activity.RESULT_OK, result)
        finish()
    }

    private fun handleCreatePassword(entries: MutableList<PasswordEntry>, vaultFile: File, vaultKey: ByteArray) {
        val username = if (::usernameInput.isInitialized) usernameInput.text.toString().trim() else intent.getStringExtra(EXTRA_USERNAME).orEmpty()
        val password = if (::passwordInput.isInitialized) passwordInput.text.toString() else intent.getStringExtra(EXTRA_PASSWORD).orEmpty()
        val domain = intent.getStringExtra(EXTRA_DOMAIN) ?: "Unknown"

        if (password.isBlank()) {
            finishWithFailure("Password cannot be blank")
            return
        }

        val title = if (username.isNotBlank()) "$domain ($username)" else domain

        // Deduplication: if an entry for this domain and username already exists, update its password
        val existingIndex = entries.indexOfFirst {
            DomainMatcher.matches(it, domain) && it.username.equals(username, ignoreCase = true)
        }

        if (existingIndex >= 0) {
            val existing = entries[existingIndex]
            entries[existingIndex] = existing.copy(password = password, url = existing.url ?: "https://$domain")
        } else {
            val newEntry = PasswordEntry(
                title = title,
                username = username,
                password = password,
                url = if (domain.contains("://")) domain else "https://$domain",
                id = UUID.randomUUID().toString(),
            )
            entries.add(newEntry)
        }

        KdbxPasswordVault.saveEntries(vaultFile, vaultKey, entries)

        val result = Intent().apply {
            putExtra(CredentialProviderService.EXTRA_CREATE_CREDENTIAL_RESPONSE, CreateCredentialResponse(Bundle()))
        }
        setResult(Activity.RESULT_OK, result)
        finish()
    }

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

        const val TYPE_PUBLIC_KEY_CREDENTIAL = "android.credentials.TYPE_PUBLIC_KEY_CREDENTIAL"
        const val TYPE_PASSWORD_CREDENTIAL = "android.credentials.TYPE_PASSWORD_CREDENTIAL"
    }
}
