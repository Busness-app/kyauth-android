package org.kysecurity.authenticator

import android.Manifest
import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.content.DialogInterface
import android.content.Intent
import android.content.pm.PackageManager
import android.content.res.ColorStateList
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.PersistableBundle
import android.provider.Settings
import android.text.InputType
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.view.WindowManager
import android.widget.Button
import android.widget.EditText
import android.widget.FrameLayout
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.ScrollView
import android.widget.Space
import android.widget.Switch
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import androidx.core.view.ViewCompat
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat
import org.kysecurity.authenticator.mfa.KyAuthMessagingService
import com.google.mlkit.vision.codescanner.GmsBarcodeScanning
import org.kysecurity.authenticator.mfa.MfaChallenge
import org.kysecurity.authenticator.mfa.MfaMessage
import org.kysecurity.authenticator.mfa.MfaPushChallengeStore
import org.kysecurity.authenticator.mfa.MfaResponseClient
import org.kysecurity.authenticator.mfa.MfaResponseResult
import org.kysecurity.authenticator.pairing.DeviceSigningKey
import org.kysecurity.authenticator.pairing.PairedAccount
import org.kysecurity.authenticator.pairing.PairingClient
import org.kysecurity.authenticator.pairing.PairingStore
import org.kysecurity.authenticator.pairing.QrPairing
import org.kysecurity.authenticator.pairing.QrPairingParser
import org.kysecurity.authenticator.pairing.PushTokenProvider
import org.kysecurity.authenticator.passwords.DomainMatcher
import org.kysecurity.authenticator.passwords.KdbxPasswordVault
import org.kysecurity.authenticator.passwords.PasswordEntry
import org.kysecurity.authenticator.passwords.PasswordGenerator
import org.kysecurity.authenticator.security.AppLockManager
import org.kysecurity.authenticator.security.PinFailurePolicy
import org.kysecurity.authenticator.security.PinPolicy
import org.kysecurity.authenticator.totp.KdbxTotpVault
import org.kysecurity.authenticator.totp.TotpEntry
import org.kysecurity.authenticator.totp.TotpGenerator
import org.kysecurity.authenticator.totp.TotpUriParser
import java.io.File
import java.net.URI
import java.security.SecureRandom
import java.util.UUID
import java.util.concurrent.Executor
import kotlin.math.max
import kotlin.math.min

class MainActivity : AppCompatActivity() {
    private lateinit var store: PairingStore
    private val executor: Executor by lazy { ContextCompat.getMainExecutor(this) }
    private val handler = Handler(Looper.getMainLooper())

    private var activeTab = Tab.TOTP
    private var pendingChallenge: MfaChallenge? = null
    private var pendingTotpEntry: TotpEntry? = null
    private var totpEntries = mutableListOf<TotpEntry>()
    private var passwordEntries = mutableListOf<PasswordEntry>()
    private var copiedSensitiveLabel: String? = null
    private var isVaultLoading = false
    private val vaultFile: File by lazy { File(filesDir, "totp_vault.kdbx") }
    private val passwordVaultFile: File by lazy { File(filesDir, "passwords_vault.kdbx") }

    private val ticker = object : Runnable {
        override fun run() {
            if (!isVaultLoading && AppLockManager.isUnlocked() && activeTab == Tab.TOTP) {
                renderContent()
            }
            handler.postDelayed(this, 1000)
        }
    }

    enum class Tab { TOTP, MFA, PASSWORDS, SETTINGS }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        WindowCompat.setDecorFitsSystemWindows(window, false)
        if (!BuildConfig.ALLOW_SCREENSHOTS) {
            window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        }
        store = PairingStore(this)
        KyAuthMessagingService.ensureChannel(this)
        handler.post(ticker)
    }

    override fun onResume() {
        super.onResume()
        loadPendingPushChallenge()
        if (!AppLockManager.isUnlocked()) {
            authenticateWithBiometrics(silent = true)
        }
        renderContent()
        requestNotificationPermissionIfNeeded()
    }

    override fun onStop() {
        super.onStop()
        if (!isChangingConfigurations) lockSensitiveState()
    }

    override fun onDestroy() {
        super.onDestroy()
        handler.removeCallbacks(ticker)
    }

    private fun renderContent() {
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(ThemeManager.color(context, R.color.ky_background))
        }
        applyRootPadding(root)

        val account = store.account()
        when {
            account == null -> renderEnrollmentView(root)
            !AppLockManager.isUnlocked() -> renderLockScreen(root, account)
            else -> renderDashboard(root, account)
        }

        setRootContentView(root)
    }

    // ==========================================
    // 1. Enrollment / Pairing Screen
    // ==========================================

    private fun renderEnrollmentView(root: LinearLayout) {
        root.gravity = Gravity.CENTER_HORIZONTAL

        root.addView(brand("KyAuth", "SECURE ACCESS"))
        root.addView(title("Connect your account"))
        root.addView(message("Scan the 90-second QR code from KySignOn. The pairing credential is used once and never stored."))

        val error = message("").apply { setTextColor(ThemeManager.color(context, R.color.ky_error)) }
        val progress = ProgressBar(this).apply { visibility = ProgressBar.GONE }

        val btnScan = primaryButton(getString(R.string.scan_qr)).apply {
            setOnClickListener {
                error.text = ""
                GmsBarcodeScanning.getClient(this@MainActivity).startScan()
                    .addOnSuccessListener { result ->
                        val pairing = runCatching { QrPairingParser.parse(result.rawValue.orEmpty()) }
                        pairing.onSuccess { showPairingConfirmation(it, this, progress, error) }
                            .onFailure { error.text = it.message ?: "Invalid KySignOn QR code" }
                    }
                    .addOnFailureListener { error.text = "Unable to scan QR code" }
            }
        }

        val btnManual = secondaryButton("Enter code manually").apply {
            setOnClickListener { showManualPairingDialog(progress, error) }
        }

        root.addView(btnScan, fullWidthParams())
        root.addView(btnManual, fullWidthParams(top = 10))
        root.addView(progress)
        root.addView(error)
    }

    private fun showPairingConfirmation(pairing: QrPairing, triggerBtn: Button?, progress: ProgressBar, error: TextView) {
        val host = runCatching { URI(pairing.serverUrl).host }.getOrNull().orEmpty()
        AlertDialog.Builder(this)
            .setTitle(getString(R.string.pairing_title))
            .setMessage("QR code read. Pair this device with $host?")
            .setNegativeButton("Cancel", null)
            .setPositiveButton("Pair") { _, _ ->
                authenticateWithBiometrics(
                    reason = "Pair with $host",
                    onSuccess = {
                        triggerBtn?.isEnabled = false
                        progress.visibility = ProgressBar.VISIBLE
                        Thread {
                            val result = runCatching {
                                val pushToken = PushTokenProvider.currentToken().getOrThrow()
                                PairingClient().register(
                                    pairing = pairing,
                                    deviceName = android.os.Build.MODEL,
                                    deviceIdentifier = store.deviceIdentifier(),
                                    pushToken = pushToken,
                                )
                            }
                            runOnUiThread {
                                progress.visibility = ProgressBar.GONE
                                triggerBtn?.isEnabled = true
                                result.onSuccess { account ->
                                    store.save(account)
                                    unlockVault(
                                        unlock = { AppLockManager.unlockWithBiometrics(this@MainActivity) },
                                        onError = {
                                            renderContent()
                                            Toast.makeText(this@MainActivity, "Unlock failed. Use your PIN to recover the vault.", Toast.LENGTH_LONG).show()
                                        },
                                    )
                                }.onFailure { error.text = it.message ?: "Pairing failed" }
                            }
                        }.start()
                    },
                    onError = { error.text = it },
                )
            }
            .show()
    }

    private fun showManualPairingDialog(progress: ProgressBar, error: TextView) {
        val container = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(48, 24, 48, 24)
        }
        val serverInput = EditText(this).apply { hint = "Server URL (e.g. https://auth.example.com)"; styleInput(this) }
        val tokenInput = EditText(this).apply { hint = "Pairing Token or PIN"; styleInput(this) }
        val userInput = EditText(this).apply { hint = "User ID (optional if using token)"; styleInput(this) }

        container.addView(serverInput)
        container.addView(tokenInput)
        container.addView(userInput)

        AlertDialog.Builder(this)
            .setTitle("Manual KySignOn Pairing")
            .setView(container)
            .setNegativeButton("Cancel", null)
            .setPositiveButton("Pair") { _, _ ->
                val serverUrl = serverInput.text.toString().trim()
                val tokenOrPin = tokenInput.text.toString().trim()
                val userId = userInput.text.toString().trim().ifBlank { null }
                if (serverUrl.isBlank() || tokenOrPin.isBlank()) {
                    error.text = "Server URL and Pairing Token/PIN are required"
                    return@setPositiveButton
                }

                val pairing = if (tokenOrPin.length == 6 && tokenOrPin.all { it.isDigit() } && userId != null) {
                    QrPairing(serverUrl = serverUrl, pinCode = tokenOrPin, userId = userId)
                } else {
                    QrPairing(serverUrl = serverUrl, pairingToken = tokenOrPin)
                }
                showPairingConfirmation(pairing, null, progress, error)
            }
            .show()
    }

    // ==========================================
    // 2. Lock Screen / Authentication Gate
    // ==========================================

    private fun renderLockScreen(root: LinearLayout, account: PairedAccount) {
        root.gravity = Gravity.CENTER

        root.addView(kyAuthWordmark(textSize = 34f, iconSizeDp = 64, centered = true))
        root.addView(TextView(this).apply {
            text = "VAULT LOCKED"
            textSize = 12f
            typeface = Typeface.MONOSPACE
            gravity = Gravity.CENTER
            letterSpacing = 0.18f
            setTextColor(ThemeManager.color(context, R.color.ky_cyan_dim))
            setPadding(0, dp(4), 0, dp(24))
        })
        root.addView(TextView(this).apply {
            text = "Unlock your vault"
            textSize = 24f
            typeface = Typeface.DEFAULT_BOLD
            gravity = Gravity.CENTER
            setTextColor(ThemeManager.color(context, R.color.ky_text))
        })
        root.addView(TextView(this).apply {
            text = "Paired to ${account.serverUrl}\nAuthenticate to access your codes and sign-in approvals."
            textSize = 15f
            gravity = Gravity.CENTER
            setTextColor(ThemeManager.color(context, R.color.ky_muted))
            setPadding(dp(16), dp(10), dp(16), dp(24))
        })

        fun lockActionParams(top: Int = 0) = fullWidthParams(top).apply {
            marginStart = dp(12)
            marginEnd = dp(12)
        }

        val error = message("").apply { setTextColor(ThemeManager.color(context, R.color.ky_error)) }
        val failureState = AppLockManager.getFailureState(this)
        val nowSec = System.currentTimeMillis() / 1000
        val retryWaitSec = PinFailurePolicy.secondsUntilRetry(failureState, nowSec)

        if (retryWaitSec > 0) {
            error.text = "Too many failed attempts. Try again in $retryWaitSec seconds."
        } else if (failureState.failedAttempts > 0) {
            val remaining = PinFailurePolicy.attemptsRemaining(failureState)
            error.text = "Failed attempt. $remaining attempts remaining before automatic data wipe."
        }

        val btnBiometric = primaryButton(getString(R.string.unlock_biometrics)).apply {
            minHeight = dp(56)
            setOnClickListener {
                authenticateWithBiometrics(
                    reason = "Unlock KyAuth",
                    onSuccess = {
                        unlockVault(
                            unlock = { AppLockManager.unlockWithBiometrics(this@MainActivity) },
                            onError = {
                                renderContent()
                                Toast.makeText(this@MainActivity, "Unlock failed. Use your PIN to recover the vault.", Toast.LENGTH_LONG).show()
                            },
                        )
                    },
                    onError = { error.text = it },
                )
            }
        }
        root.addView(btnBiometric, lockActionParams())

        if (AppLockManager.isPinEnabled(this) && AppLockManager.hasPinSet(this)) {
            val pinInput = EditText(this).apply {
                hint = "Enter PIN"
                inputType = InputType.TYPE_CLASS_NUMBER or InputType.TYPE_NUMBER_VARIATION_PASSWORD
                gravity = Gravity.CENTER
                styleInput(this)
            }
            val btnPin = secondaryButton("Unlock with PIN").apply {
                setOnClickListener {
                    val pin = pinInput.text.toString()
                    unlockVault(
                        unlock = { AppLockManager.unlockWithPin(this@MainActivity, pin) },
                        onError = {
                            renderContent()
                            Toast.makeText(this@MainActivity, "Unable to unlock vault.", Toast.LENGTH_LONG).show()
                        },
                    )
                }
            }
            root.addView(pinInput, lockActionParams(top = 14))
            root.addView(btnPin, lockActionParams(top = 10))
        }

        root.addView(error.apply { gravity = Gravity.CENTER }, fullWidthParams(top = 8))
        root.addView(secondaryButton("About KyAuth").apply {
            setOnClickListener { showAboutDialog(this@MainActivity) }
        }, lockActionParams(top = 8))
    }

    // ==========================================
    // 3. Main Dashboard & Tabs
    // ==========================================

    private fun renderDashboard(root: LinearLayout, account: PairedAccount) {
        val header = kyAuthWordmark(textSize = 32f, iconSizeDp = 56).apply {
            setPadding(0, dp(12), 0, dp(28))
        }
        root.addView(header, centeredWidthParams(maxWidthDp = dashboardMaxWidthDp()))

        val scroll = dashboardScroll()
        val container = dashboardContainer()
        scroll.addView(container, scrollContentParams())
        renderActiveTab(container, account)
        root.addView(scroll)
        root.addView(bottomNavigation(), navigationParams())
    }

    private fun dashboardScroll() = ScrollView(this).apply {
        isFillViewport = true
        layoutParams = LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT,
            0,
            1f,
        ).apply { bottomMargin = dp(16) }
    }

    private fun dashboardContainer() = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
    }

    private fun renderActiveTab(container: LinearLayout, account: PairedAccount) {
        when (activeTab) {
            Tab.TOTP -> renderTotpTab(container)
            Tab.MFA -> renderMfaTab(container, account)
            Tab.PASSWORDS -> renderPasswordsTab(container)
            Tab.SETTINGS -> renderSettingsTab(container, account)
        }
    }

    // ==========================================
    // Tab 1: TOTP Vault
    // ==========================================

    private fun renderTotpTab(container: LinearLayout) {
        if (totpEntries.isEmpty()) {
            container.addView(emptyState("No codes yet", "Add a code from Settings."))
            return
        }

        val nowSec = System.currentTimeMillis() / 1000
        val cards = mutableListOf<View>()
        for (entry in totpEntries) {
            val card = LinearLayout(this).apply {
                orientation = LinearLayout.VERTICAL
                background = cardBackground()
                setPadding(dp(20), dp(18), dp(20), dp(18))
                layoutParams = fullWidthParams(bottom = 12)
            }

            val code = TotpGenerator.generate(entry, nowSec)
            val remainingSec = TotpGenerator.secondsRemaining(entry, nowSec)
            val formattedCode = if (code.length == 6) "${code.substring(0, 3)} ${code.substring(3)}" else code

            val titleView = TextView(this).apply {
                text = entry.title
                textSize = 17f
                typeface = Typeface.DEFAULT_BOLD
                setTextColor(ThemeManager.color(context, R.color.ky_text))
            }
            val codeView = TextView(this).apply {
                text = formattedCode
                textSize = 34f
                typeface = Typeface.create(Typeface.MONOSPACE, Typeface.BOLD)
                setTextColor(ThemeManager.color(context, R.color.ky_cyan))
                setPadding(0, 8, 0, 8)
                setOnClickListener {
                    val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                    copyTotpCode(clipboard, code, remainingSec)
                    Toast.makeText(this@MainActivity, getString(R.string.copy_code), Toast.LENGTH_SHORT).show()
                }
            }
            val timerView = TextView(this).apply {
                text = "TAP TO COPY  ·  EXPIRES IN $remainingSec S"
                textSize = 14f
                setTextColor(ThemeManager.color(context, R.color.ky_muted))
            }

            card.addView(titleView)
            card.addView(codeView)
            card.addView(timerView)
            card.addView(ProgressBar(this, null, android.R.attr.progressBarStyleHorizontal).apply {
                progressTintList = ColorStateList.valueOf(ThemeManager.color(context, R.color.ky_cyan))
                progressBackgroundTintList = ColorStateList.valueOf(ThemeManager.color(context, R.color.ky_border))
                max = entry.periodSeconds.toInt()
                progress = max(0, remainingSec.toInt())
            }, LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, dp(4)).apply { topMargin = dp(14) })

            card.setOnLongClickListener {
                showEditOrDeleteTotpDialog(entry)
                true
            }
            cards.add(card)
        }
        addAdaptiveCards(container, cards)
    }

    private fun showAddTotpDialog() {
        val container = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(48, 24, 48, 24)
        }
        val titleInput = EditText(this).apply { hint = "Account Name (e.g. GitHub)"; styleInput(this) }
        val secretInput = EditText(this).apply { hint = "Secret Key (Base32)"; styleInput(this) }
        container.addView(titleInput)
        container.addView(secretInput)

        AlertDialog.Builder(this)
            .setTitle(getString(R.string.add_manually))
            .setView(container)
            .setNegativeButton("Cancel", null)
            .setPositiveButton("Save") { _, _ ->
                val title = titleInput.text.toString().trim()
                val secret = secretInput.text.toString().trim().replace(" ", "")
                if (title.isNotBlank() && secret.isNotBlank()) {
                    runCatching {
                        TotpEntry(title = title, secretBase32 = secret)
                    }.onSuccess { addTotpEntry(it) }
                        .onFailure { Toast.makeText(this, it.message ?: "Invalid secret", Toast.LENGTH_SHORT).show() }
                }
            }
            .showKyDialog()
    }

    private fun showEditOrDeleteTotpDialog(entry: TotpEntry) {
        AlertDialog.Builder(this)
            .setTitle(entry.title)
            .setItems(arrayOf("Delete Entry")) { _, which ->
                if (which == 0) {
                    totpEntries.removeAll { it.id == entry.id }
                    saveTotpEntries()
                    renderContent()
                }
            }
            .show()
    }

    private fun loadTotpEntries() {
        val vaultKey = AppLockManager.getVaultKey() ?: return
        totpEntries = KdbxTotpVault.loadEntries(vaultFile, vaultKey).toMutableList()
        pendingTotpEntry?.let {
            pendingTotpEntry = null
            totpEntries.add(it)
            saveTotpEntries()
        }
    }

    private fun saveTotpEntries() {
        val vaultKey = AppLockManager.getVaultKey() ?: return
        KdbxTotpVault.saveEntries(vaultFile, vaultKey, totpEntries)
    }

    private fun loadPasswordEntries() {
        val vaultKey = AppLockManager.getPasswordVaultKey() ?: return
        passwordEntries = KdbxPasswordVault.loadEntries(passwordVaultFile, vaultKey).toMutableList()
    }

    private fun savePasswordEntries() {
        val vaultKey = AppLockManager.getPasswordVaultKey() ?: return
        KdbxPasswordVault.saveEntries(passwordVaultFile, vaultKey, passwordEntries)
    }

    private fun addTotpEntry(entry: TotpEntry) {
        totpEntries.add(entry)
        saveTotpEntries()
        renderContent()
    }

    private fun queueTotpEntry(entry: TotpEntry) {
        if (AppLockManager.isUnlocked()) {
            addTotpEntry(entry)
        } else {
            pendingTotpEntry = entry
            Toast.makeText(this, "Unlock to save the scanned TOTP entry.", Toast.LENGTH_SHORT).show()
            renderContent()
        }
    }

    // ==========================================
    // Tab 3: Password Vault
    // ==========================================

    private fun renderPasswordsTab(container: LinearLayout) {
        val addButton = primaryButton("Add password").apply {
            setOnClickListener { showAddPasswordDialog() }
        }
        container.addView(addButton, fullWidthParams(bottom = 16))

        if (passwordEntries.isEmpty()) {
            container.addView(emptyState("No passwords yet", "Add a local password entry to this separate vault."))
            return
        }

        val cards = mutableListOf<View>()
        passwordEntries.sortedBy { it.title.lowercase() }.forEach { entry ->
            val card = LinearLayout(this).apply {
                orientation = LinearLayout.VERTICAL
                background = cardBackground()
                setPadding(dp(20), dp(18), dp(20), dp(18))
                layoutParams = fullWidthParams(bottom = 12)
                setOnClickListener {
                    authenticateWithBiometrics(
                        reason = if (entry.isPasskey) "View passkey for ${entry.title}" else "Reveal password for ${entry.title}",
                        onSuccess = { showPasswordDetails(entry) },
                    )
                }
            }

            val headerRow = LinearLayout(this).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER_VERTICAL
            }
            headerRow.addView(TextView(this).apply {
                text = entry.title
                textSize = 18f
                typeface = Typeface.DEFAULT_BOLD
                setTextColor(ThemeManager.color(context, R.color.ky_text))
                layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
            })

            if (entry.isPasskey) {
                headerRow.addView(TextView(this).apply {
                    text = "PASSKEY"
                    textSize = 11f
                    typeface = Typeface.DEFAULT_BOLD
                    setTextColor(ThemeManager.color(context, R.color.ky_cyan))
                    background = GradientDrawable().apply {
                        setColor(ThemeManager.color(context, R.color.ky_surface_elevated))
                        cornerRadius = dp(6).toFloat()
                        setStroke(dp(1), ThemeManager.color(context, R.color.ky_cyan))
                    }
                    setPadding(dp(8), dp(2), dp(8), dp(2))
                })
            }
            card.addView(headerRow)

            card.addView(TextView(this).apply {
                text = entry.username.ifBlank { if (entry.isPasskey) "Passkey credential" else "No username" }
                textSize = 14f
                setTextColor(ThemeManager.color(context, R.color.ky_muted))
                setPadding(0, dp(4), 0, 0)
            })
            entry.url?.let { url ->
                card.addView(TextView(this).apply {
                    text = url
                    textSize = 13f
                    setTextColor(ThemeManager.color(context, R.color.ky_cyan))
                    setPadding(0, dp(6), 0, 0)
                })
            }
            cards.add(card)
        }
        addAdaptiveCards(container, cards)
    }

    private fun showAddPasswordDialog() {
        val form = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(24), dp(8), dp(24), dp(24))
        }
        val titleInput = EditText(this).apply { hint = "Account name"; styleInput(this) }
        val usernameInput = EditText(this).apply { hint = "Username or email"; styleInput(this) }
        val passwordInput = EditText(this).apply {
            hint = "Password"
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
            styleInput(this)
        }
        val urlInput = EditText(this).apply { hint = "Website (optional)"; styleInput(this) }
        val notesInput = EditText(this).apply {
            hint = "Notes (optional)"
            minLines = 3
            gravity = Gravity.TOP
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_CAP_SENTENCES or InputType.TYPE_TEXT_FLAG_MULTI_LINE
            styleInput(this)
        }
        form.addView(TextView(this).apply {
            text = "Stored only in your separate local password vault."
            setTextColor(ThemeManager.color(this@MainActivity, R.color.ky_muted))
            textSize = 14f
        }, fullWidthParams(bottom = 16))
        form.addView(titleInput, fullWidthParams(bottom = 10))
        form.addView(usernameInput, fullWidthParams(bottom = 10))
        form.addView(passwordInput, fullWidthParams(bottom = 10))
        form.addView(secondaryButton("Generate a 20-character password").apply {
            setOnClickListener { passwordInput.setText(generatePassword()) }
        }, fullWidthParams(bottom = 18))
        form.addView(urlInput, fullWidthParams(bottom = 10))
        form.addView(notesInput, fullWidthParams())
        val scrollView = ScrollView(this).apply {
            clipToPadding = false
            addView(form)
        }

        AlertDialog.Builder(this)
            .setTitle("Add password")
            .setView(scrollView)
            .setNegativeButton("Cancel", null)
            .setPositiveButton("Save") { _, _ ->
                runCatching {
                    PasswordEntry(
                        title = titleInput.text.toString().trim(),
                        username = usernameInput.text.toString().trim(),
                        password = passwordInput.text.toString(),
                        url = urlInput.text.toString().trim().ifBlank { null },
                        notes = notesInput.text.toString().trim().ifBlank { null },
                    )
                }.onSuccess {
                    passwordEntries.add(it)
                    savePasswordEntries()
                    renderContent()
                }.onFailure {
                    Toast.makeText(this, "Account name and password are required", Toast.LENGTH_SHORT).show()
                }
            }
            .showKyDialog()
    }

    private fun showPasswordDetails(entry: PasswordEntry) {
        val container = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(24), dp(8), dp(24), dp(8))
        }
        container.addView(TextView(this).apply {
            text = entry.username.ifBlank { "No username" }
            textSize = 15f
            setTextColor(ThemeManager.color(context, R.color.ky_muted))
        })

        if (entry.isPasskey) {
            val passkey = entry.passkey!!
            container.addView(TextView(this).apply {
                text = "FIDO2 / WebAuthn Passkey"
                textSize = 18f
                typeface = Typeface.DEFAULT_BOLD
                setTextColor(ThemeManager.color(context, R.color.ky_cyan))
                setPadding(0, dp(12), 0, dp(4))
            })
            container.addView(TextView(this).apply {
                text = "Relying Party: ${passkey.rpId}\nSignatures: ${passkey.signCount}"
                textSize = 14f
                setTextColor(ThemeManager.color(context, R.color.ky_text))
                setPadding(0, 0, 0, dp(12))
            })
        } else {
            container.addView(TextView(this).apply {
                text = entry.password
                textSize = 22f
                typeface = Typeface.MONOSPACE
                setTextIsSelectable(true)
                setTextColor(ThemeManager.color(context, R.color.ky_text))
                setPadding(0, dp(16), 0, dp(16))
            })
        }

        entry.url?.let { container.addView(message(it)) }
        entry.notes?.let { container.addView(message(it)) }

        val builder = AlertDialog.Builder(this)
            .setTitle(entry.title)
            .setView(container)
            .setNegativeButton("Delete") { _, _ ->
                passwordEntries.removeAll { it.id == entry.id }
                savePasswordEntries()
                renderContent()
            }

        if (!entry.isPasskey && entry.password.isNotBlank()) {
            builder.setNeutralButton("Copy") { _, _ ->
                copySensitiveText(entry.password, 30)
                Toast.makeText(this, "Password copied for 30 seconds", Toast.LENGTH_SHORT).show()
            }
        }

        builder.setPositiveButton("Close", null).show()
    }

    private fun generatePassword(length: Int = 20): String =
        PasswordGenerator.generate(length = length)

    // ==========================================
    // Tab 4: Push MFA Approvals
    // ==========================================

    private fun renderMfaTab(container: LinearLayout, account: PairedAccount) {
        val challenge = pendingChallenge
        if (challenge == null) {
            container.gravity = Gravity.CENTER
            container.addView(mfaEmptyState())
            return
        }
        val challengeStore = MfaPushChallengeStore(this)
        if (challengeStore.isExpired(challenge)) {
            pendingChallenge = null
            challengeStore.clear()
            container.gravity = Gravity.CENTER
            container.addView(emptyState("Request expired", "New sign-in requests will appear here."))
            return
        }

        val card = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            background = cardBackground()
            setPadding(dp(20), dp(20), dp(20), dp(20))
        }
        card.addView(title("Sign-in Request"))
        card.addView(message("A sign-in request was received for:\n${challenge.serverUrl}\nUser: ${challenge.username ?: account.deviceName}\nExpires in ${challengeStore.secondsRemaining(challenge)} seconds.\n\nEnter the 2-digit number shown on your computer screen:"))
        val digits = EditText(this).apply {
            hint = "00"
            inputType = InputType.TYPE_CLASS_NUMBER
            setSingleLine(true)
            gravity = Gravity.CENTER
            textSize = 24f
        }
        card.addView(digits)
        card.addView(primaryButton("Approve request").apply {
            setOnClickListener { onNumberSelected(challenge, digits.text.toString().trim(), account) }
        })

        val btnDeny = secondaryButton("Deny request").apply {
            setTextColor(ThemeManager.color(context, R.color.ky_error))
            setOnClickListener { onDenyClicked(challenge, account) }
        }
        card.addView(btnDeny)
        container.addView(card)
    }

    private fun onNumberSelected(challenge: MfaChallenge, selectedDigit: String, account: PairedAccount) {
        val sig = runCatching { DeviceSigningKey.initSignature() }.getOrElse {
            Toast.makeText(this, "Unable to authorize this request. Use your fingerprint or re-pair KyAuth.", Toast.LENGTH_LONG).show()
            return
        }
        val cryptoObject = BiometricPrompt.CryptoObject(sig)
        val prompt = BiometricPrompt(this, executor, object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                val authedSig = result.cryptoObject?.signature ?: sig
                val payload = MfaMessage.formatPayload(challenge.challengeId, approve = true, selectedDigit)
                val signature = runCatching { DeviceSigningKey.sign(payload, authedSig) }.getOrElse {
                    Toast.makeText(this@MainActivity, "Unable to authorize this request. Use your fingerprint or re-pair KyAuth.", Toast.LENGTH_LONG).show()
                    return
                }
                Thread {
                    val result = MfaResponseClient().respond(
                        serverUrl = challenge.serverUrl,
                        challengeId = challenge.challengeId,
                        selectedDigits = selectedDigit,
                        approve = true,
                        signature = signature,
                    )
                    runOnUiThread {
                        when (result) {
                            is MfaResponseResult.Success -> {
                                pendingChallenge = null
                                MfaPushChallengeStore(this@MainActivity).clear()
                                val message = if (result.approved) "Sign-in Approved" else "Sign-in Denied"
                                Toast.makeText(this@MainActivity, message, Toast.LENGTH_SHORT).show()
                            }
                            is MfaResponseResult.Error -> {
                                Toast.makeText(this@MainActivity, result.message, Toast.LENGTH_LONG).show()
                            }
                        }
                        renderContent()
                    }
                }.start()
            }
            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                Toast.makeText(this@MainActivity, "Unlock required: $errString", Toast.LENGTH_SHORT).show()
            }
        })
        prompt.authenticate(
            BiometricPrompt.PromptInfo.Builder()
                .setTitle("KyAuth")
                .setSubtitle("Approve sign-in match $selectedDigit")
                .setAllowedAuthenticators(
                    BiometricManager.Authenticators.BIOMETRIC_STRONG or BiometricManager.Authenticators.DEVICE_CREDENTIAL,
                )
                .build(),
            cryptoObject,
        )
    }

    private fun onDenyClicked(challenge: MfaChallenge, account: PairedAccount) {
        val sig = runCatching { DeviceSigningKey.initSignature() }.getOrElse {
            Toast.makeText(this, "Unable to authorize this request. Use your fingerprint or re-pair KyAuth.", Toast.LENGTH_LONG).show()
            return
        }
        val cryptoObject = BiometricPrompt.CryptoObject(sig)
        val prompt = BiometricPrompt(this, executor, object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                val authedSig = result.cryptoObject?.signature ?: sig
                val payload = MfaMessage.formatPayload(challenge.challengeId, approve = false, challenge.matchDigits)
                val signature = runCatching { DeviceSigningKey.sign(payload, authedSig) }.getOrElse {
                    Toast.makeText(this@MainActivity, "Unable to authorize this request. Use your fingerprint or re-pair KyAuth.", Toast.LENGTH_LONG).show()
                    return
                }
                Thread {
                    val result = MfaResponseClient().respond(
                        serverUrl = challenge.serverUrl,
                        challengeId = challenge.challengeId,
                        selectedDigits = challenge.matchDigits,
                        approve = false,
                        signature = signature,
                    )
                    runOnUiThread {
                        when (result) {
                            is MfaResponseResult.Success -> {
                                pendingChallenge = null
                                MfaPushChallengeStore(this@MainActivity).clear()
                                Toast.makeText(this@MainActivity, "Sign-in Denied", Toast.LENGTH_SHORT).show()
                            }
                            is MfaResponseResult.Error -> {
                                Toast.makeText(this@MainActivity, result.message, Toast.LENGTH_LONG).show()
                            }
                        }
                        renderContent()
                    }
                }.start()
            }
            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                Toast.makeText(this@MainActivity, "Unlock required: $errString", Toast.LENGTH_SHORT).show()
            }
        })
        prompt.authenticate(
            BiometricPrompt.PromptInfo.Builder()
                .setTitle("KyAuth")
                .setSubtitle("Deny sign-in request")
                .setAllowedAuthenticators(
                    BiometricManager.Authenticators.BIOMETRIC_STRONG or BiometricManager.Authenticators.DEVICE_CREDENTIAL,
                )
                .build(),
            cryptoObject,
        )
    }

    // ==========================================
    // Tab 3: Settings & Security
    // ==========================================

    private fun renderSettingsTab(container: LinearLayout, account: PairedAccount) {
        val sections = mutableListOf<View>()

        val appearanceSection = settingsCard()
        appearanceSection.addView(title("Appearance"))
        appearanceSection.addView(message("Theme: ${ThemeManager.currentName(this)}"))
        appearanceSection.addView(secondaryButton("Select theme").apply {
            setOnClickListener { showThemePicker() }
        }, fullWidthParams())
        sections.add(appearanceSection)

        val vaultSection = settingsCard()
        vaultSection.addView(title("TOTP Vault"))
        val totpActions = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        val btnScanOtp = primaryButton("Scan QR").apply {
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
            setOnClickListener {
                GmsBarcodeScanning.getClient(this@MainActivity).startScan()
                    .addOnSuccessListener { result ->
                        runCatching { TotpUriParser.parse(result.rawValue.orEmpty()) }
                            .onSuccess { queueTotpEntry(it) }
                            .onFailure { Toast.makeText(this@MainActivity, "Invalid OTP QR code", Toast.LENGTH_SHORT).show() }
                    }
            }
        }
        val btnManualOtp = secondaryButton("Add manually").apply {
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
            setOnClickListener { showAddTotpDialog() }
        }
        totpActions.addView(btnScanOtp)
        totpActions.addView(btnManualOtp)
        vaultSection.addView(totpActions)
        sections.add(vaultSection)

        val providerSection = settingsCard()
        providerSection.addView(title("Password & Passkey Provider"))
        providerSection.addView(message("Set KyAuth as your default system provider to autofill passwords and use passkeys across apps and websites."))
        providerSection.addView(primaryButton("Set as default provider").apply {
            setOnClickListener { openCredentialProviderSettings() }
        }, fullWidthParams())
        sections.add(providerSection)

        val accountSection = settingsCard()
        accountSection.addView(title("Paired Account"))
        accountSection.addView(message("Server: ${account.serverUrl}\nDevice ID: ${account.deviceId}\nDevice Name: ${account.deviceName}\nUser ID: ${account.userId ?: "N/A"}"))

        val btnUnpair = secondaryButton(getString(R.string.unpair_account)).apply {
            setTextColor(ThemeManager.color(context, R.color.ky_error))
            setOnClickListener {
                AlertDialog.Builder(this@MainActivity)
                    .setTitle("Unpair Device")
                    .setMessage("Are you sure you want to unpair this device from KySignOn?")
                    .setNegativeButton("Cancel", null)
                    .setPositiveButton("Unpair") { _, _ ->
                        store.clear()
                        lockSensitiveState()
                        renderContent()
                    }
                    .show()
            }
        }
        accountSection.addView(btnUnpair, fullWidthParams())
        sections.add(accountSection)

        val securitySection = settingsCard()
        securitySection.addView(title("Security & App Lock"))
        val pinSwitch = Switch(this).apply {
            text = getString(R.string.enable_pin)
            isChecked = AppLockManager.isPinEnabled(this@MainActivity)
            setTextColor(ThemeManager.color(context, R.color.ky_text))
            setOnCheckedChangeListener { _, isChecked ->
                if (isChecked && !AppLockManager.hasPinSet(this@MainActivity)) {
                    showSetPinDialog()
                } else {
                    AppLockManager.setPinEnabled(this@MainActivity, isChecked)
                }
            }
        }
        securitySection.addView(pinSwitch)

        val btnChangePin = secondaryButton(getString(R.string.change_pin)).apply {
            setOnClickListener { showSetPinDialog() }
        }
        securitySection.addView(btnChangePin, fullWidthParams())

        securitySection.addView(message("Auto-wipe policy: After 5 consecutive failed PIN attempts, all vault keys, accounts, and pairing data will be automatically wiped."))
        sections.add(securitySection)

        val aboutSection = settingsCard()
        aboutSection.addView(title("About"))
        aboutSection.addView(message("KyAuth v${BuildConfig.VERSION_NAME}"))
        aboutSection.addView(secondaryButton("About KyAuth").apply {
            setOnClickListener { showAboutDialog(this@MainActivity) }
        }, fullWidthParams())
        sections.add(aboutSection)

        addAdaptiveCards(container, sections)
    }

    private fun showSetPinDialog() {
        val container = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(48, 24, 48, 24)
        }
        val pinInput = EditText(this).apply {
            hint = "New PIN (4-12 digits)"
            inputType = InputType.TYPE_CLASS_NUMBER or InputType.TYPE_NUMBER_VARIATION_PASSWORD
            styleInput(this)
        }
        container.addView(pinInput)

        AlertDialog.Builder(this)
            .setTitle(getString(R.string.change_pin))
            .setView(container)
            .setNegativeButton("Cancel", null)
            .setPositiveButton("Set PIN") { _, _ ->
                val pin = pinInput.text.toString().trim()
                val validation = PinPolicy.validate(pin)
                if (validation is PinPolicy.ValidationResult.Valid) {
                    AppLockManager.setupPin(this, pin)
                    Toast.makeText(this, "PIN saved successfully", Toast.LENGTH_SHORT).show()
                    renderContent()
                } else {
                    Toast.makeText(this, (validation as PinPolicy.ValidationResult.Error).message, Toast.LENGTH_LONG).show()
                }
            }
            .showKyDialog()
    }

    private fun showThemePicker() {
        val names = ThemeManager.names()
        AlertDialog.Builder(this)
            .setTitle("Choose theme")
            .setSingleChoiceItems(names, names.indexOf(ThemeManager.currentName(this))) { dialog, which ->
                ThemeManager.set(this, names[which])
                dialog.dismiss()
                renderContent()
            }
            .show()
    }

    private fun openCredentialProviderSettings() {
        val autofillIntent = Intent(Settings.ACTION_REQUEST_SET_AUTOFILL_SERVICE).apply {
            data = Uri.parse("package:$packageName")
        }
        val credentialIntent = Intent("android.settings.CREDENTIAL_PROVIDER")

        runCatching {
            startActivity(autofillIntent)
            return
        }
        runCatching {
            startActivity(credentialIntent)
            return
        }
        runCatching {
            startActivity(Intent(Settings.ACTION_SETTINGS))
        }.onFailure {
            Toast.makeText(this, "Could not open system credential settings", Toast.LENGTH_SHORT).show()
        }
    }

    // ==========================================
    // Biometric Authentication Helper
    // ==========================================

    private fun unlockVault(unlock: () -> Boolean, onError: () -> Unit) {
        isVaultLoading = true
        renderVaultUnlocking()
        Thread {
            val success = runCatching {
                check(unlock())
                loadTotpEntries()
                loadPasswordEntries()
            }.isSuccess
            runOnUiThread {
                isVaultLoading = false
                if (success) renderContent() else onError()
            }
        }.start()
    }

    private fun renderVaultUnlocking() {
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER
            setBackgroundColor(ThemeManager.color(context, R.color.ky_background))
        }
        applyRootPadding(root)
        root.addView(ProgressBar(this))
        root.addView(message("Unlocking vault…"), LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.WRAP_CONTENT,
            LinearLayout.LayoutParams.WRAP_CONTENT,
        ).apply { topMargin = dp(16) })
        setRootContentView(root)
    }

    private fun authenticateWithBiometrics(
        reason: String = "Unlock KyAuth",
        silent: Boolean = false,
        onSuccess: () -> Unit = {
            unlockVault(
                unlock = { AppLockManager.unlockWithBiometrics(this) },
                onError = {
                    renderContent()
                    Toast.makeText(this, "Unlock failed. Use your PIN to recover the vault.", Toast.LENGTH_LONG).show()
                },
            )
        },
        onError: (String) -> Unit = {},
    ) {
        val biometricManager = BiometricManager.from(this)
        val canAuthenticate = biometricManager.canAuthenticate(
            BiometricManager.Authenticators.BIOMETRIC_STRONG or BiometricManager.Authenticators.DEVICE_CREDENTIAL,
        )

        if (canAuthenticate != BiometricManager.BIOMETRIC_SUCCESS && silent) {
            return
        }

        BiometricPrompt(this, executor, object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) = onSuccess()
            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                if (!silent) onError("Unlock required: $errString")
            }
        }).authenticate(
            BiometricPrompt.PromptInfo.Builder()
                .setTitle("KyAuth")
                .setSubtitle(reason)
                .setAllowedAuthenticators(
                    BiometricManager.Authenticators.BIOMETRIC_STRONG or BiometricManager.Authenticators.DEVICE_CREDENTIAL,
                )
                .build(),
        )
    }

    private fun dp(value: Int): Int = (value * resources.displayMetrics.density).toInt()

    private fun loadPendingPushChallenge() {
        MfaPushChallengeStore(this).load()?.let {
            pendingChallenge = it
            activeTab = Tab.MFA
        }
    }

    private fun requestNotificationPermissionIfNeeded() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU || store.account() == null) return
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED) return
        ActivityCompat.requestPermissions(this, arrayOf(Manifest.permission.POST_NOTIFICATIONS), 1001)
    }

    private fun applyRootPadding(root: View) {
        val horizontal = dp(screenEdgePaddingDp())
        root.setPadding(
            horizontal,
            dp(12) + systemBarFallbackHeight("status_bar_height"),
            horizontal,
            dp(16) + systemBarFallbackHeight("navigation_bar_height"),
        )
        ViewCompat.setOnApplyWindowInsetsListener(root) { view, insets ->
            val bars = insets.getInsets(WindowInsetsCompat.Type.systemBars())
            view.setPadding(horizontal, dp(12) + bars.top, horizontal, dp(16) + bars.bottom)
            insets
        }
    }

    private fun setRootContentView(root: View) {
        setContentView(root)
        ViewCompat.requestApplyInsets(root)
    }

    private fun systemBarFallbackHeight(name: String): Int {
        val id = resources.getIdentifier(name, "dimen", "android")
        return if (id > 0) resources.getDimensionPixelSize(id) else 0
    }

    private fun screenEdgePaddingDp() = when {
        isExpandedWidth() -> 40
        isCompactWidth() -> 20
        else -> 28
    }

    private fun brand(title: String, subtitle: String): LinearLayout = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        gravity = Gravity.CENTER_HORIZONTAL
        setPadding(0, dp(40), 0, dp(40))
        addView(kyAuthWordmark(title, textSize = 28f, iconSizeDp = 48, centered = true))
        addView(TextView(context).apply {
            text = subtitle
            textSize = 12f
            typeface = Typeface.MONOSPACE
            setTextColor(ThemeManager.color(context, R.color.ky_cyan_dim))
            gravity = Gravity.CENTER
            letterSpacing = 0.2f
        })
    }

    private fun kyAuthWordmark(
        title: String = "KyAuth",
        textSize: Float,
        iconSizeDp: Int,
        centered: Boolean = false,
    ) = LinearLayout(this).apply {
        orientation = LinearLayout.HORIZONTAL
        gravity = if (centered) Gravity.CENTER else Gravity.CENTER_VERTICAL
        contentDescription = title
        addView(ImageView(context).apply {
            setImageResource(R.drawable.ic_launcher_foreground)
            importantForAccessibility = View.IMPORTANT_FOR_ACCESSIBILITY_NO
            scaleType = ImageView.ScaleType.CENTER_INSIDE
        }, LinearLayout.LayoutParams(dp(iconSizeDp), dp(iconSizeDp)).apply { marginEnd = dp(10) })
        addView(TextView(context).apply {
            text = title
            this.textSize = textSize
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(ThemeManager.color(context, R.color.ky_text))
            includeFontPadding = false
        })
    }

    private fun title(value: String) = TextView(this).apply {
        text = value
        textSize = 22f
        setTextColor(ThemeManager.color(context, R.color.ky_text))
        typeface = Typeface.DEFAULT_BOLD
        setPadding(0, dp(16), 0, dp(8))
    }

    private fun message(value: String) = TextView(this).apply {
        text = value
        textSize = 15f
        setTextColor(ThemeManager.color(context, R.color.ky_muted))
        setPadding(0, dp(4), 0, dp(16))
    }

    private fun primaryButton(label: String) = Button(this).apply {
        text = label
        transformationMethod = null
        background = roundedButtonBackground(R.color.ky_cyan)
        setTextColor(ThemeManager.buttonText(context))
        typeface = Typeface.DEFAULT_BOLD
        minHeight = dp(48)
        stateListAnimator = null
        elevation = 0f
    }

    private fun secondaryButton(label: String) = Button(this).apply {
        text = label
        transformationMethod = null
        background = roundedButtonBackground(R.color.ky_surface_elevated, R.color.ky_border)
        setTextColor(ThemeManager.color(context, R.color.ky_cyan))
        minHeight = dp(48)
        stateListAnimator = null
        elevation = 0f
    }

    private fun ghostButton(label: String) = Button(this).apply {
        text = label
        transformationMethod = null
        backgroundTintList = ColorStateList.valueOf(android.graphics.Color.TRANSPARENT)
        setTextColor(ThemeManager.color(context, R.color.ky_cyan))
        textSize = 14f
        stateListAnimator = null
        elevation = 0f
    }

    private fun bottomNavigation() = LinearLayout(this).apply {
        orientation = LinearLayout.HORIZONTAL
        gravity = Gravity.CENTER_VERTICAL
        background = GradientDrawable().apply {
            setColor(ThemeManager.color(this@MainActivity, R.color.ky_surface))
            setStroke(dp(1), ThemeManager.color(this@MainActivity, R.color.ky_border))
            cornerRadius = dp(32).toFloat()
        }
        setPadding(dp(4), dp(4), dp(4), dp(4))

        fun destination(label: String, tab: Tab) = Button(this@MainActivity).apply {
            text = label
            textSize = 11f
            transformationMethod = null
            isAllCaps = false
            minWidth = 0
            minHeight = 0
            includeFontPadding = false
            setPadding(dp(2), 0, dp(2), 0)
            stateListAnimator = null
            elevation = 0f
            setTextColor(ThemeManager.color(context, if (activeTab == tab) R.color.ky_cyan else R.color.ky_muted))
            background = GradientDrawable().apply {
                setColor(ThemeManager.color(context, if (activeTab == tab) R.color.ky_surface_elevated else R.color.ky_surface))
                cornerRadius = dp(22).toFloat()
            }
            layoutParams = LinearLayout.LayoutParams(0, dp(56), 1f)
            setOnClickListener {
                activeTab = tab
                renderContent()
            }
        }

        addView(destination(getString(R.string.tab_totp), Tab.TOTP))
        addView(destination(getString(R.string.tab_approvals), Tab.MFA))
        addView(Button(this@MainActivity).apply {
            contentDescription = "Lock KyAuth"
            minWidth = 0
            minHeight = 0
            stateListAnimator = null
            elevation = 0f
            setCompoundDrawablesWithIntrinsicBounds(0, R.drawable.ic_nav_lock, 0, 0)
            compoundDrawables[1]?.setTint(ThemeManager.color(context, R.color.ky_cyan))
            background = GradientDrawable().apply {
                setColor(ThemeManager.color(context, R.color.ky_surface_elevated))
                cornerRadius = dp(22).toFloat()
            }
            layoutParams = LinearLayout.LayoutParams(dp(56), dp(56)).apply { marginStart = dp(2); marginEnd = dp(2) }
            setOnClickListener {
                AppLockManager.lock()
                renderContent()
            }
        })
        addView(destination(getString(R.string.tab_passwords), Tab.PASSWORDS))
        addView(destination(getString(R.string.tab_settings), Tab.SETTINGS))
    }

    private fun numberButton(label: String) = Button(this).apply {
        text = label
        textSize = 24f
        typeface = Typeface.DEFAULT_BOLD
        backgroundTintList = ColorStateList.valueOf(ThemeManager.color(context, R.color.ky_surface))
        setTextColor(ThemeManager.color(context, R.color.ky_text))
        stateListAnimator = null
        elevation = 0f
    }

    private fun styleInput(editText: EditText) {
        editText.apply {
            setTextColor(ThemeManager.color(context, R.color.ky_text))
            setHintTextColor(ThemeManager.color(context, R.color.ky_muted))
            background = GradientDrawable().apply {
                setColor(ThemeManager.color(context, R.color.ky_surface))
                setStroke(dp(1), ThemeManager.color(context, R.color.ky_border))
                cornerRadius = dp(14).toFloat()
            }
            setPadding(dp(16), dp(12), dp(16), dp(12))
        }
    }

    private fun AlertDialog.Builder.showKyDialog(): AlertDialog {
        return create().apply {
            val background = GradientDrawable().apply {
                setColor(ThemeManager.color(this@MainActivity, R.color.ky_surface))
                setStroke(dp(1), ThemeManager.color(this@MainActivity, R.color.ky_border))
                cornerRadius = dp(24).toFloat()
            }
            window?.setBackgroundDrawable(background)
            setOnShowListener {
                window?.setBackgroundDrawable(background)
                listOf(
                    DialogInterface.BUTTON_POSITIVE,
                    DialogInterface.BUTTON_NEGATIVE,
                    DialogInterface.BUTTON_NEUTRAL,
                ).forEach { which ->
                    getButton(which)?.setTextColor(ThemeManager.color(this@MainActivity, R.color.ky_cyan))
                }
            }
            show()
        }
    }

    private fun fullWidthParams(top: Int = 0, bottom: Int = 0) = LinearLayout.LayoutParams(
        LinearLayout.LayoutParams.MATCH_PARENT,
        LinearLayout.LayoutParams.WRAP_CONTENT
    ).apply {
        topMargin = dp(top)
        bottomMargin = dp(bottom)
    }

    private fun centeredWidthParams(top: Int = 0, bottom: Int = 0, maxWidthDp: Int) = LinearLayout.LayoutParams(
        if (isCompactWidth()) LinearLayout.LayoutParams.MATCH_PARENT else dp(cappedContentWidthDp(maxWidthDp)),
        LinearLayout.LayoutParams.WRAP_CONTENT,
    ).apply {
        gravity = Gravity.CENTER_HORIZONTAL
        topMargin = dp(top)
        bottomMargin = dp(bottom)
    }

    private fun navigationParams() = centeredWidthParams(maxWidthDp = 620).apply {
        if (isExpandedWidth()) gravity = Gravity.END
    }

    private fun scrollContentParams() = FrameLayout.LayoutParams(
        if (isCompactWidth()) FrameLayout.LayoutParams.MATCH_PARENT else dp(cappedContentWidthDp(dashboardMaxWidthDp())),
        FrameLayout.LayoutParams.WRAP_CONTENT,
    ).apply {
        gravity = Gravity.CENTER_HORIZONTAL
    }

    private fun addAdaptiveCards(container: LinearLayout, cards: List<View>) {
        if (!isExpandedWidth()) {
            cards.forEach { container.addView(it) }
            return
        }

        cards.chunked(2).forEach { rowCards ->
            val row = LinearLayout(this).apply {
                orientation = LinearLayout.HORIZONTAL
                layoutParams = fullWidthParams(bottom = 12)
            }
            rowCards.forEachIndexed { index, card ->
                row.addView(card, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f).apply {
                    marginEnd = if (index == 0) dp(6) else 0
                    marginStart = if (index == 1) dp(6) else 0
                })
            }
            if (rowCards.size == 1) {
                row.addView(Space(this), LinearLayout.LayoutParams(0, 1, 1f).apply { marginStart = dp(6) })
            }
            container.addView(row)
        }
    }

    private fun dashboardMaxWidthDp() = if (isExpandedWidth()) 960 else 560

    private fun cappedContentWidthDp(maxWidthDp: Int) = min(maxWidthDp, availableContentWidthDp())

    private fun availableContentWidthDp() = max(1, resources.configuration.screenWidthDp - (screenEdgePaddingDp() * 2))

    private fun isCompactWidth() = resources.configuration.screenWidthDp < 600

    private fun isExpandedWidth() = resources.configuration.screenWidthDp >= 840

    private fun cardBackground() = GradientDrawable().apply {
        setColor(ThemeManager.color(this@MainActivity, R.color.ky_surface))
        setStroke(dp(1), ThemeManager.color(this@MainActivity, R.color.ky_border))
        cornerRadius = dp(20).toFloat()
    }

    private fun settingsCard() = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        background = cardBackground()
        setPadding(dp(16), dp(4), dp(16), dp(16))
        layoutParams = fullWidthParams(bottom = 12)
    }

    private fun roundedButtonBackground(colorRes: Int, strokeRes: Int? = null) = GradientDrawable().apply {
        setColor(ThemeManager.color(this@MainActivity, colorRes))
        strokeRes?.let { setStroke(dp(1), ThemeManager.color(this@MainActivity, it)) }
        cornerRadius = dp(24).toFloat()
    }

    private fun emptyState(title: String, message: String): LinearLayout = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        gravity = Gravity.CENTER
        background = cardBackground()
        setPadding(dp(24), dp(42), dp(24), dp(42))
        addView(TextView(context).apply {
            text = title
            textSize = 18f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(ThemeManager.color(context, R.color.ky_text))
            gravity = Gravity.CENTER
        })
        addView(TextView(context).apply {
            text = message
            textSize = 14f
            setTextColor(ThemeManager.color(context, R.color.ky_muted))
            gravity = Gravity.CENTER
            setPadding(dp(40), dp(8), dp(40), 0)
        })
    }

    private fun mfaEmptyState() = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        gravity = Gravity.CENTER
        background = cardBackground()
        minimumHeight = dp(260)
        setPadding(dp(24), dp(32), dp(24), dp(32))
        addView(TextView(context).apply {
            text = "×"
            textSize = 58f
            typeface = Typeface.DEFAULT
            gravity = Gravity.CENTER
            setTextColor(ThemeManager.color(context, R.color.ky_cyan_dim))
        })
        addView(TextView(context).apply {
            text = getString(R.string.no_pending_challenges)
            textSize = 19f
            typeface = Typeface.DEFAULT_BOLD
            gravity = Gravity.CENTER
            setTextColor(ThemeManager.color(context, R.color.ky_text))
            setPadding(0, dp(12), 0, dp(8))
        })
        addView(TextView(context).apply {
            text = "New sign-in requests will appear here."
            textSize = 14f
            gravity = Gravity.CENTER
            setTextColor(ThemeManager.color(context, R.color.ky_muted))
        })
    }.apply { layoutParams = fullWidthParams() }

    private fun lockSensitiveState() {
        AppLockManager.lock()
        totpEntries.clear()
        passwordEntries.clear()
        copiedSensitiveLabel?.let { label ->
            val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            if (clipboard.primaryClipDescription?.label == label) clipboard.clearPrimaryClip()
        }
        copiedSensitiveLabel = null
    }

    private fun copyTotpCode(clipboard: ClipboardManager, code: String, remainingSeconds: Long) {
        copySensitiveText(code, remainingSeconds, clipboard)
    }

    private fun copySensitiveText(value: String, clearAfterSeconds: Long, clipboard: ClipboardManager? = null) {
        val targetClipboard = clipboard ?: getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        val label = "KyAuth:${UUID.randomUUID()}"
        val clip = ClipData.newPlainText(label, value).apply {
            description.extras = PersistableBundle().apply {
                putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true)
            }
        }
        copiedSensitiveLabel = label
        targetClipboard.setPrimaryClip(clip)
        handler.postDelayed({
            if (copiedSensitiveLabel == label && targetClipboard.primaryClipDescription?.label == label) {
                targetClipboard.clearPrimaryClip()
                copiedSensitiveLabel = null
            }
        }, clearAfterSeconds * 1_000)
    }
}
