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
import org.kysecurity.authenticator.pairing.PairingEndpoint
import org.kysecurity.authenticator.pairing.PairingStore
import org.kysecurity.authenticator.pairing.QrPairing
import org.kysecurity.authenticator.pairing.QrPairingParser
import org.kysecurity.authenticator.pairing.PushTokenProvider
import org.kysecurity.authenticator.passkeys.SignOnPasskey
import org.kysecurity.authenticator.passkeys.SignOnPasskeyKey
import org.kysecurity.authenticator.passkeys.SignOnPasskeyStore
import org.kysecurity.authenticator.passwords.KdbxPasswordVault
import org.kysecurity.authenticator.passwords.PasswordEntry
import org.kysecurity.authenticator.passwords.PasswordGenerator
import org.kysecurity.authenticator.passwords.kypasswords.KyPasswordClient
import org.kysecurity.authenticator.passwords.kypasswords.KyPasswordEnvelopeCrypto
import org.kysecurity.authenticator.passwords.kypasswords.KyPasswordMetadata
import org.kysecurity.authenticator.passwords.kypasswords.KyPasswordPairing
import org.kysecurity.authenticator.passwords.kypasswords.KyPasswordPairingParser
import org.kysecurity.authenticator.passwords.kypasswords.KyPasswordServerAccount
import org.kysecurity.authenticator.passwords.kypasswords.KyPasswordStore
import org.kysecurity.authenticator.security.AppLockManager
import org.kysecurity.authenticator.security.CredentialCipher
import org.kysecurity.authenticator.security.VaultUnlockPrompt
import org.kysecurity.authenticator.security.PinFailurePolicy
import org.kysecurity.authenticator.security.PinPolicy
import org.kysecurity.authenticator.security.SecurityWipe
import org.kysecurity.authenticator.totp.KdbxTotpVault
import org.kysecurity.authenticator.totp.TotpEntry
import org.kysecurity.authenticator.totp.TotpDisplay
import org.kysecurity.authenticator.totp.TotpGenerator
import org.kysecurity.authenticator.totp.TotpUriParser
import java.io.File
import java.net.URI
import java.security.SecureRandom
import java.util.UUID
import java.util.concurrent.Executor
import kotlin.math.max
import kotlin.math.min

private const val STATE_ACTIVE_TAB = "active_tab"

class MainActivity : AppCompatActivity() {
    private lateinit var store: PairingStore
    private val kyPasswordStore by lazy { KyPasswordStore(this) }
    private val kyPasswordClient by lazy { KyPasswordClient() }
    private val executor: Executor by lazy { ContextCompat.getMainExecutor(this) }
    private val handler = Handler(Looper.getMainLooper())

    private var activeTab = Tab.TOTP
    private var pendingChallenge: MfaChallenge? = null
    private var pendingTotpEntry: TotpEntry? = null
    private var totpEntries = mutableListOf<TotpEntry>()
    private var passwordEntries = mutableListOf<PasswordEntry>()
    private var copiedSensitiveLabel: String? = null
    private var isVaultLoading = false
    private data class TotpViews(
        val entry: TotpEntry,
        val code: TextView,
        val timer: TextView,
        val progress: ProgressBar,
    )
    private val totpViews = mutableListOf<TotpViews>()
    private val vaultFile: File by lazy { File(filesDir, "totp_vault.kdbx") }
    private val passwordVaultFile: File by lazy { File(filesDir, "passwords_vault.kdbx") }

    private val ticker = object : Runnable {
        override fun run() {
            if (!isVaultLoading && AppLockManager.isUnlocked() && activeTab == Tab.TOTP) {
                updateTotpViews()
            }
            handler.postDelayed(this, 1000)
        }
    }

    enum class Tab { TOTP, MFA, PASSWORDS, SETTINGS }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        activeTab = savedInstanceState?.getString(STATE_ACTIVE_TAB)
            ?.let { runCatching { Tab.valueOf(it) }.getOrNull() } ?: Tab.TOTP
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
            unlockWithPrompt(silent = true)
        } else {
            runCatching { loadTotpEntries() }
            runCatching { loadPasswordEntries() }
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

    override fun onSaveInstanceState(outState: Bundle) {
        outState.putString(STATE_ACTIVE_TAB, activeTab.name)
        super.onSaveInstanceState(outState)
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
                    .addOnFailureListener { error.text = getString(R.string.scan_failed) }
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
                                    unlockWithPrompt()
                                }.onFailure { error.text = it.message ?: "Pairing failed" }
                            }
                        }.start()
                    },
                    onError = { error.text = it },
                )
            }
            .showKyDialog()
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
                    error.text = getString(R.string.manual_pairing_required)
                    return@setPositiveButton
                }

                val pairing = if (tokenOrPin.length == 6 && tokenOrPin.all { it.isDigit() } && userId != null) {
                    QrPairing(serverUrl = serverUrl, pinCode = tokenOrPin, userId = userId)
                } else {
                    QrPairing(serverUrl = serverUrl, pairingToken = tokenOrPin)
                }
                showPairingConfirmation(pairing, null, progress, error)
            }
            .showKyDialog()
    }

    // ==========================================
    // 2. Lock Screen / Authentication Gate
    // ==========================================

    private fun renderLockScreen(root: LinearLayout, account: PairedAccount) {
        root.gravity = Gravity.CENTER

        root.addView(kyAuthWordmark(textSize = 34f, iconSizeDp = 64, centered = true))
        root.addView(TextView(this).apply {
            text = getString(R.string.vault_locked)
            textSize = 12f
            typeface = Typeface.MONOSPACE
            gravity = Gravity.CENTER
            letterSpacing = 0.18f
            setTextColor(ThemeManager.color(context, R.color.ky_cyan_dim))
            setPadding(0, dp(4), 0, dp(24))
        })
        root.addView(TextView(this).apply {
            text = getString(R.string.unlock_your_vault)
            textSize = 24f
            typeface = Typeface.DEFAULT_BOLD
            gravity = Gravity.CENTER
            setTextColor(ThemeManager.color(context, R.color.ky_text))
        })
        root.addView(TextView(this).apply {
            text = getString(R.string.paired_to, account.serverUrl)
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
            error.text = getString(R.string.pin_retry_wait, retryWaitSec)
        } else if (failureState.failedAttempts > 0) {
            val remaining = PinFailurePolicy.attemptsRemaining(failureState)
            error.text = getString(R.string.pin_attempts_remaining, remaining)
        }

        val btnBiometric = primaryButton(getString(R.string.unlock_biometrics)).apply {
            minHeight = dp(56)
            setOnClickListener {
                unlockWithPrompt(onError = { error.text = it })
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
        totpViews.clear()
        val headerRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            layoutParams = fullWidthParams(bottom = 16)
        }
        val headerTitle = TextView(this).apply {
            text = getString(R.string.tab_totp)
            textSize = 20f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(ThemeManager.color(context, R.color.ky_text))
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
        }
        val addButton = Button(this).apply {
            contentDescription = "Add TOTP account"
            minWidth = 0
            minHeight = 0
            stateListAnimator = null
            elevation = 0f
            setCompoundDrawablesWithIntrinsicBounds(0, R.drawable.ic_add, 0, 0)
            compoundDrawables[1]?.setTint(ThemeManager.color(context, R.color.ky_cyan))
            background = GradientDrawable().apply {
                setColor(ThemeManager.color(context, R.color.ky_surface_elevated))
                cornerRadius = dp(22).toFloat()
                setStroke(dp(1), ThemeManager.color(context, R.color.ky_border))
            }
            layoutParams = LinearLayout.LayoutParams(dp(44), dp(44))
            setOnClickListener { showAddTotpOptionsDialog() }
        }
        headerRow.addView(headerTitle)
        headerRow.addView(addButton)
        container.addView(headerRow)

        if (totpEntries.isEmpty()) {
            container.addView(emptyState("No codes yet", "Tap + to add an account or scan from Settings."))
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

            val display = TotpDisplay.state(entry, nowSec, getString(R.string.totp_code_unavailable))

            val titleView = TextView(this).apply {
                text = entry.title
                textSize = 17f
                typeface = Typeface.DEFAULT_BOLD
                setTextColor(ThemeManager.color(context, R.color.ky_text))
            }
            card.addView(titleView)

            entry.url?.let { url ->
                val urlView = TextView(this).apply {
                    text = url
                    textSize = 13f
                    setTextColor(ThemeManager.color(context, R.color.ky_cyan))
                    setPadding(0, dp(4), 0, 0)
                }
                card.addView(urlView)
            }

            val codeView = TextView(this).apply {
                text = display.formattedCode
                textSize = 34f
                typeface = Typeface.create(Typeface.MONOSPACE, Typeface.BOLD)
                setTextColor(ThemeManager.color(context, R.color.ky_cyan))
                setPadding(0, 8, 0, 8)
                setOnClickListener {
                    val current = TotpDisplay.state(entry, System.currentTimeMillis() / 1000, getString(R.string.totp_code_unavailable))
                    val code = current.code ?: return@setOnClickListener
                    val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                    copyTotpCode(clipboard, code, current.remainingSeconds)
                    Toast.makeText(this@MainActivity, getString(R.string.copy_code), Toast.LENGTH_SHORT).show()
                }
            }
            val timerView = TextView(this).apply {
                text = getString(R.string.totp_expiry, display.remainingSeconds)
                textSize = 14f
                setTextColor(ThemeManager.color(context, R.color.ky_muted))
            }

            card.addView(codeView)
            card.addView(timerView)
            val progressView = ProgressBar(this, null, android.R.attr.progressBarStyleHorizontal).apply {
                progressTintList = ColorStateList.valueOf(ThemeManager.color(context, R.color.ky_cyan))
                progressBackgroundTintList = ColorStateList.valueOf(ThemeManager.color(context, R.color.ky_border))
                max = entry.periodSeconds.toInt()
                progress = max(0, display.remainingSeconds.toInt())
            }
            card.addView(progressView, LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, dp(4)).apply { topMargin = dp(14) })
            totpViews.add(TotpViews(entry, codeView, timerView, progressView))

            entry.notes?.let { notes ->
                val notesView = TextView(this).apply {
                    text = notes
                    textSize = 13f
                    setTextColor(ThemeManager.color(context, R.color.ky_muted))
                    setPadding(0, dp(10), 0, 0)
                }
                card.addView(notesView)
            }

            card.setOnLongClickListener {
                showEditOrDeleteTotpDialog(entry)
                true
            }
            cards.add(card)
        }
        addAdaptiveCards(container, cards)
    }

    private fun updateTotpViews() {
        val now = System.currentTimeMillis() / 1000
        val unavailable = getString(R.string.totp_code_unavailable)
        totpViews.forEach { views ->
            val display = TotpDisplay.state(views.entry, now, unavailable)
            views.code.text = display.formattedCode
            views.timer.text = getString(R.string.totp_expiry, display.remainingSeconds)
            views.progress.progress = max(0, display.remainingSeconds.toInt())
        }
    }

    private fun showAddTotpOptionsDialog() {
        val container = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(24), dp(24), dp(24), dp(20))
        }
        val titleView = TextView(this).apply {
            text = getString(R.string.add_to_totp_vault)
            textSize = 20f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(ThemeManager.color(context, R.color.ky_text))
            setPadding(0, 0, 0, dp(4))
        }
        val messageView = TextView(this).apply {
            text = getString(R.string.add_totp_choice)
            textSize = 14f
            setTextColor(ThemeManager.color(context, R.color.ky_muted))
            setPadding(0, 0, 0, dp(18))
        }
        container.addView(titleView)
        container.addView(messageView)

        var dialog: AlertDialog? = null

        val btnScan = primaryButton("Scan QR Code").apply {
            setOnClickListener {
                dialog?.dismiss()
                scanTotpQr()
            }
        }
        val btnManual = secondaryButton("Add Manually").apply {
            setOnClickListener {
                dialog?.dismiss()
                showAddTotpDialog()
            }
        }
        val btnCancel = ghostButton("Cancel").apply {
            setOnClickListener { dialog?.dismiss() }
        }

        container.addView(btnScan, fullWidthParams(bottom = 10))
        container.addView(btnManual, fullWidthParams(bottom = 6))
        container.addView(btnCancel, fullWidthParams())

        dialog = AlertDialog.Builder(this)
            .setView(container)
            .showKyDialog()
    }

    private fun scanTotpQr() {
        GmsBarcodeScanning.getClient(this).startScan()
            .addOnSuccessListener { result ->
                runCatching { TotpUriParser.parse(result.rawValue.orEmpty()) }
                    .onSuccess { queueTotpEntry(it) }
                    .onFailure { Toast.makeText(this, "Invalid OTP QR code", Toast.LENGTH_SHORT).show() }
            }
    }

    private fun showAddTotpDialog() {
        val form = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(24), dp(24), dp(24), dp(20))
        }
        val titleView = TextView(this).apply {
            text = getString(R.string.add_manually)
            textSize = 20f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(ThemeManager.color(context, R.color.ky_text))
            setPadding(0, 0, 0, dp(4))
        }
        val subtitleView = TextView(this).apply {
            text = getString(R.string.add_totp_description)
            textSize = 14f
            setTextColor(ThemeManager.color(context, R.color.ky_muted))
            setPadding(0, 0, 0, dp(16))
        }
        form.addView(titleView)
        form.addView(subtitleView)

        val titleInput = EditText(this).apply { hint = "Account Name (e.g. GitHub)"; styleInput(this) }
        val secretInput = EditText(this).apply { hint = "Secret Key (Base32)"; styleInput(this) }
        val urlInput = EditText(this).apply { hint = "Website (URL) (optional)"; styleInput(this) }
        val notesInput = EditText(this).apply {
            hint = "Notes (optional)"
            minLines = 3
            gravity = Gravity.TOP
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_CAP_SENTENCES or InputType.TYPE_TEXT_FLAG_MULTI_LINE
            styleInput(this)
        }
        form.addView(titleInput, fullWidthParams(bottom = 10))
        form.addView(secretInput, fullWidthParams(bottom = 10))
        form.addView(urlInput, fullWidthParams(bottom = 10))
        form.addView(notesInput, fullWidthParams(bottom = 18))

        var dialog: AlertDialog? = null

        val actions = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.END
        }
        val btnCancel = ghostButton("Cancel").apply {
            setOnClickListener { dialog?.dismiss() }
        }
        val btnSave = primaryButton("Save").apply {
            setPadding(dp(24), 0, dp(24), 0)
            setOnClickListener {
                val title = titleInput.text.toString().trim()
                val secret = secretInput.text.toString().trim().replace(" ", "")
                val url = urlInput.text.toString().trim().ifBlank { null }
                val notes = notesInput.text.toString().trim().ifBlank { null }
                if (title.isNotBlank() && secret.isNotBlank()) {
                    runCatching {
                        TotpEntry(
                            title = title,
                            secretBase32 = secret,
                            url = url,
                            notes = notes,
                        )
                    }.onSuccess {
                        addTotpEntry(it)
                        dialog?.dismiss()
                    }.onFailure {
                        Toast.makeText(this@MainActivity, it.message ?: "Invalid secret", Toast.LENGTH_SHORT).show()
                    }
                } else {
                    Toast.makeText(this@MainActivity, "Account name and secret key are required", Toast.LENGTH_SHORT).show()
                }
            }
        }
        actions.addView(btnCancel)
        actions.addView(btnSave, LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply { marginStart = dp(8) })
        form.addView(actions)

        val scrollView = ScrollView(this).apply {
            clipToPadding = false
            addView(form)
        }

        dialog = AlertDialog.Builder(this)
            .setView(scrollView)
            .showKyDialog()
    }

    private fun showEditTotpDialog(entry: TotpEntry) {
        val form = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(24), dp(24), dp(24), dp(20))
        }
        val titleView = TextView(this).apply {
            text = getString(R.string.edit_account)
            textSize = 20f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(ThemeManager.color(context, R.color.ky_text))
            setPadding(0, 0, 0, dp(4))
        }
        val subtitleView = TextView(this).apply {
            text = entry.title
            textSize = 14f
            setTextColor(ThemeManager.color(context, R.color.ky_muted))
            setPadding(0, 0, 0, dp(16))
        }
        form.addView(titleView)
        form.addView(subtitleView)

        val titleInput = EditText(this).apply {
            hint = "Account Name (e.g. GitHub)"
            setText(entry.title)
            styleInput(this)
        }
        val secretInput = EditText(this).apply {
            hint = "Secret Key (Base32)"
            setText(entry.secretBase32)
            styleInput(this)
        }
        val urlInput = EditText(this).apply {
            hint = "Website (URL) (optional)"
            setText(entry.url.orEmpty())
            styleInput(this)
        }
        val notesInput = EditText(this).apply {
            hint = "Notes (optional)"
            minLines = 3
            gravity = Gravity.TOP
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_CAP_SENTENCES or InputType.TYPE_TEXT_FLAG_MULTI_LINE
            setText(entry.notes.orEmpty())
            styleInput(this)
        }
        form.addView(titleInput, fullWidthParams(bottom = 10))
        form.addView(secretInput, fullWidthParams(bottom = 10))
        form.addView(urlInput, fullWidthParams(bottom = 10))
        form.addView(notesInput, fullWidthParams(bottom = 18))

        var dialog: AlertDialog? = null

        val actions = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.END
        }
        val btnCancel = ghostButton("Cancel").apply {
            setOnClickListener { dialog?.dismiss() }
        }
        val btnSave = primaryButton("Save").apply {
            setPadding(dp(24), 0, dp(24), 0)
            setOnClickListener {
                val title = titleInput.text.toString().trim()
                val secret = secretInput.text.toString().trim().replace(" ", "")
                val url = urlInput.text.toString().trim().ifBlank { null }
                val notes = notesInput.text.toString().trim().ifBlank { null }
                if (title.isNotBlank() && secret.isNotBlank()) {
                    runCatching {
                        entry.copy(
                            title = title,
                            secretBase32 = secret,
                            url = url,
                            notes = notes,
                        )
                    }.onSuccess { updated ->
                        val idx = totpEntries.indexOfFirst { it.id == entry.id }
                        if (idx >= 0) {
                            totpEntries[idx] = updated
                        } else {
                            totpEntries.add(updated)
                        }
                        saveTotpEntries()
                        renderContent()
                        dialog?.dismiss()
                    }.onFailure {
                        Toast.makeText(this@MainActivity, it.message ?: "Invalid entry", Toast.LENGTH_SHORT).show()
                    }
                } else {
                    Toast.makeText(this@MainActivity, "Account name and secret key are required", Toast.LENGTH_SHORT).show()
                }
            }
        }
        actions.addView(btnCancel)
        actions.addView(btnSave, LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply { marginStart = dp(8) })
        form.addView(actions)

        val scrollView = ScrollView(this).apply {
            clipToPadding = false
            addView(form)
        }

        dialog = AlertDialog.Builder(this)
            .setView(scrollView)
            .showKyDialog()
    }

    private fun showEditOrDeleteTotpDialog(entry: TotpEntry) {
        val container = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(24), dp(24), dp(24), dp(20))
        }
        val titleView = TextView(this).apply {
            text = entry.title
            textSize = 20f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(ThemeManager.color(context, R.color.ky_text))
            setPadding(0, 0, 0, dp(4))
        }
        container.addView(titleView)

        entry.url?.let { url ->
            val urlView = TextView(this).apply {
                text = url
                textSize = 13f
                setTextColor(ThemeManager.color(context, R.color.ky_cyan))
                setPadding(0, 0, 0, dp(4))
            }
            container.addView(urlView)
        }

        entry.notes?.let { notes ->
            val notesView = TextView(this).apply {
                text = notes
                textSize = 13f
                setTextColor(ThemeManager.color(context, R.color.ky_muted))
                setPadding(0, dp(4), 0, dp(8))
            }
            container.addView(notesView)
        }

        var dialog: AlertDialog? = null

        val btnEdit = secondaryButton("Edit Entry").apply {
            setOnClickListener {
                dialog?.dismiss()
                showEditTotpDialog(entry)
            }
        }
        val btnDelete = secondaryButton("Delete Entry").apply {
            setTextColor(ThemeManager.color(context, R.color.ky_error))
            setOnClickListener {
                dialog?.dismiss()
                totpEntries.removeAll { it.id == entry.id }
                saveTotpEntries()
                renderContent()
            }
        }
        val btnCancel = ghostButton("Cancel").apply {
            setOnClickListener { dialog?.dismiss() }
        }

        container.addView(btnEdit, fullWidthParams(top = 10, bottom = 10))
        container.addView(btnDelete, fullWidthParams(bottom = 6))
        container.addView(btnCancel, fullWidthParams())

        dialog = AlertDialog.Builder(this)
            .setView(container)
            .showKyDialog()
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

    private fun savePasswordEntries(syncToRemote: Boolean = true) {
        val vaultKey = AppLockManager.getPasswordVaultKey() ?: return
        KdbxPasswordVault.saveEntries(passwordVaultFile, vaultKey, passwordEntries)
        if (syncToRemote) {
            val account = kyPasswordStore.account()
            if (account != null) {
                Thread {
                    runCatching {
                        val newVersion = kyPasswordClient.uploadVault(
                            serverUrl = account.serverUrl,
                            sessionToken = account.sessionToken,
                            vaultFile = passwordVaultFile,
                            expectedVersion = account.vaultVersion,
                            deviceId = account.deviceId,
                        )
                        kyPasswordStore.updateSync(newVersion)
                    }
                }.start()
            }
        }
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
        val vaultKey = AppLockManager.getPasswordVaultKey()
        val kyAccount = kyPasswordStore.account()

        if (vaultKey == null) {
            if (kyAccount == null) {
                val card = settingsCard().apply {
                    addView(title("Set up Passwords & Passkeys"))
                    addView(message("Create an encrypted vault stored only on this device, or pair a KyPasswords server for sync."))
                    val btnLocal = primaryButton("Create Local Vault").apply {
                        setOnClickListener { createLocalPasswordVault() }
                    }
                    val btnPair = secondaryButton("Pair KyPasswords Server").apply {
                        setOnClickListener { showPairKyPasswordsDialog() }
                    }
                    addView(btnLocal, fullWidthParams(top = 12, bottom = 8))
                    addView(btnPair, fullWidthParams())
                }
                container.addView(card, fullWidthParams())
                return
            } else {
                val card = settingsCard().apply {
                    addView(title("Unlock KyPasswords Vault"))
                    addView(message("Server: ${kyAccount.serverUrl}\nDevice ID: ${kyAccount.deviceId}\n\nEnter your KyPasswords master password to unlock your vault keyfile."))
                    val btnUnlock = primaryButton("Unlock Vault").apply {
                        setOnClickListener { showUnlockKyPasswordsDialog(kyAccount) }
                    }
                    val btnUnpair = secondaryButton("Unpair Server").apply {
                        setTextColor(ThemeManager.color(context, R.color.ky_error))
                        setOnClickListener { confirmUnpairKyPasswords() }
                    }
                    addView(btnUnlock, fullWidthParams(top = 12, bottom = 8))
                    addView(btnUnpair, fullWidthParams())
                }
                container.addView(card, fullWidthParams())
                return
            }
        }

        val headerActions = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
        }
        val addButton = primaryButton("Add password").apply {
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
            setOnClickListener { showAddPasswordDialog() }
        }
        val syncButton = secondaryButton("Sync").apply {
            layoutParams = LinearLayout.LayoutParams(LinearLayout.LayoutParams.WRAP_CONTENT, LinearLayout.LayoutParams.WRAP_CONTENT).apply {
                marginStart = dp(8)
            }
            setOnClickListener { syncKyPasswordsVault() }
        }
        headerActions.addView(addButton)
        if (kyAccount != null) {
            headerActions.addView(syncButton)
        }
        container.addView(headerActions, fullWidthParams(bottom = 16))

        if (kyAccount?.lastSyncError != null) {
            val errorBanner = LinearLayout(this).apply {
                orientation = LinearLayout.VERTICAL
                background = GradientDrawable().apply {
                    setColor(ThemeManager.color(context, R.color.ky_surface_elevated))
                    cornerRadius = dp(12).toFloat()
                    setStroke(dp(1), ThemeManager.color(context, R.color.ky_error))
                }
                setPadding(dp(16), dp(12), dp(16), dp(12))
                setOnClickListener {
                    showSyncErrorDialog("Sync Issue", kyAccount.lastSyncError ?: "Unknown error")
                }
            }
            errorBanner.addView(TextView(this).apply {
                text = getString(R.string.sync_issue, kyAccount.lastSyncError)
                textSize = 13f
                setTextColor(ThemeManager.color(context, R.color.ky_error))
            })
            errorBanner.addView(TextView(this).apply {
                text = getString(R.string.sync_issue_action)
                textSize = 12f
                setTextColor(ThemeManager.color(context, R.color.ky_muted))
                setPadding(0, dp(2), 0, 0)
            })
            container.addView(errorBanner, fullWidthParams(bottom = 12))
        }

        if (passwordEntries.isEmpty()) {
            container.addView(emptyState("No passwords yet", "Add a password entry or sync with your KyPasswords server."))
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

            val pairedServerUrl = PairingStore(this).account()?.serverUrl
            val stranded = entry.passkey?.let {
                SignOnPasskey.isSignOnRpId(it.rpId, pairedServerUrl)
            } == true
            if (entry.isPasskey) {
                headerRow.addView(TextView(this).apply {
                    text = if (stranded) {
                        getString(R.string.signon_passkey_restranded)
                    } else {
                        getString(R.string.passkey_badge)
                    }
                    textSize = 11f
                    typeface = Typeface.DEFAULT_BOLD
                    val accent = if (stranded) R.color.ky_error else R.color.ky_cyan
                    setTextColor(ThemeManager.color(context, accent))
                    background = GradientDrawable().apply {
                        setColor(ThemeManager.color(context, R.color.ky_surface_elevated))
                        cornerRadius = dp(6).toFloat()
                        setStroke(dp(1), ThemeManager.color(context, accent))
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

    private fun createLocalPasswordVault() {
        val vaultKey = CredentialCipher.generateVaultKey()
        runCatching {
            KdbxPasswordVault.saveEntries(passwordVaultFile, vaultKey, emptyList())
            AppLockManager.setPasswordVaultKey(this, vaultKey)
            passwordEntries.clear()
        }.onSuccess {
            Toast.makeText(this, "Local password vault created", Toast.LENGTH_SHORT).show()
            renderContent()
        }.onFailure {
            AppLockManager.clearPasswordVaultKey(this)
            vaultKey.fill(0)
            passwordVaultFile.delete()
            Toast.makeText(this, "Could not create the local password vault", Toast.LENGTH_LONG).show()
        }
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
            text = getString(R.string.local_password_storage)
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
                text = getString(R.string.webauthn_passkey)
                textSize = 18f
                typeface = Typeface.DEFAULT_BOLD
                setTextColor(ThemeManager.color(context, R.color.ky_cyan))
                setPadding(0, dp(12), 0, dp(4))
            })
            container.addView(TextView(this).apply {
                text = getString(R.string.passkey_details, passkey.rpId, passkey.signCount)
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

        builder.setPositiveButton("Close", null).showKyDialog()
    }

    private fun generatePassword(length: Int = 20): String =
        PasswordGenerator.generate(length = length)

    // ==========================================
    // KyPasswords Server Pairing & Sync Helpers
    // ==========================================

    private fun showPairKyPasswordsDialog() {
        val container = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(24), dp(24), dp(24), dp(20))
        }
        val titleView = TextView(this).apply {
            text = getString(R.string.pair_kypasswords_server)
            textSize = 20f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(ThemeManager.color(context, R.color.ky_text))
            setPadding(0, 0, 0, dp(8))
        }
        val subtitleView = TextView(this).apply {
            text = getString(R.string.pair_kypasswords_description)
            textSize = 14f
            setTextColor(ThemeManager.color(context, R.color.ky_muted))
            setPadding(0, 0, 0, dp(16))
        }
        container.addView(titleView)
        container.addView(subtitleView)

        var dialog: AlertDialog? = null

        val btnScan = primaryButton("Scan QR Code").apply {
            setOnClickListener {
                dialog?.dismiss()
                scanKyPasswordsQr()
            }
        }
        val btnManual = secondaryButton("Enter Details Manually").apply {
            setOnClickListener {
                dialog?.dismiss()
                showManualKyPasswordsPairingDialog()
            }
        }
        val btnCancel = ghostButton("Cancel").apply {
            setOnClickListener { dialog?.dismiss() }
        }

        container.addView(btnScan, fullWidthParams(bottom = 10))
        container.addView(btnManual, fullWidthParams(bottom = 10))
        container.addView(btnCancel, fullWidthParams())

        dialog = AlertDialog.Builder(this)
            .setView(container)
            .showKyDialog()
    }

    private fun scanKyPasswordsQr() {
        GmsBarcodeScanning.getClient(this).startScan()
            .addOnSuccessListener { result ->
                val raw = result.rawValue.orEmpty()
                runCatching { KyPasswordPairingParser.parse(raw) }
                    .onSuccess { pairing -> redeemAndUnlockKyPasswords(pairing) }
                    .onFailure { Toast.makeText(this, "Invalid KyPasswords QR code: ${it.message}", Toast.LENGTH_SHORT).show() }
            }
            .addOnFailureListener {
                Toast.makeText(this, "Scanner failed or canceled", Toast.LENGTH_SHORT).show()
            }
    }

    private fun showManualKyPasswordsPairingDialog() {
        val container = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(24), dp(16), dp(24), dp(16))
        }
        val titleView = TextView(this).apply {
            text = getString(R.string.manual_kypasswords_pairing)
            textSize = 18f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(ThemeManager.color(context, R.color.ky_text))
            setPadding(0, 0, 0, dp(12))
        }
        container.addView(titleView)

        val serverInput = EditText(this).apply { hint = "Server URL (e.g. https://passwords.example.com)"; styleInput(this) }
        val pinInput = EditText(this).apply { hint = "6-digit PIN or Pairing Secret"; styleInput(this) }

        container.addView(serverInput, fullWidthParams(bottom = 10))
        container.addView(pinInput, fullWidthParams())

        AlertDialog.Builder(this)
            .setView(container)
            .setNegativeButton("Cancel", null)
            .setPositiveButton("Connect") { _, _ ->
                val serverUrl = serverInput.text.toString().trim()
                val pinOrSecret = pinInput.text.toString().trim()
                if (serverUrl.isBlank() || pinOrSecret.isBlank()) {
                    Toast.makeText(this, "Server URL and PIN/Secret are required", Toast.LENGTH_SHORT).show()
                    return@setPositiveButton
                }
                runCatching {
                    KyPasswordPairing(
                        serverUrl = PairingEndpoint.validateServerUrl(serverUrl),
                        secret = if (pinOrSecret.length > 6) pinOrSecret else null,
                        pin = if (pinOrSecret.length <= 6) pinOrSecret else null,
                    )
                }.onSuccess { pairing ->
                    redeemAndUnlockKyPasswords(pairing)
                }.onFailure {
                    Toast.makeText(this, it.message ?: "Invalid server URL", Toast.LENGTH_SHORT).show()
                }
            }
            .showKyDialog()
    }

    private fun redeemAndUnlockKyPasswords(pairing: KyPasswordPairing) {
        val progressToast = Toast.makeText(this, "Pairing with KyPasswords server…", Toast.LENGTH_SHORT)
        progressToast.show()

        Thread {
            try {
                val deviceName = "${Build.MANUFACTURER} ${Build.MODEL}".trim()
                val session = kyPasswordClient.redeemPairing(
                    serverUrl = pairing.serverUrl,
                    codeOrPin = pairing.secret ?: pairing.pin!!,
                    deviceName = deviceName,
                )
                val metadata = kyPasswordClient.fetchMetadata(pairing.serverUrl, session.sessionToken)
                val account = KyPasswordServerAccount(
                    serverUrl = pairing.serverUrl,
                    deviceId = session.deviceId,
                    sessionToken = session.sessionToken,
                    userId = session.userId,
                    vaultVersion = metadata.version,
                )

                runOnUiThread {
                    if (passwordEntries.isNotEmpty()) {
                        if (metadata.version == 0L) {
                            showUploadLocalVaultDialog(account)
                        } else {
                            AlertDialog.Builder(this)
                                .setTitle("Server Vault Already Exists")
                                .setMessage("This device and server use different vault keys. The local vault was not changed or uploaded.")
                                .setPositiveButton("OK", null)
                                .showKyDialog()
                        }
                    } else {
                        kyPasswordStore.save(account)
                        showUnlockKyPasswordsDialog(account, metadata)
                    }
                }
            } catch (e: Exception) {
                runOnUiThread {
                    Toast.makeText(this, "Pairing failed: ${e.message}", Toast.LENGTH_LONG).show()
                }
            }
        }.start()
    }

    private fun showUploadLocalVaultDialog(account: KyPasswordServerAccount) {
        val passwordInput = EditText(this).apply {
            hint = "KyPasswords vault password"
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
            styleInput(this)
        }
        AlertDialog.Builder(this)
            .setTitle("Upload Local Vault")
            .setMessage("Choose the password that will unlock this vault in KyPasswords. The server receives only the encrypted vault and wrapped key.")
            .setView(passwordInput)
            .setNegativeButton("Cancel", null)
            .setPositiveButton("Upload") { _, _ ->
                val password = passwordInput.text.toString()
                val vaultKey = AppLockManager.getPasswordVaultKey()
                if (password.isBlank() || vaultKey == null) {
                    Toast.makeText(this, "A vault password is required", Toast.LENGTH_SHORT).show()
                    return@setPositiveButton
                }
                Thread {
                    runCatching {
                        val envelope = KyPasswordEnvelopeCrypto.wrapVaultKey(vaultKey, password)
                        val version = kyPasswordClient.uploadVault(
                            serverUrl = account.serverUrl,
                            sessionToken = account.sessionToken,
                            vaultFile = passwordVaultFile,
                            expectedVersion = 0L,
                            deviceId = account.deviceId,
                            passwordEnvelope = envelope,
                        )
                        kyPasswordStore.save(account.copy(vaultVersion = version))
                        version
                    }.onSuccess { version ->
                        runOnUiThread {
                            Toast.makeText(this, "Local vault uploaded to KyPasswords (v$version)", Toast.LENGTH_SHORT).show()
                            renderContent()
                        }
                    }.onFailure { error ->
                        runOnUiThread {
                            Toast.makeText(this, "Upload failed: ${error.message}", Toast.LENGTH_LONG).show()
                        }
                    }
                }.start()
            }
            .showKyDialog()
    }

    private fun showUnlockKyPasswordsDialog(
        account: KyPasswordServerAccount,
        cachedMetadata: KyPasswordMetadata? = null,
    ) {
        val container = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(24), dp(16), dp(24), dp(16))
        }
        val titleView = TextView(this).apply {
            text = getString(R.string.unlock_kypasswords_keyfile)
            textSize = 18f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(ThemeManager.color(context, R.color.ky_text))
            setPadding(0, 0, 0, dp(4))
        }
        val subtitleView = TextView(this).apply {
            text = getString(R.string.unlock_kypasswords_description)
            textSize = 14f
            setTextColor(ThemeManager.color(context, R.color.ky_muted))
            setPadding(0, 0, 0, dp(12))
        }
        container.addView(titleView)
        container.addView(subtitleView)

        val passwordInput = EditText(this).apply {
            hint = "Master Password or Recovery Key"
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
            styleInput(this)
        }
        container.addView(passwordInput, fullWidthParams())

        AlertDialog.Builder(this)
            .setView(container)
            .setNegativeButton("Cancel") { _, _ ->
                if (AppLockManager.getPasswordVaultKey() == null) {
                    Toast.makeText(this, "KyPasswords is paired. You can enter your master password anytime from the Passwords tab.", Toast.LENGTH_SHORT).show()
                }
                renderContent()
            }
            .setPositiveButton("Unlock") { _, _ ->
                val secret = passwordInput.text.toString().trim()
                if (secret.isBlank()) {
                    Toast.makeText(this, "Password is required", Toast.LENGTH_SHORT).show()
                    showUnlockKyPasswordsDialog(account, cachedMetadata)
                    return@setPositiveButton
                }

                val progressToast = Toast.makeText(this, "Unwrapping keyfile and loading vault…", Toast.LENGTH_SHORT)
                progressToast.show()

                Thread {
                    try {
                        val meta = cachedMetadata ?: kyPasswordClient.fetchMetadata(account.serverUrl, account.sessionToken)
                        val envelope = meta.passwordEnvelope ?: meta.recoveryEnvelope
                            ?: throw IllegalStateException("No key envelope found on server")

                        val vaultKey = KyPasswordEnvelopeCrypto.unwrapVaultKey(envelope, secret)
                        AppLockManager.setPasswordVaultKey(this@MainActivity, vaultKey)

                        if (meta.version > 0) {
                            kyPasswordClient.downloadVault(account.serverUrl, account.sessionToken, passwordVaultFile)
                        } else if (!passwordVaultFile.exists()) {
                            KdbxPasswordVault.saveEntries(passwordVaultFile, vaultKey, emptyList())
                        }

                        loadPasswordEntries()
                        kyPasswordStore.updateSync(meta.version)

                        runOnUiThread {
                            Toast.makeText(this@MainActivity, "KyPasswords vault unlocked successfully", Toast.LENGTH_SHORT).show()
                            renderContent()
                        }
                    } catch (e: Exception) {
                        runOnUiThread {
                            Toast.makeText(this@MainActivity, "Failed to unlock keyfile: ${e.message}", Toast.LENGTH_LONG).show()
                            showUnlockKyPasswordsDialog(account, cachedMetadata)
                        }
                    }
                }.start()
            }
            .showKyDialog()
    }

    private fun syncKyPasswordsVault() {
        val account = kyPasswordStore.account()
        val vaultKey = AppLockManager.getPasswordVaultKey()
        if (account == null || vaultKey == null) {
            Toast.makeText(this, "Vault is not paired or unlocked", Toast.LENGTH_SHORT).show()
            return
        }

        Toast.makeText(this, "Syncing KyPasswords vault…", Toast.LENGTH_SHORT).show()

        Thread {
            try {
                if (!passwordVaultFile.exists() || passwordVaultFile.length() == 0L) {
                    KdbxPasswordVault.saveEntries(passwordVaultFile, vaultKey, passwordEntries)
                }

                val metadata = kyPasswordClient.fetchMetadata(account.serverUrl, account.sessionToken)
                if (metadata.version > account.vaultVersion) {
                    val version = kyPasswordClient.downloadVault(account.serverUrl, account.sessionToken, passwordVaultFile)
                    loadPasswordEntries()
                    kyPasswordStore.updateSync(version)
                    runOnUiThread {
                        Toast.makeText(this, "Vault updated to v$version from server", Toast.LENGTH_SHORT).show()
                        renderContent()
                    }
                } else {
                    try {
                        val newVersion = kyPasswordClient.uploadVault(
                            serverUrl = account.serverUrl,
                            sessionToken = account.sessionToken,
                            vaultFile = passwordVaultFile,
                            expectedVersion = account.vaultVersion,
                            deviceId = account.deviceId,
                        )
                        kyPasswordStore.updateSync(newVersion)
                        runOnUiThread {
                            Toast.makeText(this, "Vault synced to server (v$newVersion)", Toast.LENGTH_SHORT).show()
                            renderContent()
                        }
                    } catch (conflict: org.kysecurity.authenticator.passwords.kypasswords.KyPasswordConflictException) {
                        val version = kyPasswordClient.downloadVault(account.serverUrl, account.sessionToken, passwordVaultFile)
                        val merged = KdbxPasswordVault.update(passwordVaultFile, vaultKey) { remote ->
                            val combined = (remote.toList() + passwordEntries).distinctBy { it.id }
                            remote.clear()
                            remote.addAll(combined)
                            true
                        }
                        passwordEntries = merged.toMutableList()
                        val reUploadVersion = kyPasswordClient.uploadVault(
                            serverUrl = account.serverUrl,
                            sessionToken = account.sessionToken,
                            vaultFile = passwordVaultFile,
                            expectedVersion = version,
                            deviceId = account.deviceId,
                        )
                        kyPasswordStore.updateSync(reUploadVersion)
                        runOnUiThread {
                            Toast.makeText(this, "Deconflicted & synced with server (v$reUploadVersion)", Toast.LENGTH_SHORT).show()
                            renderContent()
                        }
                    }
                }
            } catch (auth: org.kysecurity.authenticator.passwords.kypasswords.KyPasswordAuthException) {
                val msg = auth.message ?: "Authentication failed: session expired or device revoked"
                kyPasswordStore.setSyncError(msg)
                runOnUiThread {
                    showSyncErrorDialog("Session Expired", "Your pairing session with KyPasswords is no longer valid. Please unpair and re-pair this device.")
                    renderContent()
                }
            } catch (notFound: org.kysecurity.authenticator.passwords.kypasswords.KyPasswordNotFoundException) {
                runCatching {
                    val initialVersion = kyPasswordClient.uploadVault(
                        serverUrl = account.serverUrl,
                        sessionToken = account.sessionToken,
                        vaultFile = passwordVaultFile,
                        expectedVersion = 0L,
                        deviceId = account.deviceId,
                    )
                    kyPasswordStore.updateSync(initialVersion)
                    runOnUiThread {
                        Toast.makeText(this, "Initial vault uploaded to server (v$initialVersion)", Toast.LENGTH_SHORT).show()
                        renderContent()
                    }
                }.onFailure { err ->
                    val msg = err.localizedMessage ?: err.message ?: "Initial upload failed"
                    kyPasswordStore.setSyncError(msg)
                    runOnUiThread {
                        showSyncErrorDialog("Sync Failed", "Could not initialize vault on server:\n\n$msg")
                        renderContent()
                    }
                }
            } catch (e: Exception) {
                val msg = e.localizedMessage ?: e.message ?: "Unknown sync error"
                kyPasswordStore.setSyncError(msg)
                runOnUiThread {
                    showSyncErrorDialog("Sync Failed", "Could not sync with KyPasswords server:\n\n$msg")
                    renderContent()
                }
            }
        }.start()
    }

    private fun showSyncErrorDialog(title: String, message: String) {
        AlertDialog.Builder(this)
            .setTitle(title)
            .setMessage(message)
            .setPositiveButton("OK", null)
            .setNeutralButton("Retry") { _, _ -> syncKyPasswordsVault() }
            .showKyDialog()
    }

    private fun confirmUnpairKyPasswords() {
        AlertDialog.Builder(this)
            .setTitle("Unpair KyPasswords Server")
            .setMessage("Are you sure you want to unpair from KyPasswords? This will remove the local password keyfile and lock the password vault.")
            .setNegativeButton("Cancel", null)
            .setPositiveButton("Unpair") { _, _ ->
                kyPasswordStore.clear()
                AppLockManager.clearPasswordVaultKey(this)
                passwordEntries.clear()
                passwordVaultFile.delete()
                Toast.makeText(this, "KyPasswords server unpaired", Toast.LENGTH_SHORT).show()
                renderContent()
            }
            .showKyDialog()
    }

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

        val providerSection = settingsCard()
        providerSection.addView(title("Password & Passkey Provider"))
        providerSection.addView(message("Set KyAuth as your default system provider to autofill passwords and use passkeys across apps and websites."))
        providerSection.addView(primaryButton("Set as default provider").apply {
            setOnClickListener { openCredentialProviderSettings() }
        }, fullWidthParams())
        sections.add(providerSection)

        val signOnPasskeySection = settingsCard()
        signOnPasskeySection.addView(title(getString(R.string.signon_passkey_title)))
        val signOnRecord = SignOnPasskeyStore(this).record()
        if (signOnRecord == null) {
            signOnPasskeySection.addView(message(getString(R.string.signon_passkey_none)))
        } else {
            val backing = if (signOnRecord.strongBoxBacked) {
                R.string.signon_passkey_strongbox
            } else {
                R.string.signon_passkey_tee
            }
            signOnPasskeySection.addView(
                message("${signOnRecord.username.ifBlank { signOnRecord.rpId }}\n${getString(backing)}"),
            )
            val btnRemove = secondaryButton(getString(R.string.signon_passkey_remove)).apply {
                setTextColor(ThemeManager.color(context, R.color.ky_error))
                setOnClickListener {
                    AlertDialog.Builder(this@MainActivity)
                        .setTitle(getString(R.string.signon_passkey_remove))
                        .setMessage(
                            "This passkey only exists on this device and cannot be recovered. " +
                                "You will need your KySignOn recovery codes or an admin reset to " +
                                "sign in without it.",
                        )
                        .setNegativeButton("Cancel", null)
                        .setPositiveButton("Remove") { _, _ ->
                            SignOnPasskeyKey.deleteAll()
                            SignOnPasskeyStore(this@MainActivity).clear()
                            renderContent()
                        }
                        .showKyDialog()
                }
            }
            signOnPasskeySection.addView(btnRemove, fullWidthParams())
        }
        sections.add(signOnPasskeySection)

        val kyPasswordsSection = settingsCard()
        kyPasswordsSection.addView(title("KyPasswords Server"))
        val kyAccount = kyPasswordStore.account()
        if (kyAccount != null) {
            val syncDate = if (kyAccount.lastSyncedEpoch > 0) java.util.Date(kyAccount.lastSyncedEpoch * 1000).toLocaleString() else "Never"
            kyPasswordsSection.addView(message("Server: ${kyAccount.serverUrl}\nDevice ID: ${kyAccount.deviceId}\nVault Version: ${kyAccount.vaultVersion}\nLast Synced: $syncDate"))
            val btnSync = primaryButton("Sync Vault Now").apply {
                setOnClickListener { syncKyPasswordsVault() }
            }
            val btnUnpair = secondaryButton("Unpair KyPasswords Server").apply {
                setTextColor(ThemeManager.color(context, R.color.ky_error))
                setOnClickListener { confirmUnpairKyPasswords() }
            }
            kyPasswordsSection.addView(btnSync, fullWidthParams(top = 10, bottom = 6))
            kyPasswordsSection.addView(btnUnpair, fullWidthParams())
        } else {
            kyPasswordsSection.addView(message("A KyPasswords server is optional. Pair one to sync passwords and passkeys across devices."))
            val btnPair = primaryButton("Pair KyPasswords Server").apply {
                setOnClickListener { showPairKyPasswordsDialog() }
            }
            kyPasswordsSection.addView(btnPair, fullWidthParams(top = 10))
        }
        sections.add(kyPasswordsSection)

        val accountSection = settingsCard()
        accountSection.addView(title("Paired Account"))
        accountSection.addView(message("Server: ${account.serverUrl}\nDevice ID: ${account.deviceId}\nDevice Name: ${account.deviceName}\nUser ID: ${account.userId ?: "N/A"}"))

        val btnUnpair = secondaryButton(getString(R.string.unpair_account)).apply {
            setTextColor(ThemeManager.color(context, R.color.ky_error))
            setOnClickListener {
                AlertDialog.Builder(this@MainActivity)
                    .setTitle("Unpair Device")
                    .setMessage(
                        "Are you sure you want to unpair this device from KySignOn? " +
                            "This also deletes the KySignOn passkey held on this device.",
                    )
                    .setNegativeButton("Cancel", null)
                    .setPositiveButton("Unpair") { _, _ ->
                        store.clear()
                        // A passkey for a server we are no longer paired to is dead weight, and
                        // its key must not outlive the pairing.
                        SignOnPasskeyKey.deleteAll()
                        SignOnPasskeyStore(this@MainActivity).clear()
                        lockSensitiveState()
                        renderContent()
                    }
                    .showKyDialog()
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
        val current = ThemeManager.currentName(this)
        val container = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(24), dp(24), dp(24), dp(20))
        }
        val titleView = TextView(this).apply {
            text = getString(R.string.select_theme)
            textSize = 20f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(ThemeManager.color(context, R.color.ky_text))
            setPadding(0, 0, 0, dp(16))
        }
        container.addView(titleView)

        val listContainer = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
        }

        var dialog: AlertDialog? = null

        names.forEach { name ->
            val isSelected = name == current
            val itemBtn = Button(this).apply {
                text = if (isSelected) "$name  ✓" else name
                transformationMethod = null
                textSize = 15f
                typeface = if (isSelected) Typeface.DEFAULT_BOLD else Typeface.DEFAULT
                gravity = Gravity.START or Gravity.CENTER_VERTICAL
                setPadding(dp(16), dp(12), dp(16), dp(12))
                minHeight = dp(44)
                stateListAnimator = null
                elevation = 0f
                setTextColor(ThemeManager.color(context, if (isSelected) R.color.ky_cyan else R.color.ky_text))
                background = GradientDrawable().apply {
                    setColor(ThemeManager.color(context, if (isSelected) R.color.ky_surface_elevated else R.color.ky_surface))
                    cornerRadius = dp(12).toFloat()
                    if (isSelected) {
                        setStroke(dp(1), ThemeManager.color(context, R.color.ky_cyan))
                    }
                }
                setOnClickListener {
                    ThemeManager.set(this@MainActivity, name)
                    dialog?.dismiss()
                    renderContent()
                }
            }
            listContainer.addView(itemBtn, fullWidthParams(bottom = 6))
        }

        val scrollView = ScrollView(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                (resources.displayMetrics.heightPixels * 0.45f).toInt(),
            )
            addView(listContainer)
        }
        container.addView(scrollView)

        val btnCancel = ghostButton("Cancel").apply {
            setOnClickListener { dialog?.dismiss() }
        }
        container.addView(btnCancel, fullWidthParams(top = 10))

        dialog = AlertDialog.Builder(this)
            .setView(container)
            .showKyDialog()
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
                // onStop may have locked while this thread was loading; do not resurrect the vault.
                if (!AppLockManager.isUnlocked()) {
                    totpEntries.clear()
                    passwordEntries.clear()
                    renderContent()
                    return@runOnUiThread
                }
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

    /**
     * Unlocks the vault. The cipher comes from the prompt itself, so nothing is decrypted unless
     * the framework reports a successful authentication.
     */
    private fun unlockWithPrompt(
        reason: String = "Unlock KyAuth",
        silent: Boolean = false,
        onError: (String) -> Unit = {},
    ) {
        if (silent && !VaultUnlockPrompt.canAuthenticate(this)) return
        VaultUnlockPrompt.show(
            activity = this,
            subtitle = reason,
            onAuthenticated = { cipher ->
                unlockVault(
                    unlock = { AppLockManager.unlockWithBiometrics(this, cipher) },
                    onError = {
                        renderContent()
                        Toast.makeText(this, "Unlock failed. Use your PIN to recover the vault.", Toast.LENGTH_LONG).show()
                    },
                )
            },
            onFailed = { if (!silent) onError("Unlock required: $it") },
        )
    }

    private fun authenticateWithBiometrics(
        reason: String = "Unlock KyAuth",
        silent: Boolean = false,
        onSuccess: () -> Unit = {},
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

    private fun AlertDialog.Builder.showKyDialog(): AlertDialog {
        return create().apply {
            val background = GradientDrawable().apply {
                setColor(ThemeManager.color(this@MainActivity, R.color.ky_surface))
                setStroke(dp(1), ThemeManager.color(this@MainActivity, R.color.ky_border))
                cornerRadius = dp(24).toFloat()
            }
            window?.apply {
                setBackgroundDrawable(background)
                setDimAmount(0.45f)
            }
            setOnShowListener {
                window?.setBackgroundDrawable(background)
                findViewById<TextView>(androidx.appcompat.R.id.alertTitle)?.apply {
                    setTextColor(ThemeManager.color(this@MainActivity, R.color.ky_text))
                    typeface = Typeface.DEFAULT_BOLD
                }
                findViewById<TextView>(android.R.id.message)?.apply {
                    setTextColor(ThemeManager.color(this@MainActivity, R.color.ky_muted))
                }
                findViewById<TextView>(androidx.appcompat.R.id.message)?.apply {
                    setTextColor(ThemeManager.color(this@MainActivity, R.color.ky_muted))
                }
                listOf(
                    DialogInterface.BUTTON_POSITIVE,
                    DialogInterface.BUTTON_NEGATIVE,
                    DialogInterface.BUTTON_NEUTRAL,
                ).forEach { which ->
                    getButton(which)?.apply {
                        setTextColor(ThemeManager.color(this@MainActivity, R.color.ky_cyan))
                        typeface = Typeface.DEFAULT_BOLD
                    }
                }
            }
            show()
        }
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
            text = getString(R.string.mfa_empty_description)
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
