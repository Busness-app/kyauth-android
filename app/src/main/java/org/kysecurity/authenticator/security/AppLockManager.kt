package org.kysecurity.authenticator.security

import android.content.Context
import android.content.SharedPreferences
import java.util.Base64
import javax.crypto.Cipher
import org.json.JSONObject

/**
 * Owns the lock state and the two vault keys.
 *
 * Both vault keys live in a single blob wrapped by [VaultKek], an authentication-bound Keystore
 * key. Unwrapping therefore requires a cipher the framework has already authenticated, and one
 * authentication yields one unwrap — hence the single blob rather than one per vault.
 *
 * There is no entry point that reconstructs a vault key on demand. Background callers (Autofill,
 * Credential Provider) must go through [useVaultKeys], which never touches the unlocked state.
 */
object AppLockManager {
    private const val PREFS_NAME = "app_lock"
    private const val KEY_PIN_HASH = "pin_hash"
    private const val KEY_PIN_SALT = "pin_salt"
    private const val KEY_KEK_WRAPPED_KEYS = "kek_wrapped_keys"
    private const val KEY_HAS_PASSWORD_VAULT_KEY = "has_password_vault_key"
    private const val KEY_VAULT_SALT = "vault_salt"
    private const val KEY_WRAPPED_VAULT_KEY = "wrapped_vault_key"
    private const val KEY_PASSWORD_VAULT_SALT = "password_vault_salt"
    private const val KEY_WRAPPED_PASSWORD_VAULT_KEY = "wrapped_password_vault_key"
    private const val KEY_PIN_ENABLED = "pin_enabled"
    private const val KEY_FAILED_ATTEMPTS = "failed_attempts"
    private const val KEY_RETRY_AFTER_EPOCH_SEC = "retry_after_epoch_sec"

    private const val LEGACY_BIOMETRIC_WRAPPED_VAULT_KEY = "biometric_wrapped_vault_key"
    private const val LEGACY_BIOMETRIC_WRAPPED_PASSWORD_VAULT_KEY = "biometric_wrapped_password_vault_key"

    private const val JSON_TOTP = "totp"
    private const val JSON_PASSWORDS = "passwords"

    /** The two vault keys as held for the duration of one operation. */
    class VaultKeys(val totp: ByteArray, val passwords: ByteArray?) {
        fun erase() {
            totp.fill(0)
            passwords?.fill(0)
        }
    }

    @Volatile
    private var activeVaultKey: ByteArray? = null

    @Volatile
    private var activePasswordVaultKey: ByteArray? = null

    @Volatile
    private var isUnlocked: Boolean = false

    fun isUnlocked(): Boolean = isUnlocked

    fun getVaultKey(): ByteArray? = if (isUnlocked) activeVaultKey else null

    fun getPasswordVaultKey(): ByteArray? = if (isUnlocked) activePasswordVaultKey else null

    @Synchronized
    fun lock() {
        isUnlocked = false
        activeVaultKey?.fill(0)
        activeVaultKey = null
        activePasswordVaultKey?.fill(0)
        activePasswordVaultKey = null
    }

    fun onWipe() {
        lock()
        VaultKek.delete()
    }

    private fun getPrefs(context: Context): SharedPreferences =
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    fun isPinEnabled(context: Context): Boolean =
        getPrefs(context).getBoolean(KEY_PIN_ENABLED, false)

    fun hasPinSet(context: Context): Boolean =
        getPrefs(context).getString(KEY_PIN_HASH, null) != null

    fun getFailureState(context: Context): PinFailureState {
        val prefs = getPrefs(context)
        return PinFailureState(
            failedAttempts = prefs.getInt(KEY_FAILED_ATTEMPTS, 0),
            retryAfterEpochSeconds = prefs.getLong(KEY_RETRY_AFTER_EPOCH_SEC, 0L),
        )
    }

    /** Written synchronously: an attempt must be durably counted before the caller learns the result. */
    private fun saveFailureState(context: Context, state: PinFailureState) {
        getPrefs(context).edit()
            .putInt(KEY_FAILED_ATTEMPTS, state.failedAttempts)
            .putLong(KEY_RETRY_AFTER_EPOCH_SEC, state.retryAfterEpochSeconds)
            .commit()
    }

    fun clearFailureState(context: Context) {
        saveFailureState(context, PinFailureState(0, 0L))
    }

    fun hasPasswordVaultKey(context: Context): Boolean =
        activePasswordVaultKey != null || getPrefs(context).getBoolean(KEY_HAS_PASSWORD_VAULT_KEY, false)

    @Synchronized
    fun setPasswordVaultKey(context: Context, key: ByteArray) {
        check(isUnlocked) { "Unlock KyAuth before adding the password vault key" }
        activePasswordVaultKey?.fill(0)
        activePasswordVaultKey = key
        persistWrappedKeys(context)
    }

    @Synchronized
    fun clearPasswordVaultKey(context: Context) {
        activePasswordVaultKey?.fill(0)
        activePasswordVaultKey = null
        getPrefs(context).edit()
            .remove(KEY_PASSWORD_VAULT_SALT)
            .remove(KEY_WRAPPED_PASSWORD_VAULT_KEY)
            .putBoolean(KEY_HAS_PASSWORD_VAULT_KEY, false)
            .apply()
        if (isUnlocked) persistWrappedKeys(context)
    }

    /**
     * Sets or changes the local PIN. Derives keys, wraps the vault key, and stores salt/hash.
     */
    @Synchronized
    fun setupPin(context: Context, pin: String) {
        val validation = PinPolicy.validate(pin)
        require(validation is PinPolicy.ValidationResult.Valid) {
            (validation as PinPolicy.ValidationResult.Error).message
        }
        check(isUnlocked) { "Unlock KyAuth before setting a PIN" }

        KeystoreCredentialPepper.ensureExists()
        KeystorePinPepper.ensureExists()

        val pinSalt = CredentialCipher.generateRandomSalt()
        val vaultSalt = CredentialCipher.generateRandomSalt()
        val pinHash = CredentialCipher.hashPinForStorage(pin, pinSalt)

        val vaultKey = checkNotNull(activeVaultKey) { "No vault key to protect with a PIN" }
        val wrapped = CredentialCipher.wrap(vaultKey, CredentialCipher.deriveKey(pin, vaultSalt))

        val editor = getPrefs(context).edit()
            .putString(KEY_PIN_HASH, pinHash)
            .putString(KEY_PIN_SALT, Base64.getEncoder().encodeToString(pinSalt))
            .putString(KEY_VAULT_SALT, Base64.getEncoder().encodeToString(vaultSalt))
            .putString(KEY_WRAPPED_VAULT_KEY, wrapped.serialize())
            .putBoolean(KEY_PIN_ENABLED, true)

        val passwordVaultKey = activePasswordVaultKey
        if (passwordVaultKey != null) {
            val passwordVaultSalt = CredentialCipher.generateRandomSalt()
            val passwordWrapped =
                CredentialCipher.wrap(passwordVaultKey, CredentialCipher.deriveKey(pin, passwordVaultSalt))
            editor.putString(KEY_PASSWORD_VAULT_SALT, Base64.getEncoder().encodeToString(passwordVaultSalt))
                .putString(KEY_WRAPPED_PASSWORD_VAULT_KEY, passwordWrapped.serialize())
        }

        editor.commit()
        clearFailureState(context)
    }

    fun setPinEnabled(context: Context, enabled: Boolean) {
        getPrefs(context).edit().putBoolean(KEY_PIN_ENABLED, enabled).apply()
    }

    /**
     * Returns the cipher that must be handed to `BiometricPrompt.CryptoObject`, creating the
     * wrapping key on first use. Throws [VaultKek.NoSecureLockScreen] on a device that cannot bind
     * a key to user authentication — surfaced here, before the prompt, so the user is told why.
     */
    fun unlockCipher(): Cipher = VaultKek.unwrapCipher()

    /**
     * Unlocks with Biometric / Device Credential. [authenticatedCipher] must come from a
     * `BiometricPrompt.AuthenticationResult`; it may only be null on a device with no wrapped keys.
     */
    @Synchronized
    fun unlockWithBiometrics(context: Context, authenticatedCipher: Cipher?): Boolean {
        val keys = when {
            getPrefs(context).getString(KEY_KEK_WRAPPED_KEYS, null) != null -> {
                val cipher = authenticatedCipher ?: return false
                unwrapKeys(context, cipher) ?: return false
            }
            hasLegacyWrapping(context) -> migrateLegacyWrapping(context) ?: return false
            else -> VaultKeys(CredentialCipher.generateVaultKey(), null)
        }
        adopt(context, keys)
        clearFailureState(context)
        return true
    }

    /**
     * Runs [block] with the vault keys for a single background operation. The app stays locked and
     * the keys are erased before returning, so an Autofill or Credential Provider request cannot
     * leave the process holding vault material.
     */
    fun <T> useVaultKeys(context: Context, authenticatedCipher: Cipher, block: (VaultKeys) -> T): T? {
        val keys = unwrapKeys(context, authenticatedCipher) ?: return null
        return try {
            block(keys)
        } finally {
            keys.erase()
        }
    }

    /**
     * Verifies PIN and unlocks the vault. Enforces escalating delay and self-wipe after 5 failed
     * attempts. Synchronized so that concurrent attempts cannot share one failure count.
     */
    @Synchronized
    fun unlockWithPin(
        context: Context,
        pin: String,
        nowEpochSeconds: Long = System.currentTimeMillis() / 1000,
    ): Boolean {
        val state = getFailureState(context)
        if (!PinFailurePolicy.mayTry(state, nowEpochSeconds)) {
            return false
        }

        val prefs = getPrefs(context)
        val storedHash = prefs.getString(KEY_PIN_HASH, null) ?: return false
        val pinSaltB64 = prefs.getString(KEY_PIN_SALT, null) ?: return false
        val vaultSaltB64 = prefs.getString(KEY_VAULT_SALT, null) ?: return false
        val wrappedB64 = prefs.getString(KEY_WRAPPED_VAULT_KEY, null) ?: return false

        val pinSalt = Base64.getDecoder().decode(pinSaltB64)
        val candidateHash = CredentialCipher.hashPinForStorage(pin, pinSalt)

        if (candidateHash != storedHash) {
            val newState = PinFailurePolicy.registerFailure(state, nowEpochSeconds)
            saveFailureState(context, newState)

            if (PinFailurePolicy.mustWipe(newState)) {
                SecurityWipe.wipe(context)
            }
            return false
        }

        val vaultKey = runCatching {
            val wrapped = WrappedSecret.deserialize(wrappedB64) ?: return false
            CredentialCipher.unwrap(wrapped, CredentialCipher.deriveKey(pin, Base64.getDecoder().decode(vaultSaltB64)))
        }.getOrNull() ?: return false

        clearFailureState(context)
        adopt(context, VaultKeys(vaultKey, unlockPasswordVaultWithPin(context, pin)))
        return true
    }

    private fun adopt(context: Context, keys: VaultKeys) {
        activeVaultKey?.fill(0)
        activePasswordVaultKey?.fill(0)
        activeVaultKey = keys.totp
        activePasswordVaultKey = keys.passwords
        isUnlocked = true
        persistWrappedKeys(context)
    }

    private fun unwrapKeys(context: Context, authenticatedCipher: Cipher): VaultKeys? {
        val blob = getPrefs(context).getString(KEY_KEK_WRAPPED_KEYS, null) ?: return null
        return runCatching {
            val plain = VaultKek.unwrap(authenticatedCipher, Base64.getDecoder().decode(blob))
            val json = JSONObject(String(plain, Charsets.UTF_8))
            plain.fill(0)
            VaultKeys(
                totp = Base64.getDecoder().decode(json.getString(JSON_TOTP)),
                passwords = json.optString(JSON_PASSWORDS).takeIf { it.isNotBlank() }
                    ?.let { Base64.getDecoder().decode(it) },
            )
        }.getOrNull()
    }

    private fun persistWrappedKeys(context: Context) {
        val totpKey = activeVaultKey ?: return
        val json = JSONObject().put(JSON_TOTP, Base64.getEncoder().encodeToString(totpKey))
        val passwordKey = activePasswordVaultKey
        if (passwordKey != null) {
            json.put(JSON_PASSWORDS, Base64.getEncoder().encodeToString(passwordKey))
        }
        val wrapped = VaultKek.wrap(json.toString().toByteArray(Charsets.UTF_8))
        getPrefs(context).edit()
            .putString(KEY_KEK_WRAPPED_KEYS, Base64.getEncoder().encodeToString(wrapped))
            .putBoolean(KEY_HAS_PASSWORD_VAULT_KEY, passwordKey != null)
            .remove(LEGACY_BIOMETRIC_WRAPPED_VAULT_KEY)
            .remove(LEGACY_BIOMETRIC_WRAPPED_PASSWORD_VAULT_KEY)
            .commit()
    }

    private fun hasLegacyWrapping(context: Context): Boolean =
        getPrefs(context).getString(LEGACY_BIOMETRIC_WRAPPED_VAULT_KEY, null) != null

    /**
     * One-shot upgrade from the pre-[VaultKek] wrapping, which any in-process code could undo.
     * Only reachable after a successful authentication. Delete once no v0.1 installs remain.
     */
    private fun migrateLegacyWrapping(context: Context): VaultKeys? {
        val prefs = getPrefs(context)
        fun unwrapLegacy(blobKey: String, saltKey: String): ByteArray? = runCatching {
            val blob = prefs.getString(blobKey, null) ?: return null
            val salt = Base64.getDecoder().decode(prefs.getString(saltKey, null) ?: return null)
            val wrapped = WrappedSecret.deserialize(blob) ?: return null
            CredentialCipher.unwrap(wrapped, CredentialCipher.deriveLegacyWrapKey(salt))
        }.getOrNull()

        val totp = unwrapLegacy(LEGACY_BIOMETRIC_WRAPPED_VAULT_KEY, KEY_VAULT_SALT) ?: return null
        return VaultKeys(
            totp,
            unwrapLegacy(LEGACY_BIOMETRIC_WRAPPED_PASSWORD_VAULT_KEY, KEY_PASSWORD_VAULT_SALT),
        )
    }

    private fun unlockPasswordVaultWithPin(context: Context, pin: String): ByteArray? {
        val prefs = getPrefs(context)
        val vaultSaltB64 = prefs.getString(KEY_PASSWORD_VAULT_SALT, null) ?: return null
        val wrappedB64 = prefs.getString(KEY_WRAPPED_PASSWORD_VAULT_KEY, null) ?: return null
        return runCatching {
            val wrapped = WrappedSecret.deserialize(wrappedB64) ?: return null
            CredentialCipher.unwrap(
                wrapped,
                CredentialCipher.deriveKey(pin, Base64.getDecoder().decode(vaultSaltB64)),
            )
        }.getOrNull()
    }
}
