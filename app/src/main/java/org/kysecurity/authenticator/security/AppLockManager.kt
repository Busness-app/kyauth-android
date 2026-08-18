package org.kysecurity.authenticator.security

import android.content.Context
import android.content.SharedPreferences
import java.util.Base64

object AppLockManager {
    private const val PREFS_NAME = "app_lock"
    private const val KEY_PIN_HASH = "pin_hash"
    private const val KEY_PIN_SALT = "pin_salt"
    private const val KEY_VAULT_SALT = "vault_salt"
    private const val KEY_WRAPPED_VAULT_KEY = "wrapped_vault_key"
    private const val KEY_BIOMETRIC_WRAPPED_VAULT_KEY = "biometric_wrapped_vault_key"
    private const val KEY_PASSWORD_VAULT_SALT = "password_vault_salt"
    private const val KEY_WRAPPED_PASSWORD_VAULT_KEY = "wrapped_password_vault_key"
    private const val KEY_BIOMETRIC_WRAPPED_PASSWORD_VAULT_KEY = "biometric_wrapped_password_vault_key"
    private const val KEY_PIN_ENABLED = "pin_enabled"
    private const val KEY_FAILED_ATTEMPTS = "failed_attempts"
    private const val KEY_RETRY_AFTER_EPOCH_SEC = "retry_after_epoch_sec"

    @Volatile
    private var activeVaultKey: ByteArray? = null

    @Volatile
    private var activePasswordVaultKey: ByteArray? = null

    @Volatile
    private var isUnlocked: Boolean = false

    fun isUnlocked(): Boolean = isUnlocked

    fun getVaultKey(): ByteArray? = activeVaultKey

    fun getPasswordVaultKey(): ByteArray? = activePasswordVaultKey

    fun lock() {
        isUnlocked = false
        activeVaultKey = null
        activePasswordVaultKey = null
    }

    fun onWipe() {
        lock()
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

    private fun saveFailureState(context: Context, state: PinFailureState) {
        getPrefs(context).edit()
            .putInt(KEY_FAILED_ATTEMPTS, state.failedAttempts)
            .putLong(KEY_RETRY_AFTER_EPOCH_SEC, state.retryAfterEpochSeconds)
            .apply()
    }

    fun clearFailureState(context: Context) {
        saveFailureState(context, PinFailureState(0, 0L))
    }

    fun hasPasswordVaultKey(context: Context): Boolean {
        if (activePasswordVaultKey != null) return true
        val prefs = getPrefs(context)
        return prefs.getString(KEY_BIOMETRIC_WRAPPED_PASSWORD_VAULT_KEY, null) != null ||
            prefs.getString(KEY_WRAPPED_PASSWORD_VAULT_KEY, null) != null
    }

    fun setPasswordVaultKey(context: Context, key: ByteArray) {
        activePasswordVaultKey = key
        val passwordVaultSalt = CredentialCipher.generateRandomSalt()
        saveBiometricWrappedPasswordVaultKey(context, key, passwordVaultSalt)
    }

    fun clearPasswordVaultKey(context: Context) {
        activePasswordVaultKey = null
        getPrefs(context).edit()
            .remove(KEY_PASSWORD_VAULT_SALT)
            .remove(KEY_WRAPPED_PASSWORD_VAULT_KEY)
            .remove(KEY_BIOMETRIC_WRAPPED_PASSWORD_VAULT_KEY)
            .apply()
    }

    /**
     * Sets or changes the local PIN. Derives keys, wraps the vault key, and stores salt/hash.
     */
    fun setupPin(context: Context, pin: String) {
        val validation = PinPolicy.validate(pin)
        require(validation is PinPolicy.ValidationResult.Valid) {
            (validation as PinPolicy.ValidationResult.Error).message
        }

        KeystoreCredentialPepper.ensureExists()
        KeystorePinPepper.ensureExists()

        val pinSalt = CredentialCipher.generateRandomSalt()
        val vaultSalt = CredentialCipher.generateRandomSalt()
        val pinHash = CredentialCipher.hashPinForStorage(pin, pinSalt)

        val vaultKey = activeVaultKey ?: CredentialCipher.generateVaultKey()
        val derivedKey = CredentialCipher.deriveKey(pin, vaultSalt)
        val wrapped = CredentialCipher.wrap(vaultKey, derivedKey)

        val editor = getPrefs(context).edit()
            .putString(KEY_PIN_HASH, pinHash)
            .putString(KEY_PIN_SALT, Base64.getEncoder().encodeToString(pinSalt))
            .putString(KEY_VAULT_SALT, Base64.getEncoder().encodeToString(vaultSalt))
            .putString(KEY_WRAPPED_VAULT_KEY, wrapped.serialize())
            .putBoolean(KEY_PIN_ENABLED, true)

        val passwordVaultKey = activePasswordVaultKey
        if (passwordVaultKey != null) {
            val passwordVaultSalt = CredentialCipher.generateRandomSalt()
            val passwordWrapped = CredentialCipher.wrap(passwordVaultKey, CredentialCipher.deriveKey(pin, passwordVaultSalt))
            editor.putString(KEY_PASSWORD_VAULT_SALT, Base64.getEncoder().encodeToString(passwordVaultSalt))
                .putString(KEY_WRAPPED_PASSWORD_VAULT_KEY, passwordWrapped.serialize())
            saveBiometricWrappedPasswordVaultKey(context, passwordVaultKey, passwordVaultSalt)
        }

        editor.apply()
        saveBiometricWrappedVaultKey(context, vaultKey, vaultSalt)

        activeVaultKey = vaultKey
        isUnlocked = true
        clearFailureState(context)
    }

    fun setPinEnabled(context: Context, enabled: Boolean) {
        getPrefs(context).edit().putBoolean(KEY_PIN_ENABLED, enabled).apply()
    }

    /**
     * Unlocks with Biometric / Device Credential.
     */
    fun unlockWithBiometrics(context: Context): Boolean {
        clearFailureState(context)
        if (activeVaultKey == null) {
            activeVaultKey = ensureVaultKeyInitialized(context) ?: return false
        }
        if (activePasswordVaultKey == null) {
            activePasswordVaultKey = ensurePasswordVaultKeyInitialized(context)
        }
        isUnlocked = true
        return true
    }

    /**
     * Verifies PIN and unlocks the vault. Enforces escalating delay and self-wipe after 5 failed attempts.
     */
    fun unlockWithPin(context: Context, pin: String, nowEpochSeconds: Long = System.currentTimeMillis() / 1000): Boolean {
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

        // Correct PIN
        clearFailureState(context)
        val vaultSalt = Base64.getDecoder().decode(vaultSaltB64)
        val derivedKey = CredentialCipher.deriveKey(pin, vaultSalt)
        val wrapped = WrappedSecret.deserialize(wrappedB64) ?: return false
        val vaultKey = CredentialCipher.unwrap(wrapped, derivedKey)
        val passwordVaultKey = unlockPasswordVaultWithPin(context, pin)

        activeVaultKey = vaultKey
        saveBiometricWrappedVaultKey(context, vaultKey, vaultSalt)
        activePasswordVaultKey = passwordVaultKey
        isUnlocked = true
        return true
    }

    fun ensureVaultKeyInitialized(context: Context): ByteArray? {
        val existing = activeVaultKey
        if (existing != null) return existing

        val prefs = getPrefs(context)
        val biometricWrappedB64 = prefs.getString(KEY_BIOMETRIC_WRAPPED_VAULT_KEY, null)
        val vaultSaltB64 = prefs.getString(KEY_VAULT_SALT, null)
        if (biometricWrappedB64 == null && vaultSaltB64 == null && prefs.getString(KEY_WRAPPED_VAULT_KEY, null) == null) {
            val freshKey = CredentialCipher.generateVaultKey()
            val vaultSalt = CredentialCipher.generateRandomSalt()
            saveBiometricWrappedVaultKey(context, freshKey, vaultSalt)
            activeVaultKey = freshKey
            return freshKey
        }
        if (biometricWrappedB64 == null || vaultSaltB64 == null) return null
        return runCatching {
            val vaultSalt = Base64.getDecoder().decode(vaultSaltB64)
            val wrapped = WrappedSecret.deserialize(biometricWrappedB64) ?: return null
            CredentialCipher.unwrap(wrapped, CredentialCipher.deriveBiometricKey(vaultSalt))
        }.getOrNull()?.also { activeVaultKey = it }
    }

    fun ensurePasswordVaultKeyInitialized(context: Context): ByteArray? {
        val existing = activePasswordVaultKey
        if (existing != null) return existing

        val prefs = getPrefs(context)
        val biometricWrappedB64 = prefs.getString(KEY_BIOMETRIC_WRAPPED_PASSWORD_VAULT_KEY, null)
        val vaultSaltB64 = prefs.getString(KEY_PASSWORD_VAULT_SALT, null)
        if (biometricWrappedB64 == null || vaultSaltB64 == null) return null
        return runCatching {
            val vaultSalt = Base64.getDecoder().decode(vaultSaltB64)
            val wrapped = WrappedSecret.deserialize(biometricWrappedB64) ?: return null
            CredentialCipher.unwrap(wrapped, CredentialCipher.deriveBiometricKey(vaultSalt))
        }.getOrNull()?.also { activePasswordVaultKey = it }
    }

    private fun unlockPasswordVaultWithPin(context: Context, pin: String): ByteArray? {
        val prefs = getPrefs(context)
        val vaultSaltB64 = prefs.getString(KEY_PASSWORD_VAULT_SALT, null)
        val wrappedB64 = prefs.getString(KEY_WRAPPED_PASSWORD_VAULT_KEY, null)
        if (vaultSaltB64 == null || wrappedB64 == null) return null
        return runCatching {
            val vaultSalt = Base64.getDecoder().decode(vaultSaltB64)
            val wrapped = WrappedSecret.deserialize(wrappedB64) ?: return null
            val vaultKey = CredentialCipher.unwrap(wrapped, CredentialCipher.deriveKey(pin, vaultSalt))
            saveBiometricWrappedPasswordVaultKey(context, vaultKey, vaultSalt)
            vaultKey
        }.getOrNull()
    }

    private fun saveBiometricWrappedVaultKey(context: Context, vaultKey: ByteArray, vaultSalt: ByteArray) {
        KeystoreCredentialPepper.ensureExists()
        val wrapped = CredentialCipher.wrap(vaultKey, CredentialCipher.deriveBiometricKey(vaultSalt))
        getPrefs(context).edit()
            .putString(KEY_VAULT_SALT, Base64.getEncoder().encodeToString(vaultSalt))
            .putString(KEY_BIOMETRIC_WRAPPED_VAULT_KEY, wrapped.serialize())
            .apply()
    }

    private fun saveBiometricWrappedPasswordVaultKey(context: Context, vaultKey: ByteArray, vaultSalt: ByteArray) {
        KeystoreCredentialPepper.ensureExists()
        val wrapped = CredentialCipher.wrap(vaultKey, CredentialCipher.deriveBiometricKey(vaultSalt))
        getPrefs(context).edit()
            .putString(KEY_PASSWORD_VAULT_SALT, Base64.getEncoder().encodeToString(vaultSalt))
            .putString(KEY_BIOMETRIC_WRAPPED_PASSWORD_VAULT_KEY, wrapped.serialize())
            .apply()
    }
}
