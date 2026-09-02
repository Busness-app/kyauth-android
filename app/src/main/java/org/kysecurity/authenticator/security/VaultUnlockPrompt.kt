package org.kysecurity.authenticator.security

import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import java.security.Signature
import javax.crypto.Cipher

/**
 * Biometric and device-credential prompts. [show] yields a cipher bound to [VaultKek] for the vault keys; [showForSignature] yields an authenticated Keystore signature and touches no vault material.
 *
 * The cipher is bound to [VaultKek], so it cannot decrypt anything until the framework reports a
 * successful biometric or device-credential authentication. Callers receive null only on a device
 * that has no wrapped keys yet.
 */
object VaultUnlockPrompt {
    private const val AUTHENTICATORS =
        BiometricManager.Authenticators.BIOMETRIC_STRONG or BiometricManager.Authenticators.DEVICE_CREDENTIAL

    fun show(
        activity: FragmentActivity,
        subtitle: String,
        onAuthenticated: (Cipher) -> Unit,
        onFailed: (String) -> Unit,
    ) {
        val cipher = try {
            AppLockManager.unlockCipher()
        } catch (e: VaultKek.NoSecureLockScreen) {
            onFailed(e.message ?: "A device screen lock is required.")
            return
        } catch (e: Exception) {
            onFailed(e.message ?: "The vault key is unavailable.")
            return
        }

        val prompt = BiometricPrompt(
            activity,
            ContextCompat.getMainExecutor(activity),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    onAuthenticated(result.cryptoObject?.cipher ?: cipher)
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    onFailed(errString.toString())
                }
            },
        )

        val info = BiometricPrompt.PromptInfo.Builder()
            .setTitle("KyAuth")
            .setSubtitle(subtitle)
            .setAllowedAuthenticators(AUTHENTICATORS)
            .build()

        prompt.authenticate(info, BiometricPrompt.CryptoObject(cipher))
    }

    /**
     * Authenticates a Keystore [Signature] for one use. Unlike [show] this touches no vault key at
     * all: the KySignOn passkey path must keep working while the password vault is locked or
     * compromised, so it must never reach [VaultKek].
     */
    fun showForSignature(
        activity: FragmentActivity,
        subtitle: String,
        signature: Signature,
        onAuthenticated: (Signature) -> Unit,
        onFailed: (String) -> Unit,
    ) {
        val prompt = BiometricPrompt(
            activity,
            ContextCompat.getMainExecutor(activity),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    onAuthenticated(result.cryptoObject?.signature ?: signature)
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    onFailed(errString.toString())
                }
            },
        )

        val info = BiometricPrompt.PromptInfo.Builder()
            .setTitle("KyAuth")
            .setSubtitle(subtitle)
            .setAllowedAuthenticators(AUTHENTICATORS)
            .build()

        prompt.authenticate(info, BiometricPrompt.CryptoObject(signature))
    }

    fun canAuthenticate(activity: FragmentActivity): Boolean =
        BiometricManager.from(activity).canAuthenticate(AUTHENTICATORS) == BiometricManager.BIOMETRIC_SUCCESS
}
