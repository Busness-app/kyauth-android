package org.kysecurity.authenticator.passkeys

import android.app.Activity
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.service.credentials.BeginGetCredentialRequest
import android.service.credentials.CredentialProviderService
import androidx.annotation.RequiresApi
import androidx.appcompat.app.AppCompatActivity
import java.io.File
import javax.crypto.Cipher
import org.kysecurity.authenticator.pairing.PairingStore
import org.kysecurity.authenticator.parcelable
import org.kysecurity.authenticator.passwords.KdbxPasswordVault
import org.kysecurity.authenticator.passwords.KyAuthAutofillService
import org.kysecurity.authenticator.security.AppLockManager
import org.kysecurity.authenticator.security.VaultUnlockPrompt

/**
 * Answers the authentication action returned by [KyAuthCredentialProviderService] while locked.
 *
 * The vault is decrypted for this one enumeration and the keys are erased again, so listing
 * credentials never leaves the process unlocked.
 */
@RequiresApi(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
class CredentialUnlockActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val request = intent.parcelable<BeginGetCredentialRequest>(
            CredentialProviderService.EXTRA_BEGIN_GET_CREDENTIAL_REQUEST,
        ) ?: run {
            finishCancelled()
            return
        }

        VaultUnlockPrompt.show(
            activity = this,
            subtitle = "Authenticate to see your credentials",
            onAuthenticated = { cipher -> respond(request, cipher) },
            onFailed = { finishCancelled() },
        )
    }

    private fun respond(request: BeginGetCredentialRequest, cipher: Cipher) {
        // Building entries verifies native callers against the relying party over the network.
        Thread {
            val response = AppLockManager.useVaultKeys(applicationContext, cipher) { keys ->
                val vaultKey = keys.passwords ?: return@useVaultKeys null
                val entries = runCatching {
                    KdbxPasswordVault.loadEntries(File(filesDir, KyAuthAutofillService.VAULT_FILE_NAME), vaultKey)
                }.getOrNull() ?: return@useVaultKeys null
                // signOnPasskey is null: the service already surfaced it alongside the
                // authentication action, and offering it again here would duplicate it.
                CredentialEntryBuilder.build(
                    context = this,
                    request = request,
                    entries = entries,
                    signOnPasskey = null,
                    signOnServerUrl = PairingStore(this).account()?.serverUrl,
                )
            }
            runOnUiThread {
                if (response == null) {
                    finishCancelled()
                    return@runOnUiThread
                }
                setResult(
                    Activity.RESULT_OK,
                    Intent().putExtra(CredentialProviderService.EXTRA_BEGIN_GET_CREDENTIAL_RESPONSE, response),
                )
                finish()
            }
        }.start()
    }

    private fun finishCancelled() {
        setResult(Activity.RESULT_CANCELED)
        finish()
    }
}
