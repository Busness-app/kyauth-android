package org.kysecurity.authenticator.passwords

import android.app.Activity
import android.app.assist.AssistStructure
import android.content.Intent
import android.os.Bundle
import android.view.autofill.AutofillManager
import androidx.appcompat.app.AppCompatActivity
import java.io.File
import javax.crypto.Cipher
import org.kysecurity.authenticator.parcelable
import org.kysecurity.authenticator.security.AppLockManager
import org.kysecurity.authenticator.security.VaultUnlockPrompt

/**
 * Authenticates a locked Autofill request and returns the filled datasets.
 *
 * The vault keys are unwrapped for this one response and erased again, so answering an Autofill
 * request never leaves the process unlocked.
 */
class AutofillUnlockActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val structure = intent.parcelable<AssistStructure>(AutofillManager.EXTRA_ASSIST_STRUCTURE) ?: run {
            finishCancelled()
            return
        }

        VaultUnlockPrompt.show(
            activity = this,
            subtitle = "Authenticate to fill your password",
            onAuthenticated = { cipher -> respond(structure, cipher) },
            onFailed = { finishCancelled() },
        )
    }

    private fun respond(structure: AssistStructure, cipher: Cipher) {
        val fields = AutofillParser.parse(structure)
        val response = AppLockManager.useVaultKeys(applicationContext, cipher) { keys ->
            val vaultKey = keys.passwords ?: return@useVaultKeys null
            val entries = runCatching {
                KdbxPasswordVault.loadEntries(File(filesDir, KyAuthAutofillService.VAULT_FILE_NAME), vaultKey)
            }.getOrNull() ?: return@useVaultKeys null
            AutofillParser.buildDatasets(this, fields, entries)
        }

        if (response == null) {
            finishCancelled()
            return
        }
        setResult(
            Activity.RESULT_OK,
            Intent().putExtra(AutofillManager.EXTRA_AUTHENTICATION_RESULT, response),
        )
        finish()
    }

    private fun finishCancelled() {
        setResult(Activity.RESULT_CANCELED)
        finish()
    }
}
