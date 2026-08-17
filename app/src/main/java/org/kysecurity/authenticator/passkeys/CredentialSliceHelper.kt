package org.kysecurity.authenticator.passkeys

import android.app.PendingIntent
import android.app.slice.Slice
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.service.credentials.BeginCreateCredentialRequest
import android.service.credentials.BeginGetCredentialOption
import android.service.credentials.CreateEntry
import android.service.credentials.CredentialEntry

import android.app.slice.SliceSpec
import android.os.Build
import androidx.annotation.RequiresApi

@RequiresApi(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
object CredentialSliceHelper {
    private val SPEC = SliceSpec("kyauth", 1)

    fun createGetCredentialEntry(
        context: Context,
        option: BeginGetCredentialOption,
        title: String,
        subtitle: String,
        fillIntent: Intent,
        requestCode: Int,
    ): CredentialEntry {
        val pendingIntent = PendingIntent.getActivity(
            context,
            requestCode,
            fillIntent,
            PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )

        val actionSlice = Slice.Builder(Uri.parse("kyauth://action/${option.id}"), SPEC).build()
        val slice = Slice.Builder(Uri.parse("kyauth://credential/${option.id}"), SPEC)
            .addAction(pendingIntent, actionSlice, null)
            .addText(title, null, listOf(Slice.HINT_TITLE))
            .addText(subtitle, null, listOf(Slice.HINT_SUMMARY))
            .build()

        return CredentialEntry(option.id, slice)
    }

    fun createCreateCredentialEntry(
        context: Context,
        request: BeginCreateCredentialRequest,
        title: String,
        subtitle: String,
        createIntent: Intent,
        requestCode: Int,
    ): CreateEntry {
        val pendingIntent = PendingIntent.getActivity(
            context,
            requestCode,
            createIntent,
            PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )

        val actionSlice = Slice.Builder(Uri.parse("kyauth://create_action/${request.type}"), SPEC).build()
        val slice = Slice.Builder(Uri.parse("kyauth://create_credential/${request.type}"), SPEC)
            .addAction(pendingIntent, actionSlice, null)
            .addText(title, null, listOf(Slice.HINT_TITLE))
            .addText(subtitle, null, listOf(Slice.HINT_SUMMARY))
            .build()

        return CreateEntry(slice)
    }
}
