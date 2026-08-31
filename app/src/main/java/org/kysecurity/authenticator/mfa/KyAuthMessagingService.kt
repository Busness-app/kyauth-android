package org.kysecurity.authenticator.mfa

import android.Manifest
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import com.google.firebase.messaging.FirebaseMessagingService
import com.google.firebase.messaging.RemoteMessage
import org.kysecurity.authenticator.MainActivity
import org.kysecurity.authenticator.R
import org.kysecurity.authenticator.pairing.PairingStore

class KyAuthMessagingService : FirebaseMessagingService() {
    override fun onNewToken(token: String) {
        getSharedPreferences("push", MODE_PRIVATE).edit().putString("pending_token", token).apply()
    }

    override fun onMessageReceived(message: RemoteMessage) {
        // Only the paired server is ever used; an unpaired device drops the message.
        val pairedServer = runCatching { PairingStore(this).account()?.serverUrl }.getOrNull()
        val challenge = runCatching {
            MfaPushChallengeParser.parse(message.data, pairedServer)
        }.getOrNull() ?: return

        MfaPushChallengeStore(this).save(challenge)
        showChallengeNotification(challenge)
    }

    private fun showChallengeNotification(challenge: MfaChallenge) {
        ensureChannel()
        val intent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        val pendingIntent = PendingIntent.getActivity(
            this,
            0,
            intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        val notification = NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_nav_lock)
            .setContentTitle("KyAuth sign-in request")
            .setContentText("Tap to review the sign-in request.")
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setCategory(NotificationCompat.CATEGORY_STATUS)
            .setVisibility(NotificationCompat.VISIBILITY_SECRET)
            .setAutoCancel(true)
            .setContentIntent(pendingIntent)
            .build()

        if (ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) ==
            android.content.pm.PackageManager.PERMISSION_GRANTED
        ) NotificationManagerCompat.from(this).notify(challenge.challengeId.hashCode(), notification)
    }

    private fun ensureChannel() {
        val channel = NotificationChannel(
            CHANNEL_ID,
            "KyAuth sign-in requests",
            NotificationManager.IMPORTANCE_HIGH,
        )
        getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
    }

    companion object {
        private const val CHANNEL_ID = "kyauth_mfa_push"

        fun ensureChannel(context: Context) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "KyAuth sign-in requests",
                NotificationManager.IMPORTANCE_HIGH,
            )
            context.getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
        }
    }
}
