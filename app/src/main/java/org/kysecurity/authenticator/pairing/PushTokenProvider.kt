package org.kysecurity.authenticator.pairing

import com.google.firebase.messaging.FirebaseMessaging
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

object PushTokenProvider {
    fun currentToken(timeoutSeconds: Long = 10): Result<String> {
        val latch = CountDownLatch(1)
        var token: String? = null
        var failure: Exception? = null

        return runCatching {
            FirebaseMessaging.getInstance().token
                .addOnSuccessListener {
                    token = it
                    latch.countDown()
                }
                .addOnFailureListener {
                    failure = it
                    latch.countDown()
                }

            check(latch.await(timeoutSeconds, TimeUnit.SECONDS)) { "Timed out while fetching FCM push token" }
            failure?.let { throw it }
            token?.trim()?.takeIf { it.isNotBlank() } ?: error("FCM returned an empty push token")
        }
    }
}
