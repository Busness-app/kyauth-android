package org.kysecurity.authenticator

import android.content.Intent
import android.os.Build
import android.os.Parcelable

/** Type-safe [Intent] extra lookup that avoids the deprecated untyped overload on API 33+. */
inline fun <reified T : Parcelable> Intent.parcelable(name: String): T? =
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
        getParcelableExtra(name, T::class.java)
    } else {
        @Suppress("DEPRECATION")
        getParcelableExtra(name) as? T
    }
