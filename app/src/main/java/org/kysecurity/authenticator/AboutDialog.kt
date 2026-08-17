package org.kysecurity.authenticator

import android.app.Activity
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import androidx.appcompat.app.AlertDialog
import java.util.Calendar

fun showAboutDialog(activity: Activity) {
    fun dp(value: Int) = (value * activity.resources.displayMetrics.density).toInt()
    val panelColor = ThemeManager.color(activity, R.color.ky_surface)
    val backgroundColor = ThemeManager.color(activity, R.color.ky_background)
    val textColor = ThemeManager.color(activity, R.color.ky_text)
    val mutedColor = ThemeManager.color(activity, R.color.ky_muted)
    val accentColor = ThemeManager.color(activity, R.color.ky_cyan)
    val borderColor = ThemeManager.color(activity, R.color.ky_border)

    val container = LinearLayout(activity).apply {
        orientation = LinearLayout.VERTICAL
        setPadding(dp(24), dp(24), dp(24), dp(20))
    }
    val header = LinearLayout(activity).apply { gravity = Gravity.CENTER_VERTICAL }
    header.addView(TextView(activity).apply {
        text = activity.getString(R.string.about_title)
        textSize = 22f
        typeface = Typeface.DEFAULT_BOLD
        setTextColor(textColor)
    })
    header.addView(TextView(activity).apply {
        text = activity.getString(R.string.about_version_badge, BuildConfig.VERSION_NAME)
        textSize = 12f
        typeface = Typeface.DEFAULT_BOLD
        setTextColor(ThemeManager.buttonText(activity))
        setPadding(dp(10), dp(3), dp(10), dp(3))
        background = GradientDrawable().apply {
            cornerRadius = dp(100).toFloat()
            setColor(accentColor)
        }
        layoutParams = LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
            marginStart = dp(10)
        }
    })
    container.addView(header)
    container.addView(TextView(activity).apply {
        text = activity.getString(R.string.about_body, Calendar.getInstance().get(Calendar.YEAR))
        textSize = 14f
        setTextColor(mutedColor)
        setLineSpacing(dp(4).toFloat(), 1f)
        setPadding(0, dp(10), 0, 0)
    })
    container.addView(View(activity).apply {
        setBackgroundColor(accentColor)
        alpha = 0.5f
        layoutParams = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(2)).apply {
            topMargin = dp(20)
            bottomMargin = dp(16)
        }
    })
    container.addView(TextView(activity).apply {
        text = activity.getString(R.string.about_license_label)
        textSize = 12f
        typeface = Typeface.DEFAULT_BOLD
        letterSpacing = 0.08f
        setTextColor(accentColor)
        setPadding(0, 0, 0, dp(10))
    })
    val license = TextView(activity).apply {
        text = activity.resources.openRawResource(R.raw.gpl_license).bufferedReader().use { it.readText() }
        textSize = 12.5f
        setTextColor(mutedColor)
        setTextIsSelectable(true)
        setLineSpacing(dp(3).toFloat(), 1f)
        setPadding(dp(16), dp(16), dp(16), dp(16))
    }
    container.addView(ScrollView(activity).apply {
        addView(license)
        isVerticalScrollBarEnabled = true
        background = GradientDrawable().apply {
            cornerRadius = dp(14).toFloat()
            setColor(backgroundColor)
            setStroke(dp(2), borderColor)
        }
        layoutParams = LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            (activity.resources.displayMetrics.heightPixels * 0.42f).toInt(),
        )
    })
    val close = Button(activity).apply {
        text = activity.getString(android.R.string.ok)
        isAllCaps = false
        typeface = Typeface.DEFAULT_BOLD
        setTextColor(ThemeManager.buttonText(activity))
        background = GradientDrawable().apply {
            cornerRadius = dp(24).toFloat()
            setColor(accentColor)
        }
        minWidth = dp(96)
        stateListAnimator = null
        elevation = 0f
        layoutParams = LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
            gravity = Gravity.END
            topMargin = dp(20)
        }
    }
    container.addView(close)

    val dialog = AlertDialog.Builder(activity).setView(container).create()
    close.setOnClickListener { dialog.dismiss() }
    val dialogBackground = GradientDrawable().apply {
        cornerRadius = dp(20).toFloat()
        setColor(panelColor)
        setStroke(dp(1), borderColor)
    }
    dialog.window?.setBackgroundDrawable(dialogBackground)
    dialog.setOnShowListener {
        dialog.window?.setBackgroundDrawable(dialogBackground)
    }
    dialog.show()
}
