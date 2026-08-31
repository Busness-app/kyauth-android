package org.kysecurity.authenticator

import android.content.res.ColorStateList
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.view.Gravity
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView

internal fun MainActivity.dp(value: Int): Int = (value * resources.displayMetrics.density).toInt()

internal fun MainActivity.title(value: String) = TextView(this).apply {
    text = value
    textSize = 22f
    setTextColor(ThemeManager.color(context, R.color.ky_text))
    typeface = Typeface.DEFAULT_BOLD
    setPadding(0, dp(16), 0, dp(8))
}

internal fun MainActivity.message(value: String) = TextView(this).apply {
    text = value
    textSize = 15f
    setTextColor(ThemeManager.color(context, R.color.ky_muted))
    setPadding(0, dp(4), 0, dp(16))
}

internal fun MainActivity.primaryButton(label: String) = Button(this).apply {
    text = label
    transformationMethod = null
    background = roundedButtonBackground(R.color.ky_cyan)
    setTextColor(ThemeManager.buttonText(context))
    typeface = Typeface.DEFAULT_BOLD
    minHeight = dp(48)
    stateListAnimator = null
    elevation = 0f
}

internal fun MainActivity.secondaryButton(label: String) = Button(this).apply {
    text = label
    transformationMethod = null
    background = roundedButtonBackground(R.color.ky_surface_elevated, R.color.ky_border)
    setTextColor(ThemeManager.color(context, R.color.ky_cyan))
    minHeight = dp(48)
    stateListAnimator = null
    elevation = 0f
}

internal fun MainActivity.ghostButton(label: String) = Button(this).apply {
    text = label
    transformationMethod = null
    backgroundTintList = ColorStateList.valueOf(android.graphics.Color.TRANSPARENT)
    setTextColor(ThemeManager.color(context, R.color.ky_cyan))
    textSize = 14f
    stateListAnimator = null
    elevation = 0f
}

internal fun MainActivity.numberButton(label: String) = Button(this).apply {
    text = label
    textSize = 24f
    typeface = Typeface.DEFAULT_BOLD
    backgroundTintList = ColorStateList.valueOf(ThemeManager.color(context, R.color.ky_surface))
    setTextColor(ThemeManager.color(context, R.color.ky_text))
    stateListAnimator = null
    elevation = 0f
}

internal fun MainActivity.styleInput(editText: EditText) {
    editText.apply {
        setTextColor(ThemeManager.color(context, R.color.ky_text))
        setHintTextColor(ThemeManager.color(context, R.color.ky_muted))
        background = GradientDrawable().apply {
            setColor(ThemeManager.color(context, R.color.ky_surface))
            setStroke(dp(1), ThemeManager.color(context, R.color.ky_border))
            cornerRadius = dp(14).toFloat()
        }
        setPadding(dp(16), dp(12), dp(16), dp(12))
    }
}

internal fun MainActivity.fullWidthParams(top: Int = 0, bottom: Int = 0) = LinearLayout.LayoutParams(
    LinearLayout.LayoutParams.MATCH_PARENT,
    LinearLayout.LayoutParams.WRAP_CONTENT,
).apply {
    topMargin = dp(top)
    bottomMargin = dp(bottom)
}

internal fun MainActivity.cardBackground() = GradientDrawable().apply {
    setColor(ThemeManager.color(this@cardBackground, R.color.ky_surface))
    setStroke(dp(1), ThemeManager.color(this@cardBackground, R.color.ky_border))
    cornerRadius = dp(20).toFloat()
}

internal fun MainActivity.settingsCard() = LinearLayout(this).apply {
    orientation = LinearLayout.VERTICAL
    background = cardBackground()
    setPadding(dp(16), dp(4), dp(16), dp(16))
    layoutParams = fullWidthParams(bottom = 12)
}

internal fun MainActivity.roundedButtonBackground(colorRes: Int, strokeRes: Int? = null) = GradientDrawable().apply {
    setColor(ThemeManager.color(this@roundedButtonBackground, colorRes))
    strokeRes?.let { setStroke(dp(1), ThemeManager.color(this@roundedButtonBackground, it)) }
    cornerRadius = dp(24).toFloat()
}

internal fun MainActivity.emptyState(heading: String, body: String): LinearLayout = LinearLayout(this).apply {
    orientation = LinearLayout.VERTICAL
    gravity = Gravity.CENTER
    background = cardBackground()
    setPadding(dp(24), dp(42), dp(24), dp(42))
    addView(title(heading).apply { gravity = Gravity.CENTER })
    addView(message(body).apply { gravity = Gravity.CENTER })
}
