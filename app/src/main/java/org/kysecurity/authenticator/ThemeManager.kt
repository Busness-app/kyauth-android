package org.kysecurity.authenticator

import android.content.Context
import android.graphics.Color
import androidx.core.content.ContextCompat

private data class AppTheme(
    val name: String,
    val background: String,
    val surface: String,
    val text: String,
    val muted: String,
    val accent: String,
    val accentSoft: String,
    val border: String,
    val buttonText: String,
)

object ThemeManager {
    private const val PREFS = "appearance"
    private const val KEY_THEME = "theme"

    private val themes = listOf(
        AppTheme("Dark Matter", "#1a1a1e", "#252530", "#e8ddf5", "#d4c5e2", "#c29a72", "#5a3f31", "#404050", "#24170f"),
        AppTheme("Light Matter", "#f5efe5", "#fff8ee", "#2d1f15", "#4c3d32", "#c29a72", "#e6d2be", "#c5b29d", "#24170f"),
        AppTheme("Tropics", "#f4f1eb", "#fffaf0", "#241a14", "#43362d", "#9bc400", "#d4e3a0", "#c4b7a3", "#243100"),
        AppTheme("Tropic Night", "#15131a", "#221f2b", "#e8ddf5", "#cdbde0", "#9bc400", "#6b4a42", "#3c3650", "#1a2400"),
        AppTheme("Ocean", "#0f1b24", "#152a36", "#e0f2fb", "#b8d8e8", "#5ea9be", "#214657", "#2f5567", "#0a1b22"),
        AppTheme("Coffee", "#1d1714", "#2a211d", "#f0ded2", "#d6c0b3", "#b47f5c", "#5f3f2f", "#4a3830", "#220f08"),
        AppTheme("White Cliffs", "#f7f9fb", "#ffffff", "#163246", "#2e4c63", "#5ea8d8", "#dff1fb", "#8fc3df", "#103246"),
        AppTheme("Cyber Punk", "#120918", "#1e1028", "#ffe9ff", "#f5d0ff", "#00f5d4", "#3b1760", "#5c2d84", "#051d1a"),
        AppTheme("Neon Purple", "#130b1d", "#231233", "#f2e6ff", "#e4ccff", "#c86cff", "#47206c", "#63358a", "#210a35"),
        AppTheme("Space", "#0b0f1a", "#151c2d", "#e7efff", "#c8d5f0", "#86a8ff", "#263e74", "#34496f", "#101930"),
        AppTheme("Sky", "#dff1ff", "#f4fbff", "#183142", "#2f4f64", "#6db3d6", "#b6dced", "#93bdd2", "#0f2e3f"),
        AppTheme("Forest", "#142018", "#1f2f24", "#e3f0df", "#c7dbc7", "#8faa74", "#3a5837", "#4f694f", "#12200f"),
        AppTheme("Sun", "#fff3dc", "#fff9ec", "#392611", "#5a4024", "#e0ab4f", "#f1d9a2", "#d4b27a", "#2a1808"),
        AppTheme("Patina Ky", "#0d0f14", "#161a22", "#e2e8f0", "#94a3b8", "#4deeea", "#0e4a48", "#1e293b", "#04120d"),
        AppTheme("Polished Ky", "#eef2f6", "#ffffff", "#0f172a", "#475569", "#0891b2", "#cffafe", "#cbd5e1", "#042f2e"),
    )

    fun names(): Array<String> = themes.map(AppTheme::name).toTypedArray()

    fun currentName(context: Context): String = current(context).name

    fun set(context: Context, name: String) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().putString(KEY_THEME, name).apply()
    }

    fun color(context: Context, colorRes: Int): Int {
        val theme = current(context)
        val value = when (colorRes) {
            R.color.ky_background -> theme.background
            R.color.ky_surface, R.color.ky_surface_elevated -> theme.surface
            R.color.ky_text -> theme.text
            R.color.ky_muted -> theme.muted
            R.color.ky_cyan -> theme.accent
            R.color.ky_cyan_dim -> theme.accentSoft
            R.color.ky_border -> theme.border
            else -> return ContextCompat.getColor(context, colorRes)
        }
        return Color.parseColor(value)
    }

    fun buttonText(context: Context): Int = Color.parseColor(current(context).buttonText)

    private fun current(context: Context): AppTheme {
        val saved = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString(KEY_THEME, "Patina Ky")
        return themes.firstOrNull { it.name == saved } ?: themes.first { it.name == "Patina Ky" }
    }
}
