package org.kysecurity.authenticator.passwords

/**
 * The packages whose `webDomain` KyAuth is willing to believe.
 *
 * An Autofill request carries a web domain only because the app that drew the form said so:
 * `ViewStructure.setWebDomain` is public API and Android does not check that the caller is a
 * browser or that it has any claim to the domain. Believing it from an arbitrary app is what lets
 * a fake login screen ask for — and be handed — the credential for someone else's site.
 *
 * So the domain is honoured only for a known browser, and every other caller is matched on its own
 * package instead. The list is deliberately conservative: a browser missing from it falls back to
 * package matching and simply offers nothing, which is the safe direction to be wrong in.
 *
 * Package names are unique on a device, but a sideloaded app can still claim one that is not
 * installed. Pinning each browser's signing certificate is the remaining hardening step.
 */
object TrustedBrowsers {
    private val PACKAGES = setOf(
        "com.android.chrome",
        "com.chrome.beta",
        "com.chrome.dev",
        "com.chrome.canary",
        "org.chromium.chrome",
        "org.mozilla.firefox",
        "org.mozilla.firefox_beta",
        "org.mozilla.fenix",
        "org.mozilla.focus",
        "com.microsoft.emmx",
        "com.brave.browser",
        "com.brave.browser_beta",
        "com.opera.browser",
        "com.opera.browser.beta",
        "com.opera.gx",
        "com.opera.mini.native",
        "com.duckduckgo.mobile.android",
        "com.sec.android.app.sbrowser",
        "com.sec.android.app.sbrowser.beta",
        "com.vivaldi.browser",
        "com.vivaldi.browser.snapshot",
        "com.kiwibrowser.browser",
        "com.ecosia.android",
    )

    fun isTrusted(packageName: String?): Boolean = packageName != null && packageName in PACKAGES
}
