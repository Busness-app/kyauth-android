package org.kysecurity.authenticator.passwords

/**
 * Registry boundaries below which credentials must never be shared.
 *
 * This is a short bundled list, not the full Public Suffix List: it covers the multi-label
 * suffixes a phishing site is realistically registered under, and every single-label TLD is
 * caught by the label-count rule in [isPublicSuffix]. A vendored PSL with a refresh path is the
 * proper fix and is tracked in AGENTS.md.
 */
object PublicSuffix {
    private val MULTI_LABEL = setOf(
        // ccTLD second levels
        "ac.uk", "co.uk", "gov.uk", "ltd.uk", "me.uk", "net.uk", "org.uk", "plc.uk", "sch.uk",
        "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp",
        "com.au", "net.au", "org.au", "edu.au", "gov.au", "id.au",
        "com.br", "net.br", "org.br", "gov.br",
        "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn",
        "co.in", "net.in", "org.in", "gen.in", "firm.in", "ind.in",
        "co.nz", "net.nz", "org.nz", "govt.nz", "ac.nz",
        "co.za", "org.za", "net.za", "gov.za",
        "co.kr", "or.kr", "ne.kr", "go.kr",
        "com.mx", "com.ar", "com.co", "com.pe", "com.ve", "com.ec", "com.uy",
        "com.tr", "com.pl", "com.ua", "com.ru", "com.sg", "com.hk", "com.tw",
        "com.my", "com.ph", "com.vn", "com.pk", "com.bd", "com.np",
        "com.eg", "com.sa", "com.ng", "com.gh", "com.qa", "com.kw",
        "co.il", "co.id", "co.th", "co.ke", "co.tz", "co.ug",
        // Common shared application hosts
        "github.io", "gitlab.io", "pages.dev", "workers.dev", "vercel.app", "netlify.app",
        "firebaseapp.com", "web.app", "herokuapp.com", "appspot.com", "azurewebsites.net",
        "cloudfront.net", "s3.amazonaws.com", "blogspot.com", "glitch.me", "ngrok.io",
        "onrender.com", "fly.dev", "surge.sh", "repl.co", "trycloudflare.com",
    )

    /** True when [host] is a registry boundary that no single owner controls. */
    fun isPublicSuffix(host: String): Boolean {
        val normalized = host.trim().lowercase().trim('.')
        if (normalized.isBlank()) return true
        if (!normalized.contains('.')) return true
        return normalized in MULTI_LABEL
    }
}
