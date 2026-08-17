package org.kysecurity.authenticator.pairing

import java.net.URI
import org.kysecurity.authenticator.BuildConfig

object PairingEndpoint {
    fun registrationUrl(serverUrl: String): URI {
        val server = URI(serverUrl.trim())
        require(server.host != null && server.userInfo == null && server.query == null && server.fragment == null) {
            "Enter a complete server URL without credentials or a path query"
        }
        require(server.scheme == "https" || (BuildConfig.DEBUG && server.scheme == "http" && isLoopback(server.host))) {
            "KySignOn must use HTTPS except for loopback development"
        }
        val basePath = server.path.orEmpty().trimEnd('/')
        return URI(server.scheme, null, server.host, server.port, "$basePath/api/notifications/native/register", null, null)
    }

    fun validatedRegistrationUrl(serverUrl: String, candidate: String?): URI {
        val fallback = registrationUrl(serverUrl)
        if (candidate.isNullOrBlank()) return fallback
        val registration = URI(candidate.trim())
        require(registration.scheme == "https" || (BuildConfig.DEBUG && registration.scheme == "http" && isLoopback(registration.host.orEmpty()))) {
            "Registration URL must use HTTPS"
        }
        require(registration.host != null && registration.userInfo == null && registration.query == null && registration.fragment == null) {
            "Invalid registration URL"
        }
        require(sameOrigin(registration, URI(serverUrl.trim()))) {
            "Registration URL must be on the same server as the QR code"
        }
        return registration
    }

    private fun sameOrigin(a: URI, b: URI): Boolean =
        a.scheme.equals(b.scheme, ignoreCase = true) &&
            a.host.equals(b.host, ignoreCase = true) &&
            effectivePort(a) == effectivePort(b)

    private fun effectivePort(uri: URI): Int =
        if (uri.port != -1) uri.port else if (uri.scheme.equals("https", ignoreCase = true)) 443 else 80

    private fun isLoopback(host: String): Boolean =
        host.equals("localhost", ignoreCase = true) || host == "127.0.0.1" || host == "::1" || host == "10.0.2.2"
}
