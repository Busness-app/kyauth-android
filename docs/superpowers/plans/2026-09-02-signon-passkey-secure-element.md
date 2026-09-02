# KySignOn Passkey in the Secure Element — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Store the KySignOn login passkey as a non-exportable AndroidKeyStore key in the device's secure element, so a KyPasswords compromise cannot yield a KySignOn authentication factor.

**Architecture:** A passkey whose RP ID equals the paired KySignOn host is routed away from `passwords_vault.kdbx` entirely. Its private key is generated in AndroidKeyStore (StrongBox where available, TEE otherwise) and never leaves hardware; only non-secret metadata is persisted, in an `EncryptedSharedPreferences` store. Because there is no key to unwrap, the assertion path never calls `AppLockManager.useVaultKeys`, which is what makes the factor independent of the password vault.

**Tech Stack:** Kotlin, Android `minSdk 31` / `compileSdk 36`, `androidx.security:security-crypto`, `androidx.biometric`, `android.service.credentials` Credential Provider API, JUnit 4, AndroidJUnitRunner.

**Spec:** `docs/superpowers/specs/2026-09-02-signon-passkey-secure-element-design.md`

## Global Constraints

- `minSdk = 31`. `setIsStrongBoxBacked`, `setUnlockedDeviceRequired`, `setUserAuthenticationParameters` and `AUTH_DEVICE_CREDENTIAL` are all available unconditionally. The Credential Provider stays `@RequiresApi(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)` (34).
- No new Gradle dependencies. There is no Robolectric in this project: anything touching `Context`, AndroidKeyStore or `EncryptedSharedPreferences` is an instrumented test under `app/src/androidTest`, and everything else is a JVM unit test under `app/src/test`.
- Keystore aliases must begin with `kyauth` so `SecurityWipe.isAppAlias` matches them.
- Never fall back to a software-backed or vault-held key. If hardware backing cannot be obtained, enrolment fails closed.
- The KySignOn assertion and creation paths must never call `AppLockManager.useVaultKeys` and must never hold a vault key.
- User-visible text uses the name "KyAuth" (`AGENTS.md` UI contract).
- Verification gate for every commit: `./gradlew test lintDebug assembleDebug compileDebugAndroidTestSources`.

---

### Task 1: Routing predicate

The one rule that decides local-vs-vault. Pure, so it is unit-testable and can be reused by the service, the entry builder and the UI without any of them re-deriving it.

**Files:**
- Create: `app/src/main/java/org/kysecurity/authenticator/passkeys/SignOnPasskey.kt`
- Test: `app/src/test/java/org/kysecurity/authenticator/passkeys/SignOnPasskeyRoutingTest.kt`

**Interfaces:**
- Consumes: `RpId.normalize`, `DomainMatcher.extractDomain` (both already exist).
- Produces: `SignOnPasskey.signOnRpId(serverUrl: String?): String?` and `SignOnPasskey.isSignOnRpId(rpId: String?, serverUrl: String?): Boolean`.

- [ ] **Step 1: Write the failing test**

Create `app/src/test/java/org/kysecurity/authenticator/passkeys/SignOnPasskeyRoutingTest.kt`:

```kotlin
package org.kysecurity.authenticator.passkeys

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class SignOnPasskeyRoutingTest {

    @Test
    fun `derives the rp id from the paired server url`() {
        assertEquals("signon.example.com", SignOnPasskey.signOnRpId("https://signon.example.com"))
        assertEquals("signon.example.com", SignOnPasskey.signOnRpId("https://signon.example.com:8443/pair"))
    }

    @Test
    fun `unpaired device has no signon rp id`() {
        assertNull(SignOnPasskey.signOnRpId(null))
        assertNull(SignOnPasskey.signOnRpId(""))
    }

    @Test
    fun `matches only the paired host exactly`() {
        val server = "https://signon.example.com"
        assertTrue(SignOnPasskey.isSignOnRpId("signon.example.com", server))
        // Subdomain and parent must not match: WebAuthn scopes a credential to exactly one RP ID.
        assertFalse(SignOnPasskey.isSignOnRpId("login.signon.example.com", server))
        assertFalse(SignOnPasskey.isSignOnRpId("example.com", server))
        assertFalse(SignOnPasskey.isSignOnRpId("signon.example.com.evil.test", server))
    }

    @Test
    fun `an unpaired device routes nothing to the local store`() {
        assertFalse(SignOnPasskey.isSignOnRpId("signon.example.com", null))
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./gradlew testDebugUnitTest --tests '*SignOnPasskeyRoutingTest*'`
Expected: FAIL, "Unresolved reference 'SignOnPasskey'".

- [ ] **Step 3: Write minimal implementation**

Create `app/src/main/java/org/kysecurity/authenticator/passkeys/SignOnPasskey.kt`:

```kotlin
package org.kysecurity.authenticator.passkeys

import org.kysecurity.authenticator.passwords.DomainMatcher

/**
 * Decides whether a relying party is the paired KySignOn server.
 *
 * A KySignOn login passkey must not live in `passwords_vault.kdbx`, because that vault syncs to
 * KyPasswords: a KyPasswords compromise plus the master password would otherwise yield a KySignOn
 * authentication factor. This predicate is the single place that decision is made.
 *
 * The paired server URL is a locally held fact, never a caller assertion, so a hostile relying
 * party cannot route itself into the local store by naming an RP ID.
 */
object SignOnPasskey {

    /** The RP ID of the paired KySignOn server, or null when unpaired or unusable as an RP ID. */
    fun signOnRpId(serverUrl: String?): String? =
        RpId.normalize(DomainMatcher.extractDomain(serverUrl))

    /** Exact match only; a passkey for `example.com` is not a passkey for `login.example.com`. */
    fun isSignOnRpId(rpId: String?, serverUrl: String?): Boolean {
        val paired = signOnRpId(serverUrl) ?: return false
        return RpId.normalize(rpId) == paired
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./gradlew testDebugUnitTest --tests '*SignOnPasskeyRoutingTest*'`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add app/src/main/java/org/kysecurity/authenticator/passkeys/SignOnPasskey.kt \
        app/src/test/java/org/kysecurity/authenticator/passkeys/SignOnPasskeyRoutingTest.kt
git commit -m "feat: route passkeys for the paired KySignOn host away from the synced vault"
```

---

### Task 2: The metadata record and its serialization

Split from storage on purpose: the record and its JSON form are pure and unit-testable, while `EncryptedSharedPreferences` needs a device. Keeping them apart means the format is covered by fast tests.

**Files:**
- Modify: `app/src/main/java/org/kysecurity/authenticator/passkeys/SignOnPasskey.kt`
- Test: `app/src/test/java/org/kysecurity/authenticator/passkeys/SignOnPasskeyRecordTest.kt`

**Interfaces:**
- Consumes: nothing new.
- Produces: `SignOnPasskeyRecord(rpId: String, username: String, userHandle: ByteArray, credentialId: ByteArray, signCount: Int, alias: String, strongBoxBacked: Boolean)`, with `toJson(): String` and `SignOnPasskeyRecord.fromJson(String?): SignOnPasskeyRecord?`.

- [ ] **Step 1: Write the failing test**

Create `app/src/test/java/org/kysecurity/authenticator/passkeys/SignOnPasskeyRecordTest.kt`:

```kotlin
package org.kysecurity.authenticator.passkeys

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class SignOnPasskeyRecordTest {

    private fun record() = SignOnPasskeyRecord(
        rpId = "signon.example.com",
        username = "yoshi",
        userHandle = byteArrayOf(1, 2, 3),
        credentialId = byteArrayOf(9, 8, 7, 6),
        signCount = 4,
        alias = "kyauth_signon_passkey_a",
        strongBoxBacked = true,
    )

    @Test
    fun `round trips through json`() {
        assertEquals(record(), SignOnPasskeyRecord.fromJson(record().toJson()))
    }

    @Test
    fun `rejects malformed or absent json instead of throwing`() {
        assertNull(SignOnPasskeyRecord.fromJson(null))
        assertNull(SignOnPasskeyRecord.fromJson(""))
        assertNull(SignOnPasskeyRecord.fromJson("not json"))
        assertNull(SignOnPasskeyRecord.fromJson("""{"rpId":"signon.example.com"}"""))
    }

    @Test
    fun `an empty user handle survives the round trip`() {
        val empty = record().copy(userHandle = ByteArray(0))
        assertEquals(empty, SignOnPasskeyRecord.fromJson(empty.toJson()))
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./gradlew testDebugUnitTest --tests '*SignOnPasskeyRecordTest*'`
Expected: FAIL, "Unresolved reference 'SignOnPasskeyRecord'".

- [ ] **Step 3: Write minimal implementation**

Append to `app/src/main/java/org/kysecurity/authenticator/passkeys/SignOnPasskey.kt`, and add the imports `java.util.Base64` and `org.json.JSONObject` at the top of the file:

```kotlin
/**
 * Everything about a KySignOn passkey except the private key, which is non-exportable and lives in
 * AndroidKeyStore under [alias]. None of these fields is key material, so this record is what gets
 * persisted; there is no secret left to put in a vault.
 */
data class SignOnPasskeyRecord(
    val rpId: String,
    val username: String,
    val userHandle: ByteArray,
    val credentialId: ByteArray,
    val signCount: Int,
    val alias: String,
    val strongBoxBacked: Boolean,
) {
    fun toJson(): String = JSONObject()
        .put(F_RP_ID, rpId)
        .put(F_USERNAME, username)
        .put(F_USER_HANDLE, b64(userHandle))
        .put(F_CREDENTIAL_ID, b64(credentialId))
        .put(F_SIGN_COUNT, signCount)
        .put(F_ALIAS, alias)
        .put(F_STRONGBOX, strongBoxBacked)
        .toString()

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is SignOnPasskeyRecord) return false
        return rpId == other.rpId &&
            username == other.username &&
            userHandle.contentEquals(other.userHandle) &&
            credentialId.contentEquals(other.credentialId) &&
            signCount == other.signCount &&
            alias == other.alias &&
            strongBoxBacked == other.strongBoxBacked
    }

    override fun hashCode(): Int {
        var result = rpId.hashCode()
        result = 31 * result + username.hashCode()
        result = 31 * result + userHandle.contentHashCode()
        result = 31 * result + credentialId.contentHashCode()
        result = 31 * result + signCount
        result = 31 * result + alias.hashCode()
        result = 31 * result + strongBoxBacked.hashCode()
        return result
    }

    companion object {
        private const val F_RP_ID = "rpId"
        private const val F_USERNAME = "username"
        private const val F_USER_HANDLE = "userHandle"
        private const val F_CREDENTIAL_ID = "credentialId"
        private const val F_SIGN_COUNT = "signCount"
        private const val F_ALIAS = "alias"
        private const val F_STRONGBOX = "strongBox"

        fun fromJson(serialized: String?): SignOnPasskeyRecord? {
            if (serialized.isNullOrBlank()) return null
            return runCatching {
                val json = JSONObject(serialized)
                SignOnPasskeyRecord(
                    rpId = json.getString(F_RP_ID),
                    username = json.getString(F_USERNAME),
                    userHandle = unb64(json.getString(F_USER_HANDLE)),
                    credentialId = unb64(json.getString(F_CREDENTIAL_ID)),
                    signCount = json.getInt(F_SIGN_COUNT),
                    alias = json.getString(F_ALIAS),
                    strongBoxBacked = json.getBoolean(F_STRONGBOX),
                )
            }.getOrNull()
        }

        private fun b64(bytes: ByteArray): String = Base64.getEncoder().encodeToString(bytes)

        private fun unb64(value: String): ByteArray = Base64.getDecoder().decode(value)
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./gradlew testDebugUnitTest --tests '*SignOnPasskeyRecordTest*'`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add app/src/main/java/org/kysecurity/authenticator/passkeys/SignOnPasskey.kt \
        app/src/test/java/org/kysecurity/authenticator/passkeys/SignOnPasskeyRecordTest.kt
git commit -m "feat: add the KySignOn passkey metadata record"
```

---

### Task 3: The metadata store

**Files:**
- Create: `app/src/main/java/org/kysecurity/authenticator/passkeys/SignOnPasskeyStore.kt`
- Test: `app/src/androidTest/java/org/kysecurity/authenticator/passkeys/SignOnPasskeyStoreTest.kt`

**Interfaces:**
- Consumes: `SignOnPasskeyRecord` (Task 2).
- Produces: `SignOnPasskeyStore(context: Context)` with `record(): SignOnPasskeyRecord?`, `save(record: SignOnPasskeyRecord)`, `clear()`.

- [ ] **Step 1: Write the failing test**

Create `app/src/androidTest/java/org/kysecurity/authenticator/passkeys/SignOnPasskeyStoreTest.kt`:

```kotlin
package org.kysecurity.authenticator.passkeys

import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class SignOnPasskeyStoreTest {

    private val store = SignOnPasskeyStore(ApplicationProvider.getApplicationContext())

    private fun record() = SignOnPasskeyRecord(
        rpId = "signon.example.com",
        username = "yoshi",
        userHandle = byteArrayOf(1, 2, 3),
        credentialId = byteArrayOf(9, 8, 7, 6),
        signCount = 0,
        alias = "kyauth_signon_passkey_a",
        strongBoxBacked = false,
    )

    @Before fun setUp() = store.clear()

    @After fun tearDown() = store.clear()

    @Test
    fun startsEmpty() {
        assertNull(store.record())
    }

    @Test
    fun savesAndReadsBack() {
        store.save(record())
        assertEquals(record(), store.record())
    }

    @Test
    fun saveReplacesRatherThanAccumulates() {
        store.save(record())
        store.save(record().copy(signCount = 7))
        assertEquals(7, store.record()?.signCount)
    }

    @Test
    fun clearRemovesTheRecord() {
        store.save(record())
        store.clear()
        assertNull(store.record())
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./gradlew compileDebugAndroidTestSources`
Expected: FAIL, "Unresolved reference 'SignOnPasskeyStore'". (An emulator is needed to actually run it; compiling is enough to see red here.)

- [ ] **Step 3: Write minimal implementation**

Create `app/src/main/java/org/kysecurity/authenticator/passkeys/SignOnPasskeyStore.kt`:

```kotlin
package org.kysecurity.authenticator.passkeys

import android.content.Context
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

/**
 * Persists the non-secret half of the KySignOn passkey. The private key is non-exportable and
 * never passes through here — only rpId, credential id, user handle, sign count, the Keystore
 * alias and which hardware backed it.
 *
 * Modelled on [org.kysecurity.authenticator.pairing.PairingStore]: same dependency, same pattern,
 * no new crypto and deliberately not a third KDBX vault.
 */
class SignOnPasskeyStore(context: Context) {

    private val preferences = EncryptedSharedPreferences.create(
        context,
        "signon_passkey",
        MasterKey.Builder(context).setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build(),
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
    )

    fun record(): SignOnPasskeyRecord? =
        SignOnPasskeyRecord.fromJson(preferences.getString(KEY_RECORD, null))

    fun save(record: SignOnPasskeyRecord) {
        preferences.edit().putString(KEY_RECORD, record.toJson()).apply()
    }

    fun clear() {
        preferences.edit().remove(KEY_RECORD).apply()
    }

    private companion object {
        const val KEY_RECORD = "record"
    }
}
```

- [ ] **Step 4: Run the gate to verify it compiles**

Run: `./gradlew test compileDebugAndroidTestSources`
Expected: PASS. Run `./gradlew connectedDebugAndroidTest --tests '*SignOnPasskeyStoreTest*'` if an emulator is available; if not, note it as unrun rather than claiming it passed.

- [ ] **Step 5: Commit**

```bash
git add app/src/main/java/org/kysecurity/authenticator/passkeys/SignOnPasskeyStore.kt \
        app/src/androidTest/java/org/kysecurity/authenticator/passkeys/SignOnPasskeyStoreTest.kt
git commit -m "feat: persist KySignOn passkey metadata outside any KDBX vault"
```

---

### Task 4: Sign an assertion from a Keystore `Signature`

A Keystore private key cannot be handed out as an `ECPrivateKey`; the caller only ever gets a `Signature` the framework has authenticated. Add that entry point and make the existing one delegate, so there stays one signing path rather than two that can drift.

**Files:**
- Modify: `app/src/main/java/org/kysecurity/authenticator/passkeys/WebAuthnEngine.kt:139-150`
- Test: `app/src/test/java/org/kysecurity/authenticator/passkeys/WebAuthnAssertionTest.kt`

**Interfaces:**
- Produces: `WebAuthnEngine.signAssertion(signature: Signature, authData: ByteArray, clientDataHash: ByteArray): ByteArray`. The existing `signAssertion(privateKey: ECPrivateKey, ...)` keeps its signature and behaviour.

- [ ] **Step 1: Write the failing test**

Append to `app/src/test/java/org/kysecurity/authenticator/passkeys/WebAuthnAssertionTest.kt` (inside the existing class):

```kotlin
    @Test
    fun `signing through a Signature matches signing through a private key`() {
        val keyPair = WebAuthnEngine.generateEcKeyPair()
        val authData = WebAuthnEngine.buildAssertionAuthData("example.com", 1)
        val clientDataHash = WebAuthnEngine.sha256("client data".toByteArray())

        val viaSignature = java.security.Signature.getInstance("SHA256withECDSA").apply {
            initSign(keyPair.private)
        }
        val fromSignature = WebAuthnEngine.signAssertion(viaSignature, authData, clientDataHash)

        // ECDSA is randomised, so the bytes differ every time; both must verify against the key.
        val verifier = java.security.Signature.getInstance("SHA256withECDSA").apply {
            initVerify(keyPair.public)
            update(authData)
            update(clientDataHash)
        }
        org.junit.Assert.assertTrue(verifier.verify(fromSignature))
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./gradlew testDebugUnitTest --tests '*WebAuthnAssertionTest*'`
Expected: FAIL, "None of the following candidates is applicable" for `signAssertion`.

- [ ] **Step 3: Write minimal implementation**

In `WebAuthnEngine.kt`, replace the existing `signAssertion` with:

```kotlin
    /**
     * Signs with an already-initialised [Signature]. A Keystore-resident private key is never
     * handed out as an [ECPrivateKey] — the caller only ever holds a Signature the framework has
     * authenticated — so this is the primitive and the key-based overload delegates to it.
     */
    fun signAssertion(
        signature: Signature,
        authData: ByteArray,
        clientDataHash: ByteArray,
    ): ByteArray {
        signature.update(authData)
        signature.update(clientDataHash)
        return signature.sign()
    }

    fun signAssertion(
        privateKey: ECPrivateKey,
        authData: ByteArray,
        clientDataHash: ByteArray,
    ): ByteArray = signAssertion(
        Signature.getInstance("SHA256withECDSA").apply { initSign(privateKey) },
        authData,
        clientDataHash,
    )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `./gradlew testDebugUnitTest --tests '*WebAuthn*'`
Expected: PASS, including the pre-existing assertion tests — the concatenation order is unchanged.

- [ ] **Step 5: Commit**

```bash
git add app/src/main/java/org/kysecurity/authenticator/passkeys/WebAuthnEngine.kt \
        app/src/test/java/org/kysecurity/authenticator/passkeys/WebAuthnAssertionTest.kt
git commit -m "refactor: sign assertions through a Signature so Keystore keys can be used"
```

---

### Task 5: The hardware key

Two alternating aliases, because enrolment must be atomic. Generating straight over a live alias would destroy a working passkey if the user then cancelled the biometric prompt, leaving the server holding a credential whose key no longer exists. The new key goes into the spare alias and the pointer only flips on success.

**Files:**
- Create: `app/src/main/java/org/kysecurity/authenticator/passkeys/SignOnPasskeyKey.kt`
- Test: `app/src/androidTest/java/org/kysecurity/authenticator/passkeys/SignOnPasskeyKeyTest.kt`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces:
  - `SignOnPasskeyKey.ALIAS_A = "kyauth_signon_passkey_a"`, `ALIAS_B = "kyauth_signon_passkey_b"`
  - `SignOnPasskeyKey.spareAlias(liveAlias: String?): String`
  - `SignOnPasskeyKey.Generated(val publicKey: ECPublicKey, val alias: String, val strongBoxBacked: Boolean)`
  - `SignOnPasskeyKey.generate(alias: String): Generated` — throws `NoHardwareKeystore` if the result is software-backed
  - `SignOnPasskeyKey.signatureFor(alias: String): Signature?`
  - `SignOnPasskeyKey.delete(alias: String)`, `SignOnPasskeyKey.deleteAll()`
  - `class SignOnPasskeyKey.NoHardwareKeystore : IllegalStateException`

- [ ] **Step 1: Write the failing test**

Create `app/src/androidTest/java/org/kysecurity/authenticator/passkeys/SignOnPasskeyKeyTest.kt`:

```kotlin
package org.kysecurity.authenticator.passkeys

import androidx.test.ext.junit.runners.AndroidJUnit4
import java.security.KeyStore
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class SignOnPasskeyKeyTest {

    @After fun tearDown() = SignOnPasskeyKey.deleteAll()

    @Test
    fun generatesAHardwareBackedP256Key() {
        val generated = SignOnPasskeyKey.generate(SignOnPasskeyKey.ALIAS_A)
        assertEquals("EC", generated.publicKey.algorithm)
        assertEquals(256, generated.publicKey.params.curve.field.fieldSize)
    }

    @Test
    fun thePrivateKeyIsNotExportable() {
        SignOnPasskeyKey.generate(SignOnPasskeyKey.ALIAS_A)
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val privateKey = keyStore.getKey(SignOnPasskeyKey.ALIAS_A, null)
        assertNotNull(privateKey)
        // A Keystore key never yields its bytes; this is the property the whole design rests on.
        assertNull(privateKey.encoded)
    }

    @Test
    fun spareAliasAlternatesSoEnrolmentNeverOverwritesALiveKey() {
        assertEquals(SignOnPasskeyKey.ALIAS_A, SignOnPasskeyKey.spareAlias(null))
        assertEquals(SignOnPasskeyKey.ALIAS_B, SignOnPasskeyKey.spareAlias(SignOnPasskeyKey.ALIAS_A))
        assertEquals(SignOnPasskeyKey.ALIAS_A, SignOnPasskeyKey.spareAlias(SignOnPasskeyKey.ALIAS_B))
    }

    @Test
    fun generatingTheSpareLeavesTheLiveKeyIntact() {
        SignOnPasskeyKey.generate(SignOnPasskeyKey.ALIAS_A)
        SignOnPasskeyKey.generate(SignOnPasskeyKey.ALIAS_B)
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        assertTrue(keyStore.containsAlias(SignOnPasskeyKey.ALIAS_A))
        assertTrue(keyStore.containsAlias(SignOnPasskeyKey.ALIAS_B))
    }

    @Test
    fun deleteRemovesOnlyTheNamedAlias() {
        SignOnPasskeyKey.generate(SignOnPasskeyKey.ALIAS_A)
        SignOnPasskeyKey.generate(SignOnPasskeyKey.ALIAS_B)
        SignOnPasskeyKey.delete(SignOnPasskeyKey.ALIAS_A)
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        assertTrue(!keyStore.containsAlias(SignOnPasskeyKey.ALIAS_A))
        assertTrue(keyStore.containsAlias(SignOnPasskeyKey.ALIAS_B))
    }

    @Test
    fun signatureForAnAbsentAliasIsNull() {
        assertNull(SignOnPasskeyKey.signatureFor(SignOnPasskeyKey.ALIAS_A))
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./gradlew compileDebugAndroidTestSources`
Expected: FAIL, "Unresolved reference 'SignOnPasskeyKey'".

- [ ] **Step 3: Write minimal implementation**

Create `app/src/main/java/org/kysecurity/authenticator/passkeys/SignOnPasskeyKey.kt`:

```kotlin
package org.kysecurity.authenticator.passkeys

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec

/**
 * The KySignOn login passkey's private key: generated in, and never leaving, the device's secure
 * hardware. StrongBox where the device has a discrete secure element, the TEE otherwise.
 *
 * There is deliberately no software fallback. A software-backed key would be exportable, which is
 * the property this whole design exists to remove, so generation fails closed instead.
 *
 * Two alternating aliases exist because enrolment must be atomic: generating over the live alias
 * would destroy a working passkey if the user then cancelled the prompt, stranding the credential
 * the server has already registered. A new key goes into the spare and the caller flips the
 * pointer only once the response is built.
 */
object SignOnPasskeyKey {

    const val ALIAS_A = "kyauth_signon_passkey_a"
    const val ALIAS_B = "kyauth_signon_passkey_b"

    private const val ANDROID_KEYSTORE = "AndroidKeyStore"

    /** Raised when the device cannot hold the key in hardware. Enrolment must not proceed. */
    class NoHardwareKeystore :
        IllegalStateException("KyAuth needs hardware-backed key storage for a KySignOn passkey.")

    class Generated(val publicKey: ECPublicKey, val alias: String, val strongBoxBacked: Boolean)

    /** The alias not currently in use, so generating never overwrites a live key. */
    fun spareAlias(liveAlias: String?): String = if (liveAlias == ALIAS_A) ALIAS_B else ALIAS_A

    /**
     * Generates a fresh P-256 key at [alias], replacing anything already there. Tries StrongBox
     * first and falls back to the TEE, then verifies the result really is hardware-backed.
     */
    fun generate(alias: String): Generated {
        delete(alias)
        val strongBox = runCatching { generateKey(alias, strongBox = true) }
            .fold(onSuccess = { true }, onFailure = { error ->
                if (error !is StrongBoxUnavailableException) throw error
                generateKey(alias, strongBox = false)
                false
            })

        val publicKey = keyStore().getCertificate(alias)?.publicKey as? ECPublicKey
            ?: throw NoHardwareKeystore()
        if (!isHardwareBacked(alias)) {
            delete(alias)
            throw NoHardwareKeystore()
        }
        return Generated(publicKey, alias, strongBox)
    }

    /**
     * A [Signature] for `BiometricPrompt.CryptoObject`. The key requires per-use authentication, so
     * signing fails until the prompt succeeds. Null when no key exists at [alias].
     */
    fun signatureFor(alias: String): Signature? = runCatching {
        val privateKey = keyStore().getKey(alias, null) as? PrivateKey ?: return null
        Signature.getInstance("SHA256withECDSA").apply { initSign(privateKey) }
    }.getOrNull()

    fun delete(alias: String) {
        runCatching { keyStore().takeIf { it.containsAlias(alias) }?.deleteEntry(alias) }
    }

    fun deleteAll() {
        delete(ALIAS_A)
        delete(ALIAS_B)
    }

    private fun generateKey(alias: String, strongBox: Boolean) {
        KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE).apply {
            initialize(
                KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                    .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setUserAuthenticationRequired(true)
                    .setUserAuthenticationParameters(
                        0,
                        KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL,
                    )
                    .setUnlockedDeviceRequired(true)
                    .setIsStrongBoxBacked(strongBox)
                    .build(),
            )
        }.generateKeyPair()
    }

    /** Asks the platform what actually backs the key rather than trusting the request. */
    private fun isHardwareBacked(alias: String): Boolean = runCatching {
        val privateKey = keyStore().getKey(alias, null) as PrivateKey
        val info = KeyFactory.getInstance(privateKey.algorithm, ANDROID_KEYSTORE)
            .getKeySpec(privateKey, KeyInfo::class.java)
        info.securityLevel != KeyProperties.SECURITY_LEVEL_SOFTWARE
    }.getOrDefault(false)

    private fun keyStore(): KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
}
```

- [ ] **Step 4: Run the gate**

Run: `./gradlew test lintDebug assembleDebug compileDebugAndroidTestSources`
Expected: PASS. Run `./gradlew connectedDebugAndroidTest --tests '*SignOnPasskeyKeyTest*'` on an emulator with a secure lock screen configured; without one, record it as unrun.

- [ ] **Step 5: Commit**

```bash
git add app/src/main/java/org/kysecurity/authenticator/passkeys/SignOnPasskeyKey.kt \
        app/src/androidTest/java/org/kysecurity/authenticator/passkeys/SignOnPasskeyKeyTest.kt
git commit -m "feat: generate the KySignOn passkey key in secure hardware, failing closed"
```

---

### Task 6: A biometric prompt that yields a `Signature`

**Files:**
- Modify: `app/src/main/java/org/kysecurity/authenticator/security/VaultUnlockPrompt.kt`

**Interfaces:**
- Produces: `VaultUnlockPrompt.showForSignature(activity: FragmentActivity, subtitle: String, signature: Signature, onAuthenticated: (Signature) -> Unit, onFailed: (String) -> Unit)`.

There is no test step here: this is pure `BiometricPrompt` plumbing with no logic to assert off-device, and it is exercised by the manual device verification already tracked in `AGENTS.md`. Task 7 is where its behaviour becomes observable.

- [ ] **Step 1: Add the signature variant**

In `VaultUnlockPrompt.kt`, add `import java.security.Signature`, then add this function after `show`:

```kotlin
    /**
     * Authenticates a Keystore [Signature] for one use. Unlike [show] this touches no vault key at
     * all: the KySignOn passkey path must keep working while the password vault is locked or
     * compromised, so it must never reach [VaultKek].
     */
    fun showForSignature(
        activity: FragmentActivity,
        subtitle: String,
        signature: Signature,
        onAuthenticated: (Signature) -> Unit,
        onFailed: (String) -> Unit,
    ) {
        val prompt = BiometricPrompt(
            activity,
            ContextCompat.getMainExecutor(activity),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    onAuthenticated(result.cryptoObject?.signature ?: signature)
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    onFailed(errString.toString())
                }
            },
        )

        val info = BiometricPrompt.PromptInfo.Builder()
            .setTitle("KyAuth")
            .setSubtitle(subtitle)
            .setAllowedAuthenticators(AUTHENTICATORS)
            .build()

        prompt.authenticate(info, BiometricPrompt.CryptoObject(signature))
    }
```

Also update the object's KDoc first line, which currently claims to be the single way to obtain a cipher, to: `Biometric and device-credential prompts. [show] yields a cipher bound to [VaultKek] for the vault keys; [showForSignature] yields an authenticated Keystore signature and touches no vault material.`

- [ ] **Step 2: Run the gate**

Run: `./gradlew test lintDebug assembleDebug compileDebugAndroidTestSources`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add app/src/main/java/org/kysecurity/authenticator/security/VaultUnlockPrompt.kt
git commit -m "feat: add a biometric prompt that authenticates a Keystore signature"
```

---

### Task 7: Enrolment

**Files:**
- Modify: `app/src/main/java/org/kysecurity/authenticator/passkeys/KyAuthCredentialProviderService.kt:69-134` (the `TYPE_PUBLIC_KEY` branch of `buildCreateResponse`)
- Modify: `app/src/main/java/org/kysecurity/authenticator/passkeys/CredentialAuthActivity.kt`

**Interfaces:**
- Consumes: `SignOnPasskey.isSignOnRpId` (Task 1), `SignOnPasskeyRecord` (Task 2), `SignOnPasskeyStore` (Task 3), `SignOnPasskeyKey` (Task 5), `VaultUnlockPrompt.showForSignature` (Task 6).
- Produces: `CredentialAuthActivity.ACTION_CREATE_SIGNON_PASSKEY = "org.kysecurity.authenticator.action.CREATE_SIGNON_PASSKEY"`.

- [ ] **Step 1: Route creation in the service**

In `KyAuthCredentialProviderService.kt`, add these imports:

```kotlin
import org.kysecurity.authenticator.pairing.PairingStore
```

In `buildCreateResponse`, inside the `TYPE_PUBLIC_KEY` branch, immediately after the `DigitalAssetLinks` check and before `val userObj = json.optJSONObject("user")`, insert:

```kotlin
                val isSignOn = SignOnPasskey.isSignOnRpId(rpId, PairingStore(this).account()?.serverUrl)
```

Then change the two lines that build the title, subtitle and action so they read:

```kotlin
                val title = if (isSignOn) {
                    "Create KySignOn Passkey"
                } else if (username.isNotBlank()) {
                    "Create Passkey for $username"
                } else {
                    "Create Passkey"
                }
                val subtitle = if (isSignOn) {
                    "Stays on this device, in secure hardware"
                } else {
                    "Save Passkey for $rpId in KyAuth"
                }
```

and change the action extra to:

```kotlin
                    putExtra(
                        CredentialAuthActivity.EXTRA_ACTION,
                        if (isSignOn) {
                            CredentialAuthActivity.ACTION_CREATE_SIGNON_PASSKEY
                        } else {
                            CredentialAuthActivity.ACTION_CREATE_PASSKEY
                        },
                    )
```

- [ ] **Step 2: Handle the action in the activity**

In `CredentialAuthActivity.kt`, add the imports:

```kotlin
import java.security.Signature
import org.kysecurity.authenticator.pairing.PairingStore
```

Add the constant to the companion object:

```kotlin
        const val ACTION_CREATE_SIGNON_PASSKEY = "org.kysecurity.authenticator.action.CREATE_SIGNON_PASSKEY"
```

In `onCreate`, change the `isCreation` line so the new action still renders the username field and the "Save" button:

```kotlin
        val isCreation = action == ACTION_CREATE_PASSWORD ||
            action == ACTION_CREATE_PASSKEY ||
            action == ACTION_CREATE_SIGNON_PASSKEY
```

and change the `else if (action == ACTION_CREATE_PASSKEY)` branch that adds `usernameInput` to:

```kotlin
        } else if (action == ACTION_CREATE_PASSKEY || action == ACTION_CREATE_SIGNON_PASSKEY) {
```

In `authenticateAndExecute`, branch before the prompt is built — the authenticated object differs, so this cannot be decided later:

```kotlin
    private fun authenticateAndExecute(action: String) {
        if (action == ACTION_CREATE_SIGNON_PASSKEY) {
            createSignOnPasskey()
            return
        }
        val isCreation = action == ACTION_CREATE_PASSWORD || action == ACTION_CREATE_PASSKEY
        VaultUnlockPrompt.show(
            activity = this,
            subtitle = intent.getStringExtra(EXTRA_DISPLAY_TITLE) ?: "Authenticate to proceed",
            onAuthenticated = { cipher -> executeCredentialAction(action, cipher) },
            onFailed = { message ->
                if (isCreation) {
                    Toast.makeText(applicationContext, message, Toast.LENGTH_SHORT).show()
                } else {
                    finishWithCancellation()
                }
            },
        )
    }
```

Add the enrolment itself:

```kotlin
    /**
     * Enrols the KySignOn passkey into secure hardware. Nothing here touches a vault key: that
     * independence is the point, so the factor keeps working when the password vault does not.
     *
     * The new key goes into the spare alias and the stored record is only replaced once the
     * response is built, so a cancelled prompt leaves any existing passkey untouched.
     */
    private fun createSignOnPasskey() {
        val requestJson = intent.getStringExtra(EXTRA_REQUEST_JSON).orEmpty()
        val json = runCatching { JSONObject(requestJson) }.getOrNull()
            ?: return finishWithFailure("Malformed passkey request")
        val rpId = intent.getStringExtra(EXTRA_RP_ID)?.takeIf { it.isNotBlank() }
            ?: return finishWithFailure("Request has no relying party")
        if (RpId.normalize(json.optJSONObject("rp")?.optString("id")) != rpId) {
            return finishWithFailure("Relying party does not match the request")
        }
        if (!SignOnPasskey.isSignOnRpId(rpId, PairingStore(this).account()?.serverUrl)) {
            return finishWithFailure("This relying party is not the paired KySignOn server")
        }
        val challenge = json.optString("challenge").takeIf { it.isNotBlank() }
            ?: return finishWithFailure("Request has no challenge")

        val clientDataJson = if (intent.privilegedClientDataHash() != null) {
            null
        } else {
            val origin = intent.getStringExtra(EXTRA_ORIGIN)?.takeIf { it.isNotBlank() }
                ?: return finishWithFailure("Caller origin is unavailable")
            ClientData.serialize(
                ClientData.TYPE_CREATE,
                challenge,
                origin,
                intent.getStringExtra(EXTRA_CALLER_PACKAGE),
            )
        }

        val store = SignOnPasskeyStore(applicationContext)
        val live = store.record()
        val alias = SignOnPasskeyKey.spareAlias(live?.alias)
        val generated = runCatching { SignOnPasskeyKey.generate(alias) }.getOrElse { error ->
            return finishWithFailure(
                error.message ?: "This device cannot store a KySignOn passkey in secure hardware",
            )
        }
        val signature = SignOnPasskeyKey.signatureFor(alias) ?: run {
            SignOnPasskeyKey.delete(alias)
            return finishWithFailure("The new passkey could not be prepared")
        }

        VaultUnlockPrompt.showForSignature(
            activity = this,
            subtitle = "Create your KySignOn passkey",
            signature = signature,
            onAuthenticated = {
                finishSignOnEnrolment(rpId, json, generated, live, store, clientDataJson)
            },
            onFailed = { message ->
                // Roll back so a cancelled enrolment cannot strand the live key.
                SignOnPasskeyKey.delete(alias)
                Toast.makeText(applicationContext, message, Toast.LENGTH_SHORT).show()
                finishWithCancellation()
            },
        )
    }

    private fun finishSignOnEnrolment(
        rpId: String,
        json: JSONObject,
        generated: SignOnPasskeyKey.Generated,
        live: SignOnPasskeyRecord?,
        store: SignOnPasskeyStore,
        clientDataJson: ByteArray?,
    ) {
        val userObj = json.optJSONObject("user")
        val fallbackUsername = userObj?.optString("name")?.ifBlank { null }
            ?: userObj?.optString("displayName")?.ifBlank { null }
            ?: intent.getStringExtra(EXTRA_USERNAME).orEmpty()
        val username = if (::usernameInput.isInitialized) {
            usernameInput.text.toString().trim()
        } else {
            fallbackUsername
        }

        val userHandleStr = userObj?.optString("id")
        val userHandle = if (!userHandleStr.isNullOrBlank()) {
            runCatching { Base64.decode(userHandleStr, B64_FLAGS) }
                .getOrDefault(userHandleStr.toByteArray(StandardCharsets.UTF_8))
        } else {
            ByteArray(0)
        }

        val credentialId = WebAuthnEngine.generateCredentialId()
        val authData = WebAuthnEngine.buildRegistrationAuthData(
            rpId = rpId,
            signCount = 0,
            credentialId = credentialId,
            cosePublicKey = WebAuthnEngine.encodeCosePublicKey(generated.publicKey),
        )
        val attestationObject = WebAuthnEngine.buildAttestationObject(authData)

        store.save(
            SignOnPasskeyRecord(
                rpId = rpId,
                username = username,
                userHandle = userHandle,
                credentialId = credentialId,
                signCount = 0,
                alias = generated.alias,
                strongBoxBacked = generated.strongBoxBacked,
            ),
        )
        // Only now is the previous key redundant.
        live?.alias?.takeIf { it != generated.alias }?.let(SignOnPasskeyKey::delete)

        val responseJson = JSONObject().apply {
            put("id", b64(credentialId))
            put("rawId", b64(credentialId))
            put("type", "public-key")
            put(
                "response",
                JSONObject().apply {
                    put("attestationObject", b64(attestationObject))
                    if (clientDataJson != null) put("clientDataJSON", b64(clientDataJson))
                },
            )
        }

        val data = Bundle().apply {
            putString("androidx.credentials.BUNDLE_KEY_REGISTRATION_RESPONSE_JSON", responseJson.toString())
        }
        setResult(
            Activity.RESULT_OK,
            Intent().putExtra(
                CredentialProviderService.EXTRA_CREATE_CREDENTIAL_RESPONSE,
                CreateCredentialResponse(data),
            ),
        )
        finish()
    }
```

- [ ] **Step 3: Run the gate**

Run: `./gradlew test lintDebug assembleDebug compileDebugAndroidTestSources`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add app/src/main/java/org/kysecurity/authenticator/passkeys/
git commit -m "feat: enrol the KySignOn passkey into secure hardware instead of the vault"
```

---

### Task 8: Assertion, and enumeration while locked

This is the task the security property actually rests on. `buildGetResponse` currently returns nothing but an "Unlock KyAuth" action whenever the password vault key is absent — which would make every KySignOn sign-in depend on a `VaultKek` unwrap of the password vault, the exact dependency being removed. The local entry must be offered alongside the authentication action.

**Files:**
- Modify: `app/src/main/java/org/kysecurity/authenticator/passkeys/CredentialEntryBuilder.kt`
- Modify: `app/src/main/java/org/kysecurity/authenticator/passkeys/KyAuthCredentialProviderService.kt:47-56` and `:170-195`
- Modify: `app/src/main/java/org/kysecurity/authenticator/passkeys/CredentialUnlockActivity.kt:55`
- Modify: `app/src/main/java/org/kysecurity/authenticator/passkeys/CredentialAuthActivity.kt`

**Interfaces:**
- Consumes: everything from Tasks 1–6.
- Produces:
  - `CredentialEntryBuilder.build(context, request, entries, signOnPasskey: SignOnPasskeyRecord?, signOnServerUrl: String?, authenticationAction: Action?)`
  - `CredentialAuthActivity.ACTION_GET_SIGNON_PASSKEY = "org.kysecurity.authenticator.action.GET_SIGNON_PASSKEY"`

- [ ] **Step 1: Extend the entry builder**

In `CredentialEntryBuilder.kt`, add `import android.service.credentials.Action`, then change `build` to:

```kotlin
    fun build(
        context: Context,
        request: BeginGetCredentialRequest,
        entries: List<PasswordEntry>,
        signOnPasskey: SignOnPasskeyRecord?,
        signOnServerUrl: String?,
        authenticationAction: Action? = null,
    ): BeginGetCredentialResponse {
        val callingAppInfo = request.callingAppInfo
        val origin = callingAppInfo?.origin
        val webOriginHost = ClientData.webOriginHost(origin)
        val callerPackage = callingAppInfo?.packageName
        val callerOrigin = origin ?: ClientData.apkKeyHashOrigin(callingAppInfo?.signingInfo)

        val responseBuilder = BeginGetCredentialResponse.Builder()
        authenticationAction?.let(responseBuilder::addAuthenticationAction)
        var requestCode = 1000
        for (option in request.beginGetCredentialOptions) {
            when (option.type) {
                TYPE_PUBLIC_KEY, TYPE_PUBLIC_KEY_ANDX ->
                    addPasskeyEntries(
                        context, option, entries, signOnPasskey, signOnServerUrl, webOriginHost,
                        callerPackage, callerOrigin, origin, callingAppInfo?.signingInfo,
                        responseBuilder, requestCode++,
                    )
                TYPE_PASSWORD, TYPE_PASSWORD_ANDX ->
                    addPasswordEntries(
                        context, option, entries, webOriginHost ?: callerPackage,
                        responseBuilder, requestCode++,
                    )
            }
        }
        return responseBuilder.build()
    }
```

Change `addPasskeyEntries`'s parameter list to match, adding `signOnPasskey: SignOnPasskeyRecord?` and `signOnServerUrl: String?` after `entries`. Then, inside it, immediately before the existing `for (entry in entries.filter { ... })` loop, insert the local entry:

```kotlin
        // The hardware-backed KySignOn passkey. Offered without any vault key, so it survives the
        // password vault being locked, compromised, or in recovery.
        if (signOnPasskey != null && signOnPasskey.rpId == rpId) {
            val title = signOnPasskey.username.ifBlank { rpId }
            val intent = Intent(context, CredentialAuthActivity::class.java).apply {
                putExtra(CredentialAuthActivity.EXTRA_ACTION, CredentialAuthActivity.ACTION_GET_SIGNON_PASSKEY)
                putExtra(CredentialAuthActivity.EXTRA_REQUEST_JSON, requestJson)
                putExtra(CredentialAuthActivity.EXTRA_RP_ID, rpId)
                putExtra(CredentialAuthActivity.EXTRA_ORIGIN, callerOrigin)
                putExtra(CredentialAuthActivity.EXTRA_CALLER_PACKAGE, callerPackage)
                putExtra(CredentialAuthActivity.EXTRA_CLIENT_DATA_HASH, clientDataHash)
                putExtra(CredentialAuthActivity.EXTRA_DISPLAY_TITLE, "Sign in to KySignOn")
                putExtra(CredentialAuthActivity.EXTRA_DISPLAY_SUBTITLE, "$title (Passkey • this device)")
            }
            responseBuilder.addCredentialEntry(
                CredentialSliceHelper.createGetCredentialEntry(
                    context = context,
                    option = option,
                    title = title,
                    subtitle = "Passkey • this device",
                    fillIntent = intent,
                    requestCode = requestCode + 500,
                ),
            )
        }
```

and change the vault loop's filter so a stranded passkey is refused:

```kotlin
        for (entry in entries.filter { DomainMatcher.matchesPasskey(it, rpId) }) {
            val passkey = entry.passkey ?: continue
            // A KySignOn passkey in the synced vault is not offered: it must be re-enrolled into
            // secure hardware. The Passwords tab badges it so the user knows why.
            if (SignOnPasskey.isSignOnRpId(passkey.rpId, signOnServerUrl)) continue
```

- [ ] **Step 2: Offer the local entry while locked**

In `KyAuthCredentialProviderService.kt`, add `import org.kysecurity.authenticator.pairing.PairingStore` and replace `buildGetResponse` and `lockedResponse` with:

```kotlin
    private fun buildGetResponse(request: BeginGetCredentialRequest): BeginGetCredentialResponse {
        val signOnPasskey = SignOnPasskeyStore(this).record()
        val serverUrl = PairingStore(this).account()?.serverUrl
        val vaultKey = AppLockManager.getPasswordVaultKey()
        val entries = vaultKey?.let {
            runCatching {
                KdbxPasswordVault.loadEntries(File(filesDir, KyAuthAutofillService.VAULT_FILE_NAME), it)
            }.getOrNull()
        }
        // While the vault is unavailable the KySignOn passkey is still offered: it needs no vault
        // key, and routing it through "Unlock KyAuth" would make KySignOn MFA depend on the
        // password vault, which is exactly what this design removes.
        return CredentialEntryBuilder.build(
            context = this,
            request = request,
            entries = entries.orEmpty(),
            signOnPasskey = signOnPasskey,
            signOnServerUrl = serverUrl,
            authenticationAction = if (entries == null) unlockAction() else null,
        )
    }

    /** An invitation to authenticate; touches no vault material. */
    private fun unlockAction(): Action {
        val pendingIntent = PendingIntent.getActivity(
            this,
            3001,
            Intent(this, CredentialUnlockActivity::class.java),
            PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val spec = SliceSpec("kyauth", 1)
        val slice = Slice.Builder(Uri.parse("kyauth://unlock"), spec)
            .addAction(
                pendingIntent,
                Slice.Builder(Uri.parse("kyauth://unlock/action"), spec).build(),
                null,
            )
            .addText("Unlock KyAuth", null, listOf(Slice.HINT_TITLE))
            .addText("Authenticate to see your credentials", null, listOf(Slice.HINT_SUMMARY))
            .build()
        return Action(slice)
    }
```

In `CredentialUnlockActivity.kt`, add `import org.kysecurity.authenticator.pairing.PairingStore` and update the one `CredentialEntryBuilder.build` call. The local passkey is passed as null because the service already surfaced it alongside the authentication action, and offering it twice would show the user a duplicate:

```kotlin
                CredentialEntryBuilder.build(
                    context = this,
                    request = request,
                    entries = entries,
                    signOnPasskey = null,
                    signOnServerUrl = PairingStore(this).account()?.serverUrl,
                )
```

- [ ] **Step 3: Sign the assertion**

In `CredentialAuthActivity.kt`, add to the companion object:

```kotlin
        const val ACTION_GET_SIGNON_PASSKEY = "org.kysecurity.authenticator.action.GET_SIGNON_PASSKEY"
```

In `authenticateAndExecute`, add the second early branch above the existing create branch:

```kotlin
        if (action == ACTION_GET_SIGNON_PASSKEY) {
            getSignOnPasskey()
            return
        }
```

Add the handler:

```kotlin
    /**
     * Asserts with the hardware-backed KySignOn passkey. Deliberately never calls
     * [AppLockManager.useVaultKeys]: the private key is non-exportable and there is no vault key
     * to unwrap, so this path is unaffected by the password vault's state.
     */
    private fun getSignOnPasskey() {
        val store = SignOnPasskeyStore(applicationContext)
        val record = store.record() ?: return finishWithFailure("No KySignOn passkey on this device")

        val requestJson = intent.getStringExtra(EXTRA_REQUEST_JSON).orEmpty()
        val json = runCatching { JSONObject(requestJson) }.getOrNull()
            ?: return finishWithFailure("Malformed passkey request")
        val rpId = intent.getStringExtra(EXTRA_RP_ID)?.takeIf { it.isNotBlank() }
            ?: return finishWithFailure("Request has no relying party")
        if (RpId.normalize(json.optString("rpId")) != rpId) {
            return finishWithFailure("Relying party does not match the request")
        }
        if (record.rpId != rpId) {
            return finishWithFailure("This passkey does not belong to $rpId")
        }
        val challenge = json.optString("challenge").takeIf { it.isNotBlank() }
            ?: return finishWithFailure("Request has no challenge")

        val callerHash = intent.privilegedClientDataHash()
        val clientDataJson = if (callerHash != null) {
            null
        } else {
            val origin = intent.getStringExtra(EXTRA_ORIGIN)?.takeIf { it.isNotBlank() }
                ?: return finishWithFailure("Caller origin is unavailable")
            ClientData.serialize(
                ClientData.TYPE_GET,
                challenge,
                origin,
                intent.getStringExtra(EXTRA_CALLER_PACKAGE),
            )
        }
        val clientDataHash = callerHash ?: WebAuthnEngine.sha256(requireNotNull(clientDataJson))

        val signature = SignOnPasskeyKey.signatureFor(record.alias)
            ?: return finishWithFailure("The KySignOn passkey key is unavailable")

        VaultUnlockPrompt.showForSignature(
            activity = this,
            subtitle = "Sign in to KySignOn",
            signature = signature,
            onAuthenticated = { authenticated ->
                val newSignCount = record.signCount + 1
                val authData = WebAuthnEngine.buildAssertionAuthData(record.rpId, newSignCount)
                val signed = runCatching {
                    WebAuthnEngine.signAssertion(authenticated, authData, clientDataHash)
                }.getOrNull()
                if (signed == null) {
                    finishWithFailure("Could not sign the challenge")
                    return@showForSignature
                }

                store.save(record.copy(signCount = newSignCount))

                val responseJson = JSONObject().apply {
                    put("id", b64(record.credentialId))
                    put("rawId", b64(record.credentialId))
                    put("type", "public-key")
                    put(
                        "response",
                        JSONObject().apply {
                            put("authenticatorData", b64(authData))
                            put("signature", b64(signed))
                            if (record.userHandle.isNotEmpty()) put("userHandle", b64(record.userHandle))
                            if (clientDataJson != null) put("clientDataJSON", b64(clientDataJson))
                        },
                    )
                }
                val data = Bundle().apply {
                    putString("androidx.credentials.BUNDLE_KEY_AUTHENTICATION_RESPONSE_JSON", responseJson.toString())
                }
                setResult(
                    Activity.RESULT_OK,
                    Intent().putExtra(
                        CredentialProviderService.EXTRA_GET_CREDENTIAL_RESPONSE,
                        GetCredentialResponse(Credential(TYPE_PUBLIC_KEY_CREDENTIAL, data)),
                    ),
                )
                finish()
            },
            onFailed = { finishWithCancellation() },
        )
    }
```

Finally, in `onCreate`, the auto-prompt for retrieval already covers this action because `isCreation` is false for it — no change needed there.

- [ ] **Step 4: Run the gate**

Run: `./gradlew test lintDebug assembleDebug compileDebugAndroidTestSources`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add app/src/main/java/org/kysecurity/authenticator/passkeys/
git commit -m "feat: assert the KySignOn passkey without ever unlocking the password vault"
```

---

### Task 9: Settings, unpair, and the stranded-passkey badge

**Files:**
- Modify: `app/src/main/java/org/kysecurity/authenticator/MainActivity.kt:1046` (badge), `:1791` (settings tab), `:1838-1853` (unpair)
- Modify: `app/src/main/res/values/strings.xml`

**Interfaces:**
- Consumes: `SignOnPasskey`, `SignOnPasskeyStore`, `SignOnPasskeyKey`, `SignOnPasskeyRecord`.

- [ ] **Step 1: Add the strings**

In `app/src/main/res/values/strings.xml`, add:

```xml
    <string name="signon_passkey_title">KySignOn Passkey</string>
    <string name="signon_passkey_strongbox">Stored in this device\'s secure element (StrongBox). It does not sync and does not leave this device.</string>
    <string name="signon_passkey_tee">Stored in this device\'s secure hardware. It does not sync and does not leave this device.</string>
    <string name="signon_passkey_none">No KySignOn passkey on this device. Enrol one from KySignOn to use it as a second factor.</string>
    <string name="signon_passkey_remove">Remove KySignOn Passkey</string>
    <string name="signon_passkey_restranded">Re-enroll on KySignOn</string>
```

- [ ] **Step 2: Badge stranded passkeys in the Passwords tab**

In `MainActivity.kt`, add the imports (`PairingStore` may already be imported — check before adding it):

```kotlin
import org.kysecurity.authenticator.pairing.PairingStore
import org.kysecurity.authenticator.passkeys.SignOnPasskey
import org.kysecurity.authenticator.passkeys.SignOnPasskeyKey
import org.kysecurity.authenticator.passkeys.SignOnPasskeyStore
```

At line 1046, replace `if (entry.isPasskey) {` with a block that picks the right badge. Resolve the paired server URL explicitly rather than relying on a `store` field being in scope at this point in the file:

```kotlin
            val pairedServerUrl = PairingStore(this).account()?.serverUrl
            val stranded = entry.passkey?.let {
                SignOnPasskey.isSignOnRpId(it.rpId, pairedServerUrl)
            } == true
            if (entry.isPasskey) {
                headerRow.addView(TextView(this).apply {
                    text = if (stranded) {
                        getString(R.string.signon_passkey_restranded)
                    } else {
                        getString(R.string.passkey_badge)
                    }
                    textSize = 11f
                    typeface = Typeface.DEFAULT_BOLD
                    val accent = if (stranded) R.color.ky_error else R.color.ky_cyan
                    setTextColor(ThemeManager.color(context, accent))
                    background = GradientDrawable().apply {
                        setColor(ThemeManager.color(context, R.color.ky_surface_elevated))
                        cornerRadius = dp(6).toFloat()
                        setStroke(dp(1), ThemeManager.color(context, accent))
                    }
                    setPadding(dp(8), dp(2), dp(8), dp(2))
                })
            }
```

- [ ] **Step 3: Add the Settings section**

In `renderSettingsTab`, after `providerSection` is added and before the KyPasswords section, insert:

```kotlin
        val signOnPasskeySection = settingsCard()
        signOnPasskeySection.addView(title(getString(R.string.signon_passkey_title)))
        val signOnRecord = SignOnPasskeyStore(this).record()
        if (signOnRecord == null) {
            signOnPasskeySection.addView(message(getString(R.string.signon_passkey_none)))
        } else {
            val backing = if (signOnRecord.strongBoxBacked) {
                R.string.signon_passkey_strongbox
            } else {
                R.string.signon_passkey_tee
            }
            signOnPasskeySection.addView(
                message("${signOnRecord.username.ifBlank { signOnRecord.rpId }}\n${getString(backing)}"),
            )
            val btnRemove = secondaryButton(getString(R.string.signon_passkey_remove)).apply {
                setTextColor(ThemeManager.color(context, R.color.ky_error))
                setOnClickListener {
                    AlertDialog.Builder(this@MainActivity)
                        .setTitle(getString(R.string.signon_passkey_remove))
                        .setMessage(
                            "This passkey only exists on this device and cannot be recovered. " +
                                "You will need your KySignOn recovery codes or an admin reset to " +
                                "sign in without it.",
                        )
                        .setNegativeButton("Cancel", null)
                        .setPositiveButton("Remove") { _, _ ->
                            SignOnPasskeyKey.deleteAll()
                            SignOnPasskeyStore(this@MainActivity).clear()
                            renderContent()
                        }
                        .showKyDialog()
                }
            }
            signOnPasskeySection.addView(btnRemove, fullWidthParams())
        }
        sections.add(signOnPasskeySection)
```

- [ ] **Step 4: Clear the passkey on unpair**

In the KySignOn unpair handler at line 1848, change the positive-button body to:

```kotlin
                    .setPositiveButton("Unpair") { _, _ ->
                        store.clear()
                        // A passkey for a server we are no longer paired to is dead weight, and
                        // its key must not outlive the pairing.
                        SignOnPasskeyKey.deleteAll()
                        SignOnPasskeyStore(this@MainActivity).clear()
                        lockSensitiveState()
                        renderContent()
                    }
```

and change the dialog message to warn about it:

```kotlin
                    .setMessage(
                        "Are you sure you want to unpair this device from KySignOn? " +
                            "This also deletes the KySignOn passkey held on this device.",
                    )
```

- [ ] **Step 5: Run the gate**

Run: `./gradlew test lintDebug assembleDebug compileDebugAndroidTestSources`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add app/src/main/java/org/kysecurity/authenticator/MainActivity.kt \
        app/src/main/res/values/strings.xml
git commit -m "feat: manage the KySignOn passkey in Settings and badge stranded vault passkeys"
```

---

### Task 10: Documentation

`AGENTS.md:106` currently records the opposite decision for this case and will mislead the next reader if left alone.

**Files:**
- Modify: `AGENTS.md`
- Modify: `prompt.md:22`

- [ ] **Step 1: Update the product contract**

In `AGENTS.md`, after the existing line 27 about `passwords_vault.kdbx`, add:

```markdown
- A passkey whose RP ID is the paired KySignOn server's host is the exception: its private key is
  generated in AndroidKeyStore (StrongBox where available, TEE otherwise), is non-exportable, and
  never enters a KDBX vault or any synced artifact. Only its metadata is stored, in
  `SignOnPasskeyStore`. The assertion path never calls `AppLockManager.useVaultKeys`, so KySignOn
  MFA keeps working while the password vault is locked, compromised, or in recovery. The Credential
  Provider therefore offers this one entry while KyAuth is locked, alongside the unlock action.
  Losing the device means falling back to KySignOn recovery codes or an admin MFA reset.
```

- [ ] **Step 2: Correct the outstanding-work entry**

In `AGENTS.md`, replace the "Passkey private keys are exportable" bullet with:

```markdown
- **Non-KySignOn passkey private keys are exportable.** Deliberate: they live in the KDBX vault so
  they sync and restore, as other password managers do. Protection comes from the
  authentication-bound vault key. The KySignOn login passkey is the exception and is
  hardware-resident; see the product contract above.
- **KySignOn passkey attestation.** The key is hardware-backed, but `fmt` is still `none`, so the
  server has only the client's word for it. `setAttestationChallenge` plus a verifier in
  `kysignon-server` would make it evidence.
- **KySignOn passkey device verification.** The per-use biometric prompt, StrongBox fallback to TEE,
  and locked-state enumeration need manual verification on real hardware.
```

Also add the two new files to the `passkeys/` line in the project layout section:

```markdown
- `passkeys/`: FIDO2 WebAuthn crypto engine, `ClientData` (CollectedClientData), `RpId` validation,
  `SignOnPasskey` routing plus its hardware key and metadata store, CredentialProviderService, entry
  builder, slice builder, unlock activity, and auth activity.
```

- [ ] **Step 3: Extend the sync rule**

In `prompt.md`, replace line 22 with:

```markdown
- KyPasswords sync is a later feature. It must not sync TOTP data, and it must not sync the KySignOn
  login passkey, whose key is hardware-resident and device-local by design.
```

- [ ] **Step 4: Run the gate and commit**

Run: `./gradlew test lintDebug assembleDebug compileDebugAndroidTestSources`
Expected: PASS.

```bash
git add AGENTS.md prompt.md
git commit -m "docs: record the KySignOn passkey's hardware-resident placement"
```

---

## Deviations from the spec

- The spec said the instrumented tests would be added to `DeviceSecurityTest`. They are separate files (`SignOnPasskeyKeyTest`, `SignOnPasskeyStoreTest`) instead, so each has its own focused teardown.
- The spec did not mention the two alternating Keystore aliases. They were added in Task 5 because a single alias makes enrolment destructive on a cancelled prompt.
- The spec named one alias, `kyauth_signon_passkey_v1`. The implementation uses `kyauth_signon_passkey_a` / `_b`. Both still match `SecurityWipe.isAppAlias`.
