plugins {
    id("com.android.application")
}

android {
    namespace = "org.kysecurity.authenticator"
    compileSdk = 36

    defaultConfig {
        applicationId = "org.kysecurity.authenticator"
        minSdk = 31
        targetSdk = 36
        versionCode = 1
        versionName = "0.1.0"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        buildConfigField("boolean", "ALLOW_SCREENSHOTS", "false")
    }

    buildFeatures { buildConfig = true }

    buildTypes {
        debug {
            // Debug builds run in an emulator/IDE capture surface. Release remains secure by default.
            buildConfigField("boolean", "ALLOW_SCREENSHOTS", "true")
        }
        release {
            isMinifyEnabled = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    packaging {
        resources {
            // BouncyCastle ships ~1.2 MB of post-quantum lookup tables and cert-path message
            // bundles as resources. R8 shrinks classes, not resources, so these ride along
            // untouched — measured as the entire APK growth from adding bcprov. Nothing here
            // uses post-quantum algorithms or CertPathReviewer.
            excludes += "/org/bouncycastle/pqc/**"
            excludes += "/org/bouncycastle/x509/CertPathReviewerMessages*.properties"
        }
    }
}

dependencies {
    implementation("androidx.core:core-ktx:1.18.0")
    implementation("androidx.appcompat:appcompat:1.8.0")
    implementation("com.google.android.material:material:1.14.0")
    implementation("androidx.biometric:biometric:1.1.0")
    implementation("androidx.security:security-crypto:1.1.0")
    implementation("com.google.android.gms:play-services-code-scanner:16.1.0")
    implementation("com.google.firebase:firebase-messaging:25.1.2")
    implementation("app.keemobile:kotpass:0.13.0")
    // Argon2id for KyPasswords envelopes. kotpass bundles Argon2 but keeps it `internal`, and a
    // native (NDK) Argon2 would push the interop vector test into androidTest, which CI does not
    // run. BouncyCastle's lightweight API is pure Java, so the vector is checked on every push.
    implementation("org.bouncycastle:bcprov-jdk18on:1.85")
    implementation("com.google.guava:guava:33.7.1-android")

    testImplementation("junit:junit:4.13.2")
    testImplementation("org.json:json:20231013")
    androidTestImplementation("androidx.test:core:1.7.0")
    androidTestImplementation("androidx.test.ext:junit:1.3.0")
    androidTestImplementation("androidx.test:runner:1.7.0")
}
