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
}

dependencies {
    implementation("androidx.core:core-ktx:1.10.1")
    implementation("androidx.appcompat:appcompat:1.6.1")
    implementation("com.google.android.material:material:1.10.0")
    implementation("androidx.biometric:biometric:1.1.0")
    implementation("androidx.security:security-crypto:1.1.0")
    implementation("com.google.android.gms:play-services-code-scanner:16.1.0")
    implementation("com.google.firebase:firebase-messaging:24.1.2")
    implementation("app.keemobile:kotpass:0.13.0")

    testImplementation("junit:junit:4.13.2")
    testImplementation("org.json:json:20231013")
}
