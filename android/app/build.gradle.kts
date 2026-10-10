plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

// The protocol core is Go (../core). It is built for every shipped ABI before
// the APK is packaged. Pass -PskipGoCore=true to package prebuilt binaries
// already present in src/main/jniLibs.
val buildGoCore by tasks.registering(Exec::class) {
    description = "Builds the NKNGuard Go core into src/main/jniLibs"
    workingDir = rootProject.file("core")
    commandLine("sh", "build.sh", project.file("src/main/jniLibs").absolutePath)
    inputs.dir(rootProject.file("../internal"))
    inputs.dir(rootProject.file("../pkg"))
    inputs.dir(rootProject.file("core"))
    outputs.dir(project.file("src/main/jniLibs"))
    onlyIf { !project.hasProperty("skipGoCore") }
}

android {
    namespace = "io.github.viperboss.nknguard"
    compileSdk = 35

    defaultConfig {
        applicationId = "io.github.viperboss.nknguard"
        minSdk = 26
        targetSdk = 35
        versionCode = 16
        versionName = "0.2.16-preview.1"
        ndk {
            abiFilters += listOf("arm64-v8a", "armeabi-v7a", "x86_64")
        }
    }

    buildTypes {
        getByName("debug") {
            applicationIdSuffix = ".debug"
            versionNameSuffix = "-debug"
        }
        getByName("release") {
            isMinifyEnabled = false
        }
    }

    packaging {
        jniLibs {
            // The core is an executable. Legacy packaging extracts it into
            // the native library directory, the one place Android lets an app
            // execute its own files.
            useLegacyPackaging = true
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    lint {
        abortOnError = false
    }
}

dependencies {
    // Pure-Java QR decoder from Maven Central; no Google Play services, so
    // scanning works on phones sold in mainland China.
    implementation("com.google.zxing:core:3.5.3")
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.json:json:20240303")
}

tasks.named("preBuild") {
    dependsOn(buildGoCore)
}
