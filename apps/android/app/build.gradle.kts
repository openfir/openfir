// SPDX-License-Identifier: Apache-2.0
plugins {
    id("com.android.application") version "8.6.0"
    id("org.jetbrains.kotlin.android") version "2.0.20"
}

android {
    namespace = "io.openfir.app"
    compileSdk = 35

    val envNdk = System.getenv("ANDROID_NDK_HOME")?.takeIf { it.isNotBlank() }
        ?: System.getenv("ANDROID_NDK_ROOT")?.takeIf { it.isNotBlank() }
    if (envNdk != null) {
        val ndkDir = file(envNdk)
        val propsFile = file("$envNdk/source.properties")
        val detectedRev = if (propsFile.exists()) {
            propsFile.readLines()
                .firstOrNull { it.trim().startsWith("Pkg.Revision") }
                ?.substringAfter("=")
                ?.trim()
        } else {
            null
        } ?: ndkDir.name
        ndkVersion = detectedRev
        ndkPath = envNdk
    }

    defaultConfig {
        applicationId = "io.openfir.app"
        minSdk = 26
        targetSdk = 35
        versionCode = 200
        versionName = "2.0.0"
        ndk {
            abiFilters += listOf("arm64-v8a", "x86_64")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
        }
    }

    sourceSets {
        getByName("main") {
            jniLibs.srcDirs("../../../dist/android/jniLibs")
        }
    }
}
// Zero third-party dependencies block: uses strictly Android Platform SDK (android.*) + NDK!
