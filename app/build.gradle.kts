plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "dev.awaretun"
    compileSdk = 36

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    defaultConfig {
        applicationId = "dev.awaretun"
        minSdk = 29
        targetSdk = 35
        versionCode = 1
        versionName = "0.1.0"
        ndk {
            abiFilters += listOf("arm64-v8a")
        }
    }
}

val buildRustAndroid by tasks.registering(Exec::class) {
    workingDir(rootProject.file("native"))
    commandLine(
        "cargo", "ndk", "-P", "29",
        "-t", "arm64-v8a",
        "-o", layout.projectDirectory.dir("src/main/jniLibs").asFile.absolutePath,
        "build", "--release"
    )
}

tasks.named("preBuild").configure {
    dependsOn(buildRustAndroid)
}
