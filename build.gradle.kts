import org.jetbrains.kotlin.cli.jvm.main

plugins {
    kotlin("jvm") version "2.0.0-RC1"
    id("org.graalvm.buildtools.native") version "0.10.1"
}

repositories {
    mavenCentral()
    maven(url="https://repo.gradle.org/gradle/libs-releases")
}

dependencies {
    implementation("org.gradle:gradle-tooling-api:8.7")
}

graalvmNative {
    binaries.configureEach {
        javaLauncher = javaToolchains.launcherFor {
            languageVersion = JavaLanguageVersion.of(21)
            vendor = JvmVendorSpec.matching("Oracle Corporation")
        }
        if (name == "main") {
            mainClass = "bug.BugKt"
        }
        buildArgs("-H:+BuildReport")
    }
}