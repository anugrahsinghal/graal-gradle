import kotlin.concurrent.thread

tasks.register("getHomeDir") {
    println("Gradle home dir: ${gradle.gradleHomeDir}")
}

plugins {
    kotlin("jvm") version "2.0.0-RC1"
//    id("org.graalvm.buildtools.native") version "0.10.1"
    application
    `java-gradle-plugin`
    `java-library`
    id("org.graalvm.buildtools.native") version "0.10.2"
}

repositories {
    mavenCentral()
    maven(url = "https://repo.gradle.org/gradle/libs-releases")
}
val javaVersion = 21

kotlin {
    jvmToolchain(javaVersion)
}
java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(javaVersion))
    }
}
dependencies {
    implementation(gradleApi())
    // https://mvnrepository.com/artifact/org.gradle/gradle-core
    implementation("org.gradle:gradle-core:6.1.1")
}

val MAIN_CLASS = "bug.BugKt"
graalvmNative {
    useArgFile = false
    toolchainDetection = true
    agent {
        defaultMode = "standard"
        enabled = true

        builtinCallerFilter.set(true)
        builtinHeuristicFilter.set(true)
        trackReflectionMetadata.set(true)

        metadataCopy {
            inputTaskNames.add("test") // Tasks previously executed with the agent attached.
            outputDirectories.add("src/main/resources/META-INF/native-image/") // Replace <groupId> and <artifactId> with GAV coordinates of your project
            mergeWithExisting.set(true) // Instead of copying, merge with existing metadata in the output directories.
        }

    }
    binaries {
        named("main") {
            mainClass = MAIN_CLASS
            imageName = "myapp"
            javaLauncher = javaToolchains.launcherFor {
                languageVersion.set(JavaLanguageVersion.of(javaVersion))
                // vendor = JvmVendorSpec.matching("Oracle Corporation")
            }
            richOutput = true
//            useFatJar = true
        }
        all {
            excludeConfig.put("", listOf(""))
            resources.autodetect()
            sharedLibrary = false
            buildArgs("--verbose")
            buildArgs("-H:+BuildReport") // not available in 17 probably
            buildArgs("--report-unsupported-elements-at-runtime")
            // buildArgs("-H:IncludeResources=\".*.xml|.*.conf\"")
            buildArgs("-H:-AddAllFileSystemProviders")
            buildArgs("--strict-image-heap")
            buildArgs(
                "--initialize-at-build-time=" +
                        "org.gradle.internal.impldep.org.bouncycastle," +
                        "org.gradle.internal.impldep.net.i2p.crypto.eddsa.EdDSASecurityProvider"
            )
            buildArgs(
                "--initialize-at-run-time=" +
                        "org.gradle.internal.impldep.org.bouncycastle.jcajce.provider.drbg.DRBG\$Default," +
                        "org.gradle.internal.impldep.org.bouncycastle.jcajce.provider.drbg.DRBG\$NonceAndIV," +
                        "org.gradle.internal.impldep.org.bouncycastle.crypto.CryptoServicesRegistrar"
            )
        }

    }

}
application {
    mainClass = MAIN_CLASS
}

tasks.register("traceMetadata") {
    dependsOn("installDist")
    doLast {
        val p =
            ProcessBuilder(
//                "/Users/${System.getProperty("user.name")}/.sdkman/candidates/java/17.0.9-graalce/bin/java",
                "/Users/${System.getProperty("user.name")}/.sdkman/candidates/java/21.0.3-graal/bin/java",
                "-agentlib:native-image-agent=config-merge-dir=/Users/${System.getProperty("user.name")}/personal/graal-8760/src/main/resources/META-INF/native-image",
                "-cp",
                "build/libs/graal-8760.jar:build/install/graal-8760/lib/*",
                MAIN_CLASS
            )
                .start()
        val t1 = thread {
            p.errorStream.transferTo(System.err)
        }
        val t2 = thread {
            p.inputStream.transferTo(System.out)
        }
        val result = p.waitFor()
        t1.join()
        t2.join()
        if (result != 0) {
            error("non-zero")
        }
    }
}

tasks.withType(Jar::class) {
    exclude("**/META-INF/*.SF")
    exclude("**/META-INF/*.DSA")
    exclude("**/META-INF/*.RSA")
}


