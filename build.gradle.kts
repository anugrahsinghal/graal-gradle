import kotlin.concurrent.thread

plugins {
    kotlin("jvm") version "2.0.0-RC1"
    id("org.graalvm.buildtools.native") version "0.10.1"
    application
}

repositories {
    mavenCentral()
    maven(url = "https://repo.gradle.org/gradle/libs-releases")
}

dependencies {
    implementation("org.gradle:gradle-tooling-api:8.7")
}

val MAIN_CLASS = "bug.BugKt"
graalvmNative {
    binaries.configureEach {
        javaLauncher =
            javaToolchains.launcherFor {
                languageVersion = JavaLanguageVersion.of(21)
                vendor = JvmVendorSpec.matching("Oracle Corporation")
            }
        if (name == "main") {
            mainClass = MAIN_CLASS
        }
        buildArgs("-H:+BuildReport")
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
                "/Users/${System.getProperty("user.name")}/Library/Java/JavaVirtualMachines/graalvm-jdk-21.0.2+13.1/Contents/Home/bin/java",
                "-agentlib:native-image-agent=config-output-dir=build/trace-metadata",
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
