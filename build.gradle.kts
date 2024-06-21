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
}

val MAIN_CLASS = "bug.BugKt"
graalvmNative {
    useArgFile = false
    toolchainDetection = true
    agent {
        defaultMode = "standard"
        enabled = true
        modes {
            standard {
            }
            conditional {
                userCodeFilterPath.set("path-to-filter.json") // Path to a filter file that determines classes which will be used in the metadata conditions.
                extraFilterPath.set("path-to-another-filter.json") // Optional, extra filter used to further filter the collected metadata.
            }
            // The direct agent mode allows users to directly pass options to the agent.
            direct {
                // {output_dir} is a special string expanded by the plugin to where the agent files would usually be output.
                options.add("config-output-dir={output_dir}")
                options.add("experimental-configuration-with-origins")
            }
        }
//        callerFilterFiles.from("filter.json")
//        accessFilterFiles.from("filter.json")
        builtinCallerFilter.set(true)
        builtinHeuristicFilter.set(true)
//        enableExperimentalPredefinedClasses.set(false)
//        enableExperimentalUnsafeAllocationTracing.set(false)
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
//tasks.named("",Jar::class) {
//
//}

tasks.withType(Jar::class) {
//    from("collectReachabilityMetadata")
    exclude("**/META-INF/*.SF")
    exclude("**/META-INF/*.DSA")
    exclude("**/META-INF/*.RSA")
}
//    manifest {
//        attributes["Manifest-Version"] = "1.0"
//        attributes["Main-Class"] = MAIN_CLASS
//        attributes["Dependencies"] =
//            configurations.compileClasspath.get().files.joinToString(" ") { it.canonicalPath }
//        attributes["Class-Path"] =
//            configurations.compileClasspath.get().files.joinToString(" ") { it.canonicalPath }
////        doFirst {
////            manifest.
////        }
//    }
//}

/*
~/personal/graal-8760 git:[master]
        ./gradlew nativeCompile

> Task :nativeCompile
[native-image-plugin] GraalVM Toolchain detection is enabled
        [native-image-plugin] GraalVM uses toolchain detection. Selected:
[native-image-plugin]    - language version: 17
[native-image-plugin]    - vendor: GraalVM Community
        [native-image-plugin]    - runtime version: 17.0.9+9-jvmci-23.0-b22
[native-image-plugin] Native Image executable path: /Users/anugrah.singhal/.sdkman/candidates/java/17.0.9-graalce/lib/svm/bin/native-image
========================================================================================================================
GraalVM Native Image: Generating 'graal-8760' (shared library)...
========================================================================================================================
For detailed information and explanations on the build output, visit:
https://github.com/oracle/graal/blob/master/docs/reference-manual/native-image/BuildOutput.md
------------------------------------------------------------------------------------------------------------------------
Warning: Could not resolve class org.h2.message.TraceWriterAdapter for reflection configuration. Reason: java.lang.ClassNotFoundException: org.h2.message.TraceWriterAdapter.
Warning: Could not resolve class org.h2.tools.GUIConsole for reflection configuration. Reason: java.lang.ClassNotFoundException: org.h2.tools.GUIConsole.
Warning: Could not resolve class com.google.common.collect.ImmutableList$SerializedForm for reflection configuration. Reason: java.lang.ClassNotFoundException: com.google.common.collect.ImmutableList$SerializedForm.
        Warning: Method java.io.Serializable.getChildren() not found.
Warning: Method java.io.Serializable.getGroup() not found.
Warning: Method java.io.Serializable.getName() not found.
Warning: Method java.io.Serializable.getPath() not found.
Warning: Method java.io.Serializable.getProject() not found.
Warning: Method java.io.Serializable.getProjectDirectory() not found.
Warning: Method java.io.Serializable.getTasks() not found.
Warning: Method java.io.Serializable.projectPluginMap() not found.
Warning: Method java.io.Serializable.projectToExternalDependencyPaths() not found.
Warning: Method java.io.Serializable.projectToInternalDependencies() not found.
Warning: Method java.lang.Object.getArguments() not found.
Warning: Method java.lang.Object.getBuildLogLevel() not found.
Warning: Method java.lang.Object.getBuildProgressListener() not found.
Warning: Method java.lang.Object.getChildren() not found.
Warning: Method java.lang.Object.getConsumerVersion() not found.
Warning: Method java.lang.Object.getDaemonBaseDir() not found.
Warning: Method java.lang.Object.getDaemonMaxIdleTimeValue() not found.
Warning: Method java.lang.Object.getEnvironmentVariables() not found.
Warning: Method java.lang.Object.getGradleUserHomeDir() not found.
Warning: Method java.lang.Object.getGroup() not found.
Warning: Method java.lang.Object.getInjectedPluginClasspath() not found.
Warning: Method java.lang.Object.getJavaHome() not found.
Warning: Method java.lang.Object.getJvmArguments() not found.
Warning: Method java.lang.Object.getLaunchables() not found.
Warning: Method java.lang.Object.getName() not found.
Warning: Method java.lang.Object.getPath() not found.
Warning: Method java.lang.Object.getProgressListener() not found.
Warning: Method java.lang.Object.getProject() not found.
Warning: Method java.lang.Object.getProjectDir() not found.
Warning: Method java.lang.Object.getProjectDirectory() not found.
Warning: Method java.lang.Object.getStandardError() not found.
Warning: Method java.lang.Object.getStandardInput() not found.
Warning: Method java.lang.Object.getStandardOutput() not found.
Warning: Method java.lang.Object.getStartTime() not found.
Warning: Method java.lang.Object.getSystemProperties() not found.
Warning: Method java.lang.Object.getTasks() not found.
Warning: Method java.lang.Object.getVerboseLogging() not found.
Warning: Method java.lang.Object.isColorOutput() not found.
Warning: Method java.lang.Object.isEmbedded() not found.
Warning: Method java.lang.Object.projectPluginMap() not found.
Warning: Method java.lang.Object.projectToExternalDependencyPaths() not found.
Warning: Method java.lang.Object.projectToInternalDependencies() not found.
Warning: Method org.gradle.TaskExecutionRequest.getGroup() not found.
Warning: Method org.gradle.TaskExecutionRequest.getPath() not found.
Warning: Method org.gradle.TaskExecutionRequest.getProject() not found.
Warning: Could not resolve class org.gradle.api.internal.artifacts.configurations.MarkConfigurationObservedListener for reflection configuration. Reason: java.lang.ClassNotFoundException: org.gradle.api.internal.artifacts.configurations.MarkConfigurationObservedListener.
Warning: Could not resolve class org.gradle.kotlin.dsl.provider.KotlinGradleApiSpecProvider for reflection configuration. Reason: java.lang.ClassNotFoundException: org.gradle.kotlin.dsl.provider.KotlinGradleApiSpecProvider.
Warning: Could not resolve class org.gradle.kotlin.dsl.provider.plugins.KotlinDslProviderPluginsServiceRegistry for reflection configuration. Reason: java.lang.ClassNotFoundException: org.gradle.kotlin.dsl.provider.plugins.KotlinDslProviderPluginsServiceRegistry.
Warning: Could not resolve class org.gradle.kotlin.dsl.services.KotlinScriptServiceRegistry for reflection configuration. Reason: java.lang.ClassNotFoundException: org.gradle.kotlin.dsl.services.KotlinScriptServiceRegistry.
Warning: Could not resolve class org.gradle.kotlin.dsl.support.GlobalServices for reflection configuration. Reason: java.lang.ClassNotFoundException: org.gradle.kotlin.dsl.support.GlobalServices.
Warning: Method org.gradle.plugins.ide.internal.tooling.model.LaunchableGradleTask.getProject() not found.
Warning: Could not resolve class org.gradle.problems.internal.services.ProblemsGlobalServices for reflection configuration. Reason: java.lang.ClassNotFoundException: org.gradle.problems.internal.services.ProblemsGlobalServices.
Warning: Could not resolve class org.gradle.profile.BuildProfileServices for reflection configuration. Reason: java.lang.ClassNotFoundException: org.gradle.profile.BuildProfileServices.
Warning: Method org.gradle.tooling.internal.consumer.DefaultConnectionParameters.getGradleUserHomeDir(File) not found.
Warning: Method org.gradle.tooling.internal.consumer.parameters.ConsumerOperationParameters.getBuildLogLevel() not found.
Warning: Method org.gradle.tooling.internal.consumer.parameters.ConsumerOperationParameters.getEnvironmentVariables(Map) not found.
Warning: Method org.gradle.tooling.internal.consumer.parameters.ConsumerOperationParameters.getSystemProperties(Map) not found.
Warning: Method org.gradle.tooling.internal.gradle.GradleBuildIdentity.getChildren() not found.
Warning: Method org.gradle.tooling.internal.gradle.GradleBuildIdentity.getGroup() not found.
Warning: Method org.gradle.tooling.internal.gradle.GradleBuildIdentity.getName() not found.
Warning: Method org.gradle.tooling.internal.gradle.GradleBuildIdentity.getPath() not found.
Warning: Method org.gradle.tooling.internal.gradle.GradleBuildIdentity.getProject() not found.
Warning: Method org.gradle.tooling.internal.gradle.GradleBuildIdentity.getProjectDirectory() not found.
Warning: Method org.gradle.tooling.internal.gradle.GradleBuildIdentity.getTasks() not found.
Warning: Method org.gradle.tooling.internal.gradle.GradleProjectIdentity.getChildren() not found.
Warning: Method org.gradle.tooling.internal.gradle.GradleProjectIdentity.getGroup() not found.
Warning: Method org.gradle.tooling.internal.gradle.GradleProjectIdentity.getName() not found.
Warning: Method org.gradle.tooling.internal.gradle.GradleProjectIdentity.getPath() not found.
Warning: Method org.gradle.tooling.internal.gradle.GradleProjectIdentity.getProject() not found.
Warning: Method org.gradle.tooling.internal.gradle.GradleProjectIdentity.getProjectDirectory() not found.
Warning: Method org.gradle.tooling.internal.gradle.GradleProjectIdentity.getTasks() not found.
Warning: Method org.gradle.tooling.internal.protocol.BuildParameters.getArguments() not found.
Warning: Method org.gradle.tooling.internal.protocol.BuildParameters.getBuildProgressListener() not found.
Warning: Method org.gradle.tooling.internal.protocol.BuildParameters.getDaemonBaseDir() not found.
Warning: Method org.gradle.tooling.internal.protocol.BuildParameters.getDaemonMaxIdleTimeValue() not found.
Warning: Method org.gradle.tooling.internal.protocol.BuildParameters.getEnvironmentVariables() not found.
Warning: Method org.gradle.tooling.internal.protocol.BuildParameters.getGradleUserHomeDir() not found.
Warning: Method org.gradle.tooling.internal.protocol.BuildParameters.getInjectedPluginClasspath() not found.
Warning: Method org.gradle.tooling.internal.protocol.BuildParameters.getJavaHome() not found.
Warning: Method org.gradle.tooling.internal.protocol.BuildParameters.getJvmArguments() not found.
Warning: Method org.gradle.tooling.internal.protocol.BuildParameters.getLaunchables() not found.
Warning: Method org.gradle.tooling.internal.protocol.BuildParameters.getProgressListener() not found.
Warning: Method org.gradle.tooling.internal.protocol.BuildParameters.getProjectDir() not found.
Warning: Method org.gradle.tooling.internal.protocol.BuildParameters.getStandardError() not found.
Warning: Method org.gradle.tooling.internal.protocol.BuildParameters.getStandardInput() not found.
Warning: Method org.gradle.tooling.internal.protocol.BuildParameters.getStandardOutput() not found.
Warning: Method org.gradle.tooling.internal.protocol.BuildParameters.getStartTime() not found.
Warning: Method org.gradle.tooling.internal.protocol.BuildParameters.getSystemProperties() not found.
Warning: Method org.gradle.tooling.internal.protocol.BuildParameters.getTasks() not found.
Warning: Method org.gradle.tooling.internal.protocol.BuildParameters.getVerboseLogging() not found.
Warning: Method org.gradle.tooling.internal.protocol.BuildParameters.isColorOutput() not found.
Warning: Method org.gradle.tooling.internal.protocol.BuildParameters.isEmbedded() not found.
Warning: Method org.gradle.tooling.internal.protocol.ConnectionParameters.getGradleUserHomeDir() not found.
Warning: Method org.gradle.tooling.internal.protocol.ConnectionParameters.getVerboseLogging() not found.
Warning: Method org.gradle.tooling.internal.protocol.InternalLaunchable.getGroup() not found.
Warning: Method org.gradle.tooling.internal.protocol.InternalLaunchable.getPath() not found.
Warning: Method org.gradle.tooling.internal.protocol.InternalLaunchable.getProject() not found.
Warning: Method org.gradle.tooling.internal.protocol.InternalProtocolInterface.getArguments() not found.
Warning: Method org.gradle.tooling.internal.protocol.InternalProtocolInterface.getBuildProgressListener() not found.
Warning: Method org.gradle.tooling.internal.protocol.InternalProtocolInterface.getConsumerVersion() not found.
Warning: Method org.gradle.tooling.internal.protocol.InternalProtocolInterface.getDaemonBaseDir() not found.
Warning: Method org.gradle.tooling.internal.protocol.InternalProtocolInterface.getDaemonMaxIdleTimeValue() not found.
Warning: Method org.gradle.tooling.internal.protocol.InternalProtocolInterface.getEnvironmentVariables() not found.
Warning: Method org.gradle.tooling.internal.protocol.InternalProtocolInterface.getGradleUserHomeDir() not found.
Warning: Method org.gradle.tooling.internal.protocol.InternalProtocolInterface.getGroup() not found.
Warning: Method org.gradle.tooling.internal.protocol.InternalProtocolInterface.getInjectedPluginClasspath() not found.
Warning: Method org.gradle.tooling.internal.protocol.InternalProtocolInterface.getJavaHome() not found.
Warning: Method org.gradle.tooling.internal.protocol.InternalProtocolInterface.getJvmArguments() not found.
Warning: Method org.gradle.tooling.internal.protocol.InternalProtocolInterface.getLaunchables() not found.
Warning: Method org.gradle.tooling.internal.protocol.InternalProtocolInterface.getPath() not found.
Warning: Method org.gradle.tooling.internal.protocol.InternalProtocolInterface.getProgressListener() not found.
Warning: Method org.gradle.tooling.internal.protocol.InternalProtocolInterface.getProject() not found.
Warning: Method org.gradle.tooling.internal.protocol.InternalProtocolInterface.getProjectDir() not found.
Warning: Method org.gradle.tooling.internal.protocol.InternalProtocolInterface.getStandardError() not found.
Warning: Method org.gradle.tooling.internal.protocol.InternalProtocolInterface.getStandardInput() not found.
Warning: Method org.gradle.tooling.internal.protocol.InternalProtocolInterface.getStandardOutput() not found.
Warning: Method org.gradle.tooling.internal.protocol.InternalProtocolInterface.getStartTime() not found.
Warning: Method org.gradle.tooling.internal.protocol.InternalProtocolInterface.getSystemProperties() not found.
Warning: Method org.gradle.tooling.internal.protocol.InternalProtocolInterface.getTasks() not found.
Warning: Method org.gradle.tooling.internal.protocol.InternalProtocolInterface.getVerboseLogging() not found.
Warning: Method org.gradle.tooling.internal.protocol.InternalProtocolInterface.isColorOutput() not found.
Warning: Method org.gradle.tooling.internal.protocol.InternalProtocolInterface.isEmbedded() not found.
Warning: Method org.gradle.tooling.internal.provider.connection.BuildLogLevelMixIn.getEnvironmentVariables(Map) not found.
Warning: Method org.gradle.tooling.internal.provider.connection.BuildLogLevelMixIn.getSystemProperties(Map) not found.
Warning: Could not resolve class org.h2.message.TraceWriterAdapter for reflection configuration. Reason: java.lang.ClassNotFoundException: org.h2.message.TraceWriterAdapter.
Warning: Could not resolve class org.h2.tools.GUIConsole for reflection configuration. Reason: java.lang.ClassNotFoundException: org.h2.tools.GUIConsole.
Warning: Method sun.security.provider.NativePRNG.<init>(SecureRandomParameters) not found.
Warning: Could not resolve class org.h2.message.TraceWriterAdapter for reflection configuration. Reason: java.lang.ClassNotFoundException: org.h2.message.TraceWriterAdapter.
Warning: Could not resolve class org.h2.tools.GUIConsole for reflection configuration. Reason: java.lang.ClassNotFoundException: org.h2.tools.GUIConsole.
Warning: Could not resolve class com.google.common.collect.ImmutableList$SerializedForm for reflection configuration. Reason: java.lang.ClassNotFoundException: com.google.common.collect.ImmutableList$SerializedForm.
        Warning: Method java.io.Serializable.getChildren() not found.
Warning: Method java.io.Serializable.getGroup() not found.
Warning: Method java.io.Serializable.getName() not found.
Warning: Method java.io.Serializable.getPath() not found.
Warning: Method java.io.Serializable.getProject() not found.
Warning: Method java.io.Serializable.getProjectDirectory() not found.
Warning: Method java.io.Serializable.getTasks() not found.
Warning: Method java.io.Serializable.projectPluginMap() not found.
Warning: Method java.io.Serializable.projectToExternalDependencyPaths() not found.
Warning: Method java.io.Serializable.projectToInternalDependencies() not found.
Warning: Method java.lang.Object.getArguments() not found.
Warning: Method java.lang.Object.getBuildLogLevel() not found.
Warning: Method java.lang.Object.getBuildProgressListener() not found.
Warning: Method java.lang.Object.getChildren() not found.
Warning: Method java.lang.Object.getConsumerVersion() not found.
Warning: Method java.lang.Object.getDaemonBaseDir() not found.
Warning: Method java.lang.Object.getDaemonMaxIdleTimeValue() not found.
Warning: Method java.lang.Object.getEnvironmentVariables() not found.
Warning: Method java.lang.Object.getGradleUserHomeDir() not found.
Warning: Method java.lang.Object.getGroup() not found.
Warning: Method java.lang.Object.getInjectedPluginClasspath() not found.
Warning: Method java.lang.Object.getJavaHome() not found.
Warning: Method java.lang.Object.getJvmArguments() not found.
Warning: Method java.lang.Object.getLaunchables() not found.
Warning: Method java.lang.Object.getName() not found.
Warning: Method java.lang.Object.getPath() not found.
Warning: Method java.lang.Object.getProgressListener() not found.
Warning: Method java.lang.Object.getProject() not found.
Warning: Method java.lang.Object.getProjectDir() not found.
Warning: Method java.lang.Object.getProjectDirectory() not found.
Warning: Method java.lang.Object.getStandardError() not found.
Warning: Method java.lang.Object.getStandardInput() not found.
Warning: Method java.lang.Object.getStandardOutput() not found.
Warning: Method java.lang.Object.getStartTime() not found.
Warning: Method java.lang.Object.getSystemProperties() not found.
Warning: Method java.lang.Object.getTasks() not found.
Warning: Method java.lang.Object.getVerboseLogging() not found.
Warning: Method java.lang.Object.isColorOutput() not found.
Warning: Method java.lang.Object.isEmbedded() not found.
Warning: Method java.lang.Object.projectPluginMap() not found.
Warning: Method java.lang.Object.projectToExternalDependencyPaths() not found.
Warning: Method java.lang.Object.projectToInternalDependencies() not found.
Warning: Method org.gradle.TaskExecutionRequest.getGroup() not found.
Warning: Method org.gradle.TaskExecutionRequest.getPath() not found.
Warning: Method org.gradle.TaskExecutionRequest.getProject() not found.
Warning: Could not resolve class org.gradle.api.internal.artifacts.configurations.MarkConfigurationObservedListener for reflection configuration. Reason: java.lang.ClassNotFoundException: org.gradle.api.internal.artifacts.configurations.MarkConfigurationObservedListener.
Warning: Could not resolve class org.gradle.kotlin.dsl.provider.KotlinGradleApiSpecProvider for reflection configuration. Reason: java.lang.ClassNotFoundException: org.gradle.kotlin.dsl.provider.KotlinGradleApiSpecProvider.
Warning: Could not resolve class org.gradle.kotlin.dsl.provider.plugins.KotlinDslProviderPluginsServiceRegistry for reflection configuration. Reason: java.lang.ClassNotFoundException: org.gradle.kotlin.dsl.provider.plugins.KotlinDslProviderPluginsServiceRegistry.
Warning: Could not resolve class org.gradle.kotlin.dsl.services.KotlinScriptServiceRegistry for reflection configuration. Reason: java.lang.ClassNotFoundException: org.gradle.kotlin.dsl.services.KotlinScriptServiceRegistry.
Warning: Could not resolve class org.gradle.kotlin.dsl.support.GlobalServices for reflection configuration. Reason: java.lang.ClassNotFoundException: org.gradle.kotlin.dsl.support.GlobalServices.
Warning: Method org.gradle.plugins.ide.internal.tooling.model.LaunchableGradleTask.getProject() not found.
Warning: Could not resolve class org.gradle.problems.internal.services.ProblemsGlobalServices for reflection configuration. Reason: java.lang.ClassNotFoundException: org.gradle.problems.internal.services.ProblemsGlobalServices.
Warning: Could not resolve class org.gradle.profile.BuildProfileServices for reflection configuration. Reason: java.lang.ClassNotFoundException: org.gradle.profile.BuildProfileServices.
Warning: Method org.gradle.tooling.internal.consumer.DefaultConnectionParameters.getGradleUserHomeDir(File) not found.
Warning: Method org.gradle.tooling.internal.consumer.parameters.ConsumerOperationParameters.getBuildLogLevel() not found.
Warning: Method org.gradle.tooling.internal.consumer.parameters.ConsumerOperationParameters.getEnvironmentVariables(Map) not found.
Warning: Method org.gradle.tooling.internal.consumer.parameters.ConsumerOperationParameters.getSystemProperties(Map) not found.
Warning: Method org.gradle.tooling.internal.gradle.GradleBuildIdentity.getChildren() not found.
Warning: Method org.gradle.tooling.internal.gradle.GradleBuildIdentity.getGroup() not found.
Warning: Method org.gradle.tooling.internal.gradle.GradleBuildIdentity.getName() not found.
Warning: Method org.gradle.tooling.internal.gradle.GradleBuildIdentity.getPath() not found.
Warning: Method org.gradle.tooling.internal.gradle.GradleBuildIdentity.getProject() not found.
Warning: Method org.gradle.tooling.internal.gradle.GradleBuildIdentity.getProjectDirectory() not found.
Warning: Method org.gradle.tooling.internal.gradle.GradleBuildIdentity.getTasks() not found.
Warning: Method org.gradle.tooling.internal.gradle.GradleProjectIdentity.getChildren() not found.
Warning: Method org.gradle.tooling.internal.gradle.GradleProjectIdentity.getGroup() not found.
Warning: Method org.gradle.tooling.internal.gradle.GradleProjectIdentity.getName() not found.
Warning: Method org.gradle.tooling.internal.gradle.GradleProjectIdentity.getPath() not found.
Warning: Method org.gradle.tooling.internal.gradle.GradleProjectIdentity.getProject() not found.
Warning: Method org.gradle.tooling.internal.gradle.GradleProjectIdentity.getProjectDirectory() not found.
Warning: Method org.gradle.tooling.internal.gradle.GradleProjectIdentity.getTasks() not found.
Warning: Method org.gradle.tooling.internal.protocol.BuildParameters.getArguments() not found.
Warning: Method org.gradle.tooling.internal.protocol.BuildParameters.getBuildProgressListener() not found.
Warning: Method org.gradle.tooling.internal.protocol.BuildParameters.getDaemonBaseDir() not found.
Warning: Method org.gradle.tooling.internal.protocol.BuildParameters.getDaemonMaxIdleTimeValue() not found.
Warning: Method org.gradle.tooling.internal.protocol.BuildParameters.getEnvironmentVariables() not found.
Warning: Method org.gradle.tooling.internal.protocol.BuildParameters.getGradleUserHomeDir() not found.
Warning: Method org.gradle.tooling.internal.protocol.BuildParameters.getInjectedPluginClasspath() not found.
Warning: Method org.gradle.tooling.internal.protocol.BuildParameters.getJavaHome() not found.
Warning: Method org.gradle.tooling.internal.protocol.BuildParameters.getJvmArguments() not found.
Warning: Method org.gradle.tooling.internal.protocol.BuildParameters.getLaunchables() not found.
Warning: Method org.gradle.tooling.internal.protocol.BuildParameters.getProgressListener() not found.
Warning: Method org.gradle.tooling.internal.protocol.BuildParameters.getProjectDir() not found.
Warning: Method org.gradle.tooling.internal.protocol.BuildParameters.getStandardError() not found.
Warning: Method org.gradle.tooling.internal.protocol.BuildParameters.getStandardInput() not found.
Warning: Method org.gradle.tooling.internal.protocol.BuildParameters.getStandardOutput() not found.
Warning: Method org.gradle.tooling.internal.protocol.BuildParameters.getStartTime() not found.
Warning: Method org.gradle.tooling.internal.protocol.BuildParameters.getSystemProperties() not found.
Warning: Method org.gradle.tooling.internal.protocol.BuildParameters.getTasks() not found.
Warning: Method org.gradle.tooling.internal.protocol.BuildParameters.getVerboseLogging() not found.
Warning: Method org.gradle.tooling.internal.protocol.BuildParameters.isColorOutput() not found.
Warning: Method org.gradle.tooling.internal.protocol.BuildParameters.isEmbedded() not found.
Warning: Method org.gradle.tooling.internal.protocol.ConnectionParameters.getGradleUserHomeDir() not found.
Warning: Method org.gradle.tooling.internal.protocol.ConnectionParameters.getVerboseLogging() not found.
Warning: Method org.gradle.tooling.internal.protocol.InternalLaunchable.getGroup() not found.
Warning: Method org.gradle.tooling.internal.protocol.InternalLaunchable.getPath() not found.
Warning: Method org.gradle.tooling.internal.protocol.InternalLaunchable.getProject() not found.
Warning: Method org.gradle.tooling.internal.protocol.InternalProtocolInterface.getArguments() not found.
Warning: Method org.gradle.tooling.internal.protocol.InternalProtocolInterface.getBuildProgressListener() not found.
Warning: Method org.gradle.tooling.internal.protocol.InternalProtocolInterface.getConsumerVersion() not found.
Warning: Method org.gradle.tooling.internal.protocol.InternalProtocolInterface.getDaemonBaseDir() not found.
Warning: Method org.gradle.tooling.internal.protocol.InternalProtocolInterface.getDaemonMaxIdleTimeValue() not found.
Warning: Method org.gradle.tooling.internal.protocol.InternalProtocolInterface.getEnvironmentVariables() not found.
Warning: Method org.gradle.tooling.internal.protocol.InternalProtocolInterface.getGradleUserHomeDir() not found.
Warning: Method org.gradle.tooling.internal.protocol.InternalProtocolInterface.getGroup() not found.
Warning: Method org.gradle.tooling.internal.protocol.InternalProtocolInterface.getInjectedPluginClasspath() not found.
Warning: Method org.gradle.tooling.internal.protocol.InternalProtocolInterface.getJavaHome() not found.
Warning: Method org.gradle.tooling.internal.protocol.InternalProtocolInterface.getJvmArguments() not found.
Warning: Method org.gradle.tooling.internal.protocol.InternalProtocolInterface.getLaunchables() not found.
Warning: Method org.gradle.tooling.internal.protocol.InternalProtocolInterface.getPath() not found.
Warning: Method org.gradle.tooling.internal.protocol.InternalProtocolInterface.getProgressListener() not found.
Warning: Method org.gradle.tooling.internal.protocol.InternalProtocolInterface.getProject() not found.
Warning: Method org.gradle.tooling.internal.protocol.InternalProtocolInterface.getProjectDir() not found.
Warning: Method org.gradle.tooling.internal.protocol.InternalProtocolInterface.getStandardError() not found.
Warning: Method org.gradle.tooling.internal.protocol.InternalProtocolInterface.getStandardInput() not found.
Warning: Method org.gradle.tooling.internal.protocol.InternalProtocolInterface.getStandardOutput() not found.
Warning: Method org.gradle.tooling.internal.protocol.InternalProtocolInterface.getStartTime() not found.
Warning: Method org.gradle.tooling.internal.protocol.InternalProtocolInterface.getSystemProperties() not found.
Warning: Method org.gradle.tooling.internal.protocol.InternalProtocolInterface.getTasks() not found.
Warning: Method org.gradle.tooling.internal.protocol.InternalProtocolInterface.getVerboseLogging() not found.
Warning: Method org.gradle.tooling.internal.protocol.InternalProtocolInterface.isColorOutput() not found.
Warning: Method org.gradle.tooling.internal.protocol.InternalProtocolInterface.isEmbedded() not found.
Warning: Method org.gradle.tooling.internal.provider.connection.BuildLogLevelMixIn.getEnvironmentVariables(Map) not found.
Warning: Method org.gradle.tooling.internal.provider.connection.BuildLogLevelMixIn.getSystemProperties(Map) not found.
Warning: Could not resolve class org.h2.message.TraceWriterAdapter for reflection configuration. Reason: java.lang.ClassNotFoundException: org.h2.message.TraceWriterAdapter.
Warning: Could not resolve class org.h2.tools.GUIConsole for reflection configuration. Reason: java.lang.ClassNotFoundException: org.h2.tools.GUIConsole.
Warning: Method sun.security.provider.NativePRNG.<init>(SecureRandomParameters) not found.
Warning: Could not resolve com.google.common.collect.ImmutableList$SerializedForm for serialization configuration.
[1/8] Initializing...                                                                                    (8.6s @ 0.46GB)
Java version: 17.0.9+9, vendor version: GraalVM CE 17.0.9+9.1
Graal compiler: optimization level: 2, target machine: armv8-a
C compiler: cc (apple, arm64, 15.0.0)
Garbage collector: Serial GC (max heap size: 80% of RAM)
1 user-specific feature(s)
- com.oracle.svm.polyglot.groovy.GroovyIndyInterfaceFeature
# Printing class initialization configuration to: /Users/anugrah.singhal/personal/graal-8760/build/native/nativeCompile/reports/class_initialization_configuration_20240620_142752.csv
# Printing security services automatic registration to: /Users/anugrah.singhal/personal/graal-8760/build/native/nativeCompile/reports/security_services_20240620_142754.txt
# Printing class initialization configuration to: /Users/anugrah.singhal/personal/graal-8760/build/native/nativeCompile/reports/class_initialization_configuration_20240620_142758.csv
[2/8] Performing analysis...  []                                                                        (10.7s @ 1.97GB)
12,489 (84.39%) of 14,799 types reachable
19,331 (66.72%) of 28,975 fields reachable
58,902 (56.01%) of 105,155 methods reachable
4,306 types,   285 fields, and 2,565 methods registered for reflection

Error: Classes that should be initialized at run time got initialized during image building:
org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories$8 was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories$8 got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories$8
org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$10 was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$10 got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$10
org.gradle.internal.time.Time was unintentionally initialized at build time. To see why org.gradle.internal.time.Time got initialized use --trace-class-initialization=org.gradle.internal.time.Time
        org.gradle.internal.impldep.org.apache.sshd.server.forward.RejectAllForwardingFilter was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.server.forward.RejectAllForwardingFilter got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.server.forward.RejectAllForwardingFilter
        org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$6 was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$6 got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$6
org.slf4j.LoggerFactory was unintentionally initialized at build time. To see why org.slf4j.LoggerFactory got initialized use --trace-class-initialization=org.slf4j.LoggerFactory
        org.gradle.internal.impldep.org.apache.sshd.client.config.hosts.HostConfigEntry$LazyDefaultConfigFileHolder was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.client.config.hosts.HostConfigEntry$LazyDefaultConfigFileHolder got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.client.config.hosts.HostConfigEntry$LazyDefaultConfigFileHolder
org.gradle.internal.impldep.org.apache.sshd.client.config.hosts.HostPatternsHolder was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.client.config.hosts.HostPatternsHolder got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.client.config.hosts.HostPatternsHolder
        org.gradle.internal.impldep.org.apache.sshd.common.util.buffer.keys.RSABufferPublicKeyParser was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.util.buffer.keys.RSABufferPublicKeyParser got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.util.buffer.keys.RSABufferPublicKeyParser
        org.gradle.internal.impldep.org.apache.sshd.common.session.helpers.DefaultUnknownChannelReferenceHandler was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.session.helpers.DefaultUnknownChannelReferenceHandler got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.session.helpers.DefaultUnknownChannelReferenceHandler
        org.gradle.internal.impldep.org.apache.sshd.common.mac.BuiltinMacs$2 was unintentionally initialized at build time. org.gradle.internal.impldep.org.apache.sshd.common.BaseBuilder caused initialization of this class with the following trace:
at org.gradle.internal.impldep.org.apache.sshd.common.mac.BuiltinMacs$2.<clinit>(BuiltinMacs.java)
at org.gradle.internal.impldep.org.apache.sshd.common.mac.BuiltinMacs.<clinit>(BuiltinMacs.java:73)
at org.gradle.internal.impldep.org.apache.sshd.common.BaseBuilder.<clinit>(BaseBuilder.java:109)

org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures
        org.gradle.internal.impldep.org.bouncycastle.util.Strings was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.bouncycastle.util.Strings got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.bouncycastle.util.Strings
        org.gradle.internal.impldep.org.apache.sshd.client.config.keys.ClientIdentityFileWatcher was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.client.config.keys.ClientIdentityFileWatcher got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.client.config.keys.ClientIdentityFileWatcher
        org.gradle.internal.impldep.org.apache.sshd.common.kex.MontgomeryCurve was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.kex.MontgomeryCurve got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.kex.MontgomeryCurve
        org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories$14 was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories$14 got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories$14
org.gradle.internal.impldep.org.apache.sshd.common.mac.BuiltinMacs was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.mac.BuiltinMacs got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.mac.BuiltinMacs
        org.gradle.internal.impldep.org.apache.sshd.common.util.buffer.keys.OpenSSHCertPublicKeyParser was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.util.buffer.keys.OpenSSHCertPublicKeyParser got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.util.buffer.keys.OpenSSHCertPublicKeyParser
        org.gradle.internal.impldep.org.apache.sshd.common.cipher.BuiltinCiphers$4 was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.cipher.BuiltinCiphers$4 got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.cipher.BuiltinCiphers$4
org.gradle.internal.impldep.org.apache.sshd.common.compression.BuiltinCompressions$1 was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.compression.BuiltinCompressions$1 got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.compression.BuiltinCompressions$1
org.gradle.internal.impldep.org.apache.sshd.common.SyspropsMapWrapper was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.SyspropsMapWrapper got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.SyspropsMapWrapper
        org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories$11 was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories$11 got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories$11
org.gradle.internal.impldep.org.apache.sshd.client.config.keys.ClientIdentitiesWatcher was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.client.config.keys.ClientIdentitiesWatcher got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.client.config.keys.ClientIdentitiesWatcher
        org.gradle.internal.impldep.org.apache.sshd.common.keyprovider.KeyPairProvider$1 was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.keyprovider.KeyPairProvider$1 got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.keyprovider.KeyPairProvider$1
org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$14 was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$14 got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$14
org.gradle.internal.impldep.org.apache.sshd.common.config.keys.PublicKeyEntry$LazyDefaultKeysFolderHolder was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.config.keys.PublicKeyEntry$LazyDefaultKeysFolderHolder got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.config.keys.PublicKeyEntry$LazyDefaultKeysFolderHolder
org.gradle.internal.impldep.org.apache.sshd.common.NamedResource was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.NamedResource got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.NamedResource
        org.gradle.internal.logging.slf4j.OutputEventListenerBackedLoggerContext was unintentionally initialized at build time. To see why org.gradle.internal.logging.slf4j.OutputEventListenerBackedLoggerContext got initialized use --trace-class-initialization=org.gradle.internal.logging.slf4j.OutputEventListenerBackedLoggerContext
        org.gradle.internal.impldep.org.bouncycastle.jcajce.provider.drbg.DRBG was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.bouncycastle.jcajce.provider.drbg.DRBG got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.bouncycastle.jcajce.provider.drbg.DRBG
        org.gradle.internal.impldep.org.apache.sshd.common.util.threads.ThreadUtils was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.util.threads.ThreadUtils got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.util.threads.ThreadUtils
        org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories$13 was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories$13 got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories$13
org.gradle.internal.impldep.org.bouncycastle.asn1.ua.UAObjectIdentifiers was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.bouncycastle.asn1.ua.UAObjectIdentifiers got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.bouncycastle.asn1.ua.UAObjectIdentifiers
        org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$8 was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$8 got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$8
org.gradle.internal.impldep.org.bouncycastle.util.Properties was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.bouncycastle.util.Properties got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.bouncycastle.util.Properties
        org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$1 was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$1 got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$1
org.gradle.internal.impldep.org.apache.sshd.common.util.NumberUtils was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.util.NumberUtils got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.util.NumberUtils
        org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$18 was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$18 got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$18
org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$3 was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$3 got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$3
org.gradle.internal.impldep.org.apache.sshd.common.util.security.SecurityProviderRegistrar was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.util.security.SecurityProviderRegistrar got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.util.security.SecurityProviderRegistrar
        org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$7 was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$7 got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$7
org.gradle.internal.impldep.org.apache.sshd.common.kex.extension.DefaultClientKexExtensionHandler was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.kex.extension.DefaultClientKexExtensionHandler got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.kex.extension.DefaultClientKexExtensionHandler
        org.gradle.internal.impldep.org.bouncycastle.jcajce.provider.asymmetric.dsa.DSAUtil was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.bouncycastle.jcajce.provider.asymmetric.dsa.DSAUtil got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.bouncycastle.jcajce.provider.asymmetric.dsa.DSAUtil
        org.gradle.internal.impldep.org.bouncycastle.asn1.nist.NISTObjectIdentifiers was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.bouncycastle.asn1.nist.NISTObjectIdentifiers got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.bouncycastle.asn1.nist.NISTObjectIdentifiers
        org.gradle.internal.impldep.org.apache.sshd.common.util.io.IoUtils was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.util.io.IoUtils got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.util.io.IoUtils
        org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories$10 was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories$10 got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories$10
org.gradle.internal.impldep.org.apache.sshd.common.config.keys.PublicKeyEntry was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.config.keys.PublicKeyEntry got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.config.keys.PublicKeyEntry
        org.gradle.internal.impldep.org.apache.sshd.common.util.buffer.keys.SkECBufferPublicKeyParser was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.util.buffer.keys.SkECBufferPublicKeyParser got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.util.buffer.keys.SkECBufferPublicKeyParser
        org.gradle.internal.impldep.org.apache.sshd.common.keyprovider.AbstractKeyPairProvider was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.keyprovider.AbstractKeyPairProvider got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.keyprovider.AbstractKeyPairProvider
        org.gradle.internal.impldep.org.bouncycastle.asn1.x509.X509ObjectIdentifiers was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.bouncycastle.asn1.x509.X509ObjectIdentifiers got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.bouncycastle.asn1.x509.X509ObjectIdentifiers
        org.gradle.internal.impldep.org.apache.sshd.common.util.EventListenerUtils was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.util.EventListenerUtils got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.util.EventListenerUtils
        org.gradle.internal.impldep.org.apache.sshd.common.PropertyResolverUtils was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.PropertyResolverUtils got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.PropertyResolverUtils
        org.gradle.internal.impldep.org.bouncycastle.pqc.asn1.PQCObjectIdentifiers was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.bouncycastle.pqc.asn1.PQCObjectIdentifiers got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.bouncycastle.pqc.asn1.PQCObjectIdentifiers
        org.gradle.internal.impldep.org.apache.sshd.common.config.keys.BuiltinIdentities$2 was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.config.keys.BuiltinIdentities$2 got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.config.keys.BuiltinIdentities$2
org.gradle.internal.impldep.org.apache.sshd.common.config.keys.BuiltinIdentities was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.config.keys.BuiltinIdentities got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.config.keys.BuiltinIdentities
        org.gradle.internal.impldep.org.bouncycastle.asn1.gnu.GNUObjectIdentifiers was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.bouncycastle.asn1.gnu.GNUObjectIdentifiers got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.bouncycastle.asn1.gnu.GNUObjectIdentifiers
        org.gradle.internal.impldep.org.apache.sshd.common.cipher.ECCurves was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.cipher.ECCurves got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.cipher.ECCurves
        org.gradle.internal.impldep.org.bouncycastle.jcajce.provider.asymmetric.COMPOSITE was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.bouncycastle.jcajce.provider.asymmetric.COMPOSITE got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.bouncycastle.jcajce.provider.asymmetric.COMPOSITE
        org.gradle.internal.impldep.org.apache.sshd.common.util.io.PathUtils was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.util.io.PathUtils got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.util.io.PathUtils
        org.gradle.internal.impldep.org.apache.sshd.common.util.io.PathUtils$LazyDefaultUserHomeFolderHolder was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.util.io.PathUtils$LazyDefaultUserHomeFolderHolder got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.util.io.PathUtils$LazyDefaultUserHomeFolderHolder
org.gradle.internal.impldep.org.apache.sshd.common.compression.BuiltinCompressions$2 was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.compression.BuiltinCompressions$2 got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.compression.BuiltinCompressions$2
org.gradle.internal.impldep.org.apache.sshd.client.config.hosts.DefaultConfigFileHostEntryResolver was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.client.config.hosts.DefaultConfigFileHostEntryResolver got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.client.config.hosts.DefaultConfigFileHostEntryResolver
        org.gradle.internal.impldep.org.bouncycastle.asn1.iso.ISOIECObjectIdentifiers was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.bouncycastle.asn1.iso.ISOIECObjectIdentifiers got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.bouncycastle.asn1.iso.ISOIECObjectIdentifiers
        org.gradle.internal.impldep.org.apache.sshd.sftp.client.fs.SftpFileSystemProvider was unintentionally initialized at build time. org.gradle.internal.impldep.org.apache.sshd.sftp.client.fs.SftpFileSystemProvider caused initialization of this class with the following trace:
at org.gradle.internal.impldep.org.apache.sshd.sftp.client.fs.SftpFileSystemProvider.<clinit>(SftpFileSystemProvider.java:128)
at jdk.internal.reflect.NativeConstructorAccessorImpl.newInstance0(Unknown Source)
at jdk.internal.reflect.NativeConstructorAccessorImpl.newInstance(NativeConstructorAccessorImpl.java:77)
at jdk.internal.reflect.DelegatingConstructorAccessorImpl.newInstance(DelegatingConstructorAccessorImpl.java:45)
at java.lang.reflect.Constructor.newInstanceWithCaller(Constructor.java:499)
at java.lang.reflect.Constructor.newInstance(Constructor.java:480)
at java.util.ServiceLoader$ProviderImpl.newInstance(ServiceLoader.java:789)
at java.util.ServiceLoader$ProviderImpl.get(ServiceLoader.java:729)
at java.util.ServiceLoader$3.next(ServiceLoader.java:1403)
at java.nio.file.spi.FileSystemProvider.loadInstalledProviders(FileSystemProvider.java:156)
at java.nio.file.spi.FileSystemProvider$1.run(FileSystemProvider.java:207)
at java.nio.file.spi.FileSystemProvider$1.run(FileSystemProvider.java:204)
at java.security.AccessController.executePrivileged(AccessController.java:776)
at java.security.AccessController.doPrivileged(AccessController.java:318)
at java.nio.file.spi.FileSystemProvider.installedProviders(FileSystemProvider.java:204)
at java.nio.file.FileSystems.newFileSystem(FileSystems.java:336)
at java.nio.file.FileSystems.newFileSystem(FileSystems.java:288)
at com.oracle.svm.hosted.NativeImageClassLoaderSupport$LoadClassHandler.loadClassesFromPath(NativeImageClassLoaderSupport.java:664)
at com.oracle.svm.hosted.NativeImageClassLoaderSupport$LoadClassHandler$$Lambda$211/0x00000098002ffa40.accept(Unknown Source)
at java.util.stream.ForEachOps$ForEachOp$OfRef.accept(ForEachOps.java:183)
at java.util.ArrayList$ArrayListSpliterator.forEachRemaining(ArrayList.java:1625)
at java.util.stream.AbstractPipeline.copyInto(AbstractPipeline.java:509)
at java.util.stream.ForEachOps$ForEachTask.compute(ForEachOps.java:290)
at java.util.concurrent.CountedCompleter.exec(CountedCompleter.java:754)
at java.util.concurrent.ForkJoinTask.doExec(ForkJoinTask.java:373)
at java.util.concurrent.ForkJoinTask.invoke(ForkJoinTask.java:686)
at java.util.stream.ForEachOps$ForEachOp.evaluateParallel(ForEachOps.java:159)
at java.util.stream.ForEachOps$ForEachOp$OfRef.evaluateParallel(ForEachOps.java:173)
at java.util.stream.AbstractPipeline.evaluate(AbstractPipeline.java:233)
at java.util.stream.ReferencePipeline.forEach(ReferencePipeline.java:596)
at java.util.stream.ReferencePipeline$Head.forEach(ReferencePipeline.java:765)
at com.oracle.svm.hosted.NativeImageClassLoaderSupport$LoadClassHandler.run(NativeImageClassLoaderSupport.java:624)
at com.oracle.svm.hosted.NativeImageClassLoaderSupport.loadAllClasses(NativeImageClassLoaderSupport.java:181)
at com.oracle.svm.hosted.ImageClassLoader.loadAllClasses(ImageClassLoader.java:100)
at com.oracle.svm.hosted.NativeImageGeneratorRunner.buildImage(NativeImageGeneratorRunner.java:296)
at com.oracle.svm.hosted.NativeImageGeneratorRunner.build(NativeImageGeneratorRunner.java:612)
at com.oracle.svm.hosted.NativeImageGeneratorRunner.start(NativeImageGeneratorRunner.java:134)
at com.oracle.svm.hosted.NativeImageGeneratorRunner.main(NativeImageGeneratorRunner.java:94)

org.gradle.internal.impldep.org.apache.sshd.common.mac.BuiltinMacs$1 was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.mac.BuiltinMacs$1 got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.mac.BuiltinMacs$1
org.gradle.internal.time.MonotonicClock was unintentionally initialized at build time. To see why org.gradle.internal.time.MonotonicClock got initialized use --trace-class-initialization=org.gradle.internal.time.MonotonicClock
        org.gradle.internal.impldep.org.bouncycastle.asn1.sec.SECObjectIdentifiers was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.bouncycastle.asn1.sec.SECObjectIdentifiers got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.bouncycastle.asn1.sec.SECObjectIdentifiers
        org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$2 was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$2 got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$2
org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories$1 was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories$1 got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories$1
org.gradle.internal.impldep.org.bouncycastle.crypto.CryptoServicesRegistrar was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.bouncycastle.crypto.CryptoServicesRegistrar got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.bouncycastle.crypto.CryptoServicesRegistrar
        org.gradle.internal.impldep.org.bouncycastle.crypto.engines.RSABlindedEngine was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.bouncycastle.crypto.engines.RSABlindedEngine got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.bouncycastle.crypto.engines.RSABlindedEngine
        org.gradle.internal.impldep.org.bouncycastle.jce.provider.BouncyCastleProvider was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.bouncycastle.jce.provider.BouncyCastleProvider got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.bouncycastle.jce.provider.BouncyCastleProvider
        org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$9 was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$9 got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$9
org.gradle.internal.impldep.org.apache.sshd.common.util.buffer.keys.ED25519BufferPublicKeyParser was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.util.buffer.keys.ED25519BufferPublicKeyParser got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.util.buffer.keys.ED25519BufferPublicKeyParser
        org.gradle.internal.impldep.org.bouncycastle.jce.provider.BouncyCastleProviderConfiguration was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.bouncycastle.jce.provider.BouncyCastleProviderConfiguration got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.bouncycastle.jce.provider.BouncyCastleProviderConfiguration
        org.gradle.internal.impldep.org.apache.sshd.common.cipher.BuiltinCiphers$1 was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.cipher.BuiltinCiphers$1 got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.cipher.BuiltinCiphers$1
org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$16 was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$16 got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$16
org.gradle.internal.impldep.org.apache.sshd.client.auth.AuthenticationIdentitiesProvider was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.client.auth.AuthenticationIdentitiesProvider got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.client.auth.AuthenticationIdentitiesProvider
        org.gradle.internal.impldep.org.apache.sshd.client.global.OpenSshHostKeysHandler was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.client.global.OpenSshHostKeysHandler got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.client.global.OpenSshHostKeysHandler
        org.gradle.internal.impldep.org.apache.sshd.common.io.DefaultIoServiceFactoryFactory$LazyDefaultIoServiceFactoryFactoryHolder was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.io.DefaultIoServiceFactoryFactory$LazyDefaultIoServiceFactoryFactoryHolder got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.io.DefaultIoServiceFactoryFactory$LazyDefaultIoServiceFactoryFactoryHolder
org.gradle.internal.impldep.org.bouncycastle.asn1.x9.X9ObjectIdentifiers was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.bouncycastle.asn1.x9.X9ObjectIdentifiers got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.bouncycastle.asn1.x9.X9ObjectIdentifiers
        org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$15 was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$15 got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$15
org.gradle.internal.impldep.org.apache.sshd.server.forward.TcpForwardingFilter$Type was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.server.forward.TcpForwardingFilter$Type got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.server.forward.TcpForwardingFilter$Type
org.gradle.internal.impldep.org.bouncycastle.jcajce.provider.asymmetric.edec.KeyFactorySpi was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.bouncycastle.jcajce.provider.asymmetric.edec.KeyFactorySpi got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.bouncycastle.jcajce.provider.asymmetric.edec.KeyFactorySpi
        org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$11 was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$11 got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$11
org.gradle.internal.impldep.org.apache.sshd.client.config.hosts.HostConfigEntry was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.client.config.hosts.HostConfigEntry got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.client.config.hosts.HostConfigEntry
        org.gradle.internal.impldep.org.apache.sshd.client.ClientBuilder was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.client.ClientBuilder got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.client.ClientBuilder
        org.gradle.internal.impldep.org.apache.sshd.common.digest.BuiltinDigests was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.digest.BuiltinDigests got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.digest.BuiltinDigests
        org.gradle.internal.impldep.org.apache.sshd.common.util.security.SecurityUtils was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.util.security.SecurityUtils got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.util.security.SecurityUtils
        org.gradle.internal.impldep.org.apache.sshd.common.util.OsUtils was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.util.OsUtils got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.util.OsUtils
        org.gradle.internal.impldep.org.apache.sshd.common.io.BuiltinIoServiceFactoryFactories was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.io.BuiltinIoServiceFactoryFactories got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.io.BuiltinIoServiceFactoryFactories
        org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories$9 was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories$9 got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories$9
org.gradle.internal.impldep.org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers
        org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories$2 was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories$2 got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories$2
org.gradle.internal.impldep.org.apache.sshd.client.keyverifier.AcceptAllServerKeyVerifier was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.client.keyverifier.AcceptAllServerKeyVerifier got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.client.keyverifier.AcceptAllServerKeyVerifier
        org.gradle.internal.impldep.org.apache.sshd.common.cipher.BuiltinCiphers was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.cipher.BuiltinCiphers got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.cipher.BuiltinCiphers
        org.gradle.internal.impldep.org.apache.sshd.common.util.MapEntryUtils was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.util.MapEntryUtils got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.util.MapEntryUtils
        org.slf4j.impl.StaticLoggerBinder was unintentionally initialized at build time. To see why org.slf4j.impl.StaticLoggerBinder got initialized use --trace-class-initialization=org.slf4j.impl.StaticLoggerBinder
        org.gradle.internal.impldep.org.apache.sshd.common.file.nativefs.NativeFileSystemFactory was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.file.nativefs.NativeFileSystemFactory got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.file.nativefs.NativeFileSystemFactory
        org.gradle.internal.impldep.org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers
        org.gradle.internal.impldep.org.bouncycastle.jcajce.provider.symmetric.AES was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.bouncycastle.jcajce.provider.symmetric.AES got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.bouncycastle.jcajce.provider.symmetric.AES
        org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories$5 was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories$5 got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories$5
org.gradle.internal.impldep.org.apache.sshd.common.util.buffer.keys.ECBufferPublicKeyParser was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.util.buffer.keys.ECBufferPublicKeyParser got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.util.buffer.keys.ECBufferPublicKeyParser
        org.gradle.internal.impldep.org.apache.sshd.common.cipher.BuiltinCiphers$3 was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.cipher.BuiltinCiphers$3 got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.cipher.BuiltinCiphers$3
org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories$7 was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories$7 got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories$7
org.gradle.internal.impldep.org.apache.sshd.common.session.ConnectionServiceRequestHandler was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.session.ConnectionServiceRequestHandler got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.session.ConnectionServiceRequestHandler
        org.gradle.internal.impldep.org.bouncycastle.asn1.rosstandart.RosstandartObjectIdentifiers was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.bouncycastle.asn1.rosstandart.RosstandartObjectIdentifiers got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.bouncycastle.asn1.rosstandart.RosstandartObjectIdentifiers
        org.gradle.internal.impldep.org.apache.sshd.client.config.keys.DefaultClientIdentitiesWatcher was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.client.config.keys.DefaultClientIdentitiesWatcher got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.client.config.keys.DefaultClientIdentitiesWatcher
        org.gradle.internal.impldep.org.apache.sshd.common.util.ReflectionUtils was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.util.ReflectionUtils got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.util.ReflectionUtils
        org.gradle.internal.impldep.org.apache.sshd.common.BaseBuilder was unintentionally initialized at build time. org.gradle.internal.impldep.org.apache.sshd.common.BaseBuilder caused initialization of this class with the following trace:
at org.gradle.internal.impldep.org.apache.sshd.common.BaseBuilder.<clinit>(BaseBuilder.java:62)
at org.gradle.internal.impldep.org.apache.sshd.client.SshClient.setUpDefaultClient(SshClient.java:974)
at org.gradle.internal.impldep.org.apache.sshd.sftp.client.fs.SftpFileSystemProvider.<init>(SftpFileSystemProvider.java:185)
at org.gradle.internal.impldep.org.apache.sshd.sftp.client.fs.SftpFileSystemProvider.<init>(SftpFileSystemProvider.java:160)
at org.gradle.internal.impldep.org.apache.sshd.sftp.client.fs.SftpFileSystemProvider.<init>(SftpFileSystemProvider.java:156)
at org.gradle.internal.impldep.org.apache.sshd.sftp.client.fs.SftpFileSystemProvider.<init>(SftpFileSystemProvider.java:152)
at org.gradle.internal.impldep.org.apache.sshd.sftp.client.fs.SftpFileSystemProvider.<init>(SftpFileSystemProvider.java:144)
at jdk.internal.reflect.NativeConstructorAccessorImpl.newInstance0(Unknown Source)
at jdk.internal.reflect.NativeConstructorAccessorImpl.newInstance(NativeConstructorAccessorImpl.java:77)
at jdk.internal.reflect.DelegatingConstructorAccessorImpl.newInstance(DelegatingConstructorAccessorImpl.java:45)
at java.lang.reflect.Constructor.newInstanceWithCaller(Constructor.java:499)
at java.lang.reflect.Constructor.newInstance(Constructor.java:480)
at java.util.ServiceLoader$ProviderImpl.newInstance(ServiceLoader.java:789)
at java.util.ServiceLoader$ProviderImpl.get(ServiceLoader.java:729)
at java.util.ServiceLoader$3.next(ServiceLoader.java:1403)
at java.nio.file.spi.FileSystemProvider.loadInstalledProviders(FileSystemProvider.java:156)
at java.nio.file.spi.FileSystemProvider$1.run(FileSystemProvider.java:207)
at java.nio.file.spi.FileSystemProvider$1.run(FileSystemProvider.java:204)
at java.security.AccessController.executePrivileged(AccessController.java:776)
at java.security.AccessController.doPrivileged(AccessController.java:318)
at java.nio.file.spi.FileSystemProvider.installedProviders(FileSystemProvider.java:204)
at java.nio.file.FileSystems.newFileSystem(FileSystems.java:336)
at java.nio.file.FileSystems.newFileSystem(FileSystems.java:288)
at com.oracle.svm.hosted.NativeImageClassLoaderSupport$LoadClassHandler.loadClassesFromPath(NativeImageClassLoaderSupport.java:664)
at com.oracle.svm.hosted.NativeImageClassLoaderSupport$LoadClassHandler$$Lambda$211/0x00000098002ffa40.accept(Unknown Source)
at java.util.stream.ForEachOps$ForEachOp$OfRef.accept(ForEachOps.java:183)
at java.util.ArrayList$ArrayListSpliterator.forEachRemaining(ArrayList.java:1625)
at java.util.stream.AbstractPipeline.copyInto(AbstractPipeline.java:509)
at java.util.stream.ForEachOps$ForEachTask.compute(ForEachOps.java:290)
at java.util.concurrent.CountedCompleter.exec(CountedCompleter.java:754)
at java.util.concurrent.ForkJoinTask.doExec(ForkJoinTask.java:373)
at java.util.concurrent.ForkJoinTask.invoke(ForkJoinTask.java:686)
at java.util.stream.ForEachOps$ForEachOp.evaluateParallel(ForEachOps.java:159)
at java.util.stream.ForEachOps$ForEachOp$OfRef.evaluateParallel(ForEachOps.java:173)
at java.util.stream.AbstractPipeline.evaluate(AbstractPipeline.java:233)
at java.util.stream.ReferencePipeline.forEach(ReferencePipeline.java:596)
at java.util.stream.ReferencePipeline$Head.forEach(ReferencePipeline.java:765)
at com.oracle.svm.hosted.NativeImageClassLoaderSupport$LoadClassHandler.run(NativeImageClassLoaderSupport.java:624)
at com.oracle.svm.hosted.NativeImageClassLoaderSupport.loadAllClasses(NativeImageClassLoaderSupport.java:181)
at com.oracle.svm.hosted.ImageClassLoader.loadAllClasses(ImageClassLoader.java:100)
at com.oracle.svm.hosted.NativeImageGeneratorRunner.buildImage(NativeImageGeneratorRunner.java:296)
at com.oracle.svm.hosted.NativeImageGeneratorRunner.build(NativeImageGeneratorRunner.java:612)
at com.oracle.svm.hosted.NativeImageGeneratorRunner.start(NativeImageGeneratorRunner.java:134)
at com.oracle.svm.hosted.NativeImageGeneratorRunner.main(NativeImageGeneratorRunner.java:94)

org.gradle.internal.impldep.org.apache.sshd.common.cipher.BuiltinCiphers$2 was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.cipher.BuiltinCiphers$2 got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.cipher.BuiltinCiphers$2
org.gradle.internal.impldep.org.apache.sshd.common.compression.BuiltinCompressions$3 was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.compression.BuiltinCompressions$3 got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.compression.BuiltinCompressions$3
org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories
        org.gradle.internal.impldep.org.apache.sshd.client.config.keys.BuiltinClientIdentitiesWatcher was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.client.config.keys.BuiltinClientIdentitiesWatcher got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.client.config.keys.BuiltinClientIdentitiesWatcher
        org.gradle.internal.impldep.org.bouncycastle.asn1.oiw.OIWObjectIdentifiers was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.bouncycastle.asn1.oiw.OIWObjectIdentifiers got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.bouncycastle.asn1.oiw.OIWObjectIdentifiers
        org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories$12 was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories$12 got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories$12
org.gradle.internal.impldep.org.apache.sshd.common.util.security.bouncycastle.BouncyCastleRandomFactory was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.util.security.bouncycastle.BouncyCastleRandomFactory got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.util.security.bouncycastle.BouncyCastleRandomFactory
        org.gradle.internal.impldep.org.apache.sshd.common.util.buffer.keys.SkED25519BufferPublicKeyParser was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.util.buffer.keys.SkED25519BufferPublicKeyParser got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.util.buffer.keys.SkED25519BufferPublicKeyParser
        org.gradle.internal.impldep.org.bouncycastle.asn1.bc.BCObjectIdentifiers was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.bouncycastle.asn1.bc.BCObjectIdentifiers got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.bouncycastle.asn1.bc.BCObjectIdentifiers
        org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$12 was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$12 got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$12
org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories$4 was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories$4 got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories$4
org.gradle.internal.impldep.org.apache.sshd.common.util.io.ModifiableFileWatcher was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.util.io.ModifiableFileWatcher got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.util.io.ModifiableFileWatcher
        org.gradle.internal.impldep.org.bouncycastle.jcajce.provider.asymmetric.edec.KeyFactorySpi$X25519 was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.bouncycastle.jcajce.provider.asymmetric.edec.KeyFactorySpi$X25519 got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.bouncycastle.jcajce.provider.asymmetric.edec.KeyFactorySpi$X25519
org.gradle.internal.impldep.org.bouncycastle.jcajce.provider.asymmetric.edec.KeyFactorySpi$X448 was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.bouncycastle.jcajce.provider.asymmetric.edec.KeyFactorySpi$X448 got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.bouncycastle.jcajce.provider.asymmetric.edec.KeyFactorySpi$X448
org.gradle.internal.impldep.org.bouncycastle.jcajce.provider.asymmetric.edec.KeyFactorySpi$Ed25519 was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.bouncycastle.jcajce.provider.asymmetric.edec.KeyFactorySpi$Ed25519 got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.bouncycastle.jcajce.provider.asymmetric.edec.KeyFactorySpi$Ed25519
org.gradle.internal.impldep.org.apache.sshd.common.compression.BuiltinCompressions was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.compression.BuiltinCompressions got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.compression.BuiltinCompressions
        org.gradle.internal.impldep.org.apache.sshd.common.cipher.BuiltinCiphers$6 was unintentionally initialized at build time. org.gradle.internal.impldep.org.apache.sshd.common.BaseBuilder caused initialization of this class with the following trace:
at org.gradle.internal.impldep.org.apache.sshd.common.cipher.BuiltinCiphers$6.<clinit>(BuiltinCiphers.java)
at org.gradle.internal.impldep.org.apache.sshd.common.cipher.BuiltinCiphers.<clinit>(BuiltinCiphers.java:105)
at org.gradle.internal.impldep.org.apache.sshd.common.BaseBuilder.<clinit>(BaseBuilder.java:72)

org.gradle.internal.impldep.org.bouncycastle.asn1.gm.GMObjectIdentifiers was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.bouncycastle.asn1.gm.GMObjectIdentifiers got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.bouncycastle.asn1.gm.GMObjectIdentifiers
        org.gradle.internal.impldep.org.apache.sshd.common.session.helpers.AbstractConnectionServiceRequestHandler was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.session.helpers.AbstractConnectionServiceRequestHandler got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.session.helpers.AbstractConnectionServiceRequestHandler
        org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$4 was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$4 got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$4
org.gradle.internal.impldep.org.apache.sshd.common.forward.DefaultForwarderFactory was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.forward.DefaultForwarderFactory got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.forward.DefaultForwarderFactory
        org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$17 was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$17 got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$17
org.gradle.internal.impldep.org.apache.sshd.common.util.buffer.keys.DSSBufferPublicKeyParser was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.util.buffer.keys.DSSBufferPublicKeyParser got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.util.buffer.keys.DSSBufferPublicKeyParser
        org.gradle.internal.impldep.org.apache.sshd.client.config.keys.ClientIdentity was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.client.config.keys.ClientIdentity got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.client.config.keys.ClientIdentity
        org.gradle.internal.impldep.org.bouncycastle.asn1.isara.IsaraObjectIdentifiers was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.bouncycastle.asn1.isara.IsaraObjectIdentifiers got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.bouncycastle.asn1.isara.IsaraObjectIdentifiers
        org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories$6 was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories$6 got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories$6
org.gradle.internal.impldep.org.apache.sshd.common.config.keys.BuiltinIdentities$1 was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.config.keys.BuiltinIdentities$1 got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.config.keys.BuiltinIdentities$1
org.gradle.internal.impldep.org.apache.sshd.server.forward.ForwardedTcpipFactory was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.server.forward.ForwardedTcpipFactory got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.server.forward.ForwardedTcpipFactory
        org.gradle.internal.impldep.org.apache.sshd.client.config.hosts.ConfigFileHostEntryResolver was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.client.config.hosts.ConfigFileHostEntryResolver got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.client.config.hosts.ConfigFileHostEntryResolver
        org.gradle.internal.impldep.org.apache.sshd.common.util.buffer.keys.BufferPublicKeyParser was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.util.buffer.keys.BufferPublicKeyParser got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.util.buffer.keys.BufferPublicKeyParser
        org.gradle.internal.impldep.org.apache.sshd.common.global.AbstractOpenSshHostKeysHandler was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.global.AbstractOpenSshHostKeysHandler got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.global.AbstractOpenSshHostKeysHandler
        org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories$3 was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories$3 got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories$3
org.gradle.internal.impldep.org.apache.sshd.common.cipher.BuiltinCiphers$5 was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.cipher.BuiltinCiphers$5 got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.cipher.BuiltinCiphers$5
org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$13 was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$13 got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$13
org.gradle.internal.impldep.org.apache.sshd.common.forward.DefaultForwarderFactory$1 was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.forward.DefaultForwarderFactory$1 got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.forward.DefaultForwarderFactory$1
org.gradle.internal.impldep.org.apache.sshd.common.keyprovider.KeyPairProvider was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.keyprovider.KeyPairProvider got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.keyprovider.KeyPairProvider
        org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$5 was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$5 got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$5
org.gradle.internal.impldep.org.apache.sshd.common.mac.BuiltinMacs$3 was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.mac.BuiltinMacs$3 got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.mac.BuiltinMacs$3
org.gradle.internal.impldep.org.apache.sshd.common.io.DefaultIoServiceFactoryFactory was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.io.DefaultIoServiceFactoryFactory got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.io.DefaultIoServiceFactoryFactory
        org.gradle.internal.impldep.org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers
        org.gradle.internal.impldep.org.bouncycastle.asn1.edec.EdECObjectIdentifiers was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.bouncycastle.asn1.edec.EdECObjectIdentifiers got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.bouncycastle.asn1.edec.EdECObjectIdentifiers
        org.gradle.internal.impldep.org.bouncycastle.jcajce.provider.asymmetric.edec.KeyFactorySpi$Ed448 was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.bouncycastle.jcajce.provider.asymmetric.edec.KeyFactorySpi$Ed448 got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.bouncycastle.jcajce.provider.asymmetric.edec.KeyFactorySpi$Ed448
org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories$15 was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories$15 got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories$15
To see how the classes got initialized, use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories$8,org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$10,org.gradle.internal.time.Time,org.gradle.internal.impldep.org.apache.sshd.server.forward.RejectAllForwardingFilter,org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$6,org.slf4j.LoggerFactory,org.gradle.internal.impldep.org.apache.sshd.client.config.hosts.HostConfigEntry$LazyDefaultConfigFileHolder,org.gradle.internal.impldep.org.apache.sshd.client.config.hosts.HostPatternsHolder,org.gradle.internal.impldep.org.apache.sshd.common.util.buffer.keys.RSABufferPublicKeyParser,org.gradle.internal.impldep.org.apache.sshd.common.session.helpers.DefaultUnknownChannelReferenceHandler,org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures,org.gradle.internal.impldep.org.bouncycastle.util.Strings,org.gradle.internal.impldep.org.apache.sshd.client.config.keys.ClientIdentityFileWatcher,org.gradle.internal.impldep.org.apache.sshd.common.kex.MontgomeryCurve,org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories$14,org.gradle.internal.impldep.org.apache.sshd.common.mac.BuiltinMacs,org.gradle.internal.impldep.org.apache.sshd.common.util.buffer.keys.OpenSSHCertPublicKeyParser,org.gradle.internal.impldep.org.apache.sshd.common.cipher.BuiltinCiphers$4,org.gradle.internal.impldep.org.apache.sshd.common.compression.BuiltinCompressions$1,org.gradle.internal.impldep.org.apache.sshd.common.SyspropsMapWrapper,org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories$11,org.gradle.internal.impldep.org.apache.sshd.client.config.keys.ClientIdentitiesWatcher,org.gradle.internal.impldep.org.apache.sshd.common.keyprovider.KeyPairProvider$1,org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$14,org.gradle.internal.impldep.org.apache.sshd.common.config.keys.PublicKeyEntry$LazyDefaultKeysFolderHolder,org.gradle.internal.impldep.org.apache.sshd.common.NamedResource,org.gradle.internal.logging.slf4j.OutputEventListenerBackedLoggerContext,org.gradle.internal.impldep.org.bouncycastle.jcajce.provider.drbg.DRBG,org.gradle.internal.impldep.org.apache.sshd.common.util.threads.ThreadUtils,org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories$13,org.gradle.internal.impldep.org.bouncycastle.asn1.ua.UAObjectIdentifiers,org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$8,org.gradle.internal.impldep.org.bouncycastle.util.Properties,org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$1,org.gradle.internal.impldep.org.apache.sshd.common.util.NumberUtils,org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$18,org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$3,org.gradle.internal.impldep.org.apache.sshd.common.util.security.SecurityProviderRegistrar,org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$7,org.gradle.internal.impldep.org.apache.sshd.common.kex.extension.DefaultClientKexExtensionHandler,org.gradle.internal.impldep.org.bouncycastle.jcajce.provider.asymmetric.dsa.DSAUtil,org.gradle.internal.impldep.org.bouncycastle.asn1.nist.NISTObjectIdentifiers,org.gradle.internal.impldep.org.apache.sshd.common.util.io.IoUtils,org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories$10,org.gradle.internal.impldep.org.apache.sshd.common.config.keys.PublicKeyEntry,org.gradle.internal.impldep.org.apache.sshd.common.util.buffer.keys.SkECBufferPublicKeyParser,org.gradle.internal.impldep.org.apache.sshd.common.keyprovider.AbstractKeyPairProvider,org.gradle.internal.impldep.org.bouncycastle.asn1.x509.X509ObjectIdentifiers,org.gradle.internal.impldep.org.apache.sshd.common.util.EventListenerUtils,org.gradle.internal.impldep.org.apache.sshd.common.PropertyResolverUtils,org.gradle.internal.impldep.org.bouncycastle.pqc.asn1.PQCObjectIdentifiers,org.gradle.internal.impldep.org.apache.sshd.common.config.keys.BuiltinIdentities$2,org.gradle.internal.impldep.org.apache.sshd.common.config.keys.BuiltinIdentities,org.gradle.internal.impldep.org.bouncycastle.asn1.gnu.GNUObjectIdentifiers,org.gradle.internal.impldep.org.apache.sshd.common.cipher.ECCurves,org.gradle.internal.impldep.org.bouncycastle.jcajce.provider.asymmetric.COMPOSITE,org.gradle.internal.impldep.org.apache.sshd.common.util.io.PathUtils,org.gradle.internal.impldep.org.apache.sshd.common.util.io.PathUtils$LazyDefaultUserHomeFolderHolder,org.gradle.internal.impldep.org.apache.sshd.common.compression.BuiltinCompressions$2,org.gradle.internal.impldep.org.apache.sshd.client.config.hosts.DefaultConfigFileHostEntryResolver,org.gradle.internal.impldep.org.bouncycastle.asn1.iso.ISOIECObjectIdentifiers,org.gradle.internal.impldep.org.apache.sshd.common.mac.BuiltinMacs$1,org.gradle.internal.time.MonotonicClock,org.gradle.internal.impldep.org.bouncycastle.asn1.sec.SECObjectIdentifiers,org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$2,org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories$1,org.gradle.internal.impldep.org.bouncycastle.crypto.CryptoServicesRegistrar,org.gradle.internal.impldep.org.bouncycastle.crypto.engines.RSABlindedEngine,org.gradle.internal.impldep.org.bouncycastle.jce.provider.BouncyCastleProvider,org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$9,org.gradle.internal.impldep.org.apache.sshd.common.util.buffer.keys.ED25519BufferPublicKeyParser,org.gradle.internal.impldep.org.bouncycastle.jce.provider.BouncyCastleProviderConfiguration,org.gradle.internal.impldep.org.apache.sshd.common.cipher.BuiltinCiphers$1,org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$16,org.gradle.internal.impldep.org.apache.sshd.client.auth.AuthenticationIdentitiesProvider,org.gradle.internal.impldep.org.apache.sshd.client.global.OpenSshHostKeysHandler,org.gradle.internal.impldep.org.apache.sshd.common.io.DefaultIoServiceFactoryFactory$LazyDefaultIoServiceFactoryFactoryHolder,org.gradle.internal.impldep.org.bouncycastle.asn1.x9.X9ObjectIdentifiers,org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$15,org.gradle.internal.impldep.org.apache.sshd.server.forward.TcpForwardingFilter$Type,org.gradle.internal.impldep.org.bouncycastle.jcajce.provider.asymmetric.edec.KeyFactorySpi,org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$11,org.gradle.internal.impldep.org.apache.sshd.client.config.hosts.HostConfigEntry,org.gradle.internal.impldep.org.apache.sshd.client.ClientBuilder,org.gradle.internal.impldep.org.apache.sshd.common.digest.BuiltinDigests,org.gradle.internal.impldep.org.apache.sshd.common.util.security.SecurityUtils,org.gradle.internal.impldep.org.apache.sshd.common.util.OsUtils,org.gradle.internal.impldep.org.apache.sshd.common.io.BuiltinIoServiceFactoryFactories,org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories$9,org.gradle.internal.impldep.org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers,org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories$2,org.gradle.internal.impldep.org.apache.sshd.client.keyverifier.AcceptAllServerKeyVerifier,org.gradle.internal.impldep.org.apache.sshd.common.cipher.BuiltinCiphers,org.gradle.internal.impldep.org.apache.sshd.common.util.MapEntryUtils,org.slf4j.impl.StaticLoggerBinder,org.gradle.internal.impldep.org.apache.sshd.common.file.nativefs.NativeFileSystemFactory,org.gradle.internal.impldep.org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers,org.gradle.internal.impldep.org.bouncycastle.jcajce.provider.symmetric.AES,org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories$5,org.gradle.internal.impldep.org.apache.sshd.common.util.buffer.keys.ECBufferPublicKeyParser,org.gradle.internal.impldep.org.apache.sshd.common.cipher.BuiltinCiphers$3,org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories$7,org.gradle.internal.impldep.org.apache.sshd.common.session.ConnectionServiceRequestHandler,org.gradle.internal.impldep.org.bouncycastle.asn1.rosstandart.RosstandartObjectIdentifiers,org.gradle.internal.impldep.org.apache.sshd.client.config.keys.DefaultClientIdentitiesWatcher,org.gradle.internal.impldep.org.apache.sshd.common.util.ReflectionUtils,org.gradle.internal.impldep.org.apache.sshd.common.cipher.BuiltinCiphers$2,org.gradle.internal.impldep.org.apache.sshd.common.compression.BuiltinCompressions$3,org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories,org.gradle.internal.impldep.org.apache.sshd.client.config.keys.BuiltinClientIdentitiesWatcher,org.gradle.internal.impldep.org.bouncycastle.asn1.oiw.OIWObjectIdentifiers,org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories$12,org.gradle.internal.impldep.org.apache.sshd.common.util.security.bouncycastle.BouncyCastleRandomFactory,org.gradle.internal.impldep.org.apache.sshd.common.util.buffer.keys.SkED25519BufferPublicKeyParser,org.gradle.internal.impldep.org.bouncycastle.asn1.bc.BCObjectIdentifiers,org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$12,org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories$4,org.gradle.internal.impldep.org.apache.sshd.common.util.io.ModifiableFileWatcher,org.gradle.internal.impldep.org.bouncycastle.jcajce.provider.asymmetric.edec.KeyFactorySpi$X25519,org.gradle.internal.impldep.org.bouncycastle.jcajce.provider.asymmetric.edec.KeyFactorySpi$X448,org.gradle.internal.impldep.org.bouncycastle.jcajce.provider.asymmetric.edec.KeyFactorySpi$Ed25519,org.gradle.internal.impldep.org.apache.sshd.common.compression.BuiltinCompressions,org.gradle.internal.impldep.org.bouncycastle.asn1.gm.GMObjectIdentifiers,org.gradle.internal.impldep.org.apache.sshd.common.session.helpers.AbstractConnectionServiceRequestHandler,org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$4,org.gradle.internal.impldep.org.apache.sshd.common.forward.DefaultForwarderFactory,org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$17,org.gradle.internal.impldep.org.apache.sshd.common.util.buffer.keys.DSSBufferPublicKeyParser,org.gradle.internal.impldep.org.apache.sshd.client.config.keys.ClientIdentity,org.gradle.internal.impldep.org.bouncycastle.asn1.isara.IsaraObjectIdentifiers,org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories$6,org.gradle.internal.impldep.org.apache.sshd.common.config.keys.BuiltinIdentities$1,org.gradle.internal.impldep.org.apache.sshd.server.forward.ForwardedTcpipFactory,org.gradle.internal.impldep.org.apache.sshd.client.config.hosts.ConfigFileHostEntryResolver,org.gradle.internal.impldep.org.apache.sshd.common.util.buffer.keys.BufferPublicKeyParser,org.gradle.internal.impldep.org.apache.sshd.common.global.AbstractOpenSshHostKeysHandler,org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories$3,org.gradle.internal.impldep.org.apache.sshd.common.cipher.BuiltinCiphers$5,org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$13,org.gradle.internal.impldep.org.apache.sshd.common.forward.DefaultForwarderFactory$1,org.gradle.internal.impldep.org.apache.sshd.common.keyprovider.KeyPairProvider,org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$5,org.gradle.internal.impldep.org.apache.sshd.common.mac.BuiltinMacs$3,org.gradle.internal.impldep.org.apache.sshd.common.io.DefaultIoServiceFactoryFactory,org.gradle.internal.impldep.org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers,org.gradle.internal.impldep.org.bouncycastle.asn1.edec.EdECObjectIdentifiers,org.gradle.internal.impldep.org.bouncycastle.jcajce.provider.asymmetric.edec.KeyFactorySpi$Ed448,org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories$15
com.oracle.svm.core.util.UserError$UserException: Classes that should be initialized at run time got initialized during image building:
org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories$8 was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories$8 got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories$8
org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$10 was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$10 got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$10
org.gradle.internal.time.Time was unintentionally initialized at build time. To see why org.gradle.internal.time.Time got initialized use --trace-class-initialization=org.gradle.internal.time.Time
        org.gradle.internal.impldep.org.apache.sshd.server.forward.RejectAllForwardingFilter was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.server.forward.RejectAllForwardingFilter got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.server.forward.RejectAllForwardingFilter
        org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$6 was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$6 got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$6
org.slf4j.LoggerFactory was unintentionally initialized at build time. To see why org.slf4j.LoggerFactory got initialized use --trace-class-initialization=org.slf4j.LoggerFactory
        org.gradle.internal.impldep.org.apache.sshd.client.config.hosts.HostConfigEntry$LazyDefaultConfigFileHolder was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.client.config.hosts.HostConfigEntry$LazyDefaultConfigFileHolder got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.client.config.hosts.HostConfigEntry$LazyDefaultConfigFileHolder
org.gradle.internal.impldep.org.apache.sshd.client.config.hosts.HostPatternsHolder was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.client.config.hosts.HostPatternsHolder got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.client.config.hosts.HostPatternsHolder
        org.gradle.internal.impldep.org.apache.sshd.common.util.buffer.keys.RSABufferPublicKeyParser was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.util.buffer.keys.RSABufferPublicKeyParser got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.util.buffer.keys.RSABufferPublicKeyParser
        org.gradle.internal.impldep.org.apache.sshd.common.session.helpers.DefaultUnknownChannelReferenceHandler was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.session.helpers.DefaultUnknownChannelReferenceHandler got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.session.helpers.DefaultUnknownChannelReferenceHandler
        org.gradle.internal.impldep.org.apache.sshd.common.mac.BuiltinMacs$2 was unintentionally initialized at build time. org.gradle.internal.impldep.org.apache.sshd.common.BaseBuilder caused initialization of this class with the following trace:
at org.gradle.internal.impldep.org.apache.sshd.common.mac.BuiltinMacs$2.<clinit>(BuiltinMacs.java)
at org.gradle.internal.impldep.org.apache.sshd.common.mac.BuiltinMacs.<clinit>(BuiltinMacs.java:73)
at org.gradle.internal.impldep.org.apache.sshd.common.BaseBuilder.<clinit>(BaseBuilder.java:109)

org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures
        org.gradle.internal.impldep.org.bouncycastle.util.Strings was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.bouncycastle.util.Strings got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.bouncycastle.util.Strings
        org.gradle.internal.impldep.org.apache.sshd.client.config.keys.ClientIdentityFileWatcher was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.client.config.keys.ClientIdentityFileWatcher got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.client.config.keys.ClientIdentityFileWatcher
        org.gradle.internal.impldep.org.apache.sshd.common.kex.MontgomeryCurve was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.kex.MontgomeryCurve got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.kex.MontgomeryCurve
        org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories$14 was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories$14 got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories$14
org.gradle.internal.impldep.org.apache.sshd.common.mac.BuiltinMacs was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.mac.BuiltinMacs got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.mac.BuiltinMacs
        org.gradle.internal.impldep.org.apache.sshd.common.util.buffer.keys.OpenSSHCertPublicKeyParser was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.util.buffer.keys.OpenSSHCertPublicKeyParser got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.util.buffer.keys.OpenSSHCertPublicKeyParser
        org.gradle.internal.impldep.org.apache.sshd.common.cipher.BuiltinCiphers$4 was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.cipher.BuiltinCiphers$4 got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.cipher.BuiltinCiphers$4
org.gradle.internal.impldep.org.apache.sshd.common.compression.BuiltinCompressions$1 was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.compression.BuiltinCompressions$1 got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.compression.BuiltinCompressions$1
org.gradle.internal.impldep.org.apache.sshd.common.SyspropsMapWrapper was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.SyspropsMapWrapper got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.SyspropsMapWrapper
        org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories$11 was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories$11 got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories$11
org.gradle.internal.impldep.org.apache.sshd.client.config.keys.ClientIdentitiesWatcher was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.client.config.keys.ClientIdentitiesWatcher got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.client.config.keys.ClientIdentitiesWatcher
        org.gradle.internal.impldep.org.apache.sshd.common.keyprovider.KeyPairProvider$1 was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.keyprovider.KeyPairProvider$1 got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.keyprovider.KeyPairProvider$1
org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$14 was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$14 got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$14
org.gradle.internal.impldep.org.apache.sshd.common.config.keys.PublicKeyEntry$LazyDefaultKeysFolderHolder was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.config.keys.PublicKeyEntry$LazyDefaultKeysFolderHolder got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.config.keys.PublicKeyEntry$LazyDefaultKeysFolderHolder
org.gradle.internal.impldep.org.apache.sshd.common.NamedResource was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.NamedResource got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.NamedResource
        org.gradle.internal.logging.slf4j.OutputEventListenerBackedLoggerContext was unintentionally initialized at build time. To see why org.gradle.internal.logging.slf4j.OutputEventListenerBackedLoggerContext got initialized use --trace-class-initialization=org.gradle.internal.logging.slf4j.OutputEventListenerBackedLoggerContext
        org.gradle.internal.impldep.org.bouncycastle.jcajce.provider.drbg.DRBG was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.bouncycastle.jcajce.provider.drbg.DRBG got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.bouncycastle.jcajce.provider.drbg.DRBG
        ------------------------------------------------------------------------------------------------------------------------
        org.gradle.internal.impldep.org.apache.sshd.common.util.threads.ThreadUtils was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.util.threads.ThreadUtils got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.util.threads.ThreadUtils
        org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories$13 was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories$13 got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories$13
org.gradle.internal.impldep.org.bouncycastle.asn1.ua.UAObjectIdentifiers was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.bouncycastle.asn1.ua.UAObjectIdentifiers got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.bouncycastle.asn1.ua.UAObjectIdentifiers
        org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$8 was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$8 got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$8
org.gradle.internal.impldep.org.bouncycastle.util.Properties was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.bouncycastle.util.Properties got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.bouncycastle.util.Properties
        org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$1 was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$1 got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$1
org.gradle.internal.impldep.org.apache.sshd.common.util.NumberUtils was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.util.NumberUtils got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.util.NumberUtils
        org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$18 was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$18 got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$18
org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$3 was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$3 got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$3
org.gradle.internal.impldep.org.apache.sshd.common.util.security.SecurityProviderRegistrar was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.util.security.SecurityProviderRegistrar got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.util.security.SecurityProviderRegistrar
        org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$7 was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$7 got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$7
org.gradle.internal.impldep.org.apache.sshd.common.kex.extension.DefaultClientKexExtensionHandler was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.kex.extension.DefaultClientKexExtensionHandler got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.kex.extension.DefaultClientKexExtensionHandler
        org.gradle.internal.impldep.org.bouncycastle.jcajce.provider.asymmetric.dsa.DSAUtil was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.bouncycastle.jcajce.provider.asymmetric.dsa.DSAUtil got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.bouncycastle.jcajce.provider.asymmetric.dsa.DSAUtil
        org.gradle.internal.impldep.org.bouncycastle.asn1.nist.NISTObjectIdentifiers was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.bouncycastle.asn1.nist.NISTObjectIdentifiers got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.bouncycastle.asn1.nist.NISTObjectIdentifiers
        org.gradle.internal.impldep.org.apache.sshd.common.util.io.IoUtils was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.util.io.IoUtils got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.util.io.IoUtils
        org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories$10 was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories$10 got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories$10
org.gradle.internal.impldep.org.apache.sshd.common.config.keys.PublicKeyEntry was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.config.keys.PublicKeyEntry got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.config.keys.PublicKeyEntry
        org.gradle.internal.impldep.org.apache.sshd.common.util.buffer.keys.SkECBufferPublicKeyParser was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.util.buffer.keys.SkECBufferPublicKeyParser got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.util.buffer.keys.SkECBufferPublicKeyParser
        org.gradle.internal.impldep.org.apache.sshd.common.keyprovider.AbstractKeyPairProvider was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.keyprovider.AbstractKeyPairProvider got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.keyprovider.AbstractKeyPairProvider
        org.gradle.internal.impldep.org.bouncycastle.asn1.x509.X509ObjectIdentifiers was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.bouncycastle.asn1.x509.X509ObjectIdentifiers got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.bouncycastle.asn1.x509.X509ObjectIdentifiers
        org.gradle.internal.impldep.org.apache.sshd.common.util.EventListenerUtils was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.util.EventListenerUtils got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.util.EventListenerUtils
        org.gradle.internal.impldep.org.apache.sshd.common.PropertyResolverUtils was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.PropertyResolverUtils got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.PropertyResolverUtils
        org.gradle.internal.impldep.org.bouncycastle.pqc.asn1.PQCObjectIdentifiers was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.bouncycastle.pqc.asn1.PQCObjectIdentifiers got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.bouncycastle.pqc.asn1.PQCObjectIdentifiers
        org.gradle.internal.impldep.org.apache.sshd.common.config.keys.BuiltinIdentities$2 was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.config.keys.BuiltinIdentities$2 got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.config.keys.BuiltinIdentities$2
org.gradle.internal.impldep.org.apache.sshd.common.config.keys.BuiltinIdentities was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.config.keys.BuiltinIdentities got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.config.keys.BuiltinIdentities
        org.gradle.internal.impldep.org.bouncycastle.asn1.gnu.GNUObjectIdentifiers was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.bouncycastle.asn1.gnu.GNUObjectIdentifiers got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.bouncycastle.asn1.gnu.GNUObjectIdentifiers
        org.gradle.internal.impldep.org.apache.sshd.common.cipher.ECCurves was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.cipher.ECCurves got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.cipher.ECCurves
        org.gradle.internal.impldep.org.bouncycastle.jcajce.provider.asymmetric.COMPOSITE was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.bouncycastle.jcajce.provider.asymmetric.COMPOSITE got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.bouncycastle.jcajce.provider.asymmetric.COMPOSITE
        org.gradle.internal.impldep.org.apache.sshd.common.util.io.PathUtils was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.util.io.PathUtils got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.util.io.PathUtils
        org.gradle.internal.impldep.org.apache.sshd.common.util.io.PathUtils$LazyDefaultUserHomeFolderHolder was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.util.io.PathUtils$LazyDefaultUserHomeFolderHolder got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.util.io.PathUtils$LazyDefaultUserHomeFolderHolder
org.gradle.internal.impldep.org.apache.sshd.common.compression.BuiltinCompressions$2 was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.compression.BuiltinCompressions$2 got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.compression.BuiltinCompressions$2
org.gradle.internal.impldep.org.apache.sshd.client.config.hosts.DefaultConfigFileHostEntryResolver was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.client.config.hosts.DefaultConfigFileHostEntryResolver got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.client.config.hosts.DefaultConfigFileHostEntryResolver
        org.gradle.internal.impldep.org.bouncycastle.asn1.iso.ISOIECObjectIdentifiers was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.bouncycastle.asn1.iso.ISOIECObjectIdentifiers got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.bouncycastle.asn1.iso.ISOIECObjectIdentifiers
        org.gradle.internal.impldep.org.apache.sshd.sftp.client.fs.SftpFileSystemProvider was unintentionally initialized at build time. org.gradle.internal.impldep.org.apache.sshd.sftp.client.fs.SftpFileSystemProvider caused initialization of this class with the following trace:
at org.gradle.internal.impldep.org.apache.sshd.sftp.client.fs.SftpFileSystemProvider.<clinit>(SftpFileSystemProvider.java:128)
at jdk.internal.reflect.NativeConstructorAccessorImpl.newInstance0(Unknown Source)
at jdk.internal.reflect.NativeConstructorAccessorImpl.newInstance(NativeConstructorAccessorImpl.java:77)
at jdk.internal.reflect.DelegatingConstructorAccessorImpl.newInstance(DelegatingConstructorAccessorImpl.java:45)
at java.lang.reflect.Constructor.newInstanceWithCaller(Constructor.java:499)
at java.lang.reflect.Constructor.newInstance(Constructor.java:480)
at java.util.ServiceLoader$ProviderImpl.newInstance(ServiceLoader.java:789)
at java.util.ServiceLoader$ProviderImpl.get(ServiceLoader.java:729)
at java.util.ServiceLoader$3.next(ServiceLoader.java:1403)
at java.nio.file.spi.FileSystemProvider.loadInstalledProviders(FileSystemProvider.java:156)
at java.nio.file.spi.FileSystemProvider$1.run(FileSystemProvider.java:207)
at java.nio.file.spi.FileSystemProvider$1.run(FileSystemProvider.java:204)
at java.security.AccessController.executePrivileged(AccessController.java:776)
at java.security.AccessController.doPrivileged(AccessController.java:318)
at java.nio.file.spi.FileSystemProvider.installedProviders(FileSystemProvider.java:204)
at java.nio.file.FileSystems.newFileSystem(FileSystems.java:336)
at java.nio.file.FileSystems.newFileSystem(FileSystems.java:288)
at com.oracle.svm.hosted.NativeImageClassLoaderSupport$LoadClassHandler.loadClassesFromPath(NativeImageClassLoaderSupport.java:664)
at com.oracle.svm.hosted.NativeImageClassLoaderSupport$LoadClassHandler$$Lambda$211/0x00000098002ffa40.accept(Unknown Source)
at java.util.stream.ForEachOps$ForEachOp$OfRef.accept(ForEachOps.java:183)
at java.util.ArrayList$ArrayListSpliterator.forEachRemaining(ArrayList.java:1625)
at java.util.stream.AbstractPipeline.copyInto(AbstractPipeline.java:509)
at java.util.stream.ForEachOps$ForEachTask.compute(ForEachOps.java:290)
at java.util.concurrent.CountedCompleter.exec(CountedCompleter.java:754)
at java.util.concurrent.ForkJoinTask.doExec(ForkJoinTask.java:373)
at java.util.concurrent.ForkJoinTask.invoke(ForkJoinTask.java:686)
at java.util.stream.ForEachOps$ForEachOp.evaluateParallel(ForEachOps.java:159)
at java.util.stream.ForEachOps$ForEachOp$OfRef.evaluateParallel(ForEachOps.java:173)
at java.util.stream.AbstractPipeline.evaluate(AbstractPipeline.java:233)
at java.util.stream.ReferencePipeline.forEach(ReferencePipeline.java:596)
at java.util.stream.ReferencePipeline$Head.forEach(ReferencePipeline.java:765)
at com.oracle.svm.hosted.NativeImageClassLoaderSupport$LoadClassHandler.run(NativeImageClassLoaderSupport.java:624)
at com.oracle.svm.hosted.NativeImageClassLoaderSupport.loadAllClasses(NativeImageClassLoaderSupport.java:181)
at com.oracle.svm.hosted.ImageClassLoader.loadAllClasses(ImageClassLoader.java:100)
at com.oracle.svm.hosted.NativeImageGeneratorRunner.buildImage(NativeImageGeneratorRunner.java:296)
at com.oracle.svm.hosted.NativeImageGeneratorRunner.build(NativeImageGeneratorRunner.java:612)
at com.oracle.svm.hosted.NativeImageGeneratorRunner.start(NativeImageGeneratorRunner.java:134)
at com.oracle.svm.hosted.NativeImageGeneratorRunner.main(NativeImageGeneratorRunner.java:94)

org.gradle.internal.impldep.org.apache.sshd.common.mac.BuiltinMacs$1 was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.mac.BuiltinMacs$1 got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.mac.BuiltinMacs$1
org.gradle.internal.time.MonotonicClock was unintentionally initialized at build time. To see why org.gradle.internal.time.MonotonicClock got initialized use --trace-class-initialization=org.gradle.internal.time.MonotonicClock
        org.gradle.internal.impldep.org.bouncycastle.asn1.sec.SECObjectIdentifiers was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.bouncycastle.asn1.sec.SECObjectIdentifiers got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.bouncycastle.asn1.sec.SECObjectIdentifiers
        org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$2 was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$2 got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$2
org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories$1 was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories$1 got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories$1
org.gradle.internal.impldep.org.bouncycastle.crypto.CryptoServicesRegistrar was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.bouncycastle.crypto.CryptoServicesRegistrar got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.bouncycastle.crypto.CryptoServicesRegistrar
        org.gradle.internal.impldep.org.bouncycastle.crypto.engines.RSABlindedEngine was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.bouncycastle.crypto.engines.RSABlindedEngine got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.bouncycastle.crypto.engines.RSABlindedEngine
        org.gradle.internal.impldep.org.bouncycastle.jce.provider.BouncyCastleProvider was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.bouncycastle.jce.provider.BouncyCastleProvider got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.bouncycastle.jce.provider.BouncyCastleProvider
        org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$9 was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$9 got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$9
org.gradle.internal.impldep.org.apache.sshd.common.util.buffer.keys.ED25519BufferPublicKeyParser was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.util.buffer.keys.ED25519BufferPublicKeyParser got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.util.buffer.keys.ED25519BufferPublicKeyParser
        org.gradle.internal.impldep.org.bouncycastle.jce.provider.BouncyCastleProviderConfiguration was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.bouncycastle.jce.provider.BouncyCastleProviderConfiguration got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.bouncycastle.jce.provider.BouncyCastleProviderConfiguration
        org.gradle.internal.impldep.org.apache.sshd.common.cipher.BuiltinCiphers$1 was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.cipher.BuiltinCiphers$1 got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.cipher.BuiltinCiphers$1
org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$16 was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$16 got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$16
org.gradle.internal.impldep.org.apache.sshd.client.auth.AuthenticationIdentitiesProvider was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.client.auth.AuthenticationIdentitiesProvider got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.client.auth.AuthenticationIdentitiesProvider
        org.gradle.internal.impldep.org.apache.sshd.client.global.OpenSshHostKeysHandler was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.client.global.OpenSshHostKeysHandler got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.client.global.OpenSshHostKeysHandler
        org.gradle.internal.impldep.org.apache.sshd.common.io.DefaultIoServiceFactoryFactory$LazyDefaultIoServiceFactoryFactoryHolder was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.io.DefaultIoServiceFactoryFactory$LazyDefaultIoServiceFactoryFactoryHolder got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.io.DefaultIoServiceFactoryFactory$LazyDefaultIoServiceFactoryFactoryHolder
org.gradle.internal.impldep.org.bouncycastle.asn1.x9.X9ObjectIdentifiers was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.bouncycastle.asn1.x9.X9ObjectIdentifiers got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.bouncycastle.asn1.x9.X9ObjectIdentifiers
        org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$15 was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$15 got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$15
org.gradle.internal.impldep.org.apache.sshd.server.forward.TcpForwardingFilter$Type was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.server.forward.TcpForwardingFilter$Type got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.server.forward.TcpForwardingFilter$Type
org.gradle.internal.impldep.org.bouncycastle.jcajce.provider.asymmetric.edec.KeyFactorySpi was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.bouncycastle.jcajce.provider.asymmetric.edec.KeyFactorySpi got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.bouncycastle.jcajce.provider.asymmetric.edec.KeyFactorySpi
        org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$11 was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$11 got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$11
org.gradle.internal.impldep.org.apache.sshd.client.config.hosts.HostConfigEntry was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.client.config.hosts.HostConfigEntry got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.client.config.hosts.HostConfigEntry
        org.gradle.internal.impldep.org.apache.sshd.client.ClientBuilder was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.client.ClientBuilder got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.client.ClientBuilder
        org.gradle.internal.impldep.org.apache.sshd.common.digest.BuiltinDigests was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.digest.BuiltinDigests got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.digest.BuiltinDigests
        org.gradle.internal.impldep.org.apache.sshd.common.util.security.SecurityUtils was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.util.security.SecurityUtils got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.util.security.SecurityUtils
        org.gradle.internal.impldep.org.apache.sshd.common.util.OsUtils was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.util.OsUtils got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.util.OsUtils
        org.gradle.internal.impldep.org.apache.sshd.common.io.BuiltinIoServiceFactoryFactories was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.io.BuiltinIoServiceFactoryFactories got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.io.BuiltinIoServiceFactoryFactories
        org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories$9 was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories$9 got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories$9
org.gradle.internal.impldep.org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers
        org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories$2 was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories$2 got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories$2
org.gradle.internal.impldep.org.apache.sshd.client.keyverifier.AcceptAllServerKeyVerifier was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.client.keyverifier.AcceptAllServerKeyVerifier got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.client.keyverifier.AcceptAllServerKeyVerifier
        org.gradle.internal.impldep.org.apache.sshd.common.cipher.BuiltinCiphers was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.cipher.BuiltinCiphers got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.cipher.BuiltinCiphers
        org.gradle.internal.impldep.org.apache.sshd.common.util.MapEntryUtils was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.util.MapEntryUtils got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.util.MapEntryUtils
        org.slf4j.impl.StaticLoggerBinder was unintentionally initialized at build time. To see why org.slf4j.impl.StaticLoggerBinder got initialized use --trace-class-initialization=org.slf4j.impl.StaticLoggerBinder
        org.gradle.internal.impldep.org.apache.sshd.common.file.nativefs.NativeFileSystemFactory was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.file.nativefs.NativeFileSystemFactory got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.file.nativefs.NativeFileSystemFactory
        org.gradle.internal.impldep.org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers
        org.gradle.internal.impldep.org.bouncycastle.jcajce.provider.symmetric.AES was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.bouncycastle.jcajce.provider.symmetric.AES got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.bouncycastle.jcajce.provider.symmetric.AES
        org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories$5 was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories$5 got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories$5
org.gradle.internal.impldep.org.apache.sshd.common.util.buffer.keys.ECBufferPublicKeyParser was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.util.buffer.keys.ECBufferPublicKeyParser got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.util.buffer.keys.ECBufferPublicKeyParser
        org.gradle.internal.impldep.org.apache.sshd.common.cipher.BuiltinCiphers$3 was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.cipher.BuiltinCiphers$3 got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.cipher.BuiltinCiphers$3
org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories$7 was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories$7 got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories$7
org.gradle.internal.impldep.org.apache.sshd.common.session.ConnectionServiceRequestHandler was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.session.ConnectionServiceRequestHandler got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.session.ConnectionServiceRequestHandler
        org.gradle.internal.impldep.org.bouncycastle.asn1.rosstandart.RosstandartObjectIdentifiers was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.bouncycastle.asn1.rosstandart.RosstandartObjectIdentifiers got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.bouncycastle.asn1.rosstandart.RosstandartObjectIdentifiers
        org.gradle.internal.impldep.org.apache.sshd.client.config.keys.DefaultClientIdentitiesWatcher was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.client.config.keys.DefaultClientIdentitiesWatcher got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.client.config.keys.DefaultClientIdentitiesWatcher
        org.gradle.internal.impldep.org.apache.sshd.common.util.ReflectionUtils was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.util.ReflectionUtils got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.util.ReflectionUtils
        org.gradle.internal.impldep.org.apache.sshd.common.BaseBuilder was unintentionally initialized at build time. org.gradle.internal.impldep.org.apache.sshd.common.BaseBuilder caused initialization of this class with the following trace:
at org.gradle.internal.impldep.org.apache.sshd.common.BaseBuilder.<clinit>(BaseBuilder.java:62)
at org.gradle.internal.impldep.org.apache.sshd.client.SshClient.setUpDefaultClient(SshClient.java:974)
at org.gradle.internal.impldep.org.apache.sshd.sftp.client.fs.SftpFileSystemProvider.<init>(SftpFileSystemProvider.java:185)
at org.gradle.internal.impldep.org.apache.sshd.sftp.client.fs.SftpFileSystemProvider.<init>(SftpFileSystemProvider.java:160)
at org.gradle.internal.impldep.org.apache.sshd.sftp.client.fs.SftpFileSystemProvider.<init>(SftpFileSystemProvider.java:156)
at org.gradle.internal.impldep.org.apache.sshd.sftp.client.fs.SftpFileSystemProvider.<init>(SftpFileSystemProvider.java:152)
at org.gradle.internal.impldep.org.apache.sshd.sftp.client.fs.SftpFileSystemProvider.<init>(SftpFileSystemProvider.java:144)
at jdk.internal.reflect.NativeConstructorAccessorImpl.newInstance0(Unknown Source)
at jdk.internal.reflect.NativeConstructorAccessorImpl.newInstance(NativeConstructorAccessorImpl.java:77)
at jdk.internal.reflect.DelegatingConstructorAccessorImpl.newInstance(DelegatingConstructorAccessorImpl.java:45)
at java.lang.reflect.Constructor.newInstanceWithCaller(Constructor.java:499)
at java.lang.reflect.Constructor.newInstance(Constructor.java:480)
at java.util.ServiceLoader$ProviderImpl.newInstance(ServiceLoader.java:789)
at java.util.ServiceLoader$ProviderImpl.get(ServiceLoader.java:729)
at java.util.ServiceLoader$3.next(ServiceLoader.java:1403)
at java.nio.file.spi.FileSystemProvider.loadInstalledProviders(FileSystemProvider.java:156)
at java.nio.file.spi.FileSystemProvider$1.run(FileSystemProvider.java:207)
at java.nio.file.spi.FileSystemProvider$1.run(FileSystemProvider.java:204)
at java.security.AccessController.executePrivileged(AccessController.java:776)
at java.security.AccessController.doPrivileged(AccessController.java:318)
at java.nio.file.spi.FileSystemProvider.installedProviders(FileSystemProvider.java:204)
at java.nio.file.FileSystems.newFileSystem(FileSystems.java:336)
at java.nio.file.FileSystems.newFileSystem(FileSystems.java:288)
at com.oracle.svm.hosted.NativeImageClassLoaderSupport$LoadClassHandler.loadClassesFromPath(NativeImageClassLoaderSupport.java:664)
at com.oracle.svm.hosted.NativeImageClassLoaderSupport$LoadClassHandler$$Lambda$211/0x00000098002ffa40.accept(Unknown Source)
at java.util.stream.ForEachOps$ForEachOp$OfRef.accept(ForEachOps.java:183)
at java.util.ArrayList$ArrayListSpliterator.forEachRemaining(ArrayList.java:1625)
at java.util.stream.AbstractPipeline.copyInto(AbstractPipeline.java:509)
at java.util.stream.ForEachOps$ForEachTask.compute(ForEachOps.java:290)
at java.util.concurrent.CountedCompleter.exec(CountedCompleter.java:754)
at java.util.concurrent.ForkJoinTask.doExec(ForkJoinTask.java:373)
at java.util.concurrent.ForkJoinTask.invoke(ForkJoinTask.java:686)
at java.util.stream.ForEachOps$ForEachOp.evaluateParallel(ForEachOps.java:159)
at java.util.stream.ForEachOps$ForEachOp$OfRef.evaluateParallel(ForEachOps.java:173)
at java.util.stream.AbstractPipeline.evaluate(AbstractPipeline.java:233)
at java.util.stream.ReferencePipeline.forEach(ReferencePipeline.java:596)
at java.util.stream.ReferencePipeline$Head.forEach(ReferencePipeline.java:765)
at com.oracle.svm.hosted.NativeImageClassLoaderSupport$LoadClassHandler.run(NativeImageClassLoaderSupport.java:624)
at com.oracle.svm.hosted.NativeImageClassLoaderSupport.loadAllClasses(NativeImageClassLoaderSupport.java:181)
at com.oracle.svm.hosted.ImageClassLoader.loadAllClasses(ImageClassLoader.java:100)
at com.oracle.svm.hosted.NativeImageGeneratorRunner.buildImage(NativeImageGeneratorRunner.java:296)
at com.oracle.svm.hosted.NativeImageGeneratorRunner.build(NativeImageGeneratorRunner.java:612)
at com.oracle.svm.hosted.NativeImageGeneratorRunner.start(NativeImageGeneratorRunner.java:134)
at com.oracle.svm.hosted.NativeImageGeneratorRunner.main(NativeImageGeneratorRunner.java:94)

org.gradle.internal.impldep.org.apache.sshd.common.cipher.BuiltinCiphers$2 was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.cipher.BuiltinCiphers$2 got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.cipher.BuiltinCiphers$2
org.gradle.internal.impldep.org.apache.sshd.common.compression.BuiltinCompressions$3 was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.compression.BuiltinCompressions$3 got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.compression.BuiltinCompressions$3
org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories
        org.gradle.internal.impldep.org.apache.sshd.client.config.keys.BuiltinClientIdentitiesWatcher was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.client.config.keys.BuiltinClientIdentitiesWatcher got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.client.config.keys.BuiltinClientIdentitiesWatcher
        org.gradle.internal.impldep.org.bouncycastle.asn1.oiw.OIWObjectIdentifiers was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.bouncycastle.asn1.oiw.OIWObjectIdentifiers got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.bouncycastle.asn1.oiw.OIWObjectIdentifiers
        org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories$12 was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories$12 got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories$12
org.gradle.internal.impldep.org.apache.sshd.common.util.security.bouncycastle.BouncyCastleRandomFactory was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.util.security.bouncycastle.BouncyCastleRandomFactory got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.util.security.bouncycastle.BouncyCastleRandomFactory
        org.gradle.internal.impldep.org.apache.sshd.common.util.buffer.keys.SkED25519BufferPublicKeyParser was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.util.buffer.keys.SkED25519BufferPublicKeyParser got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.util.buffer.keys.SkED25519BufferPublicKeyParser
        org.gradle.internal.impldep.org.bouncycastle.asn1.bc.BCObjectIdentifiers was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.bouncycastle.asn1.bc.BCObjectIdentifiers got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.bouncycastle.asn1.bc.BCObjectIdentifiers
        org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$12 was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$12 got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$12
org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories$4 was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories$4 got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories$4
org.gradle.internal.impldep.org.apache.sshd.common.util.io.ModifiableFileWatcher was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.util.io.ModifiableFileWatcher got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.util.io.ModifiableFileWatcher
        org.gradle.internal.impldep.org.bouncycastle.jcajce.provider.asymmetric.edec.KeyFactorySpi$X25519 was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.bouncycastle.jcajce.provider.asymmetric.edec.KeyFactorySpi$X25519 got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.bouncycastle.jcajce.provider.asymmetric.edec.KeyFactorySpi$X25519
org.gradle.internal.impldep.org.bouncycastle.jcajce.provider.asymmetric.edec.KeyFactorySpi$X448 was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.bouncycastle.jcajce.provider.asymmetric.edec.KeyFactorySpi$X448 got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.bouncycastle.jcajce.provider.asymmetric.edec.KeyFactorySpi$X448
org.gradle.internal.impldep.org.bouncycastle.jcajce.provider.asymmetric.edec.KeyFactorySpi$Ed25519 was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.bouncycastle.jcajce.provider.asymmetric.edec.KeyFactorySpi$Ed25519 got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.bouncycastle.jcajce.provider.asymmetric.edec.KeyFactorySpi$Ed25519
org.gradle.internal.impldep.org.apache.sshd.common.compression.BuiltinCompressions was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.compression.BuiltinCompressions got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.compression.BuiltinCompressions
        org.gradle.internal.impldep.org.apache.sshd.common.cipher.BuiltinCiphers$6 was unintentionally initialized at build time. org.gradle.internal.impldep.org.apache.sshd.common.BaseBuilder caused initialization of this class with the following trace:
at org.gradle.internal.impldep.org.apache.sshd.common.cipher.BuiltinCiphers$6.<clinit>(BuiltinCiphers.java)
at org.gradle.internal.impldep.org.apache.sshd.common.cipher.BuiltinCiphers.<clinit>(BuiltinCiphers.java:105)
at org.gradle.internal.impldep.org.apache.sshd.common.BaseBuilder.<clinit>(BaseBuilder.java:72)

org.gradle.internal.impldep.org.bouncycastle.asn1.gm.GMObjectIdentifiers was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.bouncycastle.asn1.gm.GMObjectIdentifiers got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.bouncycastle.asn1.gm.GMObjectIdentifiers
        org.gradle.internal.impldep.org.apache.sshd.common.session.helpers.AbstractConnectionServiceRequestHandler was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.session.helpers.AbstractConnectionServiceRequestHandler got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.session.helpers.AbstractConnectionServiceRequestHandler
        org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$4 was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$4 got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$4
org.gradle.internal.impldep.org.apache.sshd.common.forward.DefaultForwarderFactory was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.forward.DefaultForwarderFactory got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.forward.DefaultForwarderFactory
        org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$17 was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$17 got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$17
org.gradle.internal.impldep.org.apache.sshd.common.util.buffer.keys.DSSBufferPublicKeyParser was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.util.buffer.keys.DSSBufferPublicKeyParser got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.util.buffer.keys.DSSBufferPublicKeyParser
        org.gradle.internal.impldep.org.apache.sshd.client.config.keys.ClientIdentity was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.client.config.keys.ClientIdentity got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.client.config.keys.ClientIdentity
        org.gradle.internal.impldep.org.bouncycastle.asn1.isara.IsaraObjectIdentifiers was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.bouncycastle.asn1.isara.IsaraObjectIdentifiers got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.bouncycastle.asn1.isara.IsaraObjectIdentifiers
        org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories$6 was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories$6 got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories$6
org.gradle.internal.impldep.org.apache.sshd.common.config.keys.BuiltinIdentities$1 was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.config.keys.BuiltinIdentities$1 got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.config.keys.BuiltinIdentities$1
org.gradle.internal.impldep.org.apache.sshd.server.forward.ForwardedTcpipFactory was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.server.forward.ForwardedTcpipFactory got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.server.forward.ForwardedTcpipFactory
        org.gradle.internal.impldep.org.apache.sshd.client.config.hosts.ConfigFileHostEntryResolver was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.client.config.hosts.ConfigFileHostEntryResolver got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.client.config.hosts.ConfigFileHostEntryResolver
        org.gradle.internal.impldep.org.apache.sshd.common.util.buffer.keys.BufferPublicKeyParser was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.util.buffer.keys.BufferPublicKeyParser got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.util.buffer.keys.BufferPublicKeyParser
        org.gradle.internal.impldep.org.apache.sshd.common.global.AbstractOpenSshHostKeysHandler was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.global.AbstractOpenSshHostKeysHandler got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.global.AbstractOpenSshHostKeysHandler
        org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories$3 was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories$3 got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories$3
org.gradle.internal.impldep.org.apache.sshd.common.cipher.BuiltinCiphers$5 was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.cipher.BuiltinCiphers$5 got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.cipher.BuiltinCiphers$5
org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$13 was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$13 got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$13
org.gradle.internal.impldep.org.apache.sshd.common.forward.DefaultForwarderFactory$1 was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.forward.DefaultForwarderFactory$1 got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.forward.DefaultForwarderFactory$1
org.gradle.internal.impldep.org.apache.sshd.common.keyprovider.KeyPairProvider was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.keyprovider.KeyPairProvider got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.keyprovider.KeyPairProvider
        org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$5 was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$5 got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$5
org.gradle.internal.impldep.org.apache.sshd.common.mac.BuiltinMacs$3 was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.mac.BuiltinMacs$3 got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.mac.BuiltinMacs$3
org.gradle.internal.impldep.org.apache.sshd.common.io.DefaultIoServiceFactoryFactory was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.io.DefaultIoServiceFactoryFactory got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.io.DefaultIoServiceFactoryFactory
        org.gradle.internal.impldep.org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers
        org.gradle.internal.impldep.org.bouncycastle.asn1.edec.EdECObjectIdentifiers was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.bouncycastle.asn1.edec.EdECObjectIdentifiers got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.bouncycastle.asn1.edec.EdECObjectIdentifiers
        org.gradle.internal.impldep.org.bouncycastle.jcajce.provider.asymmetric.edec.KeyFactorySpi$Ed448 was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.bouncycastle.jcajce.provider.asymmetric.edec.KeyFactorySpi$Ed448 got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.bouncycastle.jcajce.provider.asymmetric.edec.KeyFactorySpi$Ed448
org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories$15 was unintentionally initialized at build time. To see why org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories$15 got initialized use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories$15
1.4s (7.0% of total time) in 31 GCs | Peak RSS: 3.55GB | CPU load: 5.76To see how the classes got initialized, use --trace-class-initialization=org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories$8,org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$10,org.gradle.internal.time.Time,org.gradle.internal.impldep.org.apache.sshd.server.forward.RejectAllForwardingFilter,org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$6,org.slf4j.LoggerFactory,org.gradle.internal.impldep.org.apache.sshd.client.config.hosts.HostConfigEntry$LazyDefaultConfigFileHolder,org.gradle.internal.impldep.org.apache.sshd.client.config.hosts.HostPatternsHolder,org.gradle.internal.impldep.org.apache.sshd.common.util.buffer.keys.RSABufferPublicKeyParser,org.gradle.internal.impldep.org.apache.sshd.common.session.helpers.DefaultUnknownChannelReferenceHandler,org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures,org.gradle.internal.impldep.org.bouncycastle.util.Strings,org.gradle.internal.impldep.org.apache.sshd.client.config.keys.ClientIdentityFileWatcher,org.gradle.internal.impldep.org.apache.sshd.common.kex.MontgomeryCurve,org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories$14,org.gradle.internal.impldep.org.apache.sshd.common.mac.BuiltinMacs,org.gradle.internal.impldep.org.apache.sshd.common.util.buffer.keys.OpenSSHCertPublicKeyParser,org.gradle.internal.impldep.org.apache.sshd.common.cipher.BuiltinCiphers$4,org.gradle.internal.impldep.org.apache.sshd.common.compression.BuiltinCompressions$1,org.gradle.internal.impldep.org.apache.sshd.common.SyspropsMapWrapper,org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories$11,org.gradle.internal.impldep.org.apache.sshd.client.config.keys.ClientIdentitiesWatcher,org.gradle.internal.impldep.org.apache.sshd.common.keyprovider.KeyPairProvider$1,org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$14,org.gradle.internal.impldep.org.apache.sshd.common.config.keys.PublicKeyEntry$LazyDefaultKeysFolderHolder,org.gradle.internal.impldep.org.apache.sshd.common.NamedResource,org.gradle.internal.logging.slf4j.OutputEventListenerBackedLoggerContext,org.gradle.internal.impldep.org.bouncycastle.jcajce.provider.drbg.DRBG,org.gradle.internal.impldep.org.apache.sshd.common.util.threads.ThreadUtils,org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories$13,org.gradle.internal.impldep.org.bouncycastle.asn1.ua.UAObjectIdentifiers,org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$8,org.gradle.internal.impldep.org.bouncycastle.util.Properties,org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$1,org.gradle.internal.impldep.org.apache.sshd.common.util.NumberUtils,org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$18,org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$3,org.gradle.internal.impldep.org.apache.sshd.common.util.security.SecurityProviderRegistrar,org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$7,org.gradle.internal.impldep.org.apache.sshd.common.kex.extension.DefaultClientKexExtensionHandler,org.gradle.internal.impldep.org.bouncycastle.jcajce.provider.asymmetric.dsa.DSAUtil,org.gradle.internal.impldep.org.bouncycastle.asn1.nist.NISTObjectIdentifiers,org.gradle.internal.impldep.org.apache.sshd.common.util.io.IoUtils,org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories$10,org.gradle.internal.impldep.org.apache.sshd.common.config.keys.PublicKeyEntry,org.gradle.internal.impldep.org.apache.sshd.common.util.buffer.keys.SkECBufferPublicKeyParser,org.gradle.internal.impldep.org.apache.sshd.common.keyprovider.AbstractKeyPairProvider,org.gradle.internal.impldep.org.bouncycastle.asn1.x509.X509ObjectIdentifiers,org.gradle.internal.impldep.org.apache.sshd.common.util.EventListenerUtils,org.gradle.internal.impldep.org.apache.sshd.common.PropertyResolverUtils,org.gradle.internal.impldep.org.bouncycastle.pqc.asn1.PQCObjectIdentifiers,org.gradle.internal.impldep.org.apache.sshd.common.config.keys.BuiltinIdentities$2,org.gradle.internal.impldep.org.apache.sshd.common.config.keys.BuiltinIdentities,org.gradle.internal.impldep.org.bouncycastle.asn1.gnu.GNUObjectIdentifiers,org.gradle.internal.impldep.org.apache.sshd.common.cipher.ECCurves,org.gradle.internal.impldep.org.bouncycastle.jcajce.provider.asymmetric.COMPOSITE,org.gradle.internal.impldep.org.apache.sshd.common.util.io.PathUtils,org.gradle.internal.impldep.org.apache.sshd.common.util.io.PathUtils$LazyDefaultUserHomeFolderHolder,org.gradle.internal.impldep.org.apache.sshd.common.compression.BuiltinCompressions$2,org.gradle.internal.impldep.org.apache.sshd.client.config.hosts.DefaultConfigFileHostEntryResolver,org.gradle.internal.impldep.org.bouncycastle.asn1.iso.ISOIECObjectIdentifiers,org.gradle.internal.impldep.org.apache.sshd.common.mac.BuiltinMacs$1,org.gradle.internal.time.MonotonicClock,org.gradle.internal.impldep.org.bouncycastle.asn1.sec.SECObjectIdentifiers,org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$2,org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories$1,org.gradle.internal.impldep.org.bouncycastle.crypto.CryptoServicesRegistrar,org.gradle.internal.impldep.org.bouncycastle.crypto.engines.RSABlindedEngine,org.gradle.internal.impldep.org.bouncycastle.jce.provider.BouncyCastleProvider,org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$9,org.gradle.internal.impldep.org.apache.sshd.common.util.buffer.keys.ED25519BufferPublicKeyParser,org.gradle.internal.impldep.org.bouncycastle.jce.provider.BouncyCastleProviderConfiguration,org.gradle.internal.impldep.org.apache.sshd.common.cipher.BuiltinCiphers$1,org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$16,org.gradle.internal.impldep.org.apache.sshd.client.auth.AuthenticationIdentitiesProvider,org.gradle.internal.impldep.org.apache.sshd.client.global.OpenSshHostKeysHandler,org.gradle.internal.impldep.org.apache.sshd.common.io.DefaultIoServiceFactoryFactory$LazyDefaultIoServiceFactoryFactoryHolder,org.gradle.
internal.impldep.org.bouncycastle.asn1.x9.X9ObjectIdentifiers,org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$15,org.gradle.internal.impldep.org.apache.sshd.server.forward.TcpForwardingFilter$Type,org.gradle.internal.impldep.org.bouncycastle.jcajce.provider.asymmetric.edec.KeyFactorySpi,org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$11,org.gradle.internal.impldep.org.apache.sshd.client.config.hosts.HostConfigEntry,org.gradle.internal.impldep.org.apache.sshd.client.ClientBuilder,org.gradle.internal.impldep.org.apache.sshd.common.digest.BuiltinDigests,org.gradle.internal.impldep.org.apache.sshd.common.util.security.SecurityUtils,org.gradle.internal.impldep.org.apache.sshd.common.util.OsUtils,org.gradle.internal.impldep.org.apache.sshd.common.io.BuiltinIoServiceFactoryFactories,org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories$9,org.gradle.internal.impldep.org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers,org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories$2,org.gradle.internal.impldep.org.apache.sshd.client.keyverifier.AcceptAllServerKeyVerifier,org.gradle.internal.impldep.org.apache.sshd.common.cipher.BuiltinCiphers,org.gradle.internal.impldep.org.apache.sshd.common.util.MapEntryUtils,org.slf4j.impl.StaticLoggerBinder,org.gradle.internal.impldep.org.apache.sshd.common.file.nativefs.NativeFileSystemFactory,org.gradle.internal.impldep.org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers,org.gradle.internal.impldep.org.bouncycastle.jcajce.provider.symmetric.AES,org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories$5,org.gradle.internal.impldep.org.apache.sshd.common.util.buffer.keys.ECBufferPublicKeyParser,org.gradle.internal.impldep.org.apache.sshd.common.cipher.BuiltinCiphers$3,org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories$7,org.gradle.internal.impldep.org.apache.sshd.common.session.ConnectionServiceRequestHandler,org.gradle.internal.impldep.org.bouncycastle.asn1.rosstandart.RosstandartObjectIdentifiers,org.gradle.internal.impldep.org.apache.sshd.client.config.keys.DefaultClientIdentitiesWatcher,org.gradle.internal.impldep.org.apache.sshd.common.util.ReflectionUtils,org.gradle.internal.impldep.org.apache.sshd.common.cipher.BuiltinCiphers$2,org.gradle.internal.impldep.org.apache.sshd.common.compression.BuiltinCompressions$3,org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories,org.gradle.internal.impldep.org.apache.sshd.client.config.keys.BuiltinClientIdentitiesWatcher,org.gradle.internal.impldep.org.bouncycastle.asn1.oiw.OIWObjectIdentifiers,org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories$12,org.gradle.internal.impldep.org.apache.sshd.common.util.security.bouncycastle.BouncyCastleRandomFactory,org.gradle.internal.impldep.org.apache.sshd.common.util.buffer.keys.SkED25519BufferPublicKeyParser,org.gradle.internal.impldep.org.bouncycastle.asn1.bc.BCObjectIdentifiers,org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$12,org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories$4,org.gradle.internal.impldep.org.apache.sshd.common.util.io.ModifiableFileWatcher,org.gradle.internal.impldep.org.bouncycastle.jcajce.provider.asymmetric.edec.KeyFactorySpi$X25519,org.gradle.internal.impldep.org.bouncycastle.jcajce.provider.asymmetric.edec.KeyFactorySpi$X448,org.gradle.internal.impldep.org.bouncycastle.jcajce.provider.asymmetric.edec.KeyFactorySpi$Ed25519,org.gradle.internal.impldep.org.apache.sshd.common.compression.BuiltinCompressions,org.gradle.internal.impldep.org.bouncycastle.asn1.gm.GMObjectIdentifiers,org.gradle.internal.impldep.org.apache.sshd.common.session.helpers.AbstractConnectionServiceRequestHandler,org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$4,org.gradle.internal.impldep.org.apache.sshd.common.forward.DefaultForwarderFactory,org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$17,org.gradle.internal.impldep.org.apache.sshd.common.util.buffer.keys.DSSBufferPublicKeyParser,org.gradle.internal.impldep.org.apache.sshd.client.config.keys.ClientIdentity,org.gradle.internal.impldep.org.bouncycastle.asn1.isara.IsaraObjectIdentifiers,org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories$6,org.gradle.internal.impldep.org.apache.sshd.common.config.keys.BuiltinIdentities$1,org.gradle.internal.impldep.org.apache.sshd.server.forward.ForwardedTcpipFactory,org.gradle.internal.impldep.org.apache.sshd.client.config.hosts.ConfigFileHostEntryResolver,org.gradle.internal.impldep.org.apache.sshd.common.util.buffer.keys.BufferPublicKeyParser,org.gradle.internal.impldep.org.apache.sshd.common.global.AbstractOpenSshHostKeysHandler,org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories$3,org.gradle.internal.impldep.org.apache.sshd.common.cipher.BuiltinCiphers$5,org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$13,org.gradle.internal.impldep.org.apache.sshd.common.forward.DefaultForwarderFactory$1,org.gradle.internal.impldep.org.apache.sshd.common.keyprovider.KeyPairProvider,org.gradle.internal.impldep.org.apache.sshd.common.signature.BuiltinSignatures$5,org.gradle.internal.impldep.org.apache.sshd.common.mac.BuiltinMacs$3,org.gradle.internal.impldep.org.apache.sshd.common.io.DefaultIoServiceFactoryFactory,org.gradle.internal.impldep.org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers,org.gradle.internal.impldep.org.bouncycastle.asn1.edec.EdECObjectIdentifiers,org.gradle.internal.impldep.org.bouncycastle.jcajce.provider.asymmetric.edec.KeyFactorySpi$Ed448,org.gradle.internal.impldep.org.apache.sshd.common.kex.BuiltinDHFactories$15
at org.graalvm.nativeimage.builder/com.oracle.svm.core.util.UserError.abort(UserError.java:73)
at org.graalvm.nativeimage.builder/com.oracle.svm.hosted.classinitialization.ProvenSafeClassInitializationSupport.checkDelayedInitialization(ProvenSafeClassInitializationSupport.java:277)
at org.graalvm.nativeimage.builder/com.oracle.svm.hosted.classinitialization.ClassInitializationFeature.duringAnalysis(ClassInitializationFeature.java:164)
at org.graalvm.nativeimage.builder/com.oracle.svm.hosted.NativeImageGenerator.lambda$runPointsToAnalysis$10(NativeImageGenerator.java:770)
at org.graalvm.nativeimage.builder/com.oracle.svm.hosted.FeatureHandler.forEachFeature(FeatureHandler.java:89)
at org.graalvm.nativeimage.builder/com.oracle.svm.hosted.NativeImageGenerator.lambda$runPointsToAnalysis$11(NativeImageGenerator.java:770)
at org.graalvm.nativeimage.pointsto/com.oracle.graal.pointsto.AbstractAnalysisEngine.runAnalysis(AbstractAnalysisEngine.java:179)
========================================================================================================================
Finished generating 'graal-8760' in 19.4s.
at org.graalvm.nativeimage.builder/com.oracle.svm.hosted.NativeImageGenerator.runPointsToAnalysis(NativeImageGenerator.java:767)
at org.graalvm.nativeimage.builder/com.oracle.svm.hosted.NativeImageGenerator.doRun(NativeImageGenerator.java:582)
at org.graalvm.nativeimage.builder/com.oracle.svm.hosted.NativeImageGenerator.run(NativeImageGenerator.java:539)
at org.graalvm.nativeimage.builder/com.oracle.svm.hosted.NativeImageGeneratorRunner.buildImage(NativeImageGeneratorRunner.java:408)
at org.graalvm.nativeimage.builder/com.oracle.svm.hosted.NativeImageGeneratorRunner.build(NativeImageGeneratorRunner.java:612)
at org.graalvm.nativeimage.builder/com.oracle.svm.hosted.NativeImageGeneratorRunner.start(NativeImageGeneratorRunner.java:134)
at org.graalvm.nativeimage.builder/com.oracle.svm.hosted.NativeImageGeneratorRunner.main(NativeImageGeneratorRunner.java:94)

> Task :nativeCompile FAILED

        FAILURE: Build failed with an exception.

* What went wrong:
Execution failed for task ':nativeCompile'.
> Process 'command '/Users/anugrah.singhal/.sdkman/candidates/java/17.0.9-graalce/bin/native-image'' finished with non-zero exit value 1

* Try:
> Run with --stacktrace option to get the stack trace.
> Run with --info or --debug option to get more log output.
> Run with --scan to get full insights.
> Get more help at https://help.gradle.org.

BUILD FAILED in 21s
        7 actionable tasks: 1 executed, 6 up-to-date
*/