import org.gradle.tooling.GradleConnector
import org.gradle.tooling.model.GradleProject
import java.io.*

class ToolingApi {

//    fun findAllTasks(projectLocation: String, taskGroup: String? = null): Collection<GradleTask> {
//        val connection = GradleConnector.newConnector()
//            .forProjectDirectory(File(projectLocation))
//            .connect()
//
//        val gradleProject = connection.use { it.getModel(GradleProject::class.java) }
//
//        val childProjectTasks = gradleProject.children.flatMap { it.tasks }
//
//        val gradleTasks = gradleProject.tasks + childProjectTasks
//
//        if (taskGroup != null) {
//            return gradleTasks.filter { it.group == taskGroup }
//        }
//
//        return gradleTasks
//    }

    fun findAllProjects(projectLocation: String): Collection<GradleProject> {
        val connection = GradleConnector.newConnector()
//            .useInstallation(File("/Users/anugrah.singhal/.gradle/wrapper/dists/gradle-8.7-bin/bhs2wmbdwecv87pi65oeuq5iu/gradle-8.7"))
            .forProjectDirectory(File(projectLocation))
            .connect()

        val model = connection.model(GradleProject::class.java)
//        model.withArguments("--debug")
//        model.withArguments("-Dorg.gradle.debug=true")
        val out = ByteArrayOutputStream()
        val err = ByteArrayOutputStream()
        model.withArguments("--info")
            .setStandardOutput(out)
            .setStandardError(err)

        val gradleProject = model.get()

        val gradleProjects = gradleProject.children + gradleProject

        println(out.toString("UTF-8"))
        System.err.println(err.toString("UTF-8"))

        return gradleProjects
    }

//    fun runTaskAndGetFailureReason(projectLocation: String, taskName: String): String {
//        val connection = GradleConnector.newConnector()
//            .forProjectDirectory(File(projectLocation))
//            .connect()
//
//        val errorStream = ByteArrayOutputStream()
//        val buildTasks = connection.newBuild().forTasks(taskName).setStandardError(errorStream)
//
//        try {
//            buildTasks.run()
//        } catch (e: Exception) {
//            // just return error stream for now
//            return errorStream.toString("UTF-8")
//        }
//
//        return "no-errors"
//    }
//
//    fun findPluginsAppliedToModule(projectLocation: String, moduleName: String): Collection<String>? {
//        val connection = GradleConnector.newConnector()
//            .forProjectDirectory(File(projectLocation))
//            .connect()
//
//        val customModelBuilder = connection.model(ConfigurationDependenciesModel::class.java)
//        customModelBuilder.withArguments("--init-script", copyInitScript().absolutePath)
//
//        // Fetch the custom model
//        val customModel: ConfigurationDependenciesModel = customModelBuilder.get()
//
//        val projectPluginMap = customModel.projectPluginMap()
//
//        // todo: check module exists within project before trying to get it's data
//        return projectPluginMap[moduleName]?.toSet()
//
//    }
//
//    private fun copyInitScript(): File {
//        val init = Files.createTempFile("init", ".gradle")
//        val sb = StringBuilder()
//        val pluginJar = lookupJar(ConfigurationDependenciesModel::class.java)
//        val modelJar = lookupJar(DefaultDependenciesModel::class.java)
//        BufferedReader(
//            InputStreamReader(this::class.java.getResourceAsStream("/init.gradle"))
//        ).use { reader ->
//            reader.lines()
//                .forEach { line: String ->
//                    var repl = line
//                        .replace("%%PLUGIN_JAR%%", pluginJar.absolutePath)
//                        .replace("%%MODEL_JAR%%", modelJar.absolutePath)
//                        .replace("%%CUSTOM_JAR%%", modelJar.absolutePath)
//                    // fix paths if we're on Windows
//                    if (File.separatorChar == '\\') {
//                        repl = repl.replace('\\', '/')
//                    }
//                    sb.append(repl)
//                        .append("\n")
//                }
//        }
//        Files.copy(
//            ByteArrayInputStream(sb.toString().toByteArray(Charset.defaultCharset())),
//            init,
//            StandardCopyOption.REPLACE_EXISTING
//        )
//        return init.toFile()
//    }
//
//    @Throws(URISyntaxException::class)
//    private fun lookupJar(beaconClass: Class<*>): File {
//        val codeSource = beaconClass.protectionDomain.codeSource
//        return File(codeSource.location.toURI())
//    }
//
//    fun findArtifactForClassName(projectLocation: String, className: String): String {
//        val connection: ProjectConnection = GradleConnector.newConnector()
//            .forProjectDirectory(File(projectLocation))
//            .connect()
//
//        val customModelBuilder = connection.model(ConfigurationDependenciesModel::class.java)
//        customModelBuilder.withArguments("--init-script", copyInitScript().absolutePath)
//
//        // Fetch the custom model
//        val customModel: ConfigurationDependenciesModel = customModelBuilder.get()
//
//        val values = customModel.projectToExternalDependencyPaths().values
//        for (dependency in values.flatten()) {
//
//            try {
//                val filePath = dependency.split("__")[0]
//                val classNamesFromJarFile = getClassNamesFromJarFile(File(filePath))
//                if (classNamesFromJarFile.contains(className)) {
//                    return (dependency.split("__")[1]) // dependency co-ordinates
//                }
//            } catch (e: Exception) {
//                println(e)
//            }
//
//        }
//
//        return "NOT_FOUND"
//
//    }
//
//    fun findModuleDependencies(projectLocation: String, moduleName: String): Collection<String>? {
//        val connection: ProjectConnection = GradleConnector.newConnector()
//            .forProjectDirectory(File(projectLocation))
//            .connect()
//
//        val customModelBuilder = connection.model(ConfigurationDependenciesModel::class.java)
//        customModelBuilder.withArguments("--init-script", copyInitScript().absolutePath)
//
//        // Fetch the custom model
//        val customModel: ConfigurationDependenciesModel = customModelBuilder.get()
//
//        return customModel.projectToInternalDependencies()[moduleName]?.toSet()
//    }
//
//    fun getClassNamesFromJarFile(givenFile: File): Set<String> {
//        val classNames: MutableSet<String> = HashSet()
//        JarFile(givenFile).use { jarFile ->
//            val e: Enumeration<JarEntry> = jarFile.entries()
//            while (e.hasMoreElements()) {
//                val jarEntry: JarEntry = e.nextElement()
//                if (jarEntry.name.endsWith(".class")) {
//                    val className: String = jarEntry.name
//                        .replace("/", ".")
//                        .replace(".class", "")
//                    classNames.add(className)
//                }
//            }
//            return classNames
//        }
//    }


}
