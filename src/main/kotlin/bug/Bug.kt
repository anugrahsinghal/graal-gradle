package bug

import ToolingApi
import org.gradle.tooling.model.GradleProject
import org.gradle.tooling.model.GradleTask

val signalProject: String = System.getenv("HOME") + "/personal/Signal-Android"

fun main() {
    println("Hello Graal")
    val toolingApi = ToolingApi()
    val allProjects = toolingApi.findAllProjects(signalProject)
    printProjects(allProjects)
//
//    val allTasks = toolingApi.findAllTasks(signalProject)
//
//    printTasks(allTasks)
//
//    val buildTasks =
//        toolingApi.findAllTasks(signalProject, "build")
//
//    printTasks(buildTasks)
//
//    val failureReason =
//        toolingApi.runTaskAndGetFailureReason(
//            signalProject,
//            "tasks"
//        )
//
//    System.err.println(failureReason)
//
//    val failureReason2 =
//        toolingApi.runTaskAndGetFailureReason(
//            signalProject,
//            "version"
//        )
//
//    System.err.println(failureReason2)
//
//    val internalDependencies = toolingApi.findModuleDependencies(signalProject, "video-app")
//
//    println(internalDependencies)
//
//    val findArtifactForClassName = toolingApi.findArtifactForClassName(
//        signalProject,
//        "androidx.compose.ui.Modifier"
//    )
//    println(findArtifactForClassName)
//
//    val findPluginsAppliedToModule = toolingApi.findPluginsAppliedToModule(
//        System.getenv("HOME") + "/personal/Signal-Android/video/app",
//        "video-app"
//    )
//
//    println(findPluginsAppliedToModule)

}

private fun printTasks(tasks: Collection<GradleTask>) {
    // LaunchableGradleTask (type of GradleTask)
    tasks.forEach { task -> println("Project: ${task.project.name} --> TaskName: '${task.path}' Group: ${task.group}") }

}

private fun printProjects(projects: Collection<GradleProject>) {
    // LaunchableGradleTask (type of GradleTask)
    projects.forEach { project -> println("Path: '${project.path}' --> Directory: ${project.projectDirectory.path}") }

}