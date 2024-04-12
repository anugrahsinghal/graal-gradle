package bug

import org.gradle.tooling.GradleConnector

fun main() {
    println("Hello Graal")
    GradleConnector.newConnector()
}