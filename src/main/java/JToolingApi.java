import org.gradle.tooling.GradleConnector;
import org.gradle.tooling.model.DomainObjectSet;
import org.gradle.tooling.model.GradleProject;

import java.io.File;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

public class JToolingApi {
	//	fun findAllProjects(projectLocation: String): Collection<GradleProject> {
//		val connection = GradleConnector.newConnector()
//				.forProjectDirectory(File(projectLocation))
//				.connect()
//
//		val gradleProject = connection.use { it.getModel(GradleProject::class.java) }
//
//		val gradleProjects = gradleProject.children + gradleProject
//
//		return gradleProjects
//	}
	Collection<GradleProject> findAllProjects(String projectLocation) {
		var connection = GradleConnector.newConnector()
				.forProjectDirectory(new File(projectLocation))
				.connect();

		GradleProject gradleProject = connection.getModel(GradleProject.class);

		Set<GradleProject> gradleProjects = new HashSet<>(gradleProject.getChildren());
		gradleProjects.add(gradleProject);

		return gradleProjects;

	}
}
